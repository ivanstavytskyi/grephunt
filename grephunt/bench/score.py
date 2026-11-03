"""True positives, false positives, and misses for one findings file.

An expected case is found when a finding points at the same file and the same
kind of bug (CWE, or the class that CWE belongs to, such as command injection).
A line number is optional and matches a few lines either side. Extra findings
count as false positives. Nothing is deleted.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from grephunt.finding_model.record import Finding
from grephunt.finding_model.vuln_class import vulnerability_class


@dataclass
class ExpectedBug:
    id: str
    path: str
    cwe: str | None = None
    cve: str | None = None
    line: int | None = None
    window: int = 8
    rule_contains: str | None = None


@dataclass
class ToolScore:
    tp: int = 0
    fp: int = 0


@dataclass
class BenchScore:
    name: str
    tp: int
    fp: int
    fn: int
    matched: list[tuple[str, str]] = field(default_factory=list)
    missed: list[str] = field(default_factory=list)
    extras: list[str] = field(default_factory=list)
    by_tool: dict[str, ToolScore] = field(default_factory=dict)
    by_rule: dict[str, ToolScore] = field(default_factory=dict)
    complete: bool = True
    other: int = 0
    other_rules: list[tuple[str, int]] = field(default_factory=list)
    found: list[str] = field(default_factory=list)
    confirmed: int = 0

    @property
    def precision(self) -> float:
        total = self.tp + self.fp
        return self.tp / total if total else 1.0

    @property
    def recall(self) -> float:
        total = self.tp + self.fn
        return self.tp / total if total else 1.0


def load_findings(path: Path) -> list[Finding]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    rows = payload.get("findings") if isinstance(payload, dict) else payload
    if not isinstance(rows, list):
        raise ValueError(f"{path} does not contain a findings list")
    return [Finding.model_validate(item) for item in rows if isinstance(item, dict)]


def load_expected(path: Path) -> tuple[str, list[ExpectedBug], bool]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError(f"{path} must be a mapping with a cases list")
    cases = []
    for item in raw.get("cases") or []:
        if not isinstance(item, dict) or not item.get("id") or not item.get("path"):
            raise ValueError(f"{path} has a case without id and path")
        cases.append(
            ExpectedBug(
                id=str(item["id"]),
                path=str(item["path"]).replace("\\", "/"),
                cwe=str(item["cwe"]) if item.get("cwe") else None,
                cve=str(item["cve"]).upper() if item.get("cve") else None,
                line=int(item["line"]) if item.get("line") is not None else None,
                window=int(item.get("window") or 8),
                rule_contains=str(item["rule_contains"]) if item.get("rule_contains") else None,
            )
        )
    return str(raw.get("name") or path.stem), cases, bool(raw.get("complete", True))


def _norm(path: str) -> str:
    return path.replace("\\", "/").lstrip("./")


def _same_file(finding_path: str, expected_path: str) -> bool:
    found = _norm(finding_path)
    want = _norm(expected_path)
    return found == want or found.endswith("/" + want)


def _cwe_id(value: str) -> str:
    text = value.upper()
    marker = text.find("CWE-")
    if marker == -1:
        return text
    rest = text[marker + 4 :]
    digits = []
    for char in rest:
        if char.isdigit():
            digits.append(char)
        else:
            break
    return f"CWE-{''.join(digits)}" if digits else text


def _kind_matches(finding: Finding, expected: ExpectedBug) -> bool:
    if expected.cve:
        return expected.cve in {item.upper() for item in finding.cve}
    if not expected.cwe:
        return True
    want = _cwe_id(expected.cwe)
    if any(_cwe_id(item) == want for item in finding.cwe):
        return True
    expected_class = vulnerability_class([want], "", "")
    found_class = vulnerability_class(finding.cwe, finding.rule_id, finding.title)
    return bool(expected_class and expected_class == found_class)


def _line_matches(finding: Finding, expected: ExpectedBug) -> bool:
    if expected.line is None:
        return True
    lines = [finding.location.start_line, *(finding.lines or [])]
    return any(isinstance(line, int) and abs(line - expected.line) <= expected.window for line in lines)


def _rule_matches(finding: Finding, expected: ExpectedBug) -> bool:
    if not expected.rule_contains:
        return True
    return expected.rule_contains.lower() in finding.rule_id.lower()


def _distance(finding: Finding, expected: ExpectedBug) -> int:
    if expected.line is None:
        return 0
    primary = finding.location.path or ""
    if not _same_file(primary, expected.path):
        return expected.window
    lines = [finding.location.start_line, *(finding.lines or [])]
    distances = [abs(line - expected.line) for line in lines if isinstance(line, int)]
    return min(distances) if distances else expected.window


def matches(finding: Finding, expected: ExpectedBug) -> bool:
    primary = finding.location.path or ""
    on_primary = _same_file(primary, expected.path)
    on_copy = any(_same_file(path, expected.path) for path in finding.copies or [])
    if not on_primary and not on_copy:
        return False
    if not _kind_matches(finding, expected) or not _rule_matches(finding, expected):
        return False
    if on_primary:
        return _line_matches(finding, expected)
    return True


def score_findings(
    findings: list[Finding],
    cases: list[ExpectedBug],
    name: str = "scan",
    *,
    complete: bool = True,
) -> BenchScore:
    """Each expected bug consumes at most one finding.

    When the list is complete, every other finding is a false positive.
    When it only names the bugs we already know, the rest stay unscored.
    """
    used: set[int] = set()
    matched: list[tuple[str, str]] = []
    missed: list[str] = []
    found: list[str] = []
    by_tool: dict[str, ToolScore] = {}
    by_rule: dict[str, ToolScore] = {}

    def bucket(table: dict[str, ToolScore], key: str) -> ToolScore:
        return table.setdefault(key, ToolScore())

    for case in cases:
        candidates = [
            (_distance(finding, case), index)
            for index, finding in enumerate(findings)
            if index not in used and matches(finding, case)
        ]
        if not candidates:
            missed.append(case.id)
            continue
        _, hit = min(candidates)
        used.add(hit)
        finding = findings[hit]
        matched.append((case.id, finding.fingerprint))
        found.append(f"{case.id} via {finding.tool} {finding.rule_id}")
        bucket(by_tool, finding.tool).tp += 1
        bucket(by_rule, finding.rule_id).tp += 1
    extras = []
    confirmed = 0
    other_counts: dict[str, int] = {}
    for index, finding in enumerate(findings):
        if index in used:
            continue
        if any(matches(finding, case) for case in cases):
            confirmed += 1
            continue
        label = f"{finding.tool} {finding.rule_id} {finding.location.path or ''}:{finding.location.start_line or ''}"
        extras.append(label)
        if complete:
            bucket(by_tool, finding.tool).fp += 1
            bucket(by_rule, finding.rule_id).fp += 1
        else:
            other_counts[finding.rule_id] = other_counts.get(finding.rule_id, 0) + 1
    top_rules = sorted(other_counts.items(), key=lambda item: (-item[1], item[0]))[:12]
    return BenchScore(
        name=name,
        tp=len(matched),
        fp=len(extras) if complete else 0,
        fn=len(missed),
        matched=matched,
        missed=missed,
        extras=extras if complete else [],
        by_tool=by_tool,
        by_rule=by_rule,
        complete=complete,
        other=0 if complete else len(extras),
        other_rules=top_rules,
        found=found,
        confirmed=confirmed,
    )


def format_score(result: BenchScore) -> str:
    if result.complete:
        lines = [
            f"{result.name}: found {result.tp}, missed {result.fn}, extra {result.fp}"
            + (f", confirmed by another tool {result.confirmed}" if result.confirmed else ""),
            f"precision {result.precision:.0%}  recall {result.recall:.0%}",
        ]
    else:
        lines = [
            f"{result.name}: found {result.tp} of {result.tp + result.fn}, missed {result.fn}",
            f"recall {result.recall:.0%}",
            f"other findings: {result.other} (this list names known bugs only)",
        ]
    if result.found:
        lines.append("found:")
        lines.extend(f"  {item}" for item in result.found)
    if result.missed:
        lines.append("missed: " + ", ".join(result.missed))
    if result.by_tool:
        lines.append("by scanner:")
        for name, row in sorted(result.by_tool.items()):
            extra = f", extra {row.fp}" if result.complete else ""
            lines.append(f"  {name}: found {row.tp}{extra}")
    if result.other_rules:
        lines.append("most common other rules:")
        for rule, count in result.other_rules:
            lines.append(f"  {count} {rule}")
    return "\n".join(lines)
