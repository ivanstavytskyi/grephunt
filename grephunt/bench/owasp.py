"""Score findings against the OWASP Benchmark expected-results CSV.

A test is a true positive when the file is a real bug and a finding there
names the same CWE (or a CWE of the same kind, such as path traversal 22 and 23).
A hit on a test that is not a real bug is a false positive. Recall is
TP / (TP + FN). The false-positive rate is FP / (FP + TN). The benchmark
score is recall minus that rate.
"""
from __future__ import annotations

import csv
import re
from dataclasses import dataclass, field
from pathlib import Path

from grephunt.finding_model.record import Finding
from grephunt.finding_model.vuln_class import cwe_numbers

_TEST = re.compile(r"BenchmarkTest\d+")

# Same-kind CWE numbers. Crypto (327) stays separate from hash (328).
_SAME = {
    22: {22, 23, 35, 36, 73},
    78: {77, 78, 88},
    79: {79, 80, 83, 87},
    89: {89, 564, 566},
    90: {90},
    327: {327},
    328: {328, 916, 759, 760},
    330: {330, 338},
    501: {501},
    614: {614},
}


@dataclass
class OwaspTest:
    name: str
    category: str
    real: bool
    cwe: int


@dataclass
class CategoryScore:
    tp: int = 0
    fn: int = 0
    fp: int = 0
    tn: int = 0

    @property
    def recall(self) -> float:
        total = self.tp + self.fn
        return self.tp / total if total else 1.0

    @property
    def false_positive_rate(self) -> float:
        total = self.fp + self.tn
        return self.fp / total if total else 0.0


@dataclass
class OwaspScore:
    version: str
    tests: int
    tp: int
    fn: int
    fp: int
    tn: int
    by_category: dict[str, CategoryScore] = field(default_factory=dict)
    by_rule: dict[str, tuple[int, int]] = field(default_factory=dict)

    @property
    def recall(self) -> float:
        total = self.tp + self.fn
        return self.tp / total if total else 1.0

    @property
    def false_positive_rate(self) -> float:
        total = self.fp + self.tn
        return self.fp / total if total else 0.0

    @property
    def score(self) -> float:
        return self.recall - self.false_positive_rate


def load_owasp_csv(path: Path) -> tuple[str, list[OwaspTest]]:
    text = path.read_text(encoding="utf-8")
    version = "owasp-benchmark"
    tests: list[OwaspTest] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            marker = re.search(r"version:\s*([0-9.]+)", stripped, re.IGNORECASE)
            if marker:
                version = f"OWASP Benchmark {marker.group(1)}"
            continue
        row = next(csv.reader([stripped]))
        if len(row) < 4 or not row[0].startswith("BenchmarkTest"):
            continue
        tests.append(
            OwaspTest(
                name=row[0].strip(),
                category=row[1].strip(),
                real=row[2].strip().lower() == "true",
                cwe=int(row[3].strip()),
            )
        )
    if not tests:
        raise ValueError(f"{path} has no BenchmarkTest rows")
    return version, tests


def _test_name(path: str) -> str | None:
    match = _TEST.search(path.replace("\\", "/"))
    return match.group(0) if match else None


def _same_cwe(finding: Finding, cwe: int) -> bool:
    found = set(cwe_numbers(finding.cwe))
    return bool(found & _SAME.get(cwe, {cwe}))


def score_owasp(findings: list[Finding], tests: list[OwaspTest], version: str = "owasp-benchmark") -> OwaspScore:
    """Each test is hit once. A rule is counted once per test it hits."""
    by_name = {test.name: test for test in tests}
    hit_rules: dict[str, set[str]] = {}
    for finding in findings:
        name = _test_name(finding.location.path or "")
        test = by_name.get(name or "")
        if test is None or not _same_cwe(finding, test.cwe):
            continue
        hit_rules.setdefault(test.name, set()).add(finding.rule_id)

    categories: dict[str, CategoryScore] = {}
    rule_tp: dict[str, int] = {}
    rule_fp: dict[str, int] = {}
    tp = fn = fp = tn = 0
    for test in tests:
        row = categories.setdefault(test.category, CategoryScore())
        hit = test.name in hit_rules
        if test.real and hit:
            tp += 1
            row.tp += 1
            for rule in hit_rules[test.name]:
                rule_tp[rule] = rule_tp.get(rule, 0) + 1
        elif test.real:
            fn += 1
            row.fn += 1
        elif hit:
            fp += 1
            row.fp += 1
            for rule in hit_rules[test.name]:
                rule_fp[rule] = rule_fp.get(rule, 0) + 1
        else:
            tn += 1
            row.tn += 1
    rules = {
        rule: (rule_tp.get(rule, 0), rule_fp.get(rule, 0))
        for rule in sorted(set(rule_tp) | set(rule_fp))
    }
    return OwaspScore(
        version=version,
        tests=len(tests),
        tp=tp,
        fn=fn,
        fp=fp,
        tn=tn,
        by_category=categories,
        by_rule=rules,
    )


def format_owasp(result: OwaspScore) -> str:
    lines = [
        f"{result.version}: {result.tests} tests",
        f"found {result.tp}, missed {result.fn}, false positives {result.fp}, correctly ignored {result.tn}",
        f"recall {result.recall:.0%}  false positive rate {result.false_positive_rate:.0%}  score {result.score:.2f}",
        "by category:",
    ]
    for name, row in sorted(result.by_category.items()):
        lines.append(
            f"  {name}: recall {row.recall:.0%} ({row.tp}/{row.tp + row.fn}), "
            f"false positive rate {row.false_positive_rate:.0%} ({row.fp}/{row.fp + row.tn})"
        )
    if result.by_rule:
        lines.append("by rule:")
        ranked = sorted(result.by_rule.items(), key=lambda item: (-(item[1][0] + item[1][1]), item[0]))
        for rule, (rule_tp, rule_fp) in ranked[:15]:
            lines.append(f"  {rule}: found {rule_tp}, false positives {rule_fp}")
    return "\n".join(lines)
