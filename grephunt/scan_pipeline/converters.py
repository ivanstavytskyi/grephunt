"""Tool reports that are not SARIF, converted to SARIF 2.1.0.

The parser in sarif.py reads severity from security-severity, CWE from rule
tags, and the code from region.snippet. A converter fills those fields, and
puts the tool's own severity word in result properties as tool-severity.

A converter must not copy secret values into the SARIF: secret scanners
report where a secret is, and the value stays in the scanned code.
"""
from __future__ import annotations

import json
from typing import Callable

# Unified severity -> (SARIF level, security-severity).
_LEVEL = {
    "critical": ("error", "9.5"),
    "high": ("error", "8.0"),
    "medium": ("warning", "5.5"),
    "low": ("note", "3.0"),
    "info": ("none", "0.0"),
}


class SarifBuilder:
    def __init__(self, tool: str, version: str, information_uri: str | None = None) -> None:
        self.tool = tool
        self.version = version
        self.information_uri = information_uri
        self.rules: dict[str, dict] = {}
        self.results: list[dict] = []

    def add(
        self,
        *,
        rule_id: str,
        title: str,
        severity: str,
        path: str,
        message: str | None = None,
        start_line: int | None = None,
        end_line: int | None = None,
        start_column: int | None = None,
        end_column: int | None = None,
        snippet: str | None = None,
        cwe: list[str] | None = None,
        tags: list[str] | None = None,
        description: str | None = None,
        help_uri: str | None = None,
        tool_severity: str | None = None,
        fingerprint: str | None = None,
    ) -> None:
        level, score = _LEVEL.get(severity, _LEVEL["medium"])
        if rule_id not in self.rules:
            rule: dict = {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": title},
                "fullDescription": {"text": title},
                "defaultConfiguration": {"level": level},
                "properties": {
                    "tags": [*(cwe or []), *(tags or []), "security"],
                    "security-severity": score,
                },
            }
            if description:
                rule["help"] = {"text": description, "markdown": description}
            if help_uri:
                rule["helpUri"] = help_uri
            self.rules[rule_id] = rule
        region: dict = {}
        if isinstance(start_line, int) and start_line > 0:
            region["startLine"] = start_line
            region["endLine"] = end_line if isinstance(end_line, int) and end_line >= start_line else start_line
        if isinstance(start_column, int) and start_column > 0:
            region["startColumn"] = start_column
        if isinstance(end_column, int) and end_column > 0:
            region["endColumn"] = end_column
        if snippet and snippet.strip():
            region["snippet"] = {"text": snippet.strip()}
        result: dict = {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": message or title},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": path}, "region": region}}],
            "properties": {"security-severity": score},
        }
        if tool_severity:
            result["properties"]["tool-severity"] = tool_severity
        if fingerprint:
            result["partialFingerprints"] = {f"{self.tool.lower()}/v1": fingerprint}
        self.results.append(result)

    def document(self) -> dict:
        driver: dict = {"name": self.tool, "semanticVersion": self.version, "rules": list(self.rules.values())}
        if self.information_uri:
            driver["informationUri"] = self.information_uri
        return {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{"tool": {"driver": driver}, "results": self.results}],
        }


def _load_json(text: str) -> object:
    stripped = text.strip()
    if not stripped or stripped == "null":
        return {}
    return json.loads(stripped)


def _bandit_snippet(code: object, lines: list[int]) -> str | None:
    """Bandit prefixes each context line with its number. Keep only the flagged lines."""
    if not isinstance(code, str):
        return None
    wanted = set(lines)
    kept: list[str] = []
    for line in code.splitlines():
        number, _, text = line.partition(" ")
        if number.isdigit() and int(number) in wanted:
            kept.append(text)
    return "\n".join(kept) if kept else None


def bandit_json(text: str, descriptor) -> dict:
    report = _load_json(text)
    if not isinstance(report, dict):
        raise ValueError("the Bandit report is not a JSON object")
    sarif = SarifBuilder("Bandit", descriptor.version, "https://bandit.readthedocs.io")
    for item in report.get("results") or []:
        if not isinstance(item, dict) or not item.get("test_id"):
            continue
        severity = str(item.get("issue_severity") or "MEDIUM").lower()
        if severity not in _LEVEL:
            severity = "medium"
        confidence = str(item.get("issue_confidence") or "").upper()
        cwe_id = (item.get("issue_cwe") or {}).get("id") if isinstance(item.get("issue_cwe"), dict) else None
        line = item.get("line_number") if isinstance(item.get("line_number"), int) else None
        line_range = [value for value in item.get("line_range") or [] if isinstance(value, int)] or ([line] if line else [])
        test_id = str(item["test_id"])
        test_name = str(item.get("test_name") or test_id)
        sarif.add(
            rule_id=test_id,
            title=f"{test_id} {test_name}",
            message=str(item.get("issue_text") or test_name),
            severity=severity,
            path=str(item.get("filename") or ""),
            start_line=line,
            end_line=max(line_range) if line_range else line,
            start_column=(item.get("col_offset") + 1) if isinstance(item.get("col_offset"), int) and item["col_offset"] >= 0 else None,
            snippet=_bandit_snippet(item.get("code"), line_range),
            cwe=[f"CWE-{cwe_id}"] if isinstance(cwe_id, int) and cwe_id > 0 else [],
            help_uri=item.get("more_info") if isinstance(item.get("more_info"), str) else None,
            tool_severity=f"{severity.upper()}, confidence {confidence}" if confidence else severity.upper(),
        )
    return sarif.document()


def cyclonedx_sbom(text: str, descriptor) -> dict:
    """An SBOM is an inventory, not a list of problems. The SBOM file stays in the scan directory;
    the SARIF for it is empty."""
    document = _load_json(text)
    if not isinstance(document, dict) or document.get("bomFormat") != "CycloneDX":
        raise ValueError("the SBOM is not CycloneDX JSON")
    return SarifBuilder("Syft", descriptor.version, "https://github.com/anchore/syft").document()


def _trufflehog_location(metadata: object) -> tuple[str, int | None]:
    data = metadata.get("Data") if isinstance(metadata, dict) else None
    if not isinstance(data, dict):
        return "", None
    for source in data.values():
        if isinstance(source, dict):
            path = source.get("file") or source.get("File") or ""
            line = source.get("line") or source.get("Line")
            return str(path), line if isinstance(line, int) else None
    return "", None


def trufflehog_jsonl(text: str, descriptor) -> dict:
    """One JSON object per line. Raw, RawV2, and SecretParts hold the secret and are never copied."""
    sarif = SarifBuilder("TruffleHog", descriptor.version, "https://github.com/trufflesecurity/trufflehog")
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        item = json.loads(line)
        if not isinstance(item, dict) or not item.get("DetectorName"):
            continue
        path, number = _trufflehog_location(item.get("SourceMetadata"))
        detector = str(item["DetectorName"])
        verified = bool(item.get("Verified"))
        extra = item.get("ExtraData") if isinstance(item.get("ExtraData"), dict) else {}
        kind = extra.get("token_type") or extra.get("Type")
        title = f"{detector} {kind}" if kind else f"{detector} credential"
        sarif.add(
            rule_id=f"trufflehog.{detector.lower()}",
            title=title,
            message=f"{title} ({'verified live' if verified else 'not verified'})",
            severity="critical" if verified else "high",
            path=path,
            start_line=number,
            tags=["secret"],
            description=item.get("DetectorDescription") if isinstance(item.get("DetectorDescription"), str) else None,
            help_uri=extra.get("rotation_guide") if isinstance(extra.get("rotation_guide"), str) else None,
            tool_severity="verified" if verified else "unverified",
        )
    return sarif.document()


def secretlint_json(text: str, descriptor) -> dict:
    """ESLint-style JSON. sourceContent is the whole file, secrets included, and is never copied."""
    report = _load_json(text)
    files = report if isinstance(report, list) else []
    sarif = SarifBuilder("Secretlint", descriptor.version, "https://github.com/secretlint/secretlint")
    for entry in files:
        if not isinstance(entry, dict):
            continue
        path = str(entry.get("filePath") or "")
        for message in entry.get("messages") or []:
            if not isinstance(message, dict) or not message.get("ruleId"):
                continue
            start = (message.get("loc") or {}).get("start") or {}
            end = (message.get("loc") or {}).get("end") or {}
            level = str(message.get("severity") or "error").lower()
            sarif.add(
                rule_id=str(message["ruleId"]),
                title=str(message.get("messageId") or message["ruleId"]),
                message=str(message.get("message") or message["ruleId"]),
                severity="high" if level == "error" else "medium" if level == "warning" else "low",
                path=path,
                start_line=start.get("line") if isinstance(start.get("line"), int) else None,
                end_line=end.get("line") if isinstance(end.get("line"), int) else None,
                start_column=start["column"] + 1 if isinstance(start.get("column"), int) else None,
                tags=["secret"],
                help_uri=message.get("docsUrl") if isinstance(message.get("docsUrl"), str) else None,
                tool_severity=level,
            )
    return sarif.document()


CONVERTERS: dict[str, Callable[[str, object], dict]] = {
    "bandit-json": bandit_json,
    "cyclonedx-sbom": cyclonedx_sbom,
    "secretlint-json": secretlint_json,
    "trufflehog-jsonl": trufflehog_jsonl,
}


def convert(name: str, text: str, descriptor) -> dict:
    try:
        converter = CONVERTERS[name]
    except KeyError as exc:
        raise ValueError(f"unknown output format: {name}") from exc
    return converter(text, descriptor)
