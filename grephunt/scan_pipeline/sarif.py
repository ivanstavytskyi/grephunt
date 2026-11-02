"""Parse SARIF 2.1.0 into Finding records.

The shared parser understands standard fields. Tool-specific details belong
in a refine hook, which the task runner calls. This module does not.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import unquote, urlparse

from grephunt.finding_model.record import Category, Finding, Location, LocationKind, Module, Severity

_CWE_RE = re.compile(r"CWE-\d+")
_VULN_ID_RE = re.compile(r"\b(CVE-\d{4}-\d{4,}|GHSA(?:-[0-9a-z]{4}){3})\b", re.IGNORECASE)
_LEVEL_MAP = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "note": Severity.LOW,
    "none": Severity.INFO,
}
_SECRET_CWES = {"CWE-798", "CWE-259", "CWE-321", "CWE-312", "CWE-547"}
_SECRET_WORDS = re.compile(
    r"secret|token|password|passwd|private-key|api-key|apikey|credential|jwt",
    re.IGNORECASE,
)
_MISCONFIG_TAGS = {"misconfiguration", "iac", "terraform", "dockerfile", "kubernetes", "cloudformation"}


def _severity(result: dict, rule: dict) -> tuple[Severity, str | None]:
    """Unified severity, plus the original severity string from the tool."""
    props = {**rule.get("properties", {}), **result.get("properties", {})}
    score = props.get("security-severity")
    original: str | None = None
    for tag in rule.get("properties", {}).get("tags", []):
        if tag.lower() in Severity._value2member_map_:
            original = tag
            break
    if score is not None:
        original = original or str(score)
        try:
            value = float(score)
        except (TypeError, ValueError):
            value = None
        if value is not None:
            if value >= 9.0:
                return Severity.CRITICAL, original
            if value >= 7.0:
                return Severity.HIGH, original
            if value >= 4.0:
                return Severity.MEDIUM, original
            if value > 0:
                return Severity.LOW, original
            return Severity.INFO, original
    if original and original.lower() in Severity._value2member_map_:
        return Severity(original.lower()), original
    level = result.get("level") or rule.get("defaultConfiguration", {}).get("level", "warning")
    return _LEVEL_MAP.get(level, Severity.MEDIUM), str(level)


def _title(rule: dict, rule_id: str) -> str:
    short = (rule.get("shortDescription") or {}).get("text", "")
    if not short or short.startswith("Semgrep Finding"):
        short = (rule.get("fullDescription") or {}).get("text", "") or rule_id
    return (short or rule_id)[:2000]


def _category(rule_id: str, rule: dict, tags: list[str], cwe: list[str], cve: list[str]) -> Category:
    low_tags = {tag.lower() for tag in tags}
    name = (rule.get("name") or "").lower()
    if cve or ("vulnerability" in low_tags and "packagevulnerability" in name):
        return Category.DEPENDENCY
    if (
        "secret" in low_tags
        or name == "secret"
        or set(cwe) & _SECRET_CWES
        or (not cwe and _SECRET_WORDS.search(rule_id.rsplit(".", 1)[-1]))
    ):
        return Category.SECRET
    if low_tags & _MISCONFIG_TAGS or name == "misconfiguration":
        return Category.MISCONFIG
    return Category.CODE


def _relative_path(uri: str, project_root: Path | None) -> str:
    path = unquote(urlparse(uri).path) if uri.startswith("file:") else uri
    path = path.replace("\\", "/")
    prefixes = ["/src", "/out"]
    if project_root is not None:
        prefixes = [str(project_root.resolve()).replace("\\", "/"), str(project_root).replace("\\", "/"), *prefixes]
    for prefix in prefixes:
        if prefix and path.startswith(prefix):
            return path[len(prefix):].lstrip("/")
    return path.lstrip("/")


def _tool_version(run: dict) -> str | None:
    driver = run.get("tool", {}).get("driver", {})
    version = driver.get("semanticVersion") or driver.get("version")
    if version and str(version).lower() != "latest":
        return str(version)
    return None


def parse_sarif(
    sarif_path: Path,
    tool: str,
    project_root: Path | None = None,
    module: Module = Module.SAST,
    fallback_version: str | None = None,
    refine=None,
) -> list[Finding]:
    data = json.loads(sarif_path.read_text(encoding="utf-8"))
    findings: list[Finding] = []
    for run_index, run in enumerate(data.get("runs", [])):
        version = _tool_version(run) or fallback_version
        rules = {rule["id"]: rule for rule in run.get("tool", {}).get("driver", {}).get("rules", [])}
        for result_index, result in enumerate(run.get("results", [])):
            rule_id = result.get("ruleId", "unknown")
            rule = rules.get(rule_id, {})
            tags = rule.get("properties", {}).get("tags", [])
            location = (result.get("locations") or [{}])[0].get("physicalLocation", {})
            region = location.get("region", {})
            message = result.get("message", {}).get("text", "")
            cwe = sorted({match for tag in tags for match in _CWE_RE.findall(tag)})
            cve = sorted(
                {
                    match.upper() if match.upper().startswith("CVE") else match
                    for match in _VULN_ID_RE.findall(rule_id)
                }
            )
            severity, original = _severity(result, rule)
            uri = location.get("artifactLocation", {}).get("uri", "")
            finding = Finding(
                    module=module,
                    tool=tool,
                    tool_version=version,
                    rule_id=rule_id,
                    title=_title(rule, rule_id),
                    message=message,
                    severity=severity,
                    severity_original=original,
                    category=_category(rule_id, rule, tags, cwe, cve),
                    location=Location(
                        kind=LocationKind.FILE,
                        path=_relative_path(uri, project_root),
                        start_line=region.get("startLine"),
                        end_line=region.get("endLine"),
                    ),
                    snippet=(region.get("snippet") or {}).get("text"),
                    evidence="SARIF region" if region else "SARIF result",
                    cwe=cwe,
                    owasp=[tag for tag in tags if str(tag).startswith("OWASP")],
                    cve=cve,
                    help_uri=rule.get("helpUri"),
                    raw_ref=f"{sarif_path.name}#/runs/{run_index}/results/{result_index}",
                )
            if refine is not None:
                finding = refine(finding, result, rule)
            findings.append(finding)
    return findings
