"""Grype and OSV-Scanner: SARIF readers for package, version, and fixed version.

Both tools describe the package only in prose (a message or a help table).
These hooks read it back so that a Grype, OSV-Scanner, and Trivy finding for
the same package, version, and CVE share one identity and merge.
"""
from __future__ import annotations

import re

from grephunt.finding_model.record import Category, Finding, Severity
from grephunt.scanner_hooks.generic import GenericHook

_CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)

# Grype severity words. negligible and unknown have no CVSS meaning.
_GRYPE_SEVERITY = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "negligible": Severity.INFO,
    "unknown": Severity.MEDIUM,
}


def _field(text: str, label: str) -> str | None:
    match = re.search(rf"^{re.escape(label)}:[ \t]*(.*)$", text, re.MULTILINE)
    if not match:
        return None
    value = match.group(1).strip()
    return value or None


class GrypeHook(GenericHook):
    def refine_finding(self, finding: Finding, result: dict, rule: dict) -> Finding:
        help_text = str((rule.get("help") or {}).get("text") or "")
        label = (_field(help_text, "Severity") or "").lower()
        package = _field(help_text, "Package")
        update: dict = {"category": Category.DEPENDENCY}
        if package:
            update["package"] = package
        version = _field(help_text, "Version")
        if version:
            update["installed_version"] = version
        fixed = _field(help_text, "Fix Version")
        if fixed:
            update["fixed_version"] = fixed
        if label in _GRYPE_SEVERITY:
            # security-severity in Grype SARIF is the CVSS score, which can disagree with Grype's label.
            update["severity"] = _GRYPE_SEVERITY[label]
            update["severity_original"] = label
        return finding.model_copy(update=update)


_OSV_PACKAGE = re.compile(r"Package '(?P<name>.+)@(?P<version>[^@']+)' is vulnerable to")


def _osv_fixed(help_text: str, package: str) -> str | None:
    """The 'Fixed Versions' table: | Vulnerability ID | Package Name | Fixed Version |."""
    section = help_text.split("### Fixed Versions", 1)
    if len(section) < 2:
        return None
    versions: list[str] = []
    for line in section[1].splitlines():
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) == 3 and cells[1] == package and cells[2] and cells[2] not in versions:
            versions.append(cells[2])
    return ",".join(versions) or None


class OsvScannerHook(GenericHook):
    def refine_finding(self, finding: Finding, result: dict, rule: dict) -> Finding:
        message = str((result.get("message") or {}).get("text") or "")
        update: dict = {"category": Category.DEPENDENCY}
        aliases = [str(item) for item in rule.get("deprecatedIds") or []]
        cves = sorted({match.upper() for item in [finding.rule_id, *aliases] for match in _CVE.findall(item)})
        if cves:
            update["cve"] = cves
        match = _OSV_PACKAGE.search(message)
        if match:
            update["package"] = match.group("name")
            update["installed_version"] = match.group("version")
            fixed = _osv_fixed(str((rule.get("help") or {}).get("text") or ""), match.group("name"))
            if fixed:
                update["fixed_version"] = fixed
        return finding.model_copy(update=update)
