"""Correlate findings from one scan by correlation_key."""
from __future__ import annotations

from grephunt.finding_model.record import Finding, Severity

_RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def correlate(findings: list[Finding]) -> list[Finding]:
    """Keep the highest severity and union tools, CWE, and CVE."""
    groups: dict[str, Finding] = {}
    for finding in findings:
        key = finding.correlation_key
        current = groups.get(key)
        if current is None:
            groups[key] = finding.model_copy(deep=True)
            continue
        tools = list(dict.fromkeys(current.tools + finding.tools))
        cwe = sorted(set(current.cwe) | set(finding.cwe))
        cve = sorted(set(current.cve) | set(finding.cve))
        owasp = sorted(set(current.owasp) | set(finding.owasp))
        if _RANK[finding.severity] < _RANK[current.severity]:
            kept = finding.model_copy(deep=True)
        else:
            kept = current
        kept.tools = tools
        kept.cwe = cwe
        kept.cve = cve
        kept.owasp = owasp
        if not kept.help_uri:
            kept.help_uri = finding.help_uri or current.help_uri
        groups[key] = kept
    return list(groups.values())
