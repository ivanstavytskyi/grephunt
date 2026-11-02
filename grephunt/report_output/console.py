"""Text summary for the CLI. Prints the result. Progress arrives as events."""
from __future__ import annotations

from collections import Counter

from grephunt.finding_model.record import Finding, ScanResult, Severity

_ORDER = [severity.value for severity in Severity]


def _describe(finding: Finding) -> str:
    if finding.package:
        fix = f" -> {finding.fixed_version}" if finding.fixed_version else " (no fix available)"
        cve = ",".join(finding.cve) or finding.rule_id
        return f"{finding.package}@{finding.installed_version}{fix}  {cve}"
    cwe = f" {','.join(finding.cwe)}" if finding.cwe else ""
    return f"{finding.rule_id.split('.')[-1]}{cwe}"


def render_summary(result: ScanResult) -> str:
    lines: list[str] = []
    for run in result.runs:
        line = f"[{run.tool}] {run.status.value} in {run.duration_sec:.1f}s, findings: {len(run.findings)}"
        if run.tool_version:
            line += f", version {run.tool_version}"
        if run.error:
            line += f"\n  error: {run.error}"
        lines.append(line)

    findings = sorted(
        result.findings,
        key=lambda finding: (_ORDER.index(finding.severity.value), -len(finding.tools), finding.location.label),
    )
    confirmed = sum(1 for finding in findings if len(finding.tools) > 1)
    tail = f" (confirmed by more than one scanner: {confirmed})" if confirmed else ""
    lines.append(
        f"\nFindings from scanners: {result.raw_total}, excluded: {result.excluded}, "
        f"after correlation: {len(findings)}{tail}"
    )
    counts = Counter(finding.severity.value for finding in findings)
    lines.append("  " + "  ".join(f"{name}: {counts[name]}" for name in _ORDER if counts[name]))
    by_cat = Counter(finding.category.value for finding in findings)
    if by_cat:
        lines.append("  " + "  ".join(f"{name}: {count}" for name, count in by_cat.most_common()))
    width = max((len("+".join(finding.tools)) for finding in findings), default=8)
    for finding in findings:
        lines.append(
            f"  [{finding.severity.value.upper():8}] {'+'.join(finding.tools):{width}} "
            f"{finding.location.label}  {_describe(finding)}"
        )
    if result.merged_sarif:
        lines.append(f"\nSARIF: {result.merged_sarif}")
    return "\n".join(lines)
