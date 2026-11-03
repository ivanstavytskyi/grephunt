"""Correlate findings from one scan.

Code findings still merge on correlation_key. Dependency findings for the same
package merge when they share a vulnerability id, so GHSA, CVE, and SNYK rows
for one issue become one finding.
"""
from __future__ import annotations

import re

from grephunt.finding_model.record import Category, Finding, Severity

_RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

_VULN_ID = re.compile(
    r"\b(CVE-\d{4}-\d{4,}|GHSA(?:-[0-9a-z]{4}){3}|SNYK-[A-Z0-9]+(?:-[A-Z0-9]+){1,})\b",
    re.IGNORECASE,
)
_ECOSYSTEMS = {"npm", "pypi", "pip", "maven", "golang", "gem", "nuget", "cargo", "composer", "pub", "hex", "go"}


def normalize_package(name: str) -> str:
    """Package identity across scanners: lowercase, no purl, no trailing version."""
    text = (name or "").strip()
    if not text:
        return ""
    if text.lower().startswith("pkg:"):
        body = text.split(":", 1)[1].split("?", 1)[0]
        if "/" in body:
            body = body.split("/", 1)[1]
        text = body
    if text.startswith("@") and text.count("@") >= 2:
        text = text.rsplit("@", 1)[0]
    elif "@" in text and not text.startswith("@"):
        text = text.split("@", 1)[0]
    text = text.strip().lower()
    if "/" in text:
        head, tail = text.split("/", 1)
        if head in _ECOSYSTEMS and tail:
            text = tail
    return text


def _canon_id(value: str) -> str:
    token = value.strip()
    upper = token.upper()
    if upper.startswith("CVE-"):
        return upper
    if upper.startswith("GHSA-"):
        return token.lower()
    if upper.startswith("SNYK-"):
        return upper
    return upper


def vulnerability_ids(finding: Finding) -> set[str]:
    """CVE, GHSA, and SNYK ids mentioned on the finding."""
    chunks = [finding.rule_id or "", finding.title or "", *(finding.cve or [])]
    if finding.message:
        chunks.append(finding.message[:1500])
    if finding.description:
        chunks.append(finding.description[:1500])
    if finding.help_uri:
        chunks.append(finding.help_uri)
    found: set[str] = set()
    for chunk in chunks:
        for match in _VULN_ID.findall(chunk):
            found.add(_canon_id(match))
    return found


def _merge_pair(current: Finding, finding: Finding) -> Finding:
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
    if not kept.package:
        kept.package = finding.package or current.package
    if not kept.installed_version:
        kept.installed_version = finding.installed_version or current.installed_version
    if not kept.fixed_version:
        kept.fixed_version = finding.fixed_version or current.fixed_version
    if not kept.help_uri:
        kept.help_uri = finding.help_uri or current.help_uri
    return kept


def _merge_many(items: list[Finding]) -> Finding:
    kept = items[0].model_copy(deep=True)
    for other in items[1:]:
        kept = _merge_pair(kept, other)
    return kept


def _secret_summary(items: list[Finding]) -> Finding:
    """One row for the same secret rule repeated through a file."""
    kept = _merge_many(items)
    lines = sorted({item.location.start_line for item in items if item.location.start_line})
    if len(lines) <= 1:
        return kept
    first, last = lines[0], lines[-1]
    span = str(first) if first == last else f"{first}–{last}"
    note = f"{len(lines)} occurrences in this file (lines {span})"
    message = (kept.message or kept.title).rstrip()
    if note not in message:
        message = f"{message} — {note}"
    location = kept.location.model_copy(update={"start_line": first, "end_line": last})
    return kept.model_copy(update={"message": message, "location": location})


def _correlate_by_key(findings: list[Finding]) -> list[Finding]:
    groups: dict[str, list[Finding]] = {}
    for finding in findings:
        groups.setdefault(finding.correlation_key, []).append(finding)
    return [_merge_many(items) for items in groups.values()]


def _cluster_same_file_secrets(group: list[Finding]) -> list[Finding]:
    """Same rule anywhere in the file, or different rules on the same line."""
    parent = list(range(len(group)))

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(left: int, right: int) -> None:
        root_left, root_right = find(left), find(right)
        if root_left != root_right:
            parent[root_right] = root_left

    by_rule: dict[str, int] = {}
    by_line: dict[int, int] = {}
    for index, finding in enumerate(group):
        rule = finding.rule_id or ""
        if rule:
            previous = by_rule.get(rule)
            if previous is None:
                by_rule[rule] = index
            else:
                union(index, previous)
        line = finding.location.start_line
        if line:
            previous = by_line.get(line)
            if previous is None:
                by_line[line] = index
            else:
                union(index, previous)
    clusters: dict[int, list[Finding]] = {}
    for index, finding in enumerate(group):
        clusters.setdefault(find(index), []).append(finding)
    return [_secret_summary(items) for items in clusters.values()]


def _correlate_secrets(findings: list[Finding]) -> list[Finding]:
    by_path: dict[str, list[Finding]] = {}
    for finding in findings:
        by_path.setdefault(finding.location.path or "", []).append(finding)
    merged: list[Finding] = []
    for group in by_path.values():
        merged.extend(_cluster_same_file_secrets(group))
    return merged


def _cluster_by_shared_ids(group: list[Finding]) -> list[Finding]:
    """Merge rows of one package when any vulnerability id overlaps."""
    identified: list[Finding] = []
    anonymous: list[Finding] = []
    id_sets: list[set[str]] = []
    for finding in group:
        ids = vulnerability_ids(finding)
        if ids:
            identified.append(finding)
            id_sets.append(ids)
        else:
            anonymous.append(finding)
    parent = list(range(len(identified)))

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(left: int, right: int) -> None:
        root_left, root_right = find(left), find(right)
        if root_left != root_right:
            parent[root_right] = root_left

    owners: dict[str, int] = {}
    for index, ids in enumerate(id_sets):
        for vuln_id in ids:
            previous = owners.get(vuln_id)
            if previous is None:
                owners[vuln_id] = index
            else:
                union(index, previous)
    clusters: dict[int, list[Finding]] = {}
    for index, finding in enumerate(identified):
        clusters.setdefault(find(index), []).append(finding)
    merged: list[Finding] = []
    for items in clusters.values():
        kept = _merge_many(items)
        ids: set[str] = set()
        for item in items:
            ids |= vulnerability_ids(item)
        if ids:
            kept = kept.model_copy(update={"cve": sorted(ids)})
        merged.append(kept)
    return merged + _correlate_by_key(anonymous)


def _correlate_dependencies(findings: list[Finding]) -> list[Finding]:
    by_package: dict[str, list[Finding]] = {}
    loose: list[Finding] = []
    for finding in findings:
        name = normalize_package(finding.package or "")
        if not name:
            loose.append(finding)
            continue
        by_package.setdefault(name, []).append(finding)
    merged = _correlate_by_key(loose)
    for group in by_package.values():
        merged.extend(_cluster_by_shared_ids(group))
    return merged


def correlate(findings: list[Finding]) -> list[Finding]:
    """Keep the highest severity and union tools, CWE, and vulnerability ids."""
    code: list[Finding] = []
    secrets: list[Finding] = []
    dependencies: list[Finding] = []
    for finding in findings:
        if finding.category is Category.SECRET:
            secrets.append(finding)
        elif finding.category is Category.DEPENDENCY and finding.package:
            dependencies.append(finding)
        else:
            code.append(finding)
    return _correlate_by_key(code) + _correlate_secrets(secrets) + _correlate_dependencies(dependencies)
