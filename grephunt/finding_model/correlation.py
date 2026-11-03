"""Correlate findings from one scan.

Code findings still merge on correlation_key. Dependency findings for the same
package merge when they share a vulnerability id, so GHSA, CVE, and SNYK rows
for one issue become one finding.
"""
from __future__ import annotations

import re
from collections import Counter

from grephunt.finding_model.clustering import cluster_by_lines, cluster_by_text
from grephunt.finding_model.embeddings import EMBEDDING_THRESHOLD, similarity_matrix
from grephunt.finding_model.record import Category, Confirmation, Finding, Severity
from grephunt.finding_model.vuln_class import clean_path, iac_topic, vulnerability_class

CODE_WINDOW = 3
"""Lines apart that still count as one place in code (a statement split over lines, source and sink lines)."""
IAC_WINDOW = 15
"""Lines apart inside one infrastructure resource block."""
ANCHOR_WINDOW = 3
"""A finding within this many lines of a database call from the project map is placed on that call."""
ANCHORED_CLASSES = {"sql-injection", "nosql-injection"}

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


def _confirmations(items: list[Finding]) -> list[Confirmation]:
    seen: dict[tuple, Confirmation] = {}
    for item in items:
        for confirmation in item.confirmations or [Confirmation(tool=item.tool, rule_id=item.rule_id, title=item.title,
                                                                 line=item.location.start_line, severity=item.severity.value)]:
            seen.setdefault((confirmation.tool, confirmation.rule_id, confirmation.line), confirmation)
    return sorted(seen.values(), key=lambda item: (item.line or 0, item.tool, item.rule_id))


def _merge_cluster(items: list[Finding], line: int | None = None) -> Finding:
    """One finding for one problem: highest severity, union of tools and ids, every report kept as a confirmation."""
    confirmations = _confirmations(items)
    kept = _merge_many(items)
    update: dict = {"confirmations": confirmations}
    if line is not None and line != kept.location.start_line:
        end = kept.location.end_line
        update["location"] = kept.location.model_copy(update={"start_line": line, "end_line": max(line, end or line)})
    tools = len({item.tool for item in confirmations})
    if tools > 1:
        note = f"Reported by {tools} tools: " + ", ".join(dict.fromkeys(f"{item.tool} ({item.rule_id})" for item in confirmations))
        update["evidence"] = note[:600]
    return kept.model_copy(update=update)


def _place(items: list[Finding], anchors: set[int]) -> int | None:
    """Where the problem is: the database call the reports point at, else the line most tools name."""
    lines = [item.location.start_line for item in items if item.location.start_line]
    if not lines:
        return None
    near = [anchor for anchor in anchors if any(abs(anchor - line) <= ANCHOR_WINDOW for line in lines)]
    if near:
        return min(near, key=lambda anchor: (min(abs(anchor - line) for line in lines), anchor))
    votes = Counter(lines)
    return min(votes, key=lambda line: (-votes[line], line))


def _split_repeated_rules(cluster: list[Finding]) -> list[list[Finding]]:
    """One rule firing on two lines is two problems (two queries in a row): split around those lines."""
    by_source: dict[tuple[str, str], set[int]] = {}
    for item in cluster:
        if item.location.start_line:
            by_source.setdefault((item.tool, item.rule_id), set()).add(item.location.start_line)
    centers = max(by_source.values(), key=len, default=set())
    if len(centers) < 2:
        return [cluster]
    parts: dict[int, list[Finding]] = {center: [] for center in centers}
    loose: list[Finding] = []
    for item in cluster:
        line = item.location.start_line
        if line is None:
            loose.append(item)
            continue
        parts[min(centers, key=lambda center: (abs(center - line), center))].append(item)
    groups = [items for items in parts.values() if items]
    if loose:
        groups[0].extend(loose)
    return groups


def _snap(line: int | None, anchors: set[int]) -> int | None:
    if line is None or not anchors:
        return line
    near = [anchor for anchor in anchors if abs(anchor - line) <= ANCHOR_WINDOW]
    return min(near, key=lambda anchor: (abs(anchor - line), anchor)) if near else line


def _canonical_paths(findings: list[Finding]) -> dict[str, str]:
    """src/x and x in one scan are one file: some tools print the container mount without its slash."""
    paths = {clean_path(item.location.path or "") for item in findings}
    return {path: path[4:] for path in paths if path.startswith("src/") and path[4:] in paths}


def _correlate_places(findings: list[Finding], anchors: dict[str, set[int]]) -> list[Finding]:
    """Code and misconfiguration findings: one finding per problem and place."""
    classified: dict[tuple, list[Finding]] = {}
    unclassified: dict[tuple, list[Finding]] = {}
    canonical = _canonical_paths(findings)
    for finding in findings:
        path = clean_path(finding.location.path or finding.location.url or "")
        path = canonical.get(path, path)
        if finding.category is Category.MISCONFIG:
            kind = iac_topic(finding.rule_id, finding.title, finding.message)
        else:
            kind = vulnerability_class(finding.cwe, finding.rule_id, finding.title)
        key = (finding.category.value, finding.location.kind.value, path)
        if kind:
            classified.setdefault((*key, kind), []).append(finding)
        else:
            unclassified.setdefault(key, []).append(finding)

    merged: list[Finding] = []
    kinds: dict[int, str] = {}
    for (category, _, path, kind), group in classified.items():
        file_anchors = anchors.get(path, set()) if kind in ANCHORED_CLASSES else set()
        if category == Category.MISCONFIG.value:
            name = path.rsplit("/", 1)[-1].lower()
            window = None if name.startswith("dockerfile") or name.endswith(".dockerfile") else IAC_WINDOW
        else:
            window = CODE_WINDOW
        lines = [_snap(item.location.start_line, file_anchors) for item in group]
        for indices in cluster_by_lines(lines, window):
            for part in _split_repeated_rules([group[index] for index in indices]):
                finding = _merge_cluster(part, _place(part, file_anchors))
                kinds[id(finding)] = kind
                merged.append(finding)

    for (category, _, _path), group in unclassified.items():
        window = IAC_WINDOW if category == Category.MISCONFIG.value else CODE_WINDOW
        texts = [f"{item.rule_id} {item.title} {item.message[:300]}" for item in group]
        lines = [item.location.start_line for item in group]
        sources = [(item.tool, item.rule_id) for item in group]

        def same_source(left: int, right: int, sources: list[tuple[str, str]] = sources) -> bool:
            return sources[left] == sources[right]

        semantic = similarity_matrix([f"{item.title}. {item.message[:200]}" for item in group]) if len(group) > 1 else None
        for indices in cluster_by_text(texts, lines, window, same_source=same_source, semantic=semantic, semantic_threshold=EMBEDDING_THRESHOLD):
            part = [group[index] for index in indices]
            merged.append(_merge_cluster(part, _place(part, set())))
    return _fold_repeats(merged, kinds)


def _fold_repeats(findings: list[Finding], kinds: dict[int, str]) -> list[Finding]:
    """The same problem at several places in one file is one finding with a list of lines.

    "Unrestricted Security Group Ingress" on lines 13, 21, and 29 is one row to fix in one
    file; every line stays listed and highlighted in the code view.
    """
    by_file: dict[tuple, list[Finding]] = {}
    for finding in findings:
        kind = kinds.get(id(finding)) or "unclassified"
        by_file.setdefault((finding.category.value, clean_path(finding.location.path or ""), kind), []).append(finding)
    groups: list[list[Finding]] = []
    for items in by_file.values():
        # Fold only findings that share a rule: one check firing at several places.
        parent = list(range(len(items)))

        def find(index: int, parent: list[int] = parent) -> int:
            while parent[index] != index:
                parent[index] = parent[parent[index]]
                index = parent[index]
            return index

        owner: dict[tuple[str, str], int] = {}
        for index, item in enumerate(items):
            sources = {(confirmation.tool, confirmation.rule_id) for confirmation in item.confirmations} or {(item.tool, item.rule_id)}
            for source in sources:
                if source in owner:
                    parent[find(index)] = find(owner[source])
                else:
                    owner[source] = index
        clusters: dict[int, list[Finding]] = {}
        for index, item in enumerate(items):
            clusters.setdefault(find(index), []).append(item)
        groups.extend(clusters.values())
    folded: list[Finding] = []
    for items in groups:
        if len(items) == 1:
            folded.append(items[0])
            continue
        items.sort(key=lambda item: (item.location.start_line or 0))
        lines = sorted({item.location.start_line for item in items if item.location.start_line})
        kept = _merge_many(items)
        confirmations = _confirmations(items)
        first = lines[0] if lines else None
        update: dict = {"confirmations": confirmations, "lines": lines}
        if first is not None:
            update["location"] = kept.location.model_copy(update={"start_line": first, "end_line": first})
        note = f"{len(lines)} places in this file (lines {', '.join(map(str, lines[:20]))}{', …' if len(lines) > 20 else ''})"
        message = (kept.message or kept.title).rstrip()
        update["message"] = f"{message} — {note}" if note not in message else message
        tools = len({item.tool for item in confirmations})
        if tools > 1:
            update["evidence"] = ("Reported by " + f"{tools} tools: " + ", ".join(dict.fromkeys(f"{item.tool} ({item.rule_id})" for item in confirmations)))[:600]
        folded.append(kept.model_copy(update=update))
    return folded


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


_SEVERITY_PREFIX = re.compile(r"^(critical|high|medium|low) severity\s*-\s*", re.IGNORECASE)


def _version_key(version: str) -> tuple:
    return tuple((0, int(part)) if part.isdigit() else (1, part) for part in re.findall(r"\d+|[A-Za-z]+", version or ""))


def _advisory_title(finding: Finding) -> str:
    """What the advisory is about: 'Authentication Bypass vulnerability in jsonwebtoken', not 'jws@0.2.6'."""
    title = _SEVERITY_PREFIX.sub("", finding.title or "")
    package = finding.package or ""
    if not title or (package and title.startswith(f"{package}@")):
        return ""
    return title[:140]


def _fold_packages(findings: list[Finding]) -> list[Finding]:
    """One finding per vulnerable package: 13 sanitize-html advisories are one upgrade, not 13 rows.

    Each advisory (one CVE/GHSA/SNYK group, already merged across tools) stays listed in
    confirmations and the message; the finding takes the worst severity and the fix
    version that closes all of them.
    """
    groups: dict[str, list[Finding]] = {}
    for finding in findings:
        groups.setdefault(normalize_package(finding.package or ""), []).append(finding)
    folded: list[Finding] = []
    for name, items in groups.items():
        if not name or len(items) == 1:
            folded.extend(items)
            continue
        items.sort(key=lambda item: _RANK[item.severity])
        kept = _merge_many(items)
        versions = sorted({version.strip() for item in items for version in (item.installed_version or "").split(",") if version.strip()}, key=_version_key)
        fixes = [item.fixed_version for item in items if item.fixed_version]
        best_fix = max(fixes, key=_version_key) if fixes else None
        confirmations: list[Confirmation] = []
        lines: list[str] = []
        for item in items:
            ids = sorted(vulnerability_ids(item)) or [item.rule_id]
            primary = next((value for value in ids if value.startswith("CVE-")), ids[0])
            about = _advisory_title(item)
            confirmations.append(Confirmation(tool="+".join(item.tools), rule_id=primary, title=about, severity=item.severity.value))
            fix = f" (fixed in {item.fixed_version})" if item.fixed_version else ""
            lines.append(f"- {item.severity.value} {', '.join(ids[:3])}{': ' + about if about else ''}{fix}")
        package = items[0].package or name
        version_text = versions[0] if len(versions) == 1 else f"({', '.join(versions)})" if versions else ""
        at = f"@{version_text}" if len(versions) == 1 else f" {version_text}" if version_text else ""
        notes = sorted({item.evidence for item in items if item.evidence and item.evidence.startswith("Fix:")})
        message = f"{len(items)} vulnerabilities in {package}" + (f"; upgrading to {best_fix} fixes those with a known fix." if best_fix else ".")
        message += "\n" + "\n".join(lines)
        if notes:
            message += "\n" + "\n".join(notes)
        folded.append(kept.model_copy(update={
            "title": f"{package}{at} — {len(items)} vulnerabilities",
            "message": message,
            "installed_version": ", ".join(versions) or kept.installed_version,
            "fixed_version": best_fix,
            "confirmations": confirmations,
            "evidence": "; ".join(notes)[:600] if notes else kept.evidence,
        }))
    return folded


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


def correlate(findings: list[Finding], anchors: dict[str, set[int]] | None = None) -> list[Finding]:
    """Keep the highest severity and union tools, CWE, and vulnerability ids.

    anchors: project-relative path -> lines of database calls from the project map.
    Code findings near such a call are placed on it, so a SQL injection reported on
    the input line by one tool and on the query line by another is one finding.
    """
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
    return _correlate_places(code, anchors or {}) + _correlate_secrets(secrets) + _fold_packages(_correlate_dependencies(dependencies))
