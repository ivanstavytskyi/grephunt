"""Source lines around a finding, with marks that explain it.

Only files inside the scanned folder are read. Marks come from the project
map (where request input enters, the route, the database call) and from the
other findings in the same file.
"""
from __future__ import annotations

import json
from pathlib import Path, PurePosixPath

MAX_FILE_BYTES = 2_000_000
MAX_LINES = 2_000
MAX_MARKS = 200

LANGUAGES = {
    ".py": "python", ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".php": "php", ".go": "go", ".java": "java", ".kt": "kotlin",
    ".rb": "ruby", ".cs": "csharp", ".tf": "terraform", ".hcl": "terraform", ".yml": "yaml", ".yaml": "yaml",
    ".json": "json", ".xml": "xml", ".html": "html", ".sh": "shell", ".sql": "sql", ".c": "c", ".cpp": "cpp",
    ".rs": "rust", ".toml": "toml", ".ini": "ini", ".properties": "ini",
}


class SourceUnavailable(Exception):
    """The scan has no readable source for this path (image scan, deleted folder, outside the target)."""


def relative_path(target: Path, raw: str) -> str:
    """Finding paths can be relative, absolute inside the container (/src/...), or absolute on this machine."""
    from grephunt.project_map.finding_context import clean_path

    value = raw.replace("\\", "/").strip()
    root = target.resolve().as_posix().rstrip("/") + "/"
    value = value.removeprefix(root)
    return clean_path(value)


def resolve_inside(target: Path, raw: str) -> tuple[Path, str]:
    if not target.is_dir():
        raise SourceUnavailable("the scanned folder is no longer on this machine")
    relative = relative_path(target, raw)
    if not relative:
        raise SourceUnavailable("the finding has no file path")
    root = target.resolve()
    path = (root / relative).resolve()
    if not path.is_relative_to(root):
        raise SourceUnavailable("the path is outside the scanned folder")
    if not path.is_file():
        raise SourceUnavailable("the file is not in the scanned folder")
    return path, PurePosixPath(path.relative_to(root).as_posix()).as_posix()


def _map_marks(project_map: dict, relative: str) -> list[dict]:
    marks: list[dict] = []
    architecture = project_map.get("architecture") or {}
    labels = {node["id"]: node.get("label", node["id"]) for node in architecture.get("nodes", [])}
    for edge in architecture.get("edges", []):
        for evidence in edge.get("evidence", []):
            if evidence.get("path") != relative or not evidence.get("line"):
                continue
            kind = edge.get("kind")
            if kind == "db":
                dynamic = "(dynamic)" in (edge.get("label") or "")
                marks.append({"line": evidence["line"], "kind": "sink", "label": f"database call → {labels.get(edge['target'], edge['target'])}" + (" · query built from variables" if dynamic else "")})
            elif kind == "handles":
                marks.append({"line": evidence["line"], "kind": "route", "label": labels.get(edge["source"], edge["source"])})
            elif kind == "http":
                marks.append({"line": evidence["line"], "kind": "call", "label": f"calls {labels.get(edge['target'], edge['target'])}"})
    for node in architecture.get("nodes", []):
        meta = node.get("meta") or {}
        handler = str(meta.get("handler") or "")
        if node.get("kind") != "route" or not (handler.startswith(relative + ":") or (node.get("path") == relative)):
            continue
        for param in meta.get("params", []):
            if param.get("line"):
                marks.append({"line": param["line"], "kind": "input", "label": f"request input {param['source']}.{param['name']} ({node.get('label')})"})
    # Several edges can point at one line; keep one mark per (line, kind, label).
    unique = {(mark["line"], mark["kind"], mark["label"]): mark for mark in marks}
    return sorted(unique.values(), key=lambda mark: mark["line"])


def read_source(target: Path, raw_path: str, line: int | None, end_line: int | None, context: int,
                findings: list[dict], project_map: dict) -> dict:
    path, relative = resolve_inside(target, raw_path)
    size = path.stat().st_size
    if size > MAX_FILE_BYTES:
        raise SourceUnavailable(f"the file is too large to show ({size // 1024} KB)")
    data = path.read_bytes()
    if b"\x00" in data[:8192]:
        raise SourceUnavailable("the file is binary")
    lines = data.decode("utf-8", errors="replace").splitlines()
    total = len(lines)
    focus = max(1, min(line or 1, total or 1))
    focus_end = max(focus, min(end_line or focus, total or focus))
    if context <= 0:
        start, end = 1, min(total, MAX_LINES)
    else:
        start = max(1, focus - context)
        end = min(total, focus_end + context, start + MAX_LINES - 1)

    marks = _map_marks(project_map, relative)
    for item in findings:
        location = item.get("location") or {}
        if not location.get("path") or relative_path(target, location["path"]) != relative or not location.get("start_line"):
            continue
        marks.append({
            "line": location["start_line"], "end_line": location.get("end_line") or location["start_line"],
            "kind": "finding", "severity": item.get("severity"), "label": item.get("title") or item.get("rule_id") or "finding",
            "fingerprint": item.get("fingerprint"), "correlation_key": item.get("correlation_key"),
        })
    marks = [mark for mark in marks if start <= mark["line"] <= end][:MAX_MARKS]
    return {
        "path": relative,
        "language": LANGUAGES.get(path.suffix.lower()),
        "start": start,
        "lines": lines[start - 1:end],
        "total_lines": total,
        "focus": {"start": focus, "end": focus_end},
        "marks": marks,
    }


_MAP_CACHE: dict[str, tuple[float, dict]] = {}


def load_map(scan_dir: Path) -> dict:
    """The scan's project map, cached until the file changes (findings are polled during a scan)."""
    path = scan_dir / "project_map.json"
    try:
        mtime = path.stat().st_mtime
    except OSError:
        return {}
    cached = _MAP_CACHE.get(str(path))
    if cached and cached[0] == mtime:
        return cached[1]
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if len(_MAP_CACHE) > 16:
        _MAP_CACHE.clear()
    _MAP_CACHE[str(path)] = (mtime, data)
    return data
