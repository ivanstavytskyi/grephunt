"""The code an AI reviewer needs to judge one finding: the whole enclosing function.

A 500-character snippet around the reported line hides the check that makes the code
safe. On DVWA exec/impossible.php the is_numeric() validation sits five lines above the
shell call, outside the snippet, and the reviewer confirmed a false positive. This returns
the smallest function or method that contains the line (tree-sitter), or, for code that is
not inside a function (PHP page scripts), the whole file when it is short and a window
around the line when it is not. Every line carries its number so the verdict can cite it.
"""
from __future__ import annotations

from pathlib import Path

from grephunt.project_map.parsers import parse
from grephunt.web_console.source_view import SourceUnavailable, resolve_inside

LIMIT = 3500
_WINDOW = 40
_LANGUAGE = {
    ".py": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".mts": "typescript", ".cts": "typescript",
    ".tsx": "tsx",
    ".php": "php", ".phtml": "php", ".inc": "php",
    ".go": "go",
    ".java": "java",
}
_FUNCTION_NODES = {
    "function_definition", "function_declaration", "function_expression", "arrow_function",
    "method_definition", "method_declaration", "generator_function_declaration", "function",
    "func_literal", "constructor_declaration", "anonymous_function", "anonymous_function_creation_expression",
}


def _numbered(lines: list[str], first: int) -> str:
    return "\n".join(f"{first + offset}| {text}" for offset, text in enumerate(lines))


def _smallest_function(tree, line: int):
    """Innermost function node whose span contains the 1-based line."""
    found = None
    stack = [tree.root_node]
    target = line - 1
    while stack:
        node = stack.pop()
        if node.start_point[0] > target or node.end_point[0] < target:
            continue
        if node.type in _FUNCTION_NODES:
            found = node
        stack.extend(node.children)
    return found


def _clip(lines: list[str], first: int, line: int, limit: int) -> str:
    """Numbered lines first..; when too long, a window centred on the reported line."""
    text = _numbered(lines, first)
    if len(text) <= limit:
        return text
    centre = line - first
    half = _WINDOW
    while half > 5:
        start = max(0, centre - half)
        piece = _numbered(lines[start:centre + half + 1], first + start)
        if len(piece) <= limit:
            return piece
        half -= 5
    return _numbered(lines[max(0, centre - 5):centre + 6], first + max(0, centre - 5))[:limit]


def enclosing_code(target: Path, raw_path: str, line: int | None, limit: int = LIMIT) -> tuple[str, str] | None:
    """(kind, numbered code) for one finding, or None when the file cannot be read.

    kind is "function" (the enclosing function), "file" (short file, code not in a function)
    or "window" (lines around the finding).
    """
    if not raw_path or not isinstance(line, int) or line < 1:
        return None
    try:
        path, _relative = resolve_inside(target, raw_path)
        source = path.read_bytes()
    except (SourceUnavailable, OSError):
        return None
    lines = source.decode("utf-8", errors="replace").splitlines()
    if line > len(lines):
        return None
    language = _LANGUAGE.get(path.suffix.lower())
    node = None
    if language:
        try:
            tree = parse(language, source)
        except Exception:  # noqa: BLE001 - a parser failure falls back to a window
            tree = None
        if tree is not None:
            node = _smallest_function(tree, line)
    if node is not None:
        first = node.start_point[0] + 1
        body = lines[node.start_point[0]:node.end_point[0] + 1]
        return "function", _clip(body, first, line, limit)
    whole = _numbered(lines, 1)
    if len(whole) <= limit:
        return "file", whole
    return "window", _clip(lines, 1, line, limit)


def attach_code(findings: list, target: Path, limit: int = LIMIT) -> list:
    """Set code_context / code_kind on each finding dict that points at a readable source line."""
    for item in findings:
        if not isinstance(item, dict):
            continue
        location = item.get("location") if isinstance(item.get("location"), dict) else {}
        found = enclosing_code(target, str(location.get("path") or ""), location.get("start_line"), limit)
        if found:
            item["code_kind"], item["code_context"] = found
    return findings
