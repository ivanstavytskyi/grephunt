"""Path exclusions: what not to scan, and which findings to drop.

Pattern syntax is a small gitignore subset:
  build              — a file or directory with that name at any depth
  *.spec.ts          — a file name at any depth
  data/static/codefixes   — a path from the project root (children included)
  **/fixtures/*.json — a glob from the project root
  # comment
"""
from __future__ import annotations

from fnmatch import fnmatch
from pathlib import Path

IGNORE_FILE = ".grephuntignore"

# Tests, build output, and generated code. node_modules is not excluded:
# dependency scanners look there for vulnerable packages.
DEFAULT_EXCLUDES = [
    ".git",
    "test", "tests", "__tests__", "spec", "e2e", "cypress",
    "*.spec.*", "*.test.*", "*_test.go", "test_*.py",
    "build", "dist", "coverage", ".next", "out",
    "*.min.js", "*.map",
]


def load_ignore_file(project: Path) -> list[str]:
    path = project / IGNORE_FILE
    if not path.is_file():
        return []
    patterns = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            patterns.append(line)
    return patterns


def collect_excludes(project: Path, cli: list[str] | None, use_defaults: bool = True) -> list[str]:
    patterns = (DEFAULT_EXCLUDES if use_defaults else []) + load_ignore_file(project) + (cli or [])
    out: list[str] = []
    for pattern in patterns:
        pattern = pattern.replace("\\", "/").strip()
        while pattern.startswith("./"):
            pattern = pattern[2:]
        pattern = pattern.rstrip("/")
        if pattern and pattern not in out:
            out.append(pattern)
    return out


def is_excluded(rel_path: str, patterns: list[str]) -> bool:
    path = rel_path.replace("\\", "/")
    while path.startswith("./") or path.startswith("/"):
        path = path[1:] if path.startswith("/") else path[2:]
    parts = path.split("/")
    for pattern in patterns:
        if "/" in pattern:
            if fnmatch(path, pattern) or fnmatch(path, pattern + "/*"):
                return True
        elif any(fnmatch(part, pattern) for part in parts):
            return True
    return False
