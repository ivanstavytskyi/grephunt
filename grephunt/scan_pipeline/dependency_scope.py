"""Decide which npm packages are part of the running application.

A package is kept when application code imports it, or when a manifest lists it
under dependencies (not devDependencies). Everything else we saw in a lockfile
— dev tools, install-time helpers such as tar, and unreferenced transitive
packages such as minimatch — is left out of the report.

Packages from other ecosystems (pip, Go, Maven) are not in the npm set, so
they are kept.
"""
from __future__ import annotations

import json
import os
import re
from functools import lru_cache
from pathlib import Path

from grephunt.finding_model.correlation import normalize_package
from grephunt.finding_model.record import Category, Finding

_SKIP_DIRS = {
    "node_modules", ".git", "dist", "build", "coverage", ".next", "out",
    "test", "tests", "__tests__", "e2e", "cypress", "vendor", "bower_components",
}
_SOURCE_EXT = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".vue", ".svelte"}
_SPEC = re.compile(
    r"""(?:import\s+(?:type\s+)?(?:[^'"\n]+?\s+from\s+)?|require\s*\(\s*|import\s*\(\s*)['"]([^'"]+)['"]"""
)
_PROD_KEYS = ("dependencies", "optionalDependencies", "peerDependencies")


def suppressed_packages(project: Path | None) -> set[str]:
    """npm package names that are not referenced by the application."""
    if project is None or not project.is_dir():
        return set()
    return set(_suppressed_cached(str(project.resolve())))


def is_unreferenced_dependency(finding: Finding, suppressed: set[str]) -> bool:
    if finding.category is not Category.DEPENDENCY or not finding.package or not suppressed:
        return False
    return normalize_package(finding.package) in suppressed


@lru_cache(maxsize=8)
def _suppressed_cached(project: str) -> frozenset[str]:
    root = Path(project)
    installed: set[str] = set()
    direct: set[str] = set()
    for path in _files(root, "package-lock.json"):
        _read_package_lock(path, installed)
    for path in _files(root, "package.json"):
        _read_package_json(path, installed, direct)
    if not installed:
        return frozenset()
    referenced = _imported_packages(root)
    return frozenset(installed - direct - referenced)


def _files(root: Path, filename: str):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [name for name in dirnames if name not in _SKIP_DIRS and not name.startswith(".")]
        if filename in filenames:
            yield Path(dirpath) / filename


def _remember(bucket: set[str], name: str) -> None:
    key = normalize_package(name)
    if key:
        bucket.add(key)


def _read_package_lock(path: Path, installed: set[str]) -> None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    if not isinstance(data, dict):
        return
    packages = data.get("packages")
    if isinstance(packages, dict):
        for rel, meta in packages.items():
            if not isinstance(meta, dict):
                continue
            name = _lock_package_name(str(rel)) or str(meta.get("name") or "")
            if name:
                _remember(installed, name)
    _walk_lock_v1(data.get("dependencies"), installed)


def _walk_lock_v1(node, installed: set[str]) -> None:
    if not isinstance(node, dict):
        return
    for name, meta in node.items():
        _remember(installed, str(name))
        if isinstance(meta, dict):
            _walk_lock_v1(meta.get("dependencies"), installed)


def _read_package_json(path: Path, installed: set[str], direct: set[str]) -> None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    if not isinstance(data, dict):
        return
    for key in (*_PROD_KEYS, "devDependencies"):
        block = data.get(key)
        if not isinstance(block, dict):
            continue
        for name in block:
            _remember(installed, str(name))
            if key in _PROD_KEYS:
                _remember(direct, str(name))


def _lock_package_name(path: str) -> str:
    path = path.replace("\\", "/").strip("/")
    marker = "node_modules/"
    if marker not in path:
        return ""
    return path.rsplit(marker, 1)[-1]


def _imported_packages(root: Path) -> set[str]:
    found: set[str] = set()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [name for name in dirnames if name not in _SKIP_DIRS and not name.startswith(".")]
        for filename in filenames:
            path = Path(dirpath) / filename
            if path.suffix.lower() not in _SOURCE_EXT:
                continue
            if ".spec." in path.name or ".test." in path.name:
                continue
            try:
                if path.stat().st_size > 1_000_000:
                    continue
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for match in _SPEC.finditer(text):
                _remember(found, _package_from_spec(match.group(1)))
    return found


def _package_from_spec(spec: str) -> str:
    if not spec or spec.startswith((".", "/", "node:")):
        return ""
    if spec.startswith("@"):
        parts = spec.split("/")
        if len(parts) < 2:
            return ""
        return f"{parts[0]}/{parts[1]}"
    return spec.split("/")[0]
