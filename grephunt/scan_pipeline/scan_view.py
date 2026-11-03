"""A copy of the project without build output and installed dependencies, for the scanners.

Code, secret and IaC scanners spent minutes in node_modules, build and dist and then hit
their own limits (Trivy's 5-minute analysis deadline, KICS's thread limit, CodeQL's memory).
The findings there were dropped afterwards anyway. With the "skip build folders" rule on,
those scanners get this copy instead of the project. Files are hard links when the file
system allows it, so the copy is fast and takes no extra space.

Dependency scanners that read installed packages (descriptor.needs_dependency_dirs) and
secret scanners still get the original project (see needs_full_project).
"""
from __future__ import annotations

import os
import shutil
import uuid
import re
from fnmatch import fnmatch
from dataclasses import dataclass, field
from pathlib import Path

# Folder names skipped at any depth, grouped for the console. Only names that are almost never
# hand-written source: "packages" (monorepos) and "lib" stay scanned.
SKIP_GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Installed packages", (
        "node_modules", "bower_components", "jspm_packages", "web_modules", "vendor", "Pods", "Carthage",
        ".venv", "venv", "site-packages", ".tox", ".nox", ".eggs",
    )),
    ("Build output", (
        "build", "dist", "out", "target", "obj", "_build", "storybook-static", "DerivedData",
        "cmake-build-debug", "cmake-build-release", "bazel-out",
    )),
    ("Framework and bundler caches", (
        ".next", ".nuxt", ".svelte-kit", ".angular", ".expo", ".output", ".vercel", ".netlify",
        ".turbo", ".parcel-cache", ".cache", ".webpack", ".vite",
    )),
    ("Package manager caches", (".gradle", ".m2", ".ivy2", ".cargo", ".pub-cache", ".yarn", ".pnpm-store")),
    ("Test coverage and tool caches", (
        "coverage", ".nyc_output", "htmlcov", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    )),
    ("Infrastructure tool state", (".terraform", ".serverless", ".aws-sam")),
    ("Version control", (".git",)),
)

SKIPPED_DIRS = frozenset(name for _label, names in SKIP_GROUPS for name in names)


def needs_full_project(descriptor) -> bool:
    """Scanners that always see the whole project.

    Dependency scanners read installed packages. Secret scanners are fast and look where keys
    really leak: bundled frontend code in dist and build, and git history in .git.
    """
    if getattr(descriptor, "needs_dependency_dirs", False):
        return True
    category = getattr(descriptor, "category", None)
    return getattr(category, "value", category) == "secret"


@dataclass
class ScanView:
    root: Path
    skipped: list[str] = field(default_factory=list)
    """Project-relative paths of the folders left out."""
    skipped_files: int = 0
    copied_files: int = 0

    def remove(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)


def _place(source: str, target: str) -> None:
    try:
        os.link(source, target)
    except OSError:
        shutil.copy2(source, target)


def _count_files(path: str) -> int:
    total = 0
    for _dirpath, _dirnames, filenames in os.walk(path):
        total += len(filenames)
    return total


_Sets = tuple[set[str], list[str], list, set[str], list[str], list]


def _parse_skip(patterns) -> "_Sets":
    """Split skip patterns into what to exclude and, after a leading '!', what to keep.

    A bare name (node_modules) matches a folder of that name at any depth. A pattern with a
    slash or a wildcard (src/vendor, **/fixtures) matches the folder's path from the root.
    An "re:" prefix is a Python regular expression tested against that path (re:^vendor/.*).
    A leading '!' keeps a folder a checked list would otherwise exclude (gitignore style),
    and combines with the others: !re:..., !src/vendor, !vendor.
    """
    skip_names: set[str] = set()
    skip_paths: list[str] = []
    skip_regex: list = []
    keep_names: set[str] = set()
    keep_paths: list[str] = []
    keep_regex: list = []
    for raw in patterns:
        pattern = str(raw).strip()
        keep = pattern.startswith("!")
        if keep:
            pattern = pattern[1:].strip()
        if pattern.startswith("re:"):
            expr = pattern[3:].strip()
            if not expr:
                continue
            try:
                compiled = re.compile(expr)
            except re.error:
                continue
            (keep_regex if keep else skip_regex).append(compiled)
            continue
        pattern = pattern.replace("\\", "/").strip().strip("/")
        if not pattern:
            continue
        if "/" in pattern or "*" in pattern or "?" in pattern:
            (keep_paths if keep else skip_paths).append(pattern)
        else:
            (keep_names if keep else skip_names).add(pattern)
    return skip_names, skip_paths, skip_regex, keep_names, keep_paths, keep_regex


def _matches(rel_path: str, name: str, names: set[str], paths: list[str], regex: list) -> bool:
    if name in names:
        return True
    if any(fnmatch(rel_path, pat) or fnmatch(rel_path, pat + "/*") for pat in paths):
        return True
    return any(rx.search(rel_path) for rx in regex)


def _excluded(rel_path: str, name: str, sets: "_Sets") -> bool:
    skip_names, skip_paths, skip_regex, keep_names, keep_paths, keep_regex = sets
    if not _matches(rel_path, name, skip_names, skip_paths, skip_regex):
        return False
    return not _matches(rel_path, name, keep_names, keep_paths, keep_regex)


def make_scan_view(project: Path, parent: Path, skip: frozenset[str] = SKIPPED_DIRS) -> ScanView:
    """Copy the project into a new folder under parent, leaving out the skipped folder names."""
    root = parent / f"view-{uuid.uuid4().hex[:12]}"
    root.mkdir(parents=True)
    view = ScanView(root=root)
    sets = _parse_skip(skip)
    project = project.resolve()
    for dirpath, dirnames, filenames in os.walk(project, followlinks=False):
        rel = os.path.relpath(dirpath, project)
        target_dir = root if rel == "." else root / rel
        kept = []
        for name in dirnames:
            full = os.path.join(dirpath, name)
            if os.path.islink(full):
                continue
            dir_rel = name if rel == "." else f"{rel}/{name}".replace("\\", "/")
            if _excluded(dir_rel, name, sets):
                view.skipped.append(dir_rel)
                view.skipped_files += _count_files(full)
            else:
                kept.append(name)
        dirnames[:] = kept
        for name in kept:
            (target_dir / name).mkdir(exist_ok=True)
        for name in filenames:
            source = os.path.join(dirpath, name)
            if os.path.islink(source):
                continue
            _place(source, str(target_dir / name))
            view.copied_files += 1
    return view
