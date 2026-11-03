"""Files the running application never loads, judged from the project map.

A wrong answer here would move a real vulnerability out of the main list, so a file is
reported only when every check agrees:

- its language has static imports the map resolves: JavaScript, TypeScript or Python.
  PHP, Java, C#, Ruby and Go load code by convention or at run time (DVWA includes its
  pages through require_once with a variable), so files in those languages are never judged;
- the map calls it source code, not an entry point;
- no project file imports it, and no file in its folder is imported either: a whole folder
  of loose copies, such as coding-challenge answer variants, not one stray helper;
- no folder on its path is a framework convention folder (pages, app, routes, api, ...),
  where the framework loads files without an import;
- no other file in the project names it: not a config file (package.json, angular.json,
  tsconfig, *.config.*, Dockerfile, compose, CI), not a page or template that loads it with
  <script src> (DVWA's browser JavaScript is never imported, only linked from PHP);
- no code line that loads modules dynamically (require(), import(), loadChildren,
  importlib) names its folder.

The result is cached next to the map, keyed by the map's modification time.
"""
from __future__ import annotations

import json
import os
import re
from collections import Counter
from pathlib import Path, PurePosixPath

_LANGUAGES = {"javascript", "typescript", "tsx", "python"}
_CODE_SUFFIXES = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts", ".py")

# Framework folders whose files run without being imported.
_CONVENTION_DIRS = {
    "pages", "app", "routes", "api", "functions", "server", "middleware", "middlewares", "plugins",
    "layouts", "views", "templates", "migrations", "management", "commands", "handlers", "lambdas",
    "lambda", "bin", "scripts", "jobs", "workers", "tasks", "cron", "hooks", "blueprints", "endpoints",
    "controllers", "resolvers", "startup", "config", "settings",
}

_CONFIG_NAMES = {
    "package.json", "angular.json", "project.json", "workspace.json", "nx.json", "deno.json", "bunfig.toml",
    "vercel.json", "netlify.toml", "firebase.json", "nodemon.json", "procfile", "serverless.yml",
    "serverless.yaml", "app.yaml", "pyproject.toml", "setup.cfg", "setup.py", "tox.ini", "makefile",
    "compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml", ".gitlab-ci.yml",
}
_CONFIG_PATTERNS = (
    re.compile(r"(^|/)tsconfig[^/]*\.json$"),
    re.compile(r"(^|/)[^/]*\.config\.(js|cjs|mjs|ts)$"),
    re.compile(r"(^|/)dockerfile[^/]*$"),
    re.compile(r"(^|/)\.github/workflows/[^/]+\.ya?ml$"),
)
_DYNAMIC_LOAD = re.compile(r"\brequire\s*\(|\bimport\s*\(|loadChildren|__import__\s*\(|import_module\s*\(|\brequire\.resolve\s*\(")
_SKIP_DIRS = {"node_modules", ".git", "dist", "build", "out", ".next", "coverage", "__pycache__", ".venv", "venv"}
_MAX_READ = 400_000
_CACHE_NAME = "not_executed.json"


def _is_config(path: str) -> bool:
    lower = path.lower()
    if PurePosixPath(lower).name in _CONFIG_NAMES:
        return True
    return any(pattern.search(lower) for pattern in _CONFIG_PATTERNS)


def _read(path: Path) -> str:
    try:
        if path.stat().st_size > _MAX_READ:
            return ""
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def candidates(project_map: dict) -> list[str]:
    """Files the map alone marks as never loaded. The checks that read the project come next."""
    files = (project_map.get("files") or {}) if isinstance(project_map, dict) else {}
    nodes = [node for node in files.get("nodes") or [] if node.get("kind") == "file"]
    edges = [edge for edge in files.get("edges") or [] if edge.get("kind") == "import"]
    imported = Counter(str(edge.get("target")) for edge in edges if str(edge.get("target", "")).startswith("f:"))
    imported_dirs = {os.path.dirname(target[2:]) for target in imported}
    found = []
    for node in nodes:
        path = str(node.get("path") or "")
        if node.get("role") != "source" or node.get("entry_point"):
            continue
        if node.get("language") not in _LANGUAGES and not path.lower().endswith(_CODE_SUFFIXES):
            continue
        if imported.get(str(node.get("id"))):
            continue
        folder = os.path.dirname(path)
        if folder in imported_dirs:
            continue
        if any(part.lower() in _CONVENTION_DIRS for part in folder.split("/") if part):
            continue
        found.append(path)
    return found


_TEXT_SUFFIXES = _CODE_SUFFIXES + (
    ".php", ".phtml", ".inc", ".html", ".htm", ".xhtml", ".pug", ".jade", ".ejs", ".hbs", ".handlebars",
    ".njk", ".twig", ".jinja", ".jinja2", ".j2", ".vue", ".svelte", ".astro", ".erb", ".cshtml", ".jsp",
    ".json", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf", ".xml", ".gradle", ".properties",
)


def _is_text(path: str) -> bool:
    lower = path.lower()
    return lower.endswith(_TEXT_SUFFIXES) or _is_config(lower)


def _python_module(path: str) -> str | None:
    if not path.endswith(".py"):
        return None
    return path[:-3].replace("/", ".")


class _TextIndex:
    """Every text file of the project in one string, so a name can be searched once for all files."""

    def __init__(self, root: Path, paths: list[str]) -> None:
        chunks: list[str] = []
        self.starts: list[int] = []
        self.paths: list[str] = []
        offset = 0
        for path in paths:
            body = _read(root / path)
            if not body:
                continue
            self.starts.append(offset)
            self.paths.append(path)
            chunks.append(body)
            offset += len(body) + 1
        self.text = "\0".join(chunks)

    def _owner(self, position: int) -> str:
        import bisect

        return self.paths[bisect.bisect_right(self.starts, position) - 1]

    def named_elsewhere(self, name: str, own_path: str) -> bool:
        position = self.text.find(name)
        while position != -1:
            if self._owner(position) != own_path:
                return True
            position = self.text.find(name, position + 1)
        return False


def not_executed_files(project_map: dict, project_root: Path) -> set[str]:
    """Project-relative paths of source files the application never loads."""
    pending = candidates(project_map)
    if not pending or not project_root.is_dir():
        return set()
    files = (project_map.get("files") or {}).get("nodes") or []
    all_paths = [
        str(node.get("path") or "") for node in files
        if node.get("kind") == "file" and not any(part in _SKIP_DIRS for part in str(node.get("path") or "").split("/"))
    ]
    index = _TextIndex(project_root, [path for path in all_paths if _is_text(path)])

    named = set()
    for path in pending:
        names = [PurePosixPath(path).name, path, *("/".join(path.split("/")[start:]) for start in range(1, path.count("/")))]
        module = _python_module(path)
        if module:
            names.append(module)
        if any(index.named_elsewhere(name, path) for name in names if name):
            named.add(path)

    folders = {os.path.dirname(path) for path in pending if path not in named}
    folder_names = {folder: PurePosixPath(folder).name for folder in folders if folder}
    loaded_dynamically: set[str] = set()
    if folder_names:
        for path in all_paths:
            if not path.lower().endswith(_CODE_SUFFIXES):
                continue
            for line in _read(project_root / path).splitlines():
                if not _DYNAMIC_LOAD.search(line):
                    continue
                for folder, name in folder_names.items():
                    if folder not in loaded_dynamically and (folder in line or name in line):
                        loaded_dynamically.add(folder)
    return {path for path in pending if path not in named and os.path.dirname(path) not in loaded_dynamically}


def cached_not_executed(scan_dir: Path, project_map: dict | None, project_root: Path) -> set[str]:
    """not_executed_files, computed once per map and kept in the scan folder."""
    if not project_map:
        return set()
    map_file = scan_dir / "project_map.json"
    stamp = map_file.stat().st_mtime if map_file.is_file() else 0.0
    cache = scan_dir / _CACHE_NAME
    if cache.is_file():
        try:
            data = json.loads(cache.read_text(encoding="utf-8"))
            if data.get("map_mtime") == stamp:
                return set(data.get("files") or [])
        except (OSError, ValueError):
            pass
    result = not_executed_files(project_map, project_root)
    try:
        cache.write_text(json.dumps({"map_mtime": stamp, "files": sorted(result)}), encoding="utf-8")
    except OSError:
        pass
    return result
