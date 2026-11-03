"""Turn an import as written into a file of the project or an external package."""
from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass
from pathlib import PurePosixPath

from grephunt.project_map.parsers import ImportFact

JS_EXTENSIONS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".json", ".d.ts")
PY_STDLIB_HINT = {
    "os", "sys", "re", "json", "time", "datetime", "pathlib", "typing", "subprocess", "sqlite3", "pickle",
    "hashlib", "logging", "collections", "functools", "itertools", "asyncio", "uuid", "base64", "random",
    "math", "io", "shutil", "tempfile", "threading", "socket", "http", "urllib", "unittest", "dataclasses",
    "enum", "abc", "contextlib", "copy", "string", "struct", "zipfile", "tarfile", "csv", "xml", "html",
    "email", "argparse", "configparser", "secrets", "hmac", "traceback", "warnings", "inspect", "glob",
    "platform", "signal", "queue", "decimal", "fractions", "statistics", "textwrap", "pprint", "__future__",
}
NODE_BUILTINS = {
    "fs", "path", "http", "https", "crypto", "os", "url", "util", "child_process", "stream", "events", "net",
    "zlib", "querystring", "buffer", "assert", "dns", "tls", "readline", "vm", "worker_threads", "cluster",
}


@dataclass
class Resolved:
    file: str | None = None
    """Project-relative path of the imported file."""
    directory: str | None = None
    """Project-relative directory for package-level imports (Go)."""
    package: str | None = None
    """External package: 'npm:express', 'pypi:flask', 'go:github.com/gin-gonic/gin'."""
    builtin: bool = False


class Resolver:
    def __init__(self, files: list[str], manifests: dict[str, str]) -> None:
        self.files = set(files)
        self.by_suffix: dict[str, list[str]] = {}
        for path in files:
            parts = PurePosixPath(path).parts
            for index in range(len(parts)):
                self.by_suffix.setdefault("/".join(parts[index:]), []).append(path)
        self.dirs = {str(PurePosixPath(path).parent) for path in files}
        self.go_modules = self._go_modules(manifests)
        self.psr4 = self._psr4(manifests)
        self.python_roots = self._python_roots(files)
        self.php_declares: dict[str, str] = {}
        self.java_declares: dict[str, str] = {}

    # --- manifests ---------------------------------------------------------------------------

    @staticmethod
    def _go_modules(manifests: dict[str, str]) -> list[tuple[str, str]]:
        modules = []
        for path, content in manifests.items():
            if PurePosixPath(path).name != "go.mod":
                continue
            match = re.search(r"^module\s+(\S+)", content, re.MULTILINE)
            if match:
                modules.append((match.group(1), str(PurePosixPath(path).parent)))
        return sorted(modules, key=lambda item: -len(item[0]))

    @staticmethod
    def _psr4(manifests: dict[str, str]) -> list[tuple[str, str]]:
        mapping = []
        for path, content in manifests.items():
            if PurePosixPath(path).name != "composer.json":
                continue
            try:
                data = json.loads(content)
            except ValueError:
                continue
            base = PurePosixPath(path).parent
            for section in ("autoload", "autoload-dev"):
                for prefix, dirs in ((data.get(section) or {}).get("psr-4") or {}).items():
                    for directory in [dirs] if isinstance(dirs, str) else list(dirs or []):
                        mapping.append((prefix.strip("\\"), str(base / directory).strip("/").replace("./", "")))
        return sorted(mapping, key=lambda item: -len(item[0]))

    @staticmethod
    def _python_roots(files: list[str]) -> list[str]:
        roots = {"."}
        for path in files:
            parts = PurePosixPath(path).parts
            if "src" in parts:
                roots.add("/".join(parts[: parts.index("src") + 1]))
        return sorted(roots, key=len)

    def learn_declarations(self, path: str, language: str, declares: list[str]) -> None:
        for name in declares:
            if language == "php":
                self.php_declares[name.lstrip("\\").lower()] = path
            elif language == "java":
                self.java_declares[name] = path

    # --- resolution --------------------------------------------------------------------------

    def _first_existing(self, candidates: list[str]) -> str | None:
        for candidate in candidates:
            normal = _normalize(candidate)
            if normal is not None and normal in self.files:
                return normal
        return None

    def resolve(self, importer: str, language: str, fact: ImportFact) -> Resolved:
        spec = fact.spec.strip()
        if not spec:
            return Resolved()
        if language == "python":
            return self._python(importer, spec)
        if language in {"javascript", "typescript", "tsx"}:
            return self._javascript(importer, spec)
        if language == "php":
            return self._php(importer, fact)
        if language == "go":
            return self._go(spec)
        if language == "java":
            return self._java(spec)
        return Resolved()

    def _python(self, importer: str, spec: str) -> Resolved:
        here = PurePosixPath(importer).parent
        if spec.startswith("."):
            level = len(spec) - len(spec.lstrip("."))
            base = here
            for _ in range(level - 1):
                base = base.parent
            rest = spec.lstrip(".").replace(".", "/")
            stem = f"{base}/{rest}" if rest else str(base)
            found = self._first_existing([f"{stem}.py", f"{stem}/__init__.py"])
            return Resolved(file=found)
        module = spec.replace(".", "/")
        candidates = []
        for root in self.python_roots:
            prefix = "" if root == "." else f"{root}/"
            candidates += [f"{prefix}{module}.py", f"{prefix}{module}/__init__.py"]
        candidates += [f"{here}/{module}.py", f"{here}/{module}/__init__.py"]
        found = self._first_existing(candidates)
        if found:
            return Resolved(file=found)
        top = spec.split(".")[0]
        return Resolved(package=f"pypi:{top}", builtin=top in PY_STDLIB_HINT or top in getattr(sys, "stdlib_module_names", ()))

    def _javascript(self, importer: str, spec: str) -> Resolved:
        if spec.startswith((".", "/")):
            base = PurePosixPath(importer).parent
            stem = f"{base}/{spec}" if spec.startswith(".") else spec.lstrip("/")
            candidates = [stem] + [stem + ext for ext in JS_EXTENSIONS] + [f"{stem}/index{ext}" for ext in JS_EXTENSIONS]
            return Resolved(file=self._first_existing(candidates))
        if spec.startswith("node:"):
            return Resolved(package=f"npm:{spec}", builtin=True)
        parts = spec.split("/")
        name = "/".join(parts[:2]) if spec.startswith("@") else parts[0]
        return Resolved(package=f"npm:{name}", builtin=name in NODE_BUILTINS)

    def _php(self, importer: str, fact: ImportFact) -> Resolved:
        spec = fact.spec
        if fact.kind == "use":
            key = spec.lstrip("\\").lower()
            if key in self.php_declares:
                return Resolved(file=self.php_declares[key])
            for prefix, directory in self.psr4:
                if spec.startswith(prefix + "\\") or spec == prefix:
                    rest = spec[len(prefix):].strip("\\").replace("\\", "/")
                    found = self._first_existing([f"{directory}/{rest}.php"])
                    if found:
                        return Resolved(file=found)
            vendor = spec.split("\\")[0]
            return Resolved(package=f"php:{vendor}")
        clean = spec.replace("\\", "/")
        base = PurePosixPath(importer).parent
        candidates = [f"{base}/{clean}", clean.lstrip("/")]
        found = self._first_existing(candidates)
        if found:
            return Resolved(file=found)
        # A path built from a constant ("ROOT . 'dvwa/includes/x.php'"): match by the known tail.
        tail = clean.lstrip("./")
        matches = self.by_suffix.get(tail, [])
        if len(matches) == 1:
            return Resolved(file=matches[0])
        return Resolved()

    def _go(self, spec: str) -> Resolved:
        for module, directory in self.go_modules:
            if spec == module or spec.startswith(module + "/"):
                rest = spec[len(module):].strip("/")
                target = _normalize(f"{directory}/{rest}" if rest else directory) or "."
                if target in self.dirs:
                    return Resolved(directory=target)
                return Resolved()
        first = spec.split("/")[0]
        return Resolved(package=f"go:{spec}", builtin="." not in first)

    def _java(self, spec: str) -> Resolved:
        name = spec.removesuffix(".*")
        if name in self.java_declares:
            return Resolved(file=self.java_declares[name])
        if spec.endswith(".*"):
            directory_tail = name.replace(".", "/")
            for directory in self.dirs:
                if directory.endswith(directory_tail):
                    return Resolved(directory=directory)
        tail = name.replace(".", "/") + ".java"
        matches = self.by_suffix.get(tail, [])
        if len(matches) == 1:
            return Resolved(file=matches[0])
        top = ".".join(name.split(".")[:2])
        return Resolved(package=f"maven:{top}", builtin=name.startswith(("java.", "javax.")))


def _normalize(path: str) -> str | None:
    parts: list[str] = []
    for part in path.replace("\\", "/").split("/"):
        if part in {"", "."}:
            continue
        if part == "..":
            if not parts:
                return None
            parts.pop()
            continue
        parts.append(part)
    return "/".join(parts) if parts else "."
