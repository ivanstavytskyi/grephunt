"""List the project's files with language, role, and size. Nothing is executed."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

LANGUAGES = {
    ".py": "python", ".pyw": "python",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".mts": "typescript", ".cts": "typescript", ".tsx": "tsx",
    ".php": "php", ".phtml": "php", ".inc": "php",
    ".go": "go", ".java": "java", ".kt": "kotlin", ".rb": "ruby", ".cs": "csharp",
    ".c": "c", ".h": "c", ".cpp": "cpp", ".hpp": "cpp", ".cc": "cpp", ".rs": "rust", ".swift": "swift",
    ".html": "html", ".htm": "html", ".vue": "vue", ".svelte": "svelte",
    ".css": "css", ".scss": "css", ".less": "css",
    ".sql": "sql", ".sh": "shell", ".bash": "shell", ".ps1": "powershell",
    ".json": "json", ".yml": "yaml", ".yaml": "yaml", ".toml": "toml", ".xml": "xml", ".ini": "ini",
    ".md": "markdown", ".rst": "text", ".txt": "text", ".tf": "terraform", ".hcl": "terraform",
}
PARSED = {"python", "javascript", "typescript", "tsx", "php", "go", "java"}

VENDOR_DIRS = {"node_modules", "vendor", "bower_components", ".venv", "venv", "site-packages", "__pycache__", ".yarn"}
SKIP_DIRS = {".git", ".hg", ".svn", ".idea", ".vscode", ".pytest_cache", ".mypy_cache", ".tox", ".next", ".nuxt"}
GENERATED_DIRS = {"dist", "build", "out", "coverage", "target", ".angular"}
TEST_DIRS = {"test", "tests", "__tests__", "spec", "specs", "e2e", "cypress", "testdata", "fixtures"}
CONFIG_NAMES = {
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "composer.json", "composer.lock",
    "requirements.txt", "pyproject.toml", "setup.py", "setup.cfg", "pipfile", "pipfile.lock", "poetry.lock",
    "go.mod", "go.sum", "pom.xml", "build.gradle", "build.gradle.kts", "gemfile", "gemfile.lock",
    "tsconfig.json", "angular.json", ".env", ".env.example", "config.php", "settings.py", "webpack.config.js",
    "vite.config.ts", "vite.config.js", "nginx.conf", ".htaccess", "web.config",
}
ASSET_EXT = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".woff", ".woff2", ".ttf", ".eot", ".mp3", ".mp4", ".pdf", ".zip"}
DOC_EXT = {".md", ".rst", ".txt", ".adoc"}

MAX_FILES = 60_000
MAX_PARSE_BYTES = 1_000_000


@dataclass
class FileInfo:
    path: str
    """Relative POSIX path from the project root."""
    size: int
    language: str | None
    role: str
    lines: int | None = None

    @property
    def parsed(self) -> bool:
        return self.language in PARSED and self.role not in {"vendor", "generated"} and self.size <= MAX_PARSE_BYTES


@dataclass
class Inventory:
    root: Path
    files: list[FileInfo] = field(default_factory=list)
    vendor_dirs: dict[str, int] = field(default_factory=dict)
    """Vendor directory -> number of entries at its top (packages). Their files are not listed."""
    truncated: bool = False


def _language(name: str) -> str | None:
    lower = name.lower()
    if lower == "dockerfile" or lower.startswith("dockerfile.") or lower.endswith(".dockerfile"):
        return "dockerfile"
    if lower.endswith(".min.js"):
        return "javascript"
    return LANGUAGES.get(PurePosixPath(lower).suffix)


def _role(rel: PurePosixPath, language: str | None) -> str:
    parts = [part.lower() for part in rel.parts]
    name = parts[-1]
    suffix = rel.suffix.lower()
    if any(part in GENERATED_DIRS for part in parts[:-1]) or name.endswith((".min.js", ".map", ".bundle.js")):
        return "generated"
    if (
        any(part in TEST_DIRS for part in parts[:-1])
        or name.startswith("test_")
        or name.endswith(("_test.go", "_test.py"))
        or ".spec." in name
        or ".test." in name
    ):
        return "test"
    if language in {"dockerfile", "terraform"} or name.startswith("docker-compose") or name.startswith("compose."):
        return "iac"
    if name in CONFIG_NAMES or name.startswith(".env") or language in {"yaml", "toml", "ini", "xml"}:
        return "config"
    if language == "json":
        return "config"
    if suffix in ASSET_EXT or language == "css":
        return "asset"
    if suffix in DOC_EXT or name in {"license", "licence", "notice", "changelog"}:
        return "docs"
    return "source"


def _count_lines(path: Path, size: int) -> int | None:
    if size > MAX_PARSE_BYTES:
        return None
    try:
        with path.open("rb") as handle:
            return sum(1 for _ in handle)
    except OSError:
        return None


def collect_inventory(root: Path) -> Inventory:
    root = root.resolve()
    inventory = Inventory(root=root)
    for current, dirs, files in os.walk(root):
        current_path = Path(current)
        rel_dir = current_path.relative_to(root)
        kept: list[str] = []
        for name in sorted(dirs):
            if name in SKIP_DIRS:
                continue
            if name in VENDOR_DIRS:
                vendor_rel = (rel_dir / name).as_posix()
                # Entries at the top of the vendor dir (packages), not every file: a full walk of
                # node_modules costs tens of seconds on a mounted drive.
                try:
                    inventory.vendor_dirs[vendor_rel] = sum(1 for _ in os.scandir(current_path / name))
                except OSError:
                    inventory.vendor_dirs[vendor_rel] = 0
                continue
            if (current_path / name).is_symlink():
                continue
            kept.append(name)
        dirs[:] = kept
        for name in sorted(files):
            full = current_path / name
            if full.is_symlink():
                continue
            if len(inventory.files) >= MAX_FILES:
                inventory.truncated = True
                return inventory
            try:
                size = full.stat().st_size
            except OSError:
                continue
            rel = PurePosixPath((rel_dir / name).as_posix())
            language = _language(name)
            role = _role(rel, language)
            lines = _count_lines(full, size) if role in {"source", "test", "config", "iac"} else None
            inventory.files.append(FileInfo(path=rel.as_posix(), size=size, language=language, role=role, lines=lines))
    return inventory
