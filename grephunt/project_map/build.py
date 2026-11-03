"""Build the project map: inventory, parse, resolve, and assemble the two views."""
from __future__ import annotations

import json
import re
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path, PurePosixPath

from grephunt.project_map.inventory import Inventory, collect_inventory
from grephunt.project_map.model import Evidence, MapEdge, MapNode, MapView, ProjectMap
from grephunt.project_map.parsers import FileFacts, read_facts
from grephunt.project_map.resolve import Resolver

MAX_EVIDENCE = 5
PARSE_BUDGET_SEC = 120
MANIFEST_NAMES = {"package.json", "composer.json", "go.mod", "requirements.txt", "pyproject.toml", "pom.xml", "build.gradle", "gemfile", "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}
MAX_MANIFEST_BYTES = 2_000_000

# Dependency name (lower case) -> (kind, label). kind: framework or datastore.
KNOWN_DEPENDENCIES = {
    "express": ("framework", "Express"), "koa": ("framework", "Koa"), "fastify": ("framework", "Fastify"),
    "@nestjs/core": ("framework", "NestJS"), "next": ("framework", "Next.js"), "nuxt": ("framework", "Nuxt"),
    "@angular/core": ("framework", "Angular"), "react": ("framework", "React"), "vue": ("framework", "Vue"),
    "svelte": ("framework", "Svelte"), "jquery": ("framework", "jQuery"),
    "flask": ("framework", "Flask"), "django": ("framework", "Django"), "fastapi": ("framework", "FastAPI"),
    "starlette": ("framework", "Starlette"), "tornado": ("framework", "Tornado"),
    "laravel/framework": ("framework", "Laravel"), "symfony/symfony": ("framework", "Symfony"),
    "symfony/http-kernel": ("framework", "Symfony"), "slim/slim": ("framework", "Slim"),
    "github.com/gin-gonic/gin": ("framework", "Gin"), "github.com/labstack/echo/v4": ("framework", "Echo"),
    "github.com/gofiber/fiber/v2": ("framework", "Fiber"), "org.springframework.boot": ("framework", "Spring Boot"),
    "sequelize": ("datastore", "Sequelize (SQL)"), "typeorm": ("datastore", "TypeORM (SQL)"),
    "mongoose": ("datastore", "MongoDB"), "mongodb": ("datastore", "MongoDB"), "pg": ("datastore", "PostgreSQL"),
    "mysql": ("datastore", "MySQL"), "mysql2": ("datastore", "MySQL"), "sqlite3": ("datastore", "SQLite"),
    "redis": ("datastore", "Redis"), "ioredis": ("datastore", "Redis"), "prisma": ("datastore", "Prisma (SQL)"),
    "@prisma/client": ("datastore", "Prisma (SQL)"), "knex": ("datastore", "Knex (SQL)"),
    "sqlalchemy": ("datastore", "SQLAlchemy (SQL)"), "psycopg2": ("datastore", "PostgreSQL"),
    "psycopg2-binary": ("datastore", "PostgreSQL"), "pymongo": ("datastore", "MongoDB"),
    "pymysql": ("datastore", "MySQL"), "mysqlclient": ("datastore", "MySQL"),
    "doctrine/orm": ("datastore", "Doctrine (SQL)"), "gorm.io/gorm": ("datastore", "GORM (SQL)"),
}


def _read_manifests(inventory: Inventory) -> dict[str, str]:
    found: dict[str, str] = {}
    for info in inventory.files:
        if PurePosixPath(info.path).name.lower() in MANIFEST_NAMES and info.size <= MAX_MANIFEST_BYTES:
            try:
                found[info.path] = (inventory.root / info.path).read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
    return found


def _dependencies(manifests: dict[str, str]) -> set[str]:
    names: set[str] = set()
    for path, content in manifests.items():
        name = PurePosixPath(path).name.lower()
        if name in {"package.json", "composer.json"}:
            try:
                data = json.loads(content)
            except ValueError:
                continue
            for section in ("dependencies", "devDependencies", "require", "require-dev", "peerDependencies"):
                names.update(key.lower() for key in (data.get(section) or {}))
        elif name == "requirements.txt":
            for line in content.splitlines():
                match = re.match(r"\s*([A-Za-z0-9_.\-]+)", line)
                if match and not line.strip().startswith(("#", "-")):
                    names.add(match.group(1).lower())
        elif name == "pyproject.toml":
            names.update(item.lower() for item in re.findall(r'["\']([A-Za-z0-9_.\-]+)\s*(?:[<>=~!\[;]|["\'])', content))
        elif name == "go.mod":
            names.update(match.lower() for match in re.findall(r"^\s*(?:require\s+)?([a-z0-9.\-]+\.[a-z]+/[^\s]+)\s+v", content, re.MULTILINE))
        elif name in {"pom.xml", "build.gradle"}:
            names.update(match.lower() for match in re.findall(r"(org\.springframework\.boot)", content))
    return names


def detect_stack(inventory: Inventory, manifests: dict[str, str], imported: set[str] | None = None) -> dict:
    """Frameworks and datastores from manifests and from what the code imports.

    A release archive can lack a manifest (Juice Shop ships frontend/src without
    frontend/package.json), but the imports still show @angular/core.
    """
    languages = Counter(info.language for info in inventory.files if info.language and info.role in {"source", "test"})
    dependencies = _dependencies(manifests) | {name.lower() for name in imported or set()}
    frameworks = sorted({label for dep, (kind, label) in KNOWN_DEPENDENCIES.items() if kind == "framework" and dep in dependencies})
    datastores = sorted({label for dep, (kind, label) in KNOWN_DEPENDENCIES.items() if kind == "datastore" and dep in dependencies})
    return {
        "languages": dict(languages.most_common()),
        "frameworks": frameworks,
        "datastores": datastores,
        "manifests": sorted(manifests),
    }


def _parse_all(inventory: Inventory) -> tuple[dict[str, FileFacts], bool]:
    deadline = time.monotonic() + PARSE_BUDGET_SEC
    targets = [info for info in inventory.files if info.parsed]

    def one(info) -> tuple[str, FileFacts | None]:
        if time.monotonic() > deadline:
            return info.path, None
        try:
            source = (inventory.root / info.path).read_bytes()
        except OSError:
            return info.path, None
        try:
            return info.path, read_facts(info.language, source)
        except Exception:  # A grammar bug must not stop the scan.
            return info.path, None

    facts: dict[str, FileFacts] = {}
    truncated = False
    with ThreadPoolExecutor(max_workers=4) as pool:
        for path, result in pool.map(one, targets):
            if result is None:
                truncated = truncated or time.monotonic() > deadline
                continue
            facts[path] = result
    return facts, truncated


def _dir_id(path: str) -> str:
    return "d:" + path


def _add_dirs(nodes: dict[str, MapNode], path: str) -> str | None:
    """Create dir nodes for every ancestor of path. Returns the parent id."""
    parent = str(PurePosixPath(path).parent)
    if parent in {".", ""}:
        return None
    node_id = _dir_id(parent)
    if node_id not in nodes:
        grandparent = _add_dirs(nodes, parent)
        nodes[node_id] = MapNode(id=node_id, kind="dir", label=PurePosixPath(parent).name, path=parent, parent=grandparent)
    return node_id


def _add_edge(edges: dict[str, MapEdge], source: str, target: str, kind: str, evidence: Evidence, label: str = "") -> None:
    if source == target:
        return
    key = f"{kind}:{source}->{target}"
    edge = edges.get(key)
    if edge is None:
        edges[key] = MapEdge(id=key, source=source, target=target, kind=kind, label=label, evidence=[evidence])
        return
    edge.count += 1
    if len(edge.evidence) < MAX_EVIDENCE:
        edge.evidence.append(evidence)


def build_files_view(inventory: Inventory, facts: dict[str, FileFacts], resolver: Resolver) -> tuple[MapView, list[Evidence], Counter]:
    nodes: dict[str, MapNode] = {}
    edges: dict[str, MapEdge] = {}
    unresolved: list[Evidence] = []
    packages: Counter = Counter()
    by_path = {info.path: info for info in inventory.files}

    for info in inventory.files:
        parent = _add_dirs(nodes, info.path)
        file_facts = facts.get(info.path)
        nodes["f:" + info.path] = MapNode(
            id="f:" + info.path,
            kind="file",
            label=PurePosixPath(info.path).name,
            path=info.path,
            parent=parent,
            language=info.language,
            role=info.role,
            entry_point=bool(file_facts and file_facts.entry_point),
            lines=info.lines,
            meta={"size": info.size, **({"parse_errors": True} if file_facts and file_facts.errors else {})},
        )
    for vendor, count in inventory.vendor_dirs.items():
        node_id = _dir_id(vendor)
        nodes[node_id] = MapNode(
            id=node_id, kind="dir", label=PurePosixPath(vendor).name, path=vendor, role="vendor",
            parent=_add_dirs(nodes, vendor), meta={"files": count, "collapsed": True},
        )

    for path, file_facts in facts.items():
        language = by_path[path].language or ""
        for fact in file_facts.imports:
            evidence = Evidence(path=path, line=fact.line, text=fact.text)
            if not fact.complete:
                resolved = resolver.resolve(path, language, fact) if fact.spec else None
                if resolved is None or resolved.file is None:
                    unresolved.append(evidence)
                    continue
            else:
                resolved = resolver.resolve(path, language, fact)
            source = "f:" + path
            if resolved.file:
                _add_edge(edges, source, "f:" + resolved.file, "import", evidence)
            elif resolved.directory:
                target = _dir_id(resolved.directory) if resolved.directory != "." else None
                if target and target in nodes:
                    _add_edge(edges, source, target, "import", evidence)
            elif resolved.package and not resolved.builtin:
                packages[resolved.package] += 1
                package_id = "p:" + resolved.package
                if package_id not in nodes:
                    ecosystem, _, name = resolved.package.partition(":")
                    nodes[package_id] = MapNode(id=package_id, kind="package", label=name, meta={"ecosystem": ecosystem})
                _add_edge(edges, source, package_id, "import", evidence)
            elif not resolved.builtin and fact.kind in {"include", "require", "dynamic"}:
                unresolved.append(evidence)
    return MapView(nodes=list(nodes.values()), edges=list(edges.values())), unresolved, packages


def build_project_map(root: Path, label: str | None = None) -> ProjectMap:
    inventory = collect_inventory(root)
    manifests = _read_manifests(inventory)
    facts, parse_truncated = _parse_all(inventory)
    resolver = Resolver([info.path for info in inventory.files], manifests)
    languages = {info.path: info.language for info in inventory.files}
    for path, file_facts in facts.items():
        resolver.learn_declarations(path, languages.get(path) or "", file_facts.declares)
    files_view, unresolved, packages = build_files_view(inventory, facts, resolver)

    from grephunt.project_map.architecture import build_architecture_view

    architecture = build_architecture_view(inventory, facts, manifests, files_view)
    roles = Counter(info.role for info in inventory.files)
    stats = {
        "files": len(inventory.files),
        "parsed_files": len(facts),
        "roles": dict(roles.most_common()),
        "vendor_dirs": inventory.vendor_dirs,
        "languages_parsed": sorted({info.language for info in inventory.files if info.parsed and info.language}),
        "import_edges": sum(1 for edge in files_view.edges if edge.kind == "import"),
        "external_packages": len(packages),
        "entry_points": sorted(node.path for node in files_view.nodes if node.entry_point and node.path),
    }
    return ProjectMap(
        root_label=label or inventory.root.name,
        stats=stats,
        stack=detect_stack(inventory, manifests, {key.partition(":")[2] for key in packages}),
        files=files_view,
        architecture=architecture,
        unresolved=unresolved[:500],
        truncated=inventory.truncated or parse_truncated,
    )


def write_project_map(project_map: ProjectMap, directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "project_map.json"
    path.write_text(project_map.model_dump_json(indent=1), encoding="utf-8")
    from grephunt.project_map.export import write_exports

    write_exports(project_map, directory)
    return path
