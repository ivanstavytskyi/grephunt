"""Architecture view: frontend -> routes -> handlers -> data access -> datastores.

Every edge comes from a fact in the code (a route registration, an HTTP call,
a database call, an import) and carries that place as evidence. Calls that
match no route are kept as "unmatched" nodes rather than dropped.
"""
from __future__ import annotations

import fnmatch
import re
from collections import Counter, defaultdict, deque
from pathlib import PurePosixPath

import yaml

from grephunt.project_map.architecture_facts import DbFact, RouteFact, engine_in_text
from grephunt.project_map.inventory import Inventory
from grephunt.project_map.model import Evidence, MapEdge, MapNode, MapView
from grephunt.project_map.parsers import FileFacts, ImportFact
from grephunt.project_map.resolve import NODE_BUILTINS, Resolver

MAX_EVIDENCE = 5
MAX_HTTP_TARGETS = 3
USES_DEPTH = 3
MAX_USES = 6
SKIP_ROLES = {"test", "generated", "vendor", "docs", "asset"}

ENGINE_LABELS = {
    "sqlite": "SQLite", "mysql": "MySQL", "postgresql": "PostgreSQL", "mssql": "SQL Server", "oracle": "Oracle",
    "h2": "H2", "mongodb": "MongoDB", "redis": "Redis", "marsdb": "MarsDB", "sql": "SQL database",
}
SQL_ENGINES = {"sqlite", "mysql", "postgresql", "mssql", "oracle", "h2", "sql"}
STACK_ENGINES = {"SQLite": "sqlite", "MySQL": "mysql", "PostgreSQL": "postgresql", "MongoDB": "mongodb", "Redis": "redis", "MarsDB (NoSQL)": "marsdb"}
IMAGE_ENGINES = [
    (re.compile(r"(^|/)(mysql|mariadb|percona)"), "mysql"), (re.compile(r"(^|/)(postgres|postgis|timescale)"), "postgresql"),
    (re.compile(r"(^|/)mongo"), "mongodb"), (re.compile(r"(^|/)(redis|valkey|keydb)"), "redis"),
    (re.compile(r"(^|/)(mssql|mcr\.microsoft\.com/mssql)"), "mssql"),
]
DRIVER_ENGINES = {
    "npm:sqlite3": "sqlite", "npm:better-sqlite3": "sqlite", "npm:mysql": "mysql", "npm:mysql2": "mysql", "npm:pg": "postgresql",
    "npm:mongodb": "mongodb", "npm:redis": "redis", "npm:ioredis": "redis", "npm:marsdb": "marsdb",
    "pypi:sqlite3": "sqlite", "pypi:psycopg2": "postgresql", "pypi:psycopg": "postgresql", "pypi:pymysql": "mysql",
    "pypi:MySQLdb": "mysql", "pypi:pymongo": "mongodb", "pypi:redis": "redis",
}
POM_ENGINES = [
    (re.compile(r"<artifactId>postgresql</artifactId>|org\.postgresql:postgresql"), "postgresql"),
    (re.compile(r"mysql-connector|mariadb-java-client"), "mysql"), (re.compile(r"<artifactId>h2</artifactId>|com\.h2database"), "h2"),
    (re.compile(r"sqlite-jdbc"), "sqlite"), (re.compile(r"spring-boot-starter-data-mongodb|mongodb-driver"), "mongodb"),
    (re.compile(r"spring-boot-starter-data-redis|jedis|lettuce"), "redis"),
]
# Import prefix -> ORM label. An ORM node sits between code and the database engine.
ORMS = [
    ("sequelize", "Sequelize"), ("typeorm", "TypeORM"), ("mongoose", "Mongoose"), ("@prisma/client", "Prisma"),
    ("knex", "Knex"), ("@mikro-orm", "MikroORM"), ("sqlalchemy", "SQLAlchemy"), ("flask_sqlalchemy", "SQLAlchemy"),
    ("django.db", "Django ORM"), ("peewee", "peewee"), ("tortoise", "Tortoise ORM"), ("gorm.io/gorm", "GORM"),
    ("org.springframework.data", "Spring Data"), ("jakarta.persistence", "JPA"), ("javax.persistence", "JPA"),
    ("org.hibernate", "Hibernate"), ("Doctrine\\ORM", "Doctrine"), ("Illuminate\\Database", "Eloquent"),
]
DOCUMENT_ORMS = {"Mongoose"}
FRONTEND_PACKAGES = re.compile(r"^npm:(@angular/|react$|react-dom|vue$|svelte|jquery|preact|solid-js|lit$|@vue/|next/|nuxt)")
BACKEND_PACKAGES = {
    "npm:express", "npm:koa", "npm:fastify", "npm:@nestjs/core", "npm:sequelize", "npm:mongoose", "npm:typeorm", "npm:pg",
    "npm:mysql", "npm:mysql2", "npm:sqlite3", "npm:knex", "npm:@prisma/client", "npm:hapi", "npm:@hapi/hapi", "npm:marsdb",
}
FRONTEND_DIRS = {"frontend", "client", "web", "webapp", "ui", "public", "static", "www", "templates", "views", "pages", "components"}
JS_LIKE = {"javascript", "typescript", "tsx", "html", "vue", "svelte"}
MIDDLEWARE = re.compile(
    r"^(is[A-Z]|ensure|require|check|deny|allow|append|authenticat|authoriz|validat|rateLimit|csrf|cors|protect|guard|"
    r"upload|observe|asyncHandler|wrap|catchAsync|handleAsync|bodyParser|json$|urlencoded|static$|serveIndex|limiter|passport)"
)
FORM_RE = re.compile(r"<form\b([^>]*)>", re.IGNORECASE)
ATTR_RE = re.compile(r"""\b(action|method)\s*=\s*(["'])(.*?)\2""", re.IGNORECASE | re.DOTALL)
URL_FOR_RE = re.compile(r"""url_for\(\s*['"]([\w.]+)['"]""")
PARAM_SEGMENT = re.compile(r"^(:\w+\??|\{[^}]+\}|<[^>]+>|\[[^\]]+\])$")


# --- small helpers ----------------------------------------------------------------------------


def _ev(path: str, line: int, snippet: str) -> Evidence:
    return Evidence(path=path, line=line, text=snippet)


class _Graph:
    def __init__(self) -> None:
        self.nodes: dict[str, MapNode] = {}
        self.edges: dict[str, MapEdge] = {}

    def node(self, node_id: str, **fields) -> MapNode:
        node = self.nodes.get(node_id)
        if node is None:
            node = MapNode(id=node_id, **fields)
            self.nodes[node_id] = node
        return node

    def edge(self, source: str, target: str, kind: str, evidence: Evidence | None, label: str = "") -> None:
        if source == target:
            return
        key = f"{kind}:{source}->{target}"
        edge = self.edges.get(key)
        if edge is None:
            self.edges[key] = MapEdge(id=key, source=source, target=target, kind=kind, label=label, evidence=[evidence] if evidence else [])
            return
        edge.count += 1
        if label and label not in edge.label.split(", ") and len(edge.label) < 120:
            edge.label = f"{edge.label}, {label}" if edge.label else label
        if evidence and evidence not in edge.evidence:
            if "(dynamic)" in label:
                edge.evidence.insert(0, evidence)  # the risky call first
                del edge.evidence[MAX_EVIDENCE:]
            elif len(edge.evidence) < MAX_EVIDENCE:
                edge.evidence.append(evidence)


def _segments(path: str) -> list[str]:
    return [part for part in path.split("/") if part]


def _split_url(url: str) -> tuple[str | None, str]:
    """(external host or None, path pattern). The host is None for same-origin or unknown bases."""
    url = url.strip()
    url = re.split(r"[?#]", url, maxsplit=1)[0]
    match = re.match(r"^(https?:)?//([^/]+)(.*)$", url, re.IGNORECASE)
    if match:
        host = match.group(2).lower()
        if "*" in host or host.split(":")[0] in {"localhost", "127.0.0.1", "0.0.0.0", "[::1]"}:
            return None, match.group(3) or "/"
        return host, match.group(3) or "/"
    if url.startswith(("/", "*")):
        return None, url
    return None, "*/" + url


def _segment_match(url_part: str, route_part: str) -> int | None:
    """Score of one segment: 2 literal, 1 wildcard/param, None no match."""
    if PARAM_SEGMENT.match(route_part):
        return 1
    if "*" in url_part or "*" in route_part:
        if fnmatch.fnmatchcase(url_part.lower(), route_part.lower().replace(":", "")) or fnmatch.fnmatchcase(route_part.lower(), url_part.lower()):
            return 1
        return None
    return 2 if url_part.lower() == route_part.lower() else None


def _match(url_path: str, route_path: str, prefix_allowed: bool) -> int | None:
    url = _segments(url_path)
    route = _segments(route_path)
    if not route or len(url) < len(route):
        return None
    score = 0
    literal = False
    for url_part, route_part in zip(url[len(url) - len(route):], route):
        part = _segment_match(url_part, route_part)
        if part is None:
            return None
        score += part
        literal = literal or (part == 2 and "*" not in route_part and not PARAM_SEGMENT.match(route_part))
    if not literal:
        return None
    rest = url[: len(url) - len(route)]
    if any(part != "*" for part in rest) and not prefix_allowed:
        return None
    return score - len([part for part in rest if part != "*"])


# --- the builder ------------------------------------------------------------------------------


class ArchitectureBuilder:
    def __init__(self, inventory: Inventory, facts: dict[str, FileFacts], manifests: dict[str, str], files_view: MapView, resolver: Resolver, stack: dict) -> None:
        self.inventory = inventory
        self.by_path = {info.path: info for info in inventory.files}
        self.facts = {path: item for path, item in facts.items() if self._role(path) not in SKIP_ROLES}
        self.manifests = manifests
        self.resolver = resolver
        self.stack = stack
        self.graph = _Graph()
        self.packages: dict[str, set[str]] = defaultdict(set)
        self.imports: dict[str, dict[str, Evidence]] = defaultdict(dict)
        for edge in files_view.edges:
            if edge.kind != "import" or not edge.source.startswith("f:"):
                continue
            source = edge.source[2:]
            if edge.target.startswith("p:"):
                self.packages[source].add(edge.target[2:])
            elif edge.target.startswith("f:"):
                self.imports[source][edge.target[2:]] = edge.evidence[0] if edge.evidence else _ev(source, 1, "")
        self.imported_by: Counter = Counter(target for targets in self.imports.values() for target in targets)
        self._binding_cache: dict[tuple[str, str], str | None] = {}

    # --- per-file facts ---------------------------------------------------------------------

    def _role(self, path: str) -> str:
        info = self.by_path.get(path)
        return info.role if info else "source"

    def language(self, path: str) -> str:
        info = self.by_path.get(path)
        return (info.language if info else None) or ""

    def bind(self, path: str, name: str) -> str | None:
        """Project file a local name in path refers to, through the file's imports."""
        key = (path, name)
        if key in self._binding_cache:
            return self._binding_cache[key]
        result = None
        facts = self.facts.get(path)
        fact: ImportFact | None = facts.binding(name) if facts else None
        if fact is not None:
            resolved = self.resolver.resolve(path, self.language(path), fact)
            result = resolved.file
            if result is None and resolved.directory:
                result = "dir:" + resolved.directory
        self._binding_cache[key] = result
        return result

    def is_frontend(self, path: str) -> bool:
        if self.language(path) not in JS_LIKE:
            return False
        facts = self.facts.get(path)
        if facts and facts.routes:
            return False
        packages = self.packages.get(path, ())
        if any(FRONTEND_PACKAGES.match(package) for package in packages):
            return True
        if facts and any(fact.spec.startswith("node:") or fact.spec in NODE_BUILTINS for fact in facts.imports):
            return False
        if any(package in BACKEND_PACKAGES for package in packages):
            return False
        return any(part.lower() in FRONTEND_DIRS for part in PurePosixPath(path).parts[:-1])

    def orm_of(self, path: str, receiver: str | None) -> str | None:
        candidates = [path]
        if receiver:
            bound = self.bind(path, receiver)
            if bound and not bound.startswith("dir:"):
                candidates.insert(0, bound)
        for candidate in candidates:
            facts = self.facts.get(candidate)
            specs = [fact.spec for fact in facts.imports] if facts else []
            for prefix, label in ORMS:
                if any(spec == prefix or spec.startswith((prefix + "/", prefix + ".", prefix + "\\")) for spec in specs):
                    return label
        return None

    # --- engines ----------------------------------------------------------------------------

    def collect_engines(self) -> dict[str, list[Evidence]]:
        engines: dict[str, list[Evidence]] = defaultdict(list)
        for path, facts in self.facts.items():
            for engine in facts.engines:
                engines[engine.engine].append(_ev(path, engine.line, engine.text))
        for path, content in self.manifests.items():
            name = PurePosixPath(path).name.lower()
            if name in {"pom.xml", "build.gradle"}:
                for pattern, engine in POM_ENGINES:
                    match = pattern.search(content)
                    if match:
                        line = content[: match.start()].count("\n") + 1
                        engines[engine].append(_ev(path, line, match.group(0)))
        for info in self.inventory.files:
            if info.role in {"config", "iac"} and info.size < 200_000 and info.language in {"yaml", "ini", "json", "xml", "toml", None}:
                if not re.search(r"(application|settings|config|database|\.env|compose)", info.path, re.IGNORECASE):
                    continue
                try:
                    content = (self.inventory.root / info.path).read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                for number, line in enumerate(content.splitlines(), 1):
                    engine = engine_in_text(line)
                    if engine and len(line) < 400:
                        engines[engine].append(_ev(info.path, number, line.strip()[:160]))
        for name, spec, path in self.compose():
            image = str(spec.get("image") or "").lower()
            engine = next((engine for pattern, engine in IMAGE_ENGINES if pattern.search(image)), None)
            if engine:
                line = next((number for number, text in enumerate(self.manifests[path].splitlines(), 1) if "image:" in text and image.split(":")[0] in text.lower()), 1)
                engines[engine].append(_ev(path, line, f"{name}: image {image}"))
        for label in self.stack.get("datastores", []):
            engine = STACK_ENGINES.get(label)
            if engine and engine not in engines:
                engines[engine].append(_ev("(dependencies)", 0, label))
        return engines

    def compose(self) -> list[tuple[str, dict, str]]:
        found = []
        for path, content in self.manifests.items():
            if not re.match(r"(docker-)?compose(\.[\w-]+)?\.ya?ml$", PurePosixPath(path).name.lower()):
                continue
            try:
                data = yaml.safe_load(content) or {}
            except yaml.YAMLError:
                continue
            services = data.get("services") if isinstance(data, dict) else None
            if isinstance(services, dict):
                for name, spec in services.items():
                    if isinstance(spec, dict):
                        found.append((str(name), spec, path))
        return found

    # --- routes -----------------------------------------------------------------------------

    def route_prefix(self, path: str, route: RouteFact) -> str:
        facts = self.facts[path]
        for mount in facts.mounts:
            if mount.name == route.receiver:
                return mount.prefix
        if route.receiver in {"app", "http", "Route", ""}:
            return ""
        for other, other_facts in self.facts.items():
            for mount in other_facts.mounts:
                if self.bind(other, mount.name) == path:
                    return mount.prefix
        return ""

    def handler_of(self, path: str, route: RouteFact) -> tuple[str, str | None, list[str]]:
        """(handler file, handler function, middleware names)."""
        if route.function:
            return path, route.function, []
        bound: list[tuple[str, str, str | None]] = []
        for name, member in route.handlers:
            target = self.bind(path, name)
            if target and target.startswith("dir:"):
                directory = target[4:]
                target = next((candidate for candidate, facts in self.facts.items() if str(PurePosixPath(candidate).parent) == directory and member in facts.functions), None)
            if target is None and self.language(path) == "php":
                target = self.php_class(path, name)
            if target is None and name in (self.facts[path].functions or []):
                target = path
            if target:
                bound.append((target, name, member))
        handlers = [item for item in bound if not MIDDLEWARE.match(item[2] or item[1])]
        middleware = [f"{name}.{member}" if member else name for _, name, member in bound if MIDDLEWARE.match(member or name)]
        if handlers:
            target, name, member = handlers[-1]
            return target, member or name, middleware
        if route.inline or not bound:
            return path, None, middleware
        target, name, member = bound[-1]
        return target, member or name, middleware

    def php_class(self, path: str, short: str) -> str | None:
        facts = self.facts.get(path)
        fact = facts.binding(short) if facts else None
        if fact is not None:
            resolved = self.resolver.resolve(path, "php", fact)
            if resolved.file:
                return resolved.file
        matches = [file for name, file in self.resolver.php_declares.items() if name.split("\\")[-1] == short.lower()]
        return matches[0] if len(matches) == 1 else None

    def inputs_for(self, path: str, function: str | None) -> list[dict]:
        facts = self.facts.get(path)
        if facts is None:
            return []
        seen, out = set(), []
        for item in facts.inputs:
            if function is not None and item.function != function:
                continue
            key = (item.source, item.name)
            if key not in seen:
                seen.add(key)
                out.append({"source": item.source, "name": item.name, "line": item.line})
        return out[:40]

    # --- build ------------------------------------------------------------------------------

    def build(self) -> MapView:
        graph = self.graph
        routes = self._routes()
        handler_files: set[str] = set()
        for route_id, route_path, method, path, fact, framework in routes:
            handler, function, middleware = self.handler_of(path, fact) if framework != "php-page" else (path, None, [])
            params = self.inputs_for(handler, function if framework != "php-page" else None)
            node = graph.node(route_id, kind="route", label=f"{method} {route_path}", layer="backend",
                              meta={"method": method, "path": route_path, "framework": framework, "params": [], "middleware": []})
            node.meta["params"] = _merge(node.meta["params"], params)
            node.meta["middleware"] = sorted(set(node.meta["middleware"]) | set(middleware))
            if function:
                node.meta.setdefault("handler", f"{handler}:{function}")
            self._file_node(handler, "backend")
            handler_files.add(handler)
            graph.edge(route_id, "f:" + handler, "handles", _ev(path, fact.line, fact.text), function or "")
        self._http_calls(routes)
        self._forms(routes)
        data_files = self._data_access()
        self._uses(handler_files, data_files)
        self._external_calls()
        self._services()
        return MapView(nodes=list(graph.nodes.values()), edges=list(graph.edges.values()))

    def _file_node(self, path: str, layer: str) -> MapNode:
        info = self.by_path.get(path)
        node = self.graph.node(
            "f:" + path, kind="file", label=PurePosixPath(path).name, path=path, layer=layer,
            language=info.language if info else None, role=info.role if info else None,
            meta={"dir": str(PurePosixPath(path).parent)},
        )
        if layer == "backend" and node.layer == "frontend":
            node.layer = "backend"
        return node

    def _routes(self) -> list[tuple[str, str, str, str, RouteFact, str]]:
        out = []
        frameworks = set(self.stack.get("frameworks", []))
        php_framework = bool(frameworks & {"Laravel", "Symfony", "Slim"})
        reachable = self._reachable_from_entry_points()
        for path, facts in sorted(self.facts.items()):
            for fact in facts.routes:
                if fact.framework == "express" and path not in reachable:
                    continue  # a copy or snippet that no running code loads
                route_path = self.route_prefix(path, fact).rstrip("/") + "/" + fact.path.lstrip("/")
                route_path = re.sub(r"/+", "/", route_path) or "/"
                out.append((f"r:{fact.method} {route_path}", route_path, fact.method, path, fact, fact.framework))
            if self.language(path) == "php" and facts.page and not php_framework and self._php_reachable(path, facts):
                sources = {item.source for item in facts.inputs if item.function is None}
                method = "GET" if sources <= {"query", "header", "cookie"} else "POST" if sources <= {"body", "files", "header", "cookie"} else "ANY"
                route_path = "/" + path
                fact = RouteFact(method, route_path, 1, "", "php-page")
                out.append((f"r:{method} {route_path}", route_path, method, path, fact, "php-page"))
        return out

    def _reachable_from_entry_points(self) -> set[str]:
        starts = [path for path, facts in self.facts.items() if facts.entry_point]
        if not starts:
            return set(self.facts)
        seen = set(starts)
        queue = deque(starts)
        while queue:
            current = queue.popleft()
            for target in self.imports.get(current, {}):
                if target not in seen:
                    seen.add(target)
                    queue.append(target)
        return seen

    def _php_reachable(self, path: str, facts: FileFacts) -> bool:
        name = PurePosixPath(path).name.lower()
        parts = {part.lower() for part in PurePosixPath(path).parts[:-1]}
        if name.endswith((".inc.php", ".inc", ".class.php", ".tpl.php")) or parts & {"includes", "include", "inc", "lib", "libs", "classes", "config", "templates", "vendor"}:
            return False
        has_input = any(item.function is None for item in facts.inputs)
        return has_input or self.imported_by[path] == 0

    def _match_routes(self, method: str, url_path: str, routes) -> list[str]:
        best: list[tuple[int, str]] = []
        for use_pass in (False, True):
            for route_id, route_path, route_method, path, fact, _ in routes:
                if (route_method == "USE") != use_pass:
                    continue
                if method not in {"ANY", route_method} and route_method not in {"ANY", "USE"}:
                    continue
                score = _match(url_path, route_path, prefix_allowed=fact.receiver not in {"app", "http", "Route", ""})
                if score is not None:
                    best.append((score, route_id))
            if best:
                break
        if not best:
            return []
        top = max(score for score, _ in best)
        return sorted({route_id for score, route_id in best if score == top})[:MAX_HTTP_TARGETS]

    def _http_calls(self, routes) -> None:
        for path, facts in self.facts.items():
            if not facts.http_calls:
                continue
            frontend = self.is_frontend(path)
            for call in facts.http_calls:
                host, url_path = _split_url(call.url)
                evidence = _ev(path, call.line, call.text)
                if host:
                    continue  # handled by _external_calls
                if url_path.strip("*/") == "":
                    continue
                if not frontend:
                    continue
                source = self._file_node(path, "frontend").id
                targets = self._match_routes(call.method, url_path, routes)
                if not targets:
                    target = f"u:{call.method} {url_path}"
                    self.graph.node(target, kind="route", label=f"{call.method} {url_path}", layer="backend", meta={"method": call.method, "path": url_path, "unmatched": True})
                    targets = [target]
                for target in targets:
                    self.graph.edge(source, target, "http", evidence, f"{call.method} {call.url}"[:120])

    def _forms(self, routes) -> None:
        by_function = defaultdict(list)
        for route_id, _, _, _, fact, _ in routes:
            if fact.function:
                by_function[fact.function].append(route_id)
        for info in self.inventory.files:
            if info.language not in {"html"} or info.role in SKIP_ROLES or info.size > 500_000:
                continue
            try:
                content = (self.inventory.root / info.path).read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for match in FORM_RE.finditer(content):
                attrs = {key.lower(): value for key, _, value in ATTR_RE.findall(match.group(1))}
                action = attrs.get("action", "")
                method = attrs.get("method", "GET").upper()
                line = content[: match.start()].count("\n") + 1
                evidence = _ev(info.path, line, match.group(0)[:160])
                endpoint = URL_FOR_RE.search(action)
                if endpoint:
                    targets = by_function.get(endpoint.group(1).split(".")[-1], [])
                elif action.startswith("/"):
                    targets = self._match_routes(method, re.sub(r"\{\{.*?\}\}|\{%.*?%\}", "*", action), routes)
                else:
                    continue
                if targets:
                    source = self._file_node(info.path, "frontend").id
                    for target in targets:
                        self.graph.edge(source, target, "http", evidence, f"form {method} {action}"[:120])

    def _data_access(self) -> set[str]:
        engines = self.collect_engines()
        sql_engines = sorted((engine for engine in engines if engine in SQL_ENGINES), key=lambda engine: -len(engines[engine]))
        graph = self.graph
        data_files: set[str] = set()

        def engine_node(engine: str) -> str:
            node = graph.node("s:" + engine, kind="datastore", label=ENGINE_LABELS.get(engine, engine), layer="data", meta={"engine": engine})
            if not node.meta.get("evidence"):
                node.meta["evidence"] = [item.model_dump() for item in engines.get(engine, [])[:MAX_EVIDENCE]]
            return node.id

        project_orms = Counter(orm for orm in (self.orm_of(path, None) for path in self.facts) if orm and orm not in DOCUMENT_ORMS)
        default_orm = next(iter(project_orms)) if len(project_orms) == 1 else None
        reachable = self._reachable_from_entry_points()
        for path, facts in self.facts.items():
            if not facts.db_calls or self.is_frontend(path):
                continue
            if self.language(path) in JS_LIKE and path not in reachable:
                continue
            calls = _merge_calls(facts.db_calls)
            if not calls:
                continue
            data_files.add(path)
            source = self._file_node(path, "backend").id
            file_engines = {DRIVER_ENGINES[package] for package in self.packages.get(path, ()) if package in DRIVER_ENGINES}
            for call in calls:
                evidence = _ev(path, call.line, call.text)
                orm = call.via if call.via in {label for _, label in ORMS} else None
                if call.family in {"orm", "sql", "mongo"} and orm is None:
                    orm = self.orm_of(path, call.receiver)
                if call.family == "mongo" and orm not in DOCUMENT_ORMS:
                    orm = None
                elif call.family == "orm" and orm is None:
                    orm = default_orm
                engine = call.engine or _engine_hint(call.receiver) or (next(iter(file_engines)) if len(file_engines) == 1 else None)
                if call.family == "mongo" or orm in DOCUMENT_ORMS:
                    engine = engine or ("marsdb" if "marsdb" in engines else "mongodb")
                label = f"{call.op}{' (dynamic)' if call.dynamic else ''}"
                if orm and not call.engine:
                    orm_id = "o:" + orm.lower().replace(" ", "-")
                    graph.node(orm_id, kind="component", label=orm, layer="data", meta={"orm": True})
                    graph.edge(source, orm_id, "db", evidence, label)
                    targets = [engine] if engine else (["mongodb"] if orm in DOCUMENT_ORMS else sql_engines[:1] or ["sql"])
                    for target in targets:
                        graph.edge(orm_id, engine_node(target), "db", engines.get(target, [None])[0], "")
                    continue
                target = engine or (sql_engines[0] if sql_engines and call.family in {"sql", "orm"} else "sql")
                graph.edge(source, engine_node(target), "db", evidence, label)
            node = graph.nodes[source]
            node.meta["db_calls"] = len(calls)
            node.meta["dynamic_sql"] = sum(1 for call in calls if call.dynamic)
        for engine in engines:
            engine_node(engine)
        return data_files

    def _uses(self, handler_files: set[str], data_files: set[str]) -> None:
        """Handler -> data-access file reached through imports (controller -> service -> repository)."""
        for handler in handler_files:
            if handler in data_files:
                continue
            found = 0
            seen = {handler}
            queue = deque([(handler, 0, None)])
            while queue and found < MAX_USES:
                current, depth, first = queue.popleft()
                if depth >= USES_DEPTH:
                    continue
                for target, evidence in self.imports.get(current, {}).items():
                    if target in seen or self._role(target) in SKIP_ROLES:
                        continue
                    seen.add(target)
                    hop = first or evidence
                    if target in data_files:
                        via = "" if depth == 0 else f"via {PurePosixPath(current).name}"
                        self.graph.edge("f:" + handler, "f:" + target, "import", hop, via)
                        found += 1
                    else:
                        queue.append((target, depth + 1, hop))

    def _external_calls(self) -> None:
        for path, facts in self.facts.items():
            for call in facts.http_calls:
                host, _ = _split_url(call.url)
                if not host:
                    continue
                layer = "frontend" if self.is_frontend(path) else "backend"
                source = self._file_node(path, layer).id
                target = self.graph.node("x:" + host, kind="external", label=host, layer="external").id
                self.graph.edge(source, target, "http", _ev(path, call.line, call.text), f"{call.method} {call.url}"[:120])

    def _services(self) -> None:
        services = self.compose()
        if not services:
            return
        ids: dict[str, str] = {}
        for name, spec, path in services:
            image = str(spec.get("image") or "")
            engine = next((engine for pattern, engine in IMAGE_ENGINES if pattern.search(image.lower())), None)
            if engine is None and not spec.get("build"):
                engine = next((engine for pattern, engine in IMAGE_ENGINES if pattern.search(name.lower())), None) if not image else None
            if engine:
                node = self.graph.node("s:" + engine, kind="datastore", label=ENGINE_LABELS.get(engine, engine), layer="data", meta={"engine": engine})
                node.meta.setdefault("services", []).append(name)
                ids[name] = node.id
                continue
            build = spec.get("build")
            context = build.get("context") if isinstance(build, dict) else build
            ports = [str(port) for port in spec.get("ports") or []]
            node = self.graph.node(f"svc:{name}", kind="component", label=name, layer="other",
                                   meta={"service": True, "image": image or None, "build": str(context) if context else None, "ports": ports, "compose": path})
            ids[name] = node.id
        for name, spec, path in services:
            depends = spec.get("depends_on") or []
            names = list(depends) if isinstance(depends, (list, dict)) else []
            lines = self.manifests.get(path, "").splitlines()
            start = next((index for index, line in enumerate(lines) if re.match(rf"^\s+{re.escape(name)}\s*:", line)), 0)
            line = next((index for index in range(start, len(lines)) if "depends_on" in lines[index]), start) + 1
            for dependency in names:
                if str(dependency) in ids:
                    self.graph.edge(ids[name], ids[str(dependency)], "service", Evidence(path=path, line=line, text=f"{name} depends_on {dependency}"), "depends_on")


def _engine_hint(receiver: str | None) -> str | None:
    if not receiver:
        return None
    lower = receiver.lower()
    for key, engine in (("sqlite", "sqlite"), ("mysql", "mysql"), ("postgres", "postgresql"), ("pg", "postgresql"), ("mongo", "mongodb"), ("redis", "redis")):
        if re.search(rf"(^|[^a-z]){key}", lower):
            return engine
    return None


def _merge_calls(calls: list[DbFact]) -> list[DbFact]:
    """One fact per line: a raw SQL string and the call that runs it are one database call."""
    by_line: dict[int, DbFact] = {}
    for call in calls:
        current = by_line.get(call.line)
        if current is None:
            by_line[call.line] = call
            continue
        if current.receiver is None and call.receiver is not None:
            call.dynamic = call.dynamic or current.dynamic
            by_line[call.line] = call
        else:
            current.dynamic = current.dynamic or call.dynamic
            current.engine = current.engine or call.engine
    return sorted(by_line.values(), key=lambda call: call.line)


def _merge(existing: list[dict], new: list[dict]) -> list[dict]:
    keys = {(item["source"], item["name"]) for item in existing}
    return existing + [item for item in new if (item["source"], item["name"]) not in keys]


def build_architecture_view(inventory: Inventory, facts: dict[str, FileFacts], manifests: dict[str, str], files_view: MapView, resolver: Resolver | None = None, stack: dict | None = None) -> MapView:
    if resolver is None:
        resolver = Resolver([info.path for info in inventory.files], manifests)
    return ArchitectureBuilder(inventory, facts, manifests, files_view, resolver, stack or {}).build()
