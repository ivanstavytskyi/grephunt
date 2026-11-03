"""Routes, HTTP calls, database calls, and request inputs, read from one syntax tree.

Each fact keeps its line so the architecture view can show where it came from.
Strings are evaluated where the file itself defines the pieces
(``this.host + '/api/Products'``); anything unknown becomes ``*``.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

import tree_sitter as ts

from grephunt.project_map.parsers import FileFacts, line_of, snippet, string_value, text, walk

VERBS = {"get", "post", "put", "delete", "patch", "options", "head", "all", "any"}


@dataclass
class RouteFact:
    method: str
    """GET, POST, ..., ANY, or USE (Express middleware with a path)."""
    path: str
    line: int
    text: str
    framework: str
    receiver: str = ""
    """Router variable the route is registered on: app, router, v1."""
    handlers: list[tuple[str, str | None]] = field(default_factory=list)
    """Candidate handler references as (name, member): ('search', 'searchProducts'), ('login', None)."""
    function: str | None = None
    """Handler function defined in this file (Flask view, Spring method), if known."""
    inline: bool = False


@dataclass
class HttpCallFact:
    method: str
    url: str
    line: int
    text: str
    client: str


@dataclass
class DbFact:
    op: str
    line: int
    text: str
    family: str
    """sql, orm, mongo, redis."""
    engine: str | None = None
    via: str | None = None
    receiver: str | None = None
    function: str | None = None
    dynamic: bool = False
    """The query text is built from variables (concatenation or interpolation)."""


@dataclass
class InputFact:
    source: str
    """query, body, params, cookie, header, files, form, request."""
    name: str
    line: int
    function: str | None = None


@dataclass
class EngineFact:
    engine: str
    line: int
    text: str


@dataclass
class MountFact:
    prefix: str
    name: str
    """The router variable or import binding mounted under prefix."""
    line: int


# --- helpers ----------------------------------------------------------------------------------

STRING_TYPES = {"string", "template_string", "string_literal", "interpreted_string_literal", "raw_string_literal", "encapsed_string", "text_block"}
FRAGMENT_TYPES = {"string_fragment", "string_content", "interpreted_string_literal_content", "raw_string_literal_content"}
FUNCTION_TYPES = {
    "function_declaration", "generator_function_declaration", "method_definition", "function_definition",
    "method_declaration", "function_expression", "arrow_function",
}
INLINE_FUNCTIONS = {"arrow_function", "function_expression", "function", "anonymous_function", "arrow_function_expression", "func_literal", "lambda"}

SQL_RE = re.compile(
    r"^\s*(select\s[\s\S]*?\sfrom\b|insert\s+(ignore\s+)?into\b|update\s+[`\"\w.]+\s+set\b|delete\s+from\b|replace\s+into\b|"
    r"create\s+(temporary\s+)?table\b|drop\s+table\b|alter\s+table\b|merge\s+into\b|with\s+\w+\s+as\s*\()",
    re.IGNORECASE,
)
URL_ENGINES = [
    (re.compile(r"\bmongodb(\+srv)?://", re.IGNORECASE), "mongodb"),
    (re.compile(r"\b(postgres|postgresql)(\+\w+)?://|jdbc:postgresql:", re.IGNORECASE), "postgresql"),
    (re.compile(r"\b(mysql|mariadb)(\+\w+)?://|jdbc:(mysql|mariadb):|\bmysql:host=", re.IGNORECASE), "mysql"),
    (re.compile(r"\bsqlite(\+\w+)?:|jdbc:sqlite:|\.sqlite3?\b|\.db['\"]", re.IGNORECASE), "sqlite"),
    (re.compile(r"\bredis(s)?://", re.IGNORECASE), "redis"),
    (re.compile(r"jdbc:h2:", re.IGNORECASE), "h2"),
    (re.compile(r"\b(mssql|sqlserver)://|jdbc:sqlserver:", re.IGNORECASE), "mssql"),
    (re.compile(r"jdbc:oracle:", re.IGNORECASE), "oracle"),
]
DIALECTS = {
    "sqlite": "sqlite", "sqlite3": "sqlite", "mysql": "mysql", "mariadb": "mysql", "postgres": "postgresql",
    "postgresql": "postgresql", "pgx": "postgresql", "mssql": "mssql", "sqlserver": "mssql", "oracle": "oracle",
    "godror": "oracle", "h2": "h2",
}


def engine_in_text(value: str) -> str | None:
    for pattern, engine in URL_ENGINES:
        if pattern.search(value):
            return engine
    return None


def call_args(node: ts.Node | None) -> list[ts.Node]:
    if node is None:
        return []
    out = []
    for child in node.named_children:
        if child.type == "comment":
            continue
        if child.type == "argument":  # PHP wraps each argument
            inner = [part for part in child.named_children if part.type != "name"] or child.named_children
            if inner:
                out.append(inner[-1])
            continue
        out.append(child)
    return out


def enclosing_function(node: ts.Node) -> str | None:
    """Name of the outermost named function around node."""
    found = None
    current = node.parent
    while current is not None:
        name = None
        if current.type in {"function_declaration", "generator_function_declaration", "method_definition", "function_definition", "method_declaration"}:
            name = current.child_by_field_name("name")
        elif current.type in {"arrow_function", "function_expression", "function"} and current.parent is not None and current.parent.type == "variable_declarator":
            name = current.parent.child_by_field_name("name")
        if name is not None and name.type in {"identifier", "property_identifier", "name", "field_identifier"}:
            found = text(name)
        current = current.parent
    return found


class Strings:
    """Evaluate string expressions with the constants the file itself defines."""

    def __init__(self, tree: ts.Tree) -> None:
        self.consts: dict[str, list[ts.Node]] = {}
        for node in walk(tree.root_node):
            key, value = None, None
            kind = node.type
            if kind in {"variable_declarator", "public_field_definition", "field_definition", "const_spec", "var_spec"}:
                key, value = node.child_by_field_name("name"), node.child_by_field_name("value")
            elif kind in {"assignment_expression", "assignment", "short_var_declaration"}:
                key, value = node.child_by_field_name("left"), node.child_by_field_name("right")
            if key is None or value is None:
                continue
            if value.type == "expression_list":
                if len(value.named_children) != 1:
                    continue
                value = value.named_children[0]
            if key.type == "expression_list":
                if len(key.named_children) != 1:
                    continue
                key = key.named_children[0]
            name = text(key)
            if kind in {"public_field_definition", "field_definition"}:
                name = "this." + name
            if len(name) <= 80:
                self.consts.setdefault(name, []).append(value)

    def value(self, node: ts.Node | None, depth: int = 0) -> str:
        return _squash(self._value(node, depth))

    def _value(self, node: ts.Node | None, depth: int) -> str:
        if node is None or depth > 6:
            return "*"
        kind = node.type
        if kind in STRING_TYPES:
            plain = string_value(node)
            if plain is not None:
                return plain
            out = []
            for child in node.children:
                if child.type in FRAGMENT_TYPES:
                    out.append(text(child))
                elif child.type == "escape_sequence":
                    out.append(text(child)[1:])
                elif child.type in {"template_substitution", "interpolation"}:
                    inner = [part for part in child.named_children if part.type not in {"format_specifier", "type_conversion"}]
                    out.append(self._value(inner[0], depth + 1) if inner else "*")
                elif child.is_named and child.type not in {"string_start", "string_end"}:
                    out.append(self._value(child, depth + 1))
            return "".join(out)
        if kind == "concatenated_string":
            return "".join(self._value(child, depth + 1) for child in node.named_children)
        if kind in {"binary_expression", "binary_operator"}:
            operator = node.child_by_field_name("operator")
            if text(operator) in {"+", "."}:
                return self._value(node.child_by_field_name("left"), depth + 1) + self._value(node.child_by_field_name("right"), depth + 1)
            return "*"
        if kind in {"parenthesized_expression", "argument"} and node.named_children:
            return self._value(node.named_children[0], depth + 1)
        if kind in {"identifier", "variable_name", "member_expression", "attribute", "name"}:
            values = self.consts.get(text(node), [])
            if len(values) == 1 and values[0] is not node:
                return self._value(values[0], depth + 1)
            return "*"
        if kind in {"call_expression", "call", "function_call_expression"}:
            function = text(node.child_by_field_name("function") or (node.named_children[0] if node.named_children else None))
            arguments = call_args(node.child_by_field_name("arguments"))
            if function in {"fmt.Sprintf", "sprintf", "String.format"} and arguments:
                return re.sub(r"%[-+ #0-9.]*[a-zA-Z]", "*", self._value(arguments[0], depth + 1))
            if function.endswith(".format") and node.child_by_field_name("function") is not None:
                base = node.child_by_field_name("function").child_by_field_name("object")
                return re.sub(r"\{[^}]*\}", "*", self._value(base, depth + 1))
        return "*"


def _squash(value: str) -> str:
    return re.sub(r"\*+", "*", value)


def _sql_text(node: ts.Node) -> str:
    raw = text(node)
    return re.sub(r"^[a-zA-Z]*[\"'`]+", "", raw)[:300]


def _is_dynamic(node: ts.Node) -> bool:
    if any(child.type in {"template_substitution", "interpolation", "variable_name"} for child in node.children):
        return True
    parent = node.parent
    while parent is not None and parent.type in {"parenthesized_expression"}:
        parent = parent.parent
    if parent is not None and parent.type in {"binary_expression", "binary_operator"}:
        return any(not (child.type in STRING_TYPES and string_value(child) is not None) for child in parent.named_children)
    return False


def _raw_sql(tree: ts.Tree, source: bytes, facts: FileFacts) -> None:
    seen = set()
    for node in walk(tree.root_node):
        if node.type not in STRING_TYPES or (node.parent is not None and node.parent.type in STRING_TYPES):
            continue
        body = _sql_text(node)
        match = SQL_RE.match(body)
        if not match:
            continue
        line = line_of(node)
        if line in seen:
            continue
        seen.add(line)
        op = match.group(1).split()[0].upper()
        facts.db_calls.append(DbFact(op, line, snippet(source, node), "sql", function=enclosing_function(node), dynamic=_is_dynamic(node)))


def _engine_strings(tree: ts.Tree, source: bytes, facts: FileFacts) -> None:
    for node in walk(tree.root_node):
        if node.type not in STRING_TYPES or (node.parent is not None and node.parent.type in STRING_TYPES):
            continue
        value = text(node)
        if len(value) > 400:
            continue
        engine = engine_in_text(value)
        if engine:
            facts.engines.append(EngineFact(engine, line_of(node), snippet(source, node)))


# --- JavaScript / TypeScript ------------------------------------------------------------------

JS_HTTP_RECEIVER = re.compile(r"(^|\.)(\$?http|httpclient|axios|\$|jquery|superagent|got|ky|request|apiclient|client|instance|api)$", re.IGNORECASE)
JS_ROUTER_RECEIVER = re.compile(r"(^|\.)(app|router|server|api|routes?|\w*router|\w*app|r|v\d+)$", re.IGNORECASE)
JS_ORM_METHODS = {
    "findAll", "findOne", "findByPk", "findOrCreate", "findAndCountAll", "findById", "find", "count", "create",
    "bulkCreate", "update", "destroy", "upsert", "increment", "decrement", "aggregate", "insertMany", "updateOne",
    "updateMany", "deleteOne", "deleteMany", "countDocuments", "findOneAndUpdate", "findByIdAndUpdate", "save",
}
JS_MONGO_METHODS = {"find", "findOne", "insert", "insertOne", "insertMany", "update", "updateOne", "updateMany", "remove", "deleteOne", "deleteMany", "aggregate", "count", "countDocuments"}
JS_GLOBALS = {"Object", "Array", "Promise", "JSON", "Math", "Date", "Reflect", "Buffer", "String", "Number", "Symbol", "Map", "Set", "Error", "console", "document", "window"}
JS_RAW_DB_RECEIVER = re.compile(r"(^|\.)(sequelize|db|database|pool|conn|connection|client|knex|sql|mysql|pg|sqlite|connectionpool|em|entitymanager|datasource|prisma)$", re.IGNORECASE)
JS_INPUT_OBJECT = re.compile(r"^(req|request|ctx\.request|ctx)\.(query|body|params|cookies|signedCookies|headers|files|file)$")


def _js_handlers(arguments: list[ts.Node]) -> tuple[list[tuple[str, str | None]], bool]:
    handlers: list[tuple[str, str | None]] = []
    inline = False
    for argument in arguments:
        if argument.type in INLINE_FUNCTIONS:
            inline = True
            continue
        stack = [argument]
        while stack:
            current = stack.pop()
            if current.type in INLINE_FUNCTIONS:
                inline = True
                continue
            if current.type == "identifier":
                handlers.append((text(current), None))
                continue
            if current.type == "member_expression":
                parts = text(current).split(".")
                if parts[0] not in {"this", "req", "res"} and re.fullmatch(r"[\w$]+", parts[0]):
                    handlers.append((parts[0], parts[1] if len(parts) > 1 else None))
                continue
            stack.extend(reversed(current.named_children))
    return handlers, inline


def _js_route_paths(node: ts.Node, strings: Strings) -> list[str]:
    if node.type == "array":
        return [path for child in node.named_children for path in _js_route_paths(child, strings)]
    if node.type in STRING_TYPES:
        value = strings.value(node)
        return [value] if value.startswith("/") else []
    return []


def _js_options(node: ts.Node | None, strings: Strings) -> dict[str, str]:
    options: dict[str, str] = {}
    if node is None or node.type != "object":
        return options
    for pair in node.named_children:
        if pair.type == "pair":
            key = text(pair.child_by_field_name("key")).strip("'\"")
            options[key] = strings.value(pair.child_by_field_name("value"))
    return options


def _js_dynamic(node: ts.Node) -> bool:
    if node.type == "template_string":
        return any(child.type == "template_substitution" for child in node.children)
    return node.type in {"binary_expression", "identifier", "member_expression"}


JS_INPUT_SOURCES = {"query": "query", "body": "body", "params": "params", "cookies": "cookie", "signedCookies": "cookie", "headers": "header", "files": "files", "file": "files"}


def _javascript(tree: ts.Tree, source: bytes, facts: FileFacts, strings: Strings) -> None:
    for node in walk(tree.root_node):
        kind = node.type
        if kind == "call_expression":
            _js_call(node, source, facts, strings)
        elif kind == "new_expression":
            constructor = text(node.child_by_field_name("constructor"))
            arguments = call_args(node.child_by_field_name("arguments"))
            if constructor.endswith("Sequelize") and arguments:
                first = strings.value(arguments[0])
                engine = engine_in_text(first)
                if engine:
                    facts.engines.append(EngineFact(engine, line_of(node), snippet(source, node)))
            elif constructor in {"sqlite3.Database", "Database"} and "sqlite" in text(tree.root_node)[:4000].lower():
                facts.engines.append(EngineFact("sqlite", line_of(node), snippet(source, node)))
            elif constructor in {"MongoClient", "mongodb.MongoClient"}:
                facts.engines.append(EngineFact("mongodb", line_of(node), snippet(source, node)))
            elif constructor in {"Redis", "IORedis"}:
                facts.engines.append(EngineFact("redis", line_of(node), snippet(source, node)))
            elif constructor in {"Pool", "pg.Pool", "Client", "pg.Client"} and re.search(rb"""from ['"]pg['"]|require\(['"]pg['"]\)""", source):
                facts.engines.append(EngineFact("postgresql", line_of(node), snippet(source, node)))
        elif kind == "pair":
            key = text(node.child_by_field_name("key")).strip("'\"")
            if key == "dialect":
                value = string_value(node.child_by_field_name("value"))
                if value and value.lower() in DIALECTS:
                    facts.engines.append(EngineFact(DIALECTS[value.lower()], line_of(node), snippet(source, node)))
        elif kind == "member_expression":
            obj = node.child_by_field_name("object")
            if obj is not None and JS_INPUT_OBJECT.match(text(obj)):
                facts.inputs.append(InputFact(JS_INPUT_SOURCES[text(obj).split(".")[-1]], text(node.child_by_field_name("property")), line_of(node), enclosing_function(node)))
        elif kind == "subscript_expression":
            obj = node.child_by_field_name("object")
            index = string_value(node.child_by_field_name("index"))
            if obj is not None and index and JS_INPUT_OBJECT.match(text(obj)):
                facts.inputs.append(InputFact(JS_INPUT_SOURCES[text(obj).split(".")[-1]], index, line_of(node), enclosing_function(node)))


def _js_call(node: ts.Node, source: bytes, facts: FileFacts, strings: Strings) -> None:
    function = node.child_by_field_name("function")
    arguments = call_args(node.child_by_field_name("arguments"))
    if function is None:
        return
    name = text(function)
    line = line_of(node)
    if function.type == "identifier":
        if name == "fetch" and arguments:
            options = _js_options(arguments[1] if len(arguments) > 1 else None, strings)
            method = options.get("method", "GET").upper()
            facts.http_calls.append(HttpCallFact(method if method != "*" else "ANY", strings.value(arguments[0]), line, snippet(source, node), "fetch"))
        elif name == "axios" and arguments:
            options = _js_options(arguments[0], strings) if arguments[0].type == "object" else {}
            url = options.get("url") if options else strings.value(arguments[0])
            if url:
                facts.http_calls.append(HttpCallFact(options.get("method", "GET").upper(), url, line, snippet(source, node), "axios"))
        return
    if function.type != "member_expression":
        return
    receiver_node = function.child_by_field_name("object")
    receiver = text(receiver_node)
    method = text(function.child_by_field_name("property"))
    lower = method.lower()

    # Routes: app.get('/x', handler), router.post(...), app.use('/x', handler).
    if (lower in VERBS or lower == "use") and len(arguments) >= 2 and "http" not in receiver.lower() and "axios" not in receiver.lower():
        paths = _js_route_paths(arguments[0], strings)
        if paths and JS_ROUTER_RECEIVER.search(receiver):
            rest = arguments[1:]
            if lower == "use" and len(rest) == 1 and rest[0].type == "identifier":
                for path in paths:
                    facts.mounts.append(MountFact(path, text(rest[0]), line))
                return
            handlers, inline = _js_handlers(rest)
            verb = {"use": "USE", "all": "ANY", "any": "ANY"}.get(lower, lower.upper())
            for path in paths:
                facts.routes.append(RouteFact(verb, path, line, snippet(source, node), "express", receiver.split(".")[-1], handlers, inline=inline))
            return
    # Generated REST resources: finale.resource({ model, endpoints: ['/api/Users', '/api/Users/:id'] }).
    if method == "resource" and arguments and arguments[0].type == "object":
        for pair in arguments[0].named_children:
            if pair.type == "pair" and text(pair.child_by_field_name("key")) == "endpoints":
                for path in _js_route_paths(pair.child_by_field_name("value"), strings):
                    facts.routes.append(RouteFact("ANY", path, line, snippet(source, node), receiver or "rest"))
        return
    # HTTP clients: this.http.get(url), axios.post(url), $.ajax({url}), xhr.open('GET', url).
    if lower in VERBS - {"all", "any"} | {"request", "ajax", "getjson"} and arguments and JS_HTTP_RECEIVER.search(receiver):
        if lower == "ajax" or (lower == "request" and arguments[0].type == "object"):
            options = _js_options(arguments[0], strings)
            url = options.get("url")
            verb = (options.get("method") or options.get("type") or "GET").upper()
        else:
            url = strings.value(arguments[0])
            verb = "GET" if lower == "getjson" else lower.upper()
        if url:
            facts.http_calls.append(HttpCallFact(verb if verb != "*" else "ANY", url, line, snippet(source, node), receiver.split(".")[-1]))
        return
    if method == "open" and len(arguments) >= 2 and string_value(arguments[0]) and string_value(arguments[0]).upper() in {"GET", "POST", "PUT", "DELETE", "PATCH"}:
        facts.http_calls.append(HttpCallFact(string_value(arguments[0]).upper(), strings.value(arguments[1]), line, snippet(source, node), "xhr"))
        return

    # Databases.
    root = receiver.split(".")[0].split("(")[0]
    last = receiver.split(".")[-1]
    if method in {"query", "execute", "raw", "exec", "run", "all", "prepare", "$queryRaw", "$executeRaw", "$queryRawUnsafe", "$executeRawUnsafe"} and JS_RAW_DB_RECEIVER.search(receiver):
        dynamic = bool(arguments) and _js_dynamic(arguments[0])
        facts.db_calls.append(DbFact(method, line, snippet(source, node), "sql", receiver=root, function=enclosing_function(node), dynamic=dynamic))
        return
    if method in JS_MONGO_METHODS and (last.lower().endswith("collection") or re.search(r"\.collection\(", receiver)):
        facts.db_calls.append(DbFact(method, line, snippet(source, node), "mongo", receiver=root, function=enclosing_function(node)))
        return
    if method in JS_ORM_METHODS and receiver_node is not None and receiver_node.type == "identifier" and receiver not in JS_GLOBALS:
        if receiver[:1].isupper() or receiver.lower().endswith(("model", "repository", "repo")):
            facts.db_calls.append(DbFact(method, line, snippet(source, node), "orm", receiver=root, function=enclosing_function(node)))
        return
    if method in {"createConnection", "createPool"} and root in {"mysql", "mysql2"}:
        facts.engines.append(EngineFact("mysql", line, snippet(source, node)))
    elif method == "connect" and root in {"mongoose", "MongoClient"}:
        facts.engines.append(EngineFact("mongodb", line, snippet(source, node)))
    elif method == "createClient" and root == "redis":
        facts.engines.append(EngineFact("redis", line, snippet(source, node)))


# --- Python -----------------------------------------------------------------------------------

PY_ROUTE_METHODS = {"route", "get", "post", "put", "delete", "patch", "api_route", "websocket", "head", "options"}
PY_HTTP_ROOTS = {"requests", "httpx", "session", "client", "aiohttp", "http"}
PY_DB_RECEIVER = re.compile(r"(^|\.)(cursor|cur|c|conn|connection|con|db|database|session|engine|connection_pool|sql)$", re.IGNORECASE)
PY_INPUTS = {
    "args": "query", "form": "body", "values": "request", "cookies": "cookie", "headers": "header",
    "files": "files", "json": "body", "data": "body", "GET": "query", "POST": "body", "COOKIES": "cookie", "FILES": "files", "META": "header",
}
PY_CONNECT = {
    "sqlite3.connect": "sqlite", "psycopg2.connect": "postgresql", "psycopg.connect": "postgresql", "pymysql.connect": "mysql",
    "MySQLdb.connect": "mysql", "mysql.connector.connect": "mysql", "MongoClient": "mongodb", "pymongo.MongoClient": "mongodb",
    "redis.Redis": "redis", "redis.StrictRedis": "redis", "asyncpg.connect": "postgresql", "aiosqlite.connect": "sqlite",
}


def _python(tree: ts.Tree, source: bytes, facts: FileFacts, strings: Strings) -> None:
    django = any(fact.spec.startswith("django") for fact in facts.imports)
    for node in walk(tree.root_node):
        kind = node.type
        if kind == "decorated_definition":
            definition = node.child_by_field_name("definition")
            function = text(definition.child_by_field_name("name")) if definition is not None else None
            for decorator in node.children:
                if decorator.type != "decorator" or not decorator.named_children:
                    continue
                call = decorator.named_children[0]
                if call.type != "call":
                    continue
                target = call.child_by_field_name("function")
                if target is None or target.type != "attribute":
                    continue
                attr = text(target.child_by_field_name("attribute"))
                if attr not in PY_ROUTE_METHODS:
                    continue
                arguments = call_args(call.child_by_field_name("arguments"))
                positional = [arg for arg in arguments if arg.type != "keyword_argument"]
                path = strings.value(positional[0]) if positional else None
                if path is None or not path.startswith("/"):
                    continue
                methods = [attr.upper()] if attr not in {"route", "api_route", "websocket"} else ["GET"]
                for arg in arguments:
                    if arg.type == "keyword_argument" and text(arg.child_by_field_name("name")) == "methods":
                        listed = [string_value(item) for item in arg.child_by_field_name("value").named_children]
                        methods = [item.upper() for item in listed if item] or methods
                receiver = text(target.child_by_field_name("object"))
                framework = next((name for name in ("flask", "fastapi", "starlette", "sanic", "quart") if any(fact.spec.split(".")[0] == name for fact in facts.imports)), "python")
                for verb in methods:
                    facts.routes.append(RouteFact(verb, path, line_of(decorator), snippet(source, decorator), framework, receiver, function=function))
        elif kind == "call":
            _python_call(node, source, facts, strings, django)
        elif kind in {"attribute", "subscript"}:
            _python_input(node, facts)


def _python_call(node: ts.Node, source: bytes, facts: FileFacts, strings: Strings, django: bool) -> None:
    function = node.child_by_field_name("function")
    if function is None:
        return
    name = text(function)
    arguments = call_args(node.child_by_field_name("arguments"))
    line = line_of(node)
    if django and name in {"path", "re_path", "url"} and len(arguments) >= 2:
        route = strings.value(arguments[0])
        view = arguments[1]
        handlers = []
        if view.type == "attribute":
            parts = text(view).split(".")
            handlers.append((parts[0], parts[1] if len(parts) > 1 else None))
        elif view.type == "identifier":
            handlers.append((text(view), None))
        elif view.type == "call":
            handlers.append((text(view).split(".")[0], None))
        facts.routes.append(RouteFact("ANY", "/" + route.lstrip("^/").rstrip("$"), line, snippet(source, node), "django", "urlpatterns", handlers))
        return
    if name in PY_CONNECT:
        facts.engines.append(EngineFact(PY_CONNECT[name], line, snippet(source, node)))
        return
    if name in {"create_engine", "create_async_engine"} and arguments:
        engine = engine_in_text(strings.value(arguments[0]))
        if engine:
            facts.engines.append(EngineFact(engine, line, snippet(source, node)))
        return
    if function.type != "attribute":
        if name == "urlopen" and arguments:
            facts.http_calls.append(HttpCallFact("GET", strings.value(arguments[0]), line, snippet(source, node), "urllib"))
        return
    receiver = text(function.child_by_field_name("object"))
    method = text(function.child_by_field_name("attribute"))
    root = receiver.split(".")[0]
    if root in PY_HTTP_ROOTS and method in VERBS | {"request"} and arguments:
        if method == "request" and len(arguments) >= 2:
            verb, url = (string_value(arguments[0]) or "ANY").upper(), strings.value(arguments[1])
        else:
            verb, url = method.upper(), strings.value(arguments[0])
        facts.http_calls.append(HttpCallFact(verb, url, line, snippet(source, node), root))
    elif name.endswith("request.urlopen") and arguments:
        facts.http_calls.append(HttpCallFact("GET", strings.value(arguments[0]), line, snippet(source, node), "urllib"))
    elif method in {"execute", "executemany", "executescript"} and PY_DB_RECEIVER.search(receiver):
        dynamic = bool(arguments) and (arguments[0].type in {"binary_operator", "concatenated_string"} or any(child.type == "interpolation" for child in arguments[0].children) or text(arguments[0]).endswith(")") and "format" in text(arguments[0]))
        facts.db_calls.append(DbFact(method, line, snippet(source, node), "sql", receiver=root, function=enclosing_function(node), dynamic=dynamic))
    elif method == "query" and (root in {"session", "db"} or receiver.endswith("session")) or receiver.endswith(".query") and method in {"filter", "filter_by", "get", "all", "first", "get_or_404", "first_or_404"}:
        facts.db_calls.append(DbFact(method, line, snippet(source, node), "orm", via="SQLAlchemy", receiver=root, function=enclosing_function(node)))
    elif receiver.endswith(".objects") and method in {"filter", "get", "all", "create", "raw", "exclude", "extra"}:
        facts.db_calls.append(DbFact(method, line, snippet(source, node), "orm", via="Django ORM", receiver=root, function=enclosing_function(node), dynamic=method in {"raw", "extra"}))


def _python_input(node: ts.Node, facts: FileFacts) -> None:
    if node.type == "attribute":
        obj, attr = node.child_by_field_name("object"), text(node.child_by_field_name("attribute"))
        if obj is None or text(obj) != "request" or attr not in PY_INPUTS:
            return
        parent = node.parent
        name = "*"
        if parent is not None and parent.type == "attribute" and parent.parent is not None and parent.parent.type == "call":
            # request.args.get('id')
            arguments = call_args(parent.parent.child_by_field_name("arguments"))
            name = (string_value(arguments[0]) if arguments else None) or "*"
        elif parent is not None and parent.type == "subscript":
            name = string_value(parent.child_by_field_name("subscript")) or "*"
        facts.inputs.append(InputFact(PY_INPUTS[attr], name or "*", line_of(node), enclosing_function(node)))


# --- PHP --------------------------------------------------------------------------------------

PHP_SUPERGLOBALS = {"_GET": "query", "_POST": "body", "_REQUEST": "request", "_COOKIE": "cookie", "_FILES": "files", "_SERVER": "header"}
PHP_DB_FUNCTIONS = {
    "mysqli_query": "mysql", "mysqli_real_query": "mysql", "mysqli_multi_query": "mysql", "mysqli_prepare": "mysql",
    "mysql_query": "mysql", "pg_query": "postgresql", "pg_query_params": "postgresql", "pg_prepare": "postgresql",
    "sqlite_query": "sqlite", "odbc_exec": None, "sqlsrv_query": "mssql", "oci_parse": "oracle",
}
PHP_CONNECT = {"mysqli_connect": "mysql", "mysql_connect": "mysql", "mysql_pconnect": "mysql", "pg_connect": "postgresql", "sqlite_open": "sqlite", "sqlsrv_connect": "mssql"}
PHP_DB_RECEIVER = re.compile(r"(db|pdo|conn|mysqli|sqlite|database|dbh|link|stmt|connection|ston)", re.IGNORECASE)
PHP_DECLARATIONS = {
    "php_tag", "namespace_definition", "namespace_use_declaration", "class_declaration", "function_definition",
    "interface_declaration", "trait_declaration", "enum_declaration", "comment", "const_declaration", "declare_statement",
}


def _php(tree: ts.Tree, source: bytes, facts: FileFacts, strings: Strings) -> None:
    for child in tree.root_node.named_children:
        if child.type == "text_interpolation":
            if any(part.type == "text" and text(part).strip() for part in child.named_children):
                facts.page = True
        elif child.type not in PHP_DECLARATIONS and not (child.type == "expression_statement" and _php_only_includes(child)):
            facts.page = True
    for node in walk(tree.root_node):
        kind = node.type
        if kind == "subscript_expression" and node.named_children:
            base = node.named_children[0]
            name = text(base).lstrip("$")
            if base.type == "variable_name" and name in PHP_SUPERGLOBALS:
                index = node.named_children[1] if len(node.named_children) > 1 else None
                facts.inputs.append(InputFact(PHP_SUPERGLOBALS[name], string_value(index) or "*", line_of(node), enclosing_function(node)))
        elif kind == "function_call_expression":
            name = text(node.child_by_field_name("function"))
            arguments = call_args(node.child_by_field_name("arguments"))
            line = line_of(node)
            if name in PHP_DB_FUNCTIONS:
                query = arguments[1] if name.startswith(("mysqli_", "pg_query_params", "sqlsrv")) and len(arguments) > 1 else (arguments[0] if arguments else None)
                if name in {"pg_query", "pg_prepare"} and len(arguments) > 1:
                    query = arguments[-1]
                facts.db_calls.append(DbFact(name, line, snippet(source, node), "sql", engine=PHP_DB_FUNCTIONS[name], via=name.split("_")[0], function=enclosing_function(node), dynamic=query is not None and _php_dynamic(query)))
            elif name in PHP_CONNECT:
                facts.engines.append(EngineFact(PHP_CONNECT[name], line, snippet(source, node)))
            elif name in {"curl_init", "file_get_contents", "fopen", "get_headers"} and arguments:
                url = strings.value(arguments[0])
                if name == "curl_init" or url.lower().startswith(("http://", "https://")):
                    facts.http_calls.append(HttpCallFact("GET", url, line, snippet(source, node), name))
        elif kind == "member_call_expression":
            method = text(node.child_by_field_name("name"))
            receiver = text(node.child_by_field_name("object"))
            arguments = call_args(node.child_by_field_name("arguments"))
            line = line_of(node)
            if method in {"query", "prepare", "exec", "execute", "querySingle", "multi_query", "real_query"} and PHP_DB_RECEIVER.search(receiver):
                facts.db_calls.append(DbFact(method, line, snippet(source, node), "sql", via="PDO" if "pdo" in receiver.lower() else None, receiver=receiver, function=enclosing_function(node), dynamic=bool(arguments) and _php_dynamic(arguments[0])))
            elif method in VERBS | {"map"} and re.search(r"(app|router|route|r)$", receiver, re.IGNORECASE) and arguments:
                path = strings.value(arguments[0])
                if path.startswith("/"):
                    facts.routes.append(RouteFact(method.upper() if method not in {"any", "map"} else "ANY", path, line, snippet(source, node), "slim", receiver.lstrip("$"), _php_handlers(arguments[1:]), inline=any(arg.type in INLINE_FUNCTIONS for arg in arguments[1:])))
        elif kind == "scoped_call_expression":
            scope = text(node.child_by_field_name("scope"))
            method = text(node.child_by_field_name("name"))
            arguments = call_args(node.child_by_field_name("arguments"))
            if scope == "Route" and arguments and method in VERBS | {"match", "resource", "apiResource"}:
                path = strings.value(arguments[0])
                verb = "ANY" if method in {"any", "match", "resource", "apiResource"} else method.upper()
                facts.routes.append(RouteFact(verb, "/" + path.lstrip("/"), line_of(node), snippet(source, node), "laravel", "Route", _php_handlers(arguments[1:]), inline=any(arg.type in INLINE_FUNCTIONS for arg in arguments[1:])))
        elif kind == "object_creation_expression":
            created = text(node.named_children[0]) if node.named_children else ""
            arguments = call_args(next((child for child in node.named_children if child.type == "arguments"), None))
            if created in {"mysqli", "\\mysqli"}:
                facts.engines.append(EngineFact("mysql", line_of(node), snippet(source, node)))
            elif created in {"SQLite3", "\\SQLite3"}:
                facts.engines.append(EngineFact("sqlite", line_of(node), snippet(source, node)))
            elif created in {"PDO", "\\PDO"} and arguments:
                dsn = strings.value(arguments[0]).lower()
                engine = DIALECTS.get(dsn.split(":")[0]) or ("postgresql" if dsn.startswith("pgsql") else None)
                if engine:
                    facts.engines.append(EngineFact(engine, line_of(node), snippet(source, node)))


def _php_only_includes(statement: ts.Node) -> bool:
    inner = statement.named_children[0] if statement.named_children else None
    return inner is not None and inner.type in {"include_expression", "include_once_expression", "require_expression", "require_once_expression"}


def _php_dynamic(node: ts.Node) -> bool:
    if node.type in {"variable_name", "binary_expression"}:
        return True
    return node.type == "encapsed_string" and any(child.type in {"variable_name", "subscript_expression", "member_access_expression", "dynamic_variable_name"} for child in walk(node))


def _php_handlers(arguments: list[ts.Node]) -> list[tuple[str, str | None]]:
    handlers: list[tuple[str, str | None]] = []
    for argument in arguments:
        if argument.type == "array_creation_expression":
            items = [child.named_children[0] for child in argument.named_children if child.named_children]
            if items and items[0].type == "class_constant_access_expression":
                member = string_value(items[1]) if len(items) > 1 else None
                handlers.append((text(items[0].named_children[0]), member))
        elif argument.type == "class_constant_access_expression":
            handlers.append((text(argument.named_children[0]), None))
        else:
            value = string_value(argument)
            if value and "@" in value:
                cls, _, member = value.partition("@")
                handlers.append((cls.split("\\")[-1], member))
    return handlers


# --- Go ---------------------------------------------------------------------------------------

GO_ROUTE_FIELDS = {
    "HandleFunc": "ANY", "Handle": "ANY", "Any": "ANY", "GET": "GET", "POST": "POST", "PUT": "PUT", "DELETE": "DELETE",
    "PATCH": "PATCH", "HEAD": "HEAD", "OPTIONS": "OPTIONS", "Get": "GET", "Post": "POST", "Put": "PUT", "Delete": "DELETE", "Patch": "PATCH",
}
GO_DB_FIELDS = {"Query", "QueryRow", "QueryContext", "QueryRowContext", "Exec", "ExecContext", "Prepare", "PrepareContext", "Raw", "Select", "Get", "NamedExec", "Queryx"}
GO_DB_RECEIVER = re.compile(r"(^|\.)(db|tx|conn|stmt|pool|database|sqlx|gormdb|DB)$")
GO_INPUT_FIELDS = {
    "FormValue": "body", "PostFormValue": "body", "Param": "params", "Query": "query", "DefaultQuery": "query",
    "PostForm": "body", "DefaultPostForm": "body", "QueryParam": "query", "GetHeader": "header", "Cookie": "cookie", "FormFile": "files",
}


def _go(tree: ts.Tree, source: bytes, facts: FileFacts, strings: Strings) -> None:
    for node in walk(tree.root_node):
        if node.type != "call_expression":
            continue
        function = node.child_by_field_name("function")
        arguments = call_args(node.child_by_field_name("arguments"))
        if function is None or function.type != "selector_expression":
            continue
        operand = text(function.child_by_field_name("operand"))
        field_name = text(function.child_by_field_name("field"))
        line = line_of(node)
        first = strings.value(arguments[0]) if arguments else ""
        if field_name in GO_ROUTE_FIELDS and len(arguments) >= 2 and (first.startswith("/") or re.match(r"^[A-Z]+ /", first)):
            verb = GO_ROUTE_FIELDS[field_name]
            if " " in first:
                verb, first = first.split(" ", 1)
            handlers = []
            last = arguments[-1]
            if last.type == "selector_expression":
                handlers.append((text(last.child_by_field_name("operand")), text(last.child_by_field_name("field"))))
            elif last.type == "identifier":
                handlers.append((text(last), None))
            elif last.type == "call_expression":
                inner = last.child_by_field_name("function")
                if inner is not None and inner.type == "selector_expression":
                    handlers.append((text(inner.child_by_field_name("operand")), text(inner.child_by_field_name("field"))))
            facts.routes.append(RouteFact(verb, first, line, snippet(source, node), "go", operand, handlers, inline=last.type == "func_literal"))
        elif field_name == "Group" and arguments and first.startswith("/"):
            parent = node.parent
            if parent is not None and parent.type == "expression_list":
                parent = parent.parent
            if parent is not None and parent.type in {"short_var_declaration", "assignment_statement"}:
                left = parent.child_by_field_name("left")
                if left is not None:
                    facts.mounts.append(MountFact(first, text(left), line))
        elif operand == "http" and field_name in {"Get", "Post", "Head", "PostForm"} and arguments:
            facts.http_calls.append(HttpCallFact(field_name.upper().replace("POSTFORM", "POST"), first, line, snippet(source, node), "net/http"))
        elif operand == "http" and field_name in {"NewRequest", "NewRequestWithContext"} and len(arguments) >= 2:
            offset = 1 if field_name == "NewRequestWithContext" else 0
            verb = (string_value(arguments[offset]) or "ANY").upper()
            facts.http_calls.append(HttpCallFact(verb.replace("METHOD", ""), strings.value(arguments[offset + 1]), line, snippet(source, node), "net/http"))
        elif operand in {"sql", "sqlx"} and field_name in {"Open", "Connect"} and arguments:
            engine = DIALECTS.get(first.lower())
            if engine:
                facts.engines.append(EngineFact(engine, line, snippet(source, node)))
        elif field_name == "Open" and operand in {"mysql", "postgres", "sqlite", "sqlserver"}:
            facts.engines.append(EngineFact(DIALECTS.get(operand, operand), line, snippet(source, node)))
        elif operand == "mongo" and field_name in {"Connect", "NewClient"}:
            facts.engines.append(EngineFact("mongodb", line, snippet(source, node)))
        elif operand == "redis" and field_name in {"NewClient", "NewClusterClient"}:
            facts.engines.append(EngineFact("redis", line, snippet(source, node)))
        elif field_name in GO_DB_FIELDS and GO_DB_RECEIVER.search(operand) and arguments:
            query = arguments[1] if field_name.endswith("Context") and len(arguments) > 1 else arguments[0]
            dynamic = query.type == "binary_expression" or (query.type == "call_expression" and text(query).startswith("fmt.Sprintf"))
            facts.db_calls.append(DbFact(field_name, line, snippet(source, node), "sql", receiver=operand.split(".")[0], function=enclosing_function(node), dynamic=dynamic))
        elif field_name in GO_INPUT_FIELDS and arguments and string_value(arguments[0]):
            facts.inputs.append(InputFact(GO_INPUT_FIELDS[field_name], string_value(arguments[0]), line, enclosing_function(node)))
        elif field_name == "Get" and operand.endswith("Query()") and arguments and string_value(arguments[0]):
            facts.inputs.append(InputFact("query", string_value(arguments[0]), line, enclosing_function(node)))


# --- Java -------------------------------------------------------------------------------------

JAVA_MAPPINGS = {"GetMapping": "GET", "PostMapping": "POST", "PutMapping": "PUT", "DeleteMapping": "DELETE", "PatchMapping": "PATCH", "RequestMapping": "ANY"}
JAVA_JAXRS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
JAVA_PARAMS = {"RequestParam": "query", "PathVariable": "params", "RequestBody": "body", "RequestHeader": "header", "CookieValue": "cookie", "QueryParam": "query", "PathParam": "params", "FormParam": "body", "HeaderParam": "header"}
JAVA_DB_METHODS = {"executeQuery", "executeUpdate", "execute", "prepareStatement", "createQuery", "createNativeQuery", "query", "queryForObject", "queryForList", "queryForMap", "update", "batchUpdate", "addBatch"}
JAVA_DB_RECEIVER = re.compile(r"(stmt|statement|conn|connection|jdbc|template|em|entitymanager|session|ps|pstmt|st)$", re.IGNORECASE)


def _java_annotations(modifiers: ts.Node | None) -> list[tuple[str, ts.Node]]:
    if modifiers is None:
        return []
    return [(text(child.child_by_field_name("name")), child) for child in modifiers.named_children if child.type in {"annotation", "marker_annotation"}]


def _java_annotation_values(annotation: ts.Node, strings: Strings) -> tuple[list[str], list[str]]:
    """(paths, methods) from @RequestMapping(value = "/x", method = RequestMethod.POST) and friends."""
    arguments = annotation.child_by_field_name("arguments")
    paths: list[str] = []
    methods: list[str] = []
    if arguments is None:
        return paths, methods
    for child in arguments.named_children:
        if child.type == "element_value_pair":
            key = text(child.child_by_field_name("key"))
            value = child.child_by_field_name("value")
            if key in {"value", "path"}:
                items = value.named_children if value is not None and value.type == "element_value_array_initializer" else [value]
                paths += [strings.value(item) for item in items if item is not None]
            elif key == "method" and value is not None:
                methods += [part.split(".")[-1] for part in re.findall(r"[\w.]+", text(value)) if part.split(".")[-1] in JAVA_JAXRS]
        elif child.type == "element_value_array_initializer":
            paths += [strings.value(item) for item in child.named_children]
        else:
            paths.append(strings.value(child))
    return paths, methods


def _java(tree: ts.Tree, source: bytes, facts: FileFacts, strings: Strings) -> None:
    for node in walk(tree.root_node):
        kind = node.type
        if kind == "method_declaration":
            annotations = _java_annotations(next((child for child in node.children if child.type == "modifiers"), None))
            routes: list[tuple[str, str, ts.Node]] = []
            jaxrs_verbs = [name for name, _ in annotations if name in JAVA_JAXRS]
            for name, annotation in annotations:
                if name in JAVA_MAPPINGS:
                    paths, methods = _java_annotation_values(annotation, strings)
                    for path in paths or [""]:
                        for verb in methods or [JAVA_MAPPINGS[name]]:
                            routes.append((verb, path, annotation))
                elif name == "Path":
                    paths, _ = _java_annotation_values(annotation, strings)
                    for path in paths or [""]:
                        for verb in jaxrs_verbs or ["ANY"]:
                            routes.append((verb, path, annotation))
            if not routes and jaxrs_verbs:
                routes = [(verb, "", node) for verb in jaxrs_verbs]
            if not routes:
                continue
            prefix = _java_class_prefix(node, strings)
            function = text(node.child_by_field_name("name"))
            for verb, path, annotation in routes:
                full = "/" + "/".join(part.strip("/") for part in (prefix, path) if part and part.strip("/"))
                facts.routes.append(RouteFact(verb, full, line_of(annotation), snippet(source, annotation), "spring", "", function=function))
            for parameter in walk(node.child_by_field_name("parameters")) if node.child_by_field_name("parameters") is not None else []:
                if parameter.type != "formal_parameter":
                    continue
                for name, annotation in _java_annotations(next((child for child in parameter.children if child.type == "modifiers"), None)):
                    if name in JAVA_PARAMS:
                        values, _ = _java_annotation_values(annotation, strings)
                        named = [value for value in values if value and value != "*"]
                        facts.inputs.append(InputFact(JAVA_PARAMS[name], named[0] if named else text(parameter.child_by_field_name("name")), line_of(parameter), function))
        elif kind == "method_invocation":
            name = text(node.child_by_field_name("name"))
            receiver = text(node.child_by_field_name("object"))
            arguments = call_args(node.child_by_field_name("arguments"))
            if name in JAVA_DB_METHODS and receiver and JAVA_DB_RECEIVER.search(receiver.split(".")[-1].split("(")[0]):
                dynamic = bool(arguments) and arguments[0].type in {"binary_expression", "identifier"}
                facts.db_calls.append(DbFact(name, line_of(node), snippet(source, node), "sql", receiver=receiver.split(".")[0], function=enclosing_function(node), dynamic=dynamic))
            elif name in {"getForObject", "getForEntity", "postForObject", "postForEntity", "exchange", "put", "delete"} and "template" in receiver.lower() and arguments:
                verb = {"getForObject": "GET", "getForEntity": "GET", "postForObject": "POST", "postForEntity": "POST", "put": "PUT", "delete": "DELETE"}.get(name, "ANY")
                facts.http_calls.append(HttpCallFact(verb, strings.value(arguments[0]), line_of(node), snippet(source, node), "RestTemplate"))
            elif name == "create" and receiver == "URI" and arguments:
                facts.http_calls.append(HttpCallFact("ANY", strings.value(arguments[0]), line_of(node), snippet(source, node), "HttpClient"))
        elif kind in {"class_declaration", "interface_declaration"}:
            superclass = text(node.child_by_field_name("interfaces") or node.child_by_field_name("superclass"))
            extends = next((child for child in node.children if child.type in {"extends_interfaces", "super_interfaces"}), None)
            if re.search(r"\b(JpaRepository|CrudRepository|PagingAndSortingRepository|MongoRepository|ReactiveCrudRepository)\b", superclass + text(extends)):
                family = "mongo" if "Mongo" in text(extends) + superclass else "orm"
                facts.db_calls.append(DbFact("repository", line_of(node), snippet(source, node), family, via="Spring Data"))


def _java_class_prefix(method: ts.Node, strings: Strings) -> str:
    current = method.parent
    while current is not None and current.type not in {"class_declaration"}:
        current = current.parent
    if current is None:
        return ""
    for name, annotation in _java_annotations(next((child for child in current.children if child.type == "modifiers"), None)):
        if name in {"RequestMapping", "Path"}:
            paths, _ = _java_annotation_values(annotation, strings)
            if paths:
                return paths[0]
    return ""


_EXTRACTORS = {
    "python": _python,
    "javascript": _javascript,
    "typescript": _javascript,
    "tsx": _javascript,
    "php": _php,
    "go": _go,
    "java": _java,
}


def extract(language_name: str, tree: ts.Tree, source: bytes, facts: FileFacts) -> None:
    extractor = _EXTRACTORS.get(language_name)
    if extractor is None:
        return
    strings = Strings(tree)
    extractor(tree, source, facts, strings)
    _raw_sql(tree, source, facts)
    _engine_strings(tree, source, facts)
