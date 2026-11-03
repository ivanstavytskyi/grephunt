"""Project map, files view: inventory, imports, stack, and the API."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

from fastapi.testclient import TestClient

from grephunt.config import DEFAULT_TENANT
from grephunt.database.tables import ScanRow
from grephunt.project_map import build_project_map
from grephunt.web_console import app as console
from grephunt.web_console import scans as scan_service

ROOT = Path(__file__).resolve().parents[1]


def _write(root: Path, files: dict[str, str]) -> Path:
    for name, body in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    return root


def _edges(project_map, kind: str = "import") -> set[tuple[str, str]]:
    return {(edge.source, edge.target) for edge in project_map.files.edges if edge.kind == kind}


def test_inventory_roles_and_vendor_dirs(tmp_path: Path):
    _write(tmp_path, {
        "app/main.py": "import os\n",
        "tests/test_main.py": "",
        "web/dist/bundle.js": "",
        "web/src/app.spec.ts": "",
        "docker-compose.yml": "services: {}\n",
        "README.md": "",
        "node_modules/left-pad/index.js": "",
        "node_modules/express/index.js": "",
    })
    built = build_project_map(tmp_path)
    roles = {node.path: node.role for node in built.files.nodes if node.kind == "file"}
    assert roles["app/main.py"] == "source"
    assert roles["tests/test_main.py"] == "test"
    assert roles["web/dist/bundle.js"] == "generated"
    assert roles["web/src/app.spec.ts"] == "test"
    assert roles["docker-compose.yml"] == "iac"
    assert roles["README.md"] == "docs"
    assert not any(path.startswith("node_modules/") for path in roles)
    vendor = next(node for node in built.files.nodes if node.id == "d:node_modules")
    assert vendor.role == "vendor" and vendor.meta["files"] == 2
    assert next(node for node in built.files.nodes if node.id == "f:app/main.py").parent == "d:app"


def test_python_imports_resolve_to_files_and_packages(tmp_path: Path):
    _write(tmp_path, {
        "shop/__init__.py": "",
        "shop/app.py": "from flask import Flask\nfrom . import views\nfrom .models import User\nimport shop.db\nimport os\napp = Flask(__name__)\n",
        "shop/views.py": "",
        "shop/models.py": "",
        "shop/db.py": "import sqlalchemy\n",
        "requirements.txt": "flask==3.0\nsqlalchemy\n",
    })
    built = build_project_map(tmp_path)
    edges = _edges(built)
    assert ("f:shop/app.py", "f:shop/views.py") in edges
    assert ("f:shop/app.py", "f:shop/models.py") in edges
    assert ("f:shop/app.py", "f:shop/db.py") in edges
    assert ("f:shop/app.py", "p:pypi:flask") in edges
    assert not any(target == "p:pypi:os" for _, target in edges)
    assert built.stack["frameworks"] == ["Flask"]
    assert "SQLAlchemy (SQL)" in built.stack["datastores"]
    assert "shop/app.py" in built.stats["entry_points"]
    edge = next(edge for edge in built.files.edges if edge.target == "f:shop/models.py")
    assert edge.evidence[0].path == "shop/app.py" and edge.evidence[0].line == 3
    assert "from .models import User" in edge.evidence[0].text


def test_javascript_imports_with_extensions_index_and_packages(tmp_path: Path):
    _write(tmp_path, {
        "server.ts": "import express from 'express'\nimport { search } from './routes/search'\nconst models = require('./models')\nimport fs from 'fs'\napp.listen(3000)\n",
        "routes/search.ts": "import { sequelize } from '../models/index'\n",
        "models/index.ts": "import { Sequelize } from 'sequelize'\n",
        "frontend/src/app/search.component.ts": "import { Component } from '@angular/core'\n",
    })
    built = build_project_map(tmp_path)
    edges = _edges(built)
    assert ("f:server.ts", "f:routes/search.ts") in edges
    assert ("f:server.ts", "f:models/index.ts") in edges
    assert ("f:routes/search.ts", "f:models/index.ts") in edges
    assert ("f:server.ts", "p:npm:express") in edges
    assert ("f:frontend/src/app/search.component.ts", "p:npm:@angular/core") in edges
    assert not any(target == "p:npm:fs" for _, target in edges)
    # No frontend/package.json: Angular is still found through the import.
    assert {"Angular", "Express"} <= set(built.stack["frameworks"])
    assert "server.ts" in built.stats["entry_points"]


def test_php_includes_with_a_constant_prefix_and_psr4_use(tmp_path: Path):
    _write(tmp_path, {
        "index.php": "<?php\nrequire_once DVWA_WEB_PAGE_TO_ROOT . 'dvwa/includes/dvwaPage.inc.php';\ninclude('config/missing.php');\n",
        "dvwa/includes/dvwaPage.inc.php": "<?php\nfunction page() {}\n",
        "composer.json": json.dumps({"autoload": {"psr-4": {"App\\\\": "src/"}}}),
        "src/Http/Controller.php": "<?php\nnamespace App\\Http;\nuse App\\Models\\User;\nclass Controller {}\n",
        "src/Models/User.php": "<?php\nnamespace App\\Models;\nclass User {}\n",
    })
    built = build_project_map(tmp_path)
    edges = _edges(built)
    assert ("f:index.php", "f:dvwa/includes/dvwaPage.inc.php") in edges
    assert ("f:src/Http/Controller.php", "f:src/Models/User.php") in edges
    assert any(item.path == "index.php" and item.line == 3 for item in built.unresolved)


def test_go_and_java_imports(tmp_path: Path):
    _write(tmp_path, {
        "go.mod": "module example.com/shop\n\ngo 1.22\n",
        "main.go": 'package main\n\nimport (\n\t"fmt"\n\t"example.com/shop/internal/db"\n\t"github.com/gin-gonic/gin"\n)\n\nfunc main() {}\n',
        "internal/db/db.go": "package db\n",
        "src/main/java/shop/App.java": "package shop;\nimport shop.repo.UserRepository;\npublic class App { public static void main(String[] a) {} }\n",
        "src/main/java/shop/repo/UserRepository.java": "package shop.repo;\npublic interface UserRepository {}\n",
    })
    built = build_project_map(tmp_path)
    edges = _edges(built)
    assert ("f:main.go", "d:internal/db") in edges
    assert ("f:main.go", "p:go:github.com/gin-gonic/gin") in edges
    assert not any(target == "p:go:fmt" for _, target in edges)
    assert ("f:src/main/java/shop/App.java", "f:src/main/java/shop/repo/UserRepository.java") in edges
    assert {"main.go", "src/main/java/shop/App.java"} <= set(built.stats["entry_points"])


def test_every_edge_points_at_existing_nodes_with_evidence():
    built = build_project_map(ROOT / "samples" / "vuln_flask")
    ids = {node.id for node in built.files.nodes}
    for edge in built.files.edges:
        assert edge.source in ids and edge.target in ids
        assert edge.evidence and edge.evidence[0].line > 0


def _use_db(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("GREPHUNT_DATABASE_URL", f"sqlite:///{(tmp_path / 'map.db').as_posix()}")
    monkeypatch.setattr(scan_service, "DATA_DIR", tmp_path / "data")
    scan_service.reset_session_factory()


def _scan_row(scan_id: str, target: Path) -> None:
    with scan_service.session_factory()() as session:
        session.add(ScanRow(id=scan_id, tenant_id=DEFAULT_TENANT, target_label=target.name, target_path=str(target), status="success"))
        session.commit()


def test_map_is_built_before_the_scanners_and_served(tmp_path: Path, monkeypatch):
    _use_db(tmp_path, monkeypatch)
    project = ROOT / "samples" / "vuln_flask"
    _scan_row("map1", project)
    events = []
    asyncio.run(scan_service._build_map("map1", project, events.append))
    assert (tmp_path / "data" / "scans" / "map1" / "project_map.json").is_file()
    assert events and events[0].type.value == "map.ready" and events[0].data["ok"] is True

    client = TestClient(console.app)
    body = client.get("/api/scans/map1/map").json()
    assert body["root_label"] == "vuln_flask"
    assert any(node["path"] == "app.py" for node in body["files"]["nodes"])
    assert client.get("/api/scans/nope/map").status_code == 404


def test_old_scans_get_a_map_on_request(tmp_path: Path, monkeypatch):
    _use_db(tmp_path, monkeypatch)
    _scan_row("map2", ROOT / "samples" / "vuln_go")
    client = TestClient(console.app)
    assert client.get("/api/scans/map2/map").json() == {}
    rebuilt = client.post("/api/scans/map2/map")
    assert rebuilt.status_code == 200
    assert any(node["path"] == "main.go" for node in rebuilt.json()["files"]["nodes"])
    _scan_row("map3", tmp_path / "gone")
    assert client.post("/api/scans/map3/map").status_code == 409


# --- architecture view ------------------------------------------------------------------------


def _arch(project_map, kind: str | None = None) -> set[tuple[str, str]]:
    return {(edge.source, edge.target) for edge in project_map.architecture.edges if kind is None or edge.kind == kind}


def _node(project_map, node_id: str):
    return next(node for node in project_map.architecture.nodes if node.id == node_id)


def test_express_chain_from_angular_service_to_sqlite(tmp_path: Path):
    _write(tmp_path, {
        "server.ts": (
            "import express from 'express'\nimport * as utils from './lib/utils'\nimport * as security from './lib/insecurity'\n"
            "import { searchProducts } from './routes/search'\nconst app = express()\n"
            "app.get('/rest/products/search', security.isAuthorized(), utils.asyncHandler(searchProducts()))\n"
            "app.listen(3000)\n"
        ),
        "lib/utils.ts": "export function asyncHandler (fn) { return fn }\n",
        "lib/insecurity.ts": "export function isAuthorized () { return (req, res, next) => next() }\n",
        "routes/search.ts": (
            "import * as models from '../models/index'\nexport function searchProducts () {\n  return (req, res) => {\n"
            "    const criteria = req.query.q\n"
            "    models.sequelize.query(`SELECT * FROM Products WHERE name LIKE '%${criteria}%'`)\n  }\n}\n"
        ),
        "models/index.ts": "import { Sequelize } from 'sequelize'\nexport const sequelize = new Sequelize('db', 'u', 'p', { dialect: 'sqlite' })\n",
        "frontend/src/app/product.service.ts": (
            "import { HttpClient } from '@angular/common/http'\nimport { environment } from '../environments/environment'\n"
            "export class ProductService {\n  private readonly hostServer = environment.hostServer\n"
            "  constructor (private readonly http: HttpClient) {}\n"
            "  search (q: string) { return this.http.get(`${this.hostServer}/rest/products/search?q=${q}`) }\n"
            "  missing () { return this.http.post(this.hostServer + '/rest/nowhere', {}) }\n}\n"
        ),
        # A snippet that no running code loads: its route must not show up.
        "data/static/codefixes/searchFix.ts": "import express from 'express'\nconst app = express()\napp.get('/rest/products/search', (req, res) => res.send())\n",
    })
    built = build_project_map(tmp_path)
    route = "r:GET /rest/products/search"
    edges = _arch(built)
    assert ("f:frontend/src/app/product.service.ts", route) in edges
    assert (route, "f:routes/search.ts") in edges
    assert ("f:routes/search.ts", "o:sequelize") in edges
    assert ("o:sequelize", "s:sqlite") in edges
    assert not any(target == "f:data/static/codefixes/searchFix.ts" for _, target in edges)
    meta = _node(built, route).meta
    assert meta["handler"] == "routes/search.ts:searchProducts"
    assert meta["params"][0]["name"] == "q" and meta["params"][0]["source"] == "query"
    assert meta["middleware"] == ["security.isAuthorized", "utils.asyncHandler"]
    db_edge = next(edge for edge in built.architecture.edges if edge.source == "f:routes/search.ts")
    assert "(dynamic)" in db_edge.label and db_edge.evidence[0].line == 5
    assert _node(built, "f:frontend/src/app/product.service.ts").layer == "frontend"
    assert _node(built, "u:POST */rest/nowhere").meta["unmatched"] is True
    assert built.stats["routes"] == 1 and built.stats["dynamic_sql"] == 1


def test_flask_routes_inputs_forms_and_sqlite(tmp_path: Path):
    _write(tmp_path, {
        "app.py": (ROOT / "samples" / "vuln_flask" / "app.py").read_text(encoding="utf-8"),
        "templates/user.html": '<form action="{{ url_for(\'user\') }}" method="get"><input name="id"></form>\n',
    })
    built = build_project_map(tmp_path)
    edges = _arch(built)
    assert {("r:GET /user", "f:app.py"), ("r:POST /load", "f:app.py"), ("f:app.py", "s:sqlite")} <= edges
    assert ("f:templates/user.html", "r:GET /user") in edges
    assert _node(built, "r:GET /user").meta["params"] == [{"source": "query", "name": "id", "line": 15}]
    assert _node(built, "f:app.py").meta["dynamic_sql"] == 1


def test_php_pages_with_superglobals_and_mysqli(tmp_path: Path):
    _write(tmp_path, {
        "vulnerabilities/sqli/source/low.php": (
            "<?php\nif (isset($_REQUEST['Submit'])) {\n  $id = $_REQUEST['id'];\n"
            "  $query = \"SELECT first_name FROM users WHERE user_id = '$id';\";\n"
            "  $result = mysqli_query($GLOBALS['___mysqli_ston'], $query);\n}\n"
        ),
        "vulnerabilities/sqli/source/impossible.php": "<?php\n$id = $_GET['id'];\n$data = $db->prepare('SELECT first_name FROM users WHERE user_id = (:id) LIMIT 1;');\n",
        "dvwa/includes/dvwaPage.inc.php": "<?php\n$level = $_COOKIE['security'];\nfunction dvwaHtml() {}\n",
        "config/config.inc.php": "<?php\n$db = mysqli_connect('127.0.0.1', 'dvwa', 'p@ss');\n",
    })
    built = build_project_map(tmp_path)
    routes = {node.id for node in built.architecture.nodes if node.kind == "route"}
    assert routes == {"r:ANY /vulnerabilities/sqli/source/low.php", "r:GET /vulnerabilities/sqli/source/impossible.php"}
    low = next(edge for edge in built.architecture.edges if edge.source == "f:vulnerabilities/sqli/source/low.php")
    assert low.target == "s:mysql" and "(dynamic)" in low.label
    safe = next(edge for edge in built.architecture.edges if edge.source == "f:vulnerabilities/sqli/source/impossible.php")
    assert "(dynamic)" not in safe.label
    params = _node(built, "r:ANY /vulnerabilities/sqli/source/low.php").meta["params"]
    assert {item["name"] for item in params} == {"Submit", "id"}


def test_spring_controller_service_repository_and_compose(tmp_path: Path):
    java = "src/main/java/shop"
    _write(tmp_path, {
        f"{java}/App.java": "package shop;\n@SpringBootApplication\npublic class App { public static void main(String[] a) {} }\n",
        f"{java}/web/UserController.java": (
            "package shop.web;\nimport shop.service.UserService;\nimport org.springframework.web.bind.annotation.*;\n"
            "@RestController\n@RequestMapping(\"/api\")\npublic class UserController {\n"
            "  @GetMapping(\"/users/{id}\")\n  public String get(@PathVariable String id, @RequestParam(name = \"q\") String q) { return \"\"; }\n}\n"
        ),
        f"{java}/service/UserService.java": "package shop.service;\nimport shop.repo.UserRepository;\npublic class UserService {}\n",
        f"{java}/repo/UserRepository.java": (
            "package shop.repo;\nimport org.springframework.data.jpa.repository.JpaRepository;\n"
            "public interface UserRepository extends JpaRepository<User, Long> {}\n"
        ),
        "web/src/main.js": "export async function load (id) { return fetch(`/api/users/${id}`) }\n",
        "docker-compose.yml": "services:\n  backend:\n    build: .\n    depends_on:\n      - db\n  db:\n    image: postgres:16\n",
    })
    built = build_project_map(tmp_path)
    edges = _arch(built)
    controller = f"f:{java}/web/UserController.java"
    assert ("f:web/src/main.js", "r:GET /api/users/{id}") in edges
    assert ("r:GET /api/users/{id}", controller) in edges
    assert (controller, f"f:{java}/repo/UserRepository.java") in edges
    assert (f"f:{java}/repo/UserRepository.java", "o:spring-data") in edges
    assert ("o:spring-data", "s:postgresql") in edges
    assert ("svc:backend", "s:postgresql") in edges
    service_edge = next(edge for edge in built.architecture.edges if edge.kind == "service")
    assert service_edge.evidence[0].line == 4
    params = {item["name"] for item in _node(built, "r:GET /api/users/{id}").meta["params"]}
    assert params == {"id", "q"}


def test_go_group_prefix_and_handler_in_another_package(tmp_path: Path):
    _write(tmp_path, {
        "go.mod": "module example.com/shop\n\ngo 1.22\n",
        "main.go": (
            'package main\n\nimport (\n\t"github.com/gin-gonic/gin"\n\t"example.com/shop/handlers"\n)\n\n'
            'func main() {\n\tr := gin.Default()\n\tv1 := r.Group("/v1")\n\tv1.GET("/users/:id", handlers.GetUser)\n\tr.Run()\n}\n'
        ),
        "handlers/users.go": (
            'package handlers\n\nimport "database/sql"\n\nvar db *sql.DB\n\n'
            'func GetUser(c *gin.Context) {\n\tid := c.Param("id")\n\tdb.Query("SELECT * FROM users WHERE id = " + id)\n}\n'
        ),
    })
    built = build_project_map(tmp_path)
    edges = _arch(built)
    assert ("r:GET /v1/users/:id", "f:handlers/users.go") in edges
    assert ("f:handlers/users.go", "s:sql") in edges
    assert _node(built, "r:GET /v1/users/:id").meta["params"][0]["name"] == "id"


def test_url_matching_rules():
    from grephunt.project_map.architecture import _match, _split_url

    assert _split_url("*/rest/products/search?q=*") == (None, "*/rest/products/search")
    assert _split_url("https://api.example.com/v1/x") == ("api.example.com", "/v1/x")
    assert _split_url("http://localhost:3000/api") == (None, "/api")
    assert _match("*/api/Products/*", "/api/Products/:id", False) is not None
    assert _match("*/api/Products/*", "/api/*s/:id", False) < _match("*/api/Products/*", "/api/Products/:id", False)
    assert _match("*/*", "/:id", False) is None  # no literal segment, no match
    assert _match("/admin/api/users", "/api/users", False) is None  # literal prefix needs a mounted router
    assert _match("/admin/api/users", "/api/users", True) is not None


# --- exports ----------------------------------------------------------------------------------


def test_canvas_and_mermaid_exports_apply_edits(tmp_path: Path):
    from grephunt.project_map.export import to_canvas, to_mermaid

    built = json.loads(build_project_map(ROOT / "samples" / "vuln_flask").model_dump_json())
    overlay = {"version": 1, "views": {"architecture": {
        "labels": {"f:app.py": "Main Flask app"},
        "notes": {"r:GET /user": "SQL injection via id"},
        "blocks": [{"id": "b:waf", "label": "WAF", "x": -400, "y": 0}],
        "links": [{"id": "l:1", "source": "b:waf", "target": "r:GET /user", "label": "filters"}],
        "positions": {"f:app.py": {"x": 900, "y": 40}},
    }}}
    findings = [{"severity": "high", "location": {"path": "/src/app.py", "start_line": 17}, "context": {"routes": [{"id": "r:GET /user"}]}}]
    canvas = to_canvas(built, "architecture", overlay, findings)
    texts = {node["text"].splitlines()[0]: node for node in canvas["nodes"] if node["type"] == "text"}
    assert "**Main Flask app**" in texts and texts["**Main Flask app**"]["x"] == 900
    assert texts["**Main Flask app**"]["color"] == "2"  # high finding in app.py
    assert "SQL injection via id" in texts["**GET /user**"]["text"] and texts["**GET /user**"]["color"] == "2"
    assert "**WAF**" in texts
    by_id = {node["id"]: node for node in canvas["nodes"]}
    assert any(edge.get("label") == "filters" for edge in canvas["edges"])
    db = next(edge for edge in canvas["edges"] if by_id[edge["toNode"]]["text"].startswith("**SQLite"))
    assert db["color"] == "1"  # the query is built from variables
    for edge in canvas["edges"]:
        assert edge["fromNode"] in by_id and edge["toNode"] in by_id

    mermaid = to_mermaid(built, "architecture", overlay)
    assert mermaid.startswith("flowchart LR")
    assert 'subgraph route["Routes"]' in mermaid and "Main Flask app" in mermaid and '-.->|"filters"|' in mermaid
    assert "linkStyle" in mermaid


def test_files_export_is_folder_level_and_written_with_the_map(tmp_path: Path):
    from grephunt.project_map import write_project_map
    from grephunt.project_map.export import to_canvas

    _write(tmp_path / "p", {
        "web/a/x.js": "import y from '../b/y'\n",
        "web/b/y.js": "",
        "api/main.py": "",
    })
    built = build_project_map(tmp_path / "p")
    canvas = to_canvas(json.loads(built.model_dump_json()), "files")
    labels = sorted(node["text"].splitlines()[0] for node in canvas["nodes"])
    assert labels == ["**api/**", "**web/a/**", "**web/b/**"]
    assert len(canvas["edges"]) == 1 and canvas["edges"][0]["label"] == "1 imports"
    write_project_map(built, tmp_path / "out")
    assert json.loads((tmp_path / "out" / "project_map.canvas").read_text(encoding="utf-8"))["nodes"]
    assert (tmp_path / "out" / "project_map.mmd").read_text(encoding="utf-8").startswith("flowchart LR")


def test_export_endpoint(tmp_path: Path, monkeypatch):
    _use_db(tmp_path, monkeypatch)
    project = ROOT / "samples" / "vuln_flask"
    _scan_row("exp1", project)
    asyncio.run(scan_service._build_map("exp1", project, lambda event: None))
    client = TestClient(console.app)
    canvas = client.get("/api/scans/exp1/map/export", params={"format": "canvas"})
    assert canvas.status_code == 200 and "vuln_flask-architecture.canvas" in canvas.headers["content-disposition"]
    assert canvas.json()["nodes"]
    mermaid = client.get("/api/scans/exp1/map/export", params={"format": "mermaid", "view": "files"})
    assert mermaid.status_code == 200 and mermaid.text.startswith("flowchart LR")
    assert client.get("/api/scans/exp1/map/export", params={"format": "svg"}).status_code == 400
    _scan_row("exp2", project)
    assert client.get("/api/scans/exp2/map/export").status_code == 409
