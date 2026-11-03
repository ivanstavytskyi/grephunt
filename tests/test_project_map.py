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
