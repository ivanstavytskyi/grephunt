"""Deterministic scanner recommendation from the project map, and the AI wrapper's fallback."""
from __future__ import annotations

from grephunt.web_console.scanner_advice import recommend, recommend_with_ai

TOOLS = [
    {"name": "semgrep", "group": "code", "cloud": False},
    {"name": "bandit", "group": "code", "cloud": False},
    {"name": "gosec", "group": "code", "cloud": False},
    {"name": "gitleaks", "group": "secret", "cloud": False},
    {"name": "trufflehog", "group": "secret", "cloud": False},
    {"name": "trivy", "group": "dependency", "cloud": False},
    {"name": "osv-scanner", "group": "dependency", "cloud": False},
    {"name": "hadolint", "group": "iac", "cloud": False},
    {"name": "checkov", "group": "iac", "cloud": False},
    {"name": "kics", "group": "iac", "cloud": False},
    {"name": "zizmor", "group": "iac", "cloud": False},
    {"name": "snyk-code", "group": "code", "cloud": True},
]


def _map(nodes, frameworks=None, datastores=None):
    return {
        "files": {"nodes": nodes},
        "stats": {"files": len(nodes), "routes": 3},
        "stack": {"frameworks": frameworks or [], "datastores": datastores or []},
    }


def _file(path, language, role="source"):
    return {"kind": "file", "path": path, "language": language, "role": role}


def test_python_web_project_gets_python_secret_and_dependency_scanners():
    project_map = _map(
        [
            _file("app.py", "python"),
            _file("requirements.txt", None, "config"),
            _file("templates/x.html", "html"),
        ],
        frameworks=["Flask"],
    )
    result = recommend(project_map, TOOLS)
    assert "semgrep" in result["recommended"] and "bandit" in result["recommended"]
    assert "gitleaks" in result["recommended"] and "trufflehog" in result["recommended"]
    assert "trivy" in result["recommended"] and "osv-scanner" in result["recommended"]
    # No Dockerfile, Terraform, or workflows: those scanners stay off.
    assert "hadolint" not in result["recommended"] and "kics" not in result["recommended"] and "zizmor" not in result["recommended"]
    assert "gosec" not in result["recommended"]
    assert result["reasons"]["bandit"]


def test_infra_project_gets_the_matching_iac_scanners():
    project_map = _map([
        _file("Dockerfile", "dockerfile", "iac"),
        _file("infra/main.tf", "terraform", "iac"),
        _file(".github/workflows/ci.yml", "yaml", "config"),
        _file("main.go", "go"),
    ])
    names = recommend(project_map, TOOLS)["recommended"]
    assert {"hadolint", "checkov"} <= set(names)  # Dockerfile
    assert "kics" in names  # Terraform
    assert "zizmor" in names  # workflows
    assert "gosec" in names  # Go


def test_cloud_scanners_are_never_auto_recommended():
    assert "snyk-code" not in recommend(_map([_file("a.py", "python")]), TOOLS)["recommended"]


def test_ai_wrapper_falls_back_to_deterministic_on_bad_json(monkeypatch):
    from grephunt.web_console import scanner_advice

    monkeypatch.setattr(scanner_advice, "_call", lambda *a, **k: "not json at all")
    result = recommend_with_ai("gemini", "key", "gemini-2.5-flash", _map([_file("a.py", "python")]), TOOLS)
    assert result["source"] == "deterministic" and "semgrep" in result["recommended"]


def test_ai_wrapper_keeps_only_valid_scanner_names(monkeypatch):
    from grephunt.web_console import scanner_advice

    monkeypatch.setattr(scanner_advice, "_call", lambda *a, **k: '{"scanners": ["semgrep", "made-up", "gosec"], "reasons": {"semgrep": "broad"}, "summary": "A Go service."}')
    result = recommend_with_ai("gemini", "key", "gemini-2.5-flash", _map([_file("main.go", "go")]), TOOLS)
    assert set(result["recommended"]) == {"semgrep", "gosec"} and result["source"] == "ai"
    assert result["summary"] == "A Go service." and result["reasons"]["gosec"]


def test_analyze_endpoint_builds_a_map_and_recommends(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from grephunt.config import DATA_DIR
    from grephunt.web_console import app as console
    from grephunt.web_console import scans as scan_service

    monkeypatch.setattr(scan_service, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr(console, "DATA_DIR", tmp_path / "data")
    client = TestClient(console.app)
    files = [
        ("files", ("app.py", b"from flask import Flask, request\napp = Flask(__name__)\n", "text/plain")),
        ("files", ("requirements.txt", b"flask\n", "text/plain")),
        ("files", ("Dockerfile", b"FROM python:3.12\n", "text/plain")),
    ]
    data = {"relative_paths": ["proj/app.py", "proj/requirements.txt", "proj/Dockerfile"], "folder_name": "proj"}
    response = client.post("/api/analyze", files=files, data=data)
    assert response.status_code == 200, response.text
    body = response.json()
    assert "semgrep" in body["recommended"] and "bandit" in body["recommended"]
    assert "hadolint" in body["recommended"]  # the Dockerfile
    assert "trivy" in body["recommended"]  # requirements.txt
    assert body["source"] == "deterministic"
    assert "snyk-code" not in body["recommended"]


def test_analyze_rejects_an_image_tar(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from grephunt.web_console import app as console
    from grephunt.web_console import scans as scan_service

    monkeypatch.setattr(scan_service, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr(console, "DATA_DIR", tmp_path / "data")
    client = TestClient(console.app)
    response = client.post("/api/analyze", files={"archive": ("image.tar", b"x", "application/x-tar")})
    assert response.status_code == 400 and "image" in response.json()["detail"]
