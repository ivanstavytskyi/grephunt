"""Container image tar as a scan target."""
from __future__ import annotations

import asyncio
import io
import tarfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from grephunt.execution.request import RunOutcome
from grephunt.scan_pipeline.image_archive import IMAGE_MOUNT, detect_image_format, image_reference
from grephunt.scan_pipeline.options import ScanOptions
from grephunt.scan_pipeline.pipeline import run_scan
from grephunt.scanner_catalog import launch
from grephunt.scanner_catalog.registry import load_tools
from grephunt.web_console import app as console
from grephunt.web_console import scans as scan_service

from image_fixture import docker_archive, oci_archive

IMAGE_TOOLS = {"trivy", "grype", "syft", "osv-scanner", "trufflehog"}


def _source_tar(path: Path) -> Path:
    with tarfile.open(path, mode="w") as archive:
        data = b"print('hi')\n"
        info = tarfile.TarInfo("project/app.py")
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))
    return path


def test_detects_docker_and_oci_archives(tmp_path: Path):
    assert detect_image_format(docker_archive(tmp_path / "d.tar")) == "docker"
    assert detect_image_format(oci_archive(tmp_path / "o.tar")) == "oci"
    with pytest.raises(ValueError, match="not a container image"):
        detect_image_format(_source_tar(tmp_path / "s.tar"))
    (tmp_path / "x.tar").write_bytes(b"not a tar at all")
    with pytest.raises(ValueError):
        detect_image_format(tmp_path / "x.tar")
    assert image_reference("/image/image.tar", "oci") == "oci-archive:/image/image.tar"


def test_only_image_capable_scanners_take_images():
    tools = load_tools()
    capable = {name for name, tool in tools.items() if getattr(tool.hook, "supports_image", lambda: False)()}
    assert capable == IMAGE_TOOLS
    options = ScanOptions(target_kind="image", image_format="docker")
    trivy = tools["trivy"]
    args = trivy.hook.build_args(trivy.descriptor, IMAGE_MOUNT, "/out/trivy.sarif", options, True)
    assert args[:3] == ["image", "--input", IMAGE_MOUNT]
    assert "misconfig" not in args[args.index("--scanners") + 1]
    grype = tools["grype"]
    assert grype.hook.build_args(grype.descriptor, IMAGE_MOUNT, "/out/grype.sarif", options, True)[0] == f"docker-archive:{IMAGE_MOUNT}"
    osv = tools["osv-scanner"]
    args = osv.hook.build_args(osv.descriptor, IMAGE_MOUNT, "/out/osv-scanner.sarif", options, True)
    assert args[:3] == ["scan", "image", "--archive"] and args[-1] == IMAGE_MOUNT


def test_image_is_mounted_read_only_and_other_scanners_skip(tmp_path: Path, monkeypatch):
    image = docker_archive(tmp_path / "app.tar")
    tools = load_tools()
    requests = []

    async def fake_run(self, request):
        requests.append(request)
        output = next(arg for arg in request.args if arg.startswith("/out/"))
        name = output.split("/")[-1]
        (tmp_path / "out" / name).write_text('{"version": "2.1.0", "runs": []}', encoding="utf-8")
        return RunOutcome(returncode=0)

    async def ready(self, image_name):
        return None

    async def no_prepare(*args, **kwargs):
        return None

    monkeypatch.setattr(launch.DockerRunner, "run", fake_run)
    monkeypatch.setattr(launch.DockerRunner, "ensure_image", ready)
    monkeypatch.setattr(launch.DockerRunner, "available", lambda self: True)
    for name in ("trivy",):
        monkeypatch.setattr(tools[name].hook, "prepare", no_prepare)
    selected = [tools["grype"], tools["bandit"], tools["semgrep"]]
    monkeypatch.setattr(tools["grype"].hook, "prepare", no_prepare)
    options = ScanOptions(excludes=[], use_docker=True, target_kind="image", image_format="docker")
    result = asyncio.run(run_scan(image, tmp_path / "out", selected, options))
    statuses = {run.tool: run.status.value for run in result.runs}
    assert statuses == {"grype": "success", "bandit": "skipped", "semgrep": "skipped"}
    assert {run.error for run in result.runs if run.tool != "grype"} == {"does not scan container images"}
    assert len(requests) == 1
    binds = {container: (host, read_only) for host, container, read_only in requests[0].binds}
    assert binds[IMAGE_MOUNT] == (str(image.resolve()), True)
    assert requests[0].args[0] == f"docker-archive:{IMAGE_MOUNT}"


def test_console_accepts_an_image_tar_and_rejects_a_plain_tar(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("GREPHUNT_DATABASE_URL", f"sqlite:///{(tmp_path / 't.db').as_posix()}")
    monkeypatch.setattr(console, "DATA_DIR", tmp_path / "data")
    scan_service.reset_session_factory()
    created = {}

    def fake_create(target, label, names, configs, use_docker, target_kind="source", image_format="docker"):
        created.update(target=target, label=label, kind=target_kind, image_format=image_format, names=names)
        return "abc"

    monkeypatch.setattr(console, "create_scan", fake_create)
    monkeypatch.setattr(console, "get_scan", lambda scan_id: {"id": scan_id})
    client = TestClient(console.app)

    image = oci_archive(tmp_path / "app.tar").read_bytes()
    response = client.post(
        "/api/scans",
        data={"scanners": "trivy,grype"},
        files={"archive": ("app.tar", image, "application/x-tar")},
    )
    assert response.status_code == 200, response.text
    assert created["kind"] == "image"
    assert created["image_format"] == "oci"
    assert created["label"] == "app.tar (image)"
    assert created["target"].name == "image.tar"
    assert created["target"].read_bytes() == image

    plain = _source_tar(tmp_path / "src.tar").read_bytes()
    response = client.post(
        "/api/scans",
        data={"scanners": "trivy"},
        files={"archive": ("src.tar", plain, "application/x-tar")},
    )
    assert response.status_code == 400
    assert "not a container image" in response.json()["detail"]


def test_tool_list_marks_image_scanners(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("GREPHUNT_DATABASE_URL", f"sqlite:///{(tmp_path / 't.db').as_posix()}")
    scan_service.reset_session_factory()
    tools = {item["name"]: item for item in TestClient(console.app).get("/api/tools").json()}
    assert {name for name, item in tools.items() if item["scans_images"]} == IMAGE_TOOLS
    assert tools["semgrep"]["image"].startswith("semgrep/")
