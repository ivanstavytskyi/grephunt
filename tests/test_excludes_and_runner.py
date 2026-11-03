"""Path exclusions and run isolation."""
from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from grephunt.web_console.uploads import safe_extract
from grephunt.scan_pipeline.options import ScanOptions
from grephunt.scan_pipeline.excludes import collect_excludes, is_excluded
from grephunt.execution.docker import DockerRunner
from grephunt.execution.request import RunRequest
from grephunt.scanner_catalog.registry import load_tools
from grephunt.scanner_hooks.semgrep import SemgrepHook


def test_default_excludes_skip_tests_and_keep_node_modules():
    patterns = collect_excludes(Path("."), None, use_defaults=True)
    assert is_excluded("src/test/app.py", patterns)
    assert is_excluded("web/dist/bundle.js", patterns)
    assert is_excluded("data/static/codefixes/a.tf", ["data/static/codefixes"])
    assert not is_excluded("node_modules/leftpad/index.js", patterns)


def test_ignore_file(tmp_path: Path):
    (tmp_path / ".grephuntignore").write_text("# comment\ndata/static/codefixes\n", encoding="utf-8")
    patterns = collect_excludes(tmp_path, ["*.generated.ts"], use_defaults=False)
    assert is_excluded("data/static/codefixes/iac.tf", patterns)
    assert is_excluded("src/a.generated.ts", patterns)
    assert not is_excluded("server.ts", patterns)


def test_descriptors_pin_versions_and_trivy_scan_is_offline():
    tools = load_tools()
    assert {"bandit", "bearer", "semgrep", "trivy"} <= set(tools)
    assert tools["semgrep"].descriptor.version == "1.180.0"
    assert not tools["semgrep"].descriptor.image.endswith(":latest")
    assert tools["trivy"].descriptor.network is False
    assert tools["trivy"].descriptor.prepare_network is True
    assert tools["trivy"].descriptor.user == "65534"


def test_semgrep_asks_for_network_only_with_registry_rules(tmp_path: Path):
    hook = SemgrepHook()
    descriptor = load_tools()["semgrep"].descriptor
    local = tmp_path / "rules.yml"
    local.write_text("rules: []\n", encoding="utf-8")
    assert hook.wants_network(descriptor, ScanOptions(configs=[str(local)])) is False
    assert hook.wants_network(descriptor, ScanOptions(configs=["p/default"])) is True


def test_docker_command_drops_network_caps_and_root():
    command = DockerRunner()._command(
        RunRequest(
            image="aquasec/trivy:0.76.0",
            binary="trivy",
            args=["fs", "/src"],
            container_name="grephunt-trivy-test",
            network=False,
            user="65534",
            cpus="1",
            memory="1g",
            pids_limit=256,
        )
    )
    assert command[command.index("--network") + 1] == "none"
    assert command[command.index("--user") + 1] == "65534:65534"
    assert "--cap-drop" in command
    assert "ALL" in command
    assert "--memory" in command
    assert command[-1] == "/src"


def test_zip_slip_is_rejected(tmp_path: Path):
    archive = tmp_path / "bad.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("../evil.txt", "nope")
    with pytest.raises(ValueError):
        safe_extract(archive, tmp_path / "out")


def test_zip_roundtrip(tmp_path: Path):
    archive = tmp_path / "ok.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("app/main.py", "print('ok')\n")
    destination = tmp_path / "tree"
    safe_extract(archive, destination)
    assert (destination / "app" / "main.py").read_text(encoding="utf-8").startswith("print")
