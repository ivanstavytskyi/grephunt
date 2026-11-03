"""Live scanners. Skipped when Docker is not running."""
from __future__ import annotations

import asyncio
import shutil
import subprocess
from pathlib import Path

import pytest

from grephunt.scan_pipeline.options import ScanOptions
from grephunt.scan_pipeline.pipeline import run_scan
from grephunt.scanner_catalog.registry import load_tools

ROOT = Path(__file__).resolve().parents[1]
PLANTED = {
    "sql-injection-string-concat",
    "subprocess-shell-true",
    "eval-user-input",
    "insecure-pickle-loads",
    "hardcoded-secret",
    "flask-debug-enabled",
}


def _docker_ready() -> bool:
    if shutil.which("docker") is None:
        return False
    result = subprocess.run(["docker", "info"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    return result.returncode == 0


pytestmark = pytest.mark.integration


@pytest.mark.skipif(not _docker_ready(), reason="needs a running Docker daemon")
def test_semgrep_finds_planted_bugs_and_ignores_clean_file(tmp_path: Path):
    rules = ROOT / "rules" / "python-basic.yml"
    tool = load_tools()["semgrep"]
    options = ScanOptions(configs=[str(rules)], excludes=[], use_docker=True)
    vulnerable = asyncio.run(
        run_scan(ROOT / "samples" / "vuln_flask", tmp_path / "vuln", [tool], options)
    )
    assert vulnerable.runs[0].status.value == "success", vulnerable.runs[0].error
    found = {item.rule_id for item in vulnerable.findings}
    assert PLANTED <= found

    clean = asyncio.run(
        run_scan(ROOT / "samples" / "clean_flask", tmp_path / "clean", [tool], options)
    )
    assert clean.runs[0].status.value == "success", clean.runs[0].error
    assert clean.findings == []


@pytest.mark.skipif(not _docker_ready(), reason="needs a running Docker daemon")
def test_trivy_reports_requirements_and_stays_quiet_without_manifest(tmp_path: Path):
    tool = load_tools()["trivy"]
    options = ScanOptions(trivy_scanners=["vuln"], excludes=[], use_docker=True)
    hit = asyncio.run(
        run_scan(ROOT / "samples" / "vuln_flask", tmp_path / "deps", [tool], options)
    )
    assert hit.runs[0].status.value == "success", hit.runs[0].error
    dependencies = [item for item in hit.findings if item.category.value == "dependency" and item.cve]
    assert dependencies
    assert any(item.package and item.package.lower() in {"flask", "requests", "pyyaml"} for item in dependencies)

    quiet = asyncio.run(
        run_scan(ROOT / "samples" / "no_manifest", tmp_path / "empty", [tool], options)
    )
    assert quiet.runs[0].status.value == "success", quiet.runs[0].error
    assert [item for item in quiet.findings if item.category.value == "dependency"] == []


@pytest.mark.skipif(not _docker_ready(), reason="needs a running Docker daemon")
def test_bearer_runs_offline_with_the_pinned_rule_pack(tmp_path: Path):
    tool = load_tools()["bearer"]
    options = ScanOptions(excludes=[], use_docker=True)
    hit = asyncio.run(
        run_scan(ROOT / "samples" / "vuln_flask", tmp_path / "vuln", [tool], options)
    )
    assert hit.runs[0].status.value == "success", hit.runs[0].error
    pickle = [item for item in hit.findings if item.rule_id == "python_lang_avoid_pickle"]
    assert pickle and pickle[0].cwe == ["CWE-502"]
    assert pickle[0].location.path == "app.py"

    clean = asyncio.run(
        run_scan(ROOT / "samples" / "clean_flask", tmp_path / "clean", [tool], options)
    )
    assert clean.runs[0].status.value == "success", clean.runs[0].error
    assert clean.findings == []

    skipped = asyncio.run(
        run_scan(ROOT / "samples" / "no_manifest", tmp_path / "none", [tool], options)
    )
    assert skipped.runs[0].status.value == "skipped"


@pytest.mark.skipif(not _docker_ready(), reason="needs a running Docker daemon")
def test_bandit_installs_from_the_lock_file_and_scans_offline(tmp_path: Path):
    tool = load_tools()["bandit"]
    options = ScanOptions(excludes=[], use_docker=True)
    hit = asyncio.run(run_scan(ROOT / "samples" / "vuln_flask", tmp_path / "vuln", [tool], options))
    assert hit.runs[0].status.value == "success", hit.runs[0].error
    found = {item.rule_id for item in hit.findings}
    assert {"B602", "B301", "B307", "B608"} <= found
    assert all(item.location.path == "app.py" for item in hit.findings)

    clean = asyncio.run(run_scan(ROOT / "samples" / "clean_flask", tmp_path / "clean", [tool], options))
    assert clean.runs[0].status.value == "success", clean.runs[0].error
    assert clean.findings == []


@pytest.mark.skipif(not _docker_ready(), reason="needs a running Docker daemon")
def test_gosec_scans_go_offline(tmp_path: Path):
    tool = load_tools()["gosec"]
    options = ScanOptions(excludes=[], use_docker=True)
    hit = asyncio.run(run_scan(ROOT / "samples" / "vuln_go", tmp_path / "vuln", [tool], options))
    assert hit.runs[0].status.value == "success", hit.runs[0].error
    assert {"G402", "G401", "G501"} <= {item.rule_id for item in hit.findings}
    clean = asyncio.run(run_scan(ROOT / "samples" / "clean_go", tmp_path / "clean", [tool], options))
    assert clean.runs[0].status.value == "success", clean.runs[0].error
    assert clean.findings == []


@pytest.mark.skipif(not _docker_ready(), reason="needs a running Docker daemon")
def test_devskim_installs_from_nuget_and_scans_offline(tmp_path: Path):
    tool = load_tools()["devskim"]
    options = ScanOptions(excludes=[], use_docker=True)
    hit = asyncio.run(run_scan(ROOT / "samples" / "vuln_go", tmp_path / "vuln", [tool], options))
    assert hit.runs[0].status.value == "success", hit.runs[0].error
    assert any(item.location.path == "main.go" for item in hit.findings)


@pytest.mark.skipif(not _docker_ready(), reason="needs a running Docker daemon")
def test_dependency_scanners_find_the_old_flask(tmp_path: Path):
    tools = load_tools()
    options = ScanOptions(excludes=[], use_docker=True)
    for name in ("grype", "osv-scanner"):
        hit = asyncio.run(run_scan(ROOT / "samples" / "vuln_flask", tmp_path / name, [tools[name]], options))
        assert hit.runs[0].status.value == "success", (name, hit.runs[0].error)
        assert any((item.package or "").lower() == "flask" and item.cve for item in hit.findings), name
    sbom = asyncio.run(run_scan(ROOT / "samples" / "vuln_flask", tmp_path / "syft", [tools["syft"]], options))
    assert sbom.runs[0].status.value == "success", sbom.runs[0].error
    assert (tmp_path / "syft" / "syft.cdx.json").is_file()


@pytest.mark.skipif(not _docker_ready(), reason="needs a running Docker daemon")
def test_image_tar_is_scanned_by_image_capable_scanners(tmp_path: Path):
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from image_fixture import docker_archive

    image = docker_archive(tmp_path / "app.tar")
    tools = load_tools()
    options = ScanOptions(excludes=[], use_docker=True, target_kind="image", image_format="docker")
    for name in ("trivy", "grype"):
        result = asyncio.run(run_scan(image, tmp_path / name, [tools[name]], options))
        assert result.runs[0].status.value == "success", (name, result.runs[0].error)
        assert any((item.package or "").lower() == "flask" for item in result.findings), name
    sbom = asyncio.run(run_scan(image, tmp_path / "syft", [tools["syft"]], options))
    assert sbom.runs[0].status.value == "success", sbom.runs[0].error


@pytest.mark.skipif(not _docker_ready(), reason="needs a running Docker daemon")
def test_secret_scanners_find_the_fake_github_token(tmp_path: Path):
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from secret_fixture import fake_tokens, secret_project

    project = secret_project(tmp_path / "project")
    tools = load_tools()
    options = ScanOptions(excludes=[], use_docker=True)
    token = fake_tokens()["github"]
    for name in ("gitleaks", "betterleaks", "trufflehog", "kingfisher", "secretlint"):
        result = asyncio.run(run_scan(project, tmp_path / name, [tools[name]], options))
        assert result.runs[0].status.value == "success", (name, result.runs[0].error)
        hits = [item for item in result.findings if item.location.path == "config.py" and item.location.start_line == 2]
        assert hits, name
        assert all(token not in (item.snippet or "") + item.message for item in result.findings), name


@pytest.mark.skipif(not _docker_ready(), reason="needs a running Docker daemon")
def test_iac_scanners_flag_privileged_container(tmp_path: Path):
    tools = load_tools()
    project = ROOT / "samples" / "iac_vuln"
    options = ScanOptions(excludes=[], use_docker=True)
    for name in ("checkov", "kics", "hadolint", "kubescape", "zizmor"):
        result = asyncio.run(run_scan(project, tmp_path / name, [tools[name]], options))
        assert result.runs[0].status.value == "success", (name, result.runs[0].error)
        assert result.findings, name
        if name == "kubescape":
            assert any("privileged" in (item.message or "").lower() for item in result.findings), name


@pytest.mark.skipif(not _docker_ready(), reason="needs a running Docker daemon")
def test_snyk_open_source_with_a_connected_account(tmp_path: Path):
    from grephunt.integrations import snyk

    if not snyk.is_connected():
        pytest.skip("connect Snyk in the console first")
    tool = load_tools()["snyk-open-source"]
    result = asyncio.run(run_scan(ROOT / "samples" / "vuln_flask", tmp_path / "snyk", [tool], ScanOptions(excludes=[], use_docker=True)))
    assert result.runs[0].status.value in {"success", "skipped"}, result.runs[0].error
