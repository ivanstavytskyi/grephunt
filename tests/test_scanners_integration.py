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
