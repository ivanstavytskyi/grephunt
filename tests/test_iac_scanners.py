"""IaC scanners: Checkov, KICS, Hadolint, Kubescape, zizmor."""
from __future__ import annotations

from pathlib import Path

import pytest

from grephunt.finding_model.record import Category
from grephunt.scan_pipeline.options import ScanOptions
from grephunt.scan_pipeline.sarif import parse_sarif
from grephunt.scanner_catalog.registry import load_tools
from grephunt.scanner_hooks.generic import expand

ROOT = Path(__file__).resolve().parents[1]
IAC_TOOLS = ("checkov", "kics", "hadolint", "kubescape", "zizmor")


@pytest.mark.parametrize("tool_name", IAC_TOOLS)
def test_iac_scanner_is_registered(tool_name: str):
    assert tool_name in load_tools()


def test_checkov_args_use_sarif_output_and_redacted_path():
    tool = load_tools()["checkov"]
    args = tool.hook.build_args(tool.descriptor, "/src", "/out/checkov.sarif", ScanOptions(), True)
    assert "-o" in args and "sarif" in args
    assert tool.descriptor.produced_output == "results_sarif.sarif"


def test_hadolint_skips_projects_without_dockerfiles(tmp_path: Path):
    tool = load_tools()["hadolint"]
    empty = tmp_path / "empty"
    empty.mkdir()
    assert not tool.is_applicable(empty)
    assert tool.is_applicable(ROOT / "samples" / "iac_vuln")


def test_zizmor_only_applies_when_workflows_exist(tmp_path: Path):
    tool = load_tools()["zizmor"]
    assert not tool.is_applicable(tmp_path / "no_workflows")
    assert tool.is_applicable(ROOT / "samples" / "iac_vuln")


def test_kubescape_prepare_expands_catalog_path():
    tool = load_tools()["kubescape"]
    step = tool.descriptor.prepare
    assert step is not None
    args = expand(step.args, {"catalog": "/grephunt-catalog"}, {"grephunt-kubescape": "/opt/kubescape"})
    assert args[0].endswith("kubescape_install.py")


@pytest.mark.parametrize("tool_name", ("checkov", "kics", "hadolint", "zizmor"))
def test_iac_golden_sarif_parses_as_misconfig(tool_name: str):
    tool = load_tools()[tool_name]
    sarif = ROOT / "tests" / "golden" / "iac" / f"{tool_name}.sarif"
    assert sarif.is_file(), f"missing golden SARIF for {tool_name}"
    findings = parse_sarif(
        sarif,
        tool=tool_name,
        fallback_version=tool.descriptor.version,
        refine=tool.hook.refine_finding,
    )
    assert findings
    assert all(item.category is Category.MISCONFIG for item in findings)
