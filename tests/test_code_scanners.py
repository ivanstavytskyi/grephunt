"""gosec and DevSkim: YAML-only code scanners."""
from __future__ import annotations

from pathlib import Path

from grephunt.finding_model.correlation import correlate
from grephunt.finding_model.record import Severity
from grephunt.scan_pipeline.options import ScanOptions
from grephunt.scan_pipeline.sarif import parse_sarif
from grephunt.scanner_catalog.registry import load_tools

ROOT = Path(__file__).resolve().parents[1]
GOLDEN = ROOT / "tests" / "golden"


def _parse(tool_name: str, golden: str):
    tool = load_tools()[tool_name]
    return parse_sarif(GOLDEN / golden, tool=tool_name, project_root=Path("/src"), refine=tool.hook.refine_finding)


def test_gosec_runs_offline_on_go_projects_only():
    tool = load_tools()["gosec"]
    descriptor = tool.descriptor
    assert descriptor.network is False
    assert descriptor.environment["GOPROXY"] == "off"
    assert descriptor.environment["GOTOOLCHAIN"] == "local"
    assert tool.is_applicable(ROOT / "samples" / "vuln_go")
    assert not tool.is_applicable(ROOT / "samples" / "vuln_flask")
    args = tool.hook.build_args(descriptor, "/src", "/out/gosec.sarif", ScanOptions(), True)
    assert args[args.index("-out") + 1] == "/out/gosec.sarif"
    assert args[-1] == "/src/..."
    assert "-no-fail" in args
    assert "-quiet" not in args  # -quiet skips the report file when there are no issues


def test_gosec_cwe_comes_from_rule_relationships():
    findings = _parse("gosec", "gosec_vuln_go.sarif.json")
    by_rule = {finding.rule_id: finding for finding in findings}
    assert by_rule["G402"].cwe == ["CWE-295"]
    assert by_rule["G402"].severity is Severity.HIGH
    assert by_rule["G401"].severity is Severity.MEDIUM
    assert by_rule["G104"].severity is Severity.LOW
    assert by_rule["G204"].location.path == "main.go"
    assert by_rule["G204"].location.start_line == 20
    assert by_rule["G204"].snippet.startswith("return exec.Command")


def test_gosec_taint_and_pattern_rules_merge_on_one_line():
    findings = _parse("gosec", "gosec_vuln_go.sarif.json")
    merged = correlate(findings)
    shell = [finding for finding in merged if finding.location.start_line == 20]
    assert len(shell) == 1
    assert shell[0].severity is Severity.HIGH


def test_devskim_severity_comes_from_its_own_scale():
    findings = _parse("devskim", "devskim_shape.sarif.json")
    by_rule = {finding.rule_id: finding for finding in findings}
    assert by_rule["DS126858"].severity is Severity.HIGH
    assert by_rule["DS126858"].severity_original == "Important"
    assert by_rule["DS137138"].severity is Severity.MEDIUM
    assert by_rule["DS137138"].location.path == "web/app.js"
    assert by_rule["DS126858"].help_uri.endswith("DS126858.md")


def test_devskim_installs_a_pinned_cli_once():
    tool = load_tools()["devskim"]
    descriptor = tool.descriptor
    assert descriptor.prepare is not None
    assert descriptor.prepare.args[descriptor.prepare.args.index("--version") + 1] == descriptor.version
    assert descriptor.container_binary == f"/opt/devskim/{descriptor.version}/devskim"
    assert f"{{cache:grephunt-devskim}}/{descriptor.version}" in descriptor.prepare.args
    args = tool.hook.build_args(descriptor, "/src", "/out/devskim.sarif", ScanOptions(), True)
    assert args[:3] == ["analyze", "-I", "/src"]
    assert args[args.index("-O") + 1] == "/out/devskim.sarif"
