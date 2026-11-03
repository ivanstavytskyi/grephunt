"""Grype, Syft, and OSV-Scanner.

grype_directory.sarif.json is Grype's own SARIF snapshot (presenter/sarif
testdata at v0.121.0). osv_two_packages.sarif.json is OSV-Scanner's own
snapshot (internal/output at v2.7.0). The vulnerability databases are not
reachable from the machine that wrote these tests, so the tools' snapshots
stand in for a live run.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

from grephunt.execution.request import RunOutcome
from grephunt.finding_model.correlation import correlate
from grephunt.finding_model.record import Category, Finding, Location, Severity
from grephunt.scan_pipeline.converters import cyclonedx_sbom
from grephunt.scan_pipeline.options import ScanOptions
from grephunt.scan_pipeline.pipeline import run_scan
from grephunt.scan_pipeline.sarif import parse_sarif
from grephunt.scanner_catalog import launch
from grephunt.scanner_catalog.registry import load_tools

ROOT = Path(__file__).resolve().parents[1]
GOLDEN = ROOT / "tests" / "golden"


def _parse(tool_name: str, golden: str, root: str = "/src"):
    tool = load_tools()[tool_name]
    return parse_sarif(GOLDEN / golden, tool=tool_name, project_root=Path(root), refine=tool.hook.refine_finding)


def test_grype_reads_package_fields_and_its_own_severity():
    findings = {finding.rule_id: finding for finding in _parse("grype", "grype_directory.sarif.json")}
    first = findings["CVE-1999-0001-package-1"]
    assert first.category is Category.DEPENDENCY
    assert first.cve == ["CVE-1999-0001"]
    assert first.package == "package-1"
    assert first.installed_version == "1.1.1"
    assert first.fixed_version == "1.2.1,2.1.3,3.4.0"
    # The SARIF score is 8.2, but Grype calls it low. Grype's word wins.
    assert first.severity is Severity.LOW
    assert first.severity_original == "low"
    assert first.location.path == "some/path/somefile-1.txt"
    second = findings["CVE-1999-0002-package-2"]
    assert second.severity is Severity.CRITICAL
    assert second.fixed_version is None


def test_osv_reads_package_and_fixed_version_from_prose():
    findings = _parse("osv-scanner", "osv_two_packages.sarif.json", root="/path/to")
    regex = [finding for finding in findings if finding.package == "regex"]
    assert regex
    assert regex[0].installed_version == "1.5.1"
    assert regex[0].fixed_version == "1.5.5"
    assert regex[0].cve == ["CVE-2022-24713"]
    assert regex[0].category is Category.DEPENDENCY
    assert regex[0].location.path == "sub-rust-project/Cargo.lock"
    gogo = [finding for finding in findings if finding.package == "github.com/gogo/protobuf"][0]
    assert gogo.fixed_version == "1.3.2"
    assert gogo.severity is Severity.MEDIUM  # no score in the advisory: SARIF level warning
    assert len(correlate(findings)) == 2


def test_trivy_grype_and_osv_merge_on_package_version_and_cve():
    base = dict(
        category=Category.DEPENDENCY,
        rule_id="CVE-2018-1000656",
        title="flask",
        severity=Severity.HIGH,
        cve=["CVE-2018-1000656"],
        package="Flask",
        installed_version="0.12.2",
    )
    trivy = Finding(tool="trivy", location=Location(path="requirements.txt", start_line=1), **base)
    grype = Finding(tool="grype", location=Location(path="requirements.txt"), **{**base, "package": "flask"})
    osv = Finding(tool="osv-scanner", location=Location(path="requirements.txt"), **{**base, "package": "flask"})
    merged = correlate([trivy, grype, osv])
    assert len(merged) == 1
    assert merged[0].tools == ["trivy", "grype", "osv-scanner"]


def test_osv_empty_report_parses():
    assert _parse("osv-scanner", "osv_empty.sarif.json") == []


def test_syft_sbom_is_kept_and_adds_no_findings(tmp_path: Path):
    tool = load_tools()["syft"]
    sbom = (GOLDEN / "syft_vuln_flask.cdx.json").read_text(encoding="utf-8")
    sarif = cyclonedx_sbom(sbom, tool.descriptor)
    assert sarif["runs"][0]["results"] == []
    components = {item["name"] for item in json.loads(sbom)["components"]}
    assert {"flask", "requests", "pyyaml"} <= components


def test_arguments_and_isolation():
    tools = load_tools()
    grype = tools["grype"]
    args = grype.hook.build_args(grype.descriptor, "/src", "/out/grype.sarif", ScanOptions(), True)
    assert args[0] == "dir:/src"
    assert args[args.index("--file") + 1] == "/out/grype.sarif"
    assert grype.descriptor.network is False
    assert grype.descriptor.environment["GRYPE_DB_AUTO_UPDATE"] == "false"
    assert grype.descriptor.prepare.args == ["db", "update"]
    assert grype.descriptor.prepare.ttl_hours == 24

    syft = tools["syft"]
    args = syft.hook.build_args(syft.descriptor, "/src", "/out/syft.sarif", ScanOptions(), True)
    assert "cyclonedx-json=/out/syft.cdx.json" in args
    assert syft.descriptor.network is False

    osv = tools["osv-scanner"]
    args = osv.hook.build_args(osv.descriptor, "/src", "/out/osv-scanner.sarif", ScanOptions(), True)
    assert {"--offline", "--download-offline-databases", "--no-call-analysis=rust"} <= set(args)
    assert args[args.index("--output-file") + 1] == "/out/osv-scanner.sarif"
    assert args[-1] == "/src"
    assert osv.descriptor.ok_exit_codes == [0, 1]


def test_report_written_after_an_error_exit_is_rejected(tmp_path: Path, monkeypatch):
    """osv-scanner exits 127 and still writes an empty report when it has no database."""
    tool = load_tools()["osv-scanner"]
    monkeypatch.setattr(launch, "resolve_binary", lambda name: "/usr/bin/osv-scanner")

    async def no_database(self, request):
        output = Path(request.args[request.args.index("--output-file") + 1])
        output.write_text((GOLDEN / "osv_empty.sarif.json").read_text(encoding="utf-8"), encoding="utf-8")
        return RunOutcome(returncode=127, stderr="could not load db for PyPI ecosystem: Forbidden")

    monkeypatch.setattr(launch.LocalRunner, "run", no_database)
    result = asyncio.run(run_scan(ROOT / "samples" / "vuln_flask", tmp_path / "out", [tool], ScanOptions(excludes=[], use_docker=False)))
    run = result.runs[0]
    assert run.status.value == "failed"
    assert "could not load db" in (run.error or "")

    async def found(self, request):
        output = Path(request.args[request.args.index("--output-file") + 1])
        output.write_text((GOLDEN / "osv_two_packages.sarif.json").read_text(encoding="utf-8"), encoding="utf-8")
        return RunOutcome(returncode=1)

    monkeypatch.setattr(launch.LocalRunner, "run", found)
    result = asyncio.run(run_scan(ROOT / "samples" / "vuln_flask", tmp_path / "out2", [tool], ScanOptions(excludes=[], use_docker=False)))
    assert result.runs[0].status.value == "success", result.runs[0].error
    assert result.findings
