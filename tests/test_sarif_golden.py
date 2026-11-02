"""SARIF parsing: shared parser and the Trivy hook."""
from __future__ import annotations

import json
from pathlib import Path

from grephunt.finding_model.record import Category, Severity
from grephunt.scan_pipeline.sarif import parse_sarif
from grephunt.scanner_hooks.trivy import TrivyHook

GOLDEN = Path(__file__).resolve().parent / "golden"


def test_semgrep_golden_normalizes_location_cwe_and_version():
    findings = parse_sarif(GOLDEN / "semgrep_eval.sarif.json", tool="semgrep", fallback_version="1.180.0")
    assert len(findings) == 1
    finding = findings[0]
    assert finding.location.path == "app.py"
    assert finding.location.start_line == 33
    assert finding.location.kind.value == "file"
    assert finding.cwe == ["CWE-95"]
    assert finding.severity is Severity.CRITICAL
    assert finding.severity_original == "9.8"
    assert finding.tool_version == "1.180.0"
    assert finding.module.value == "sast"
    assert finding.snippet.startswith("return str(eval")
    assert finding.raw_ref == "semgrep_eval.sarif.json#/runs/0/results/0"
    assert finding.correlation_key == "code:app.py:33:CWE-95"
    assert finding.fingerprint == "code:app.py:CWE-95"


def test_trivy_package_fields_come_from_hook_not_generic_parser():
    path = GOLDEN / "trivy_cve.sarif.json"
    generic = parse_sarif(path, tool="trivy", fallback_version="0.76.0")
    assert generic[0].package is None
    assert generic[0].cve == ["CVE-2021-44228"]
    assert generic[0].category is Category.DEPENDENCY

    refined = parse_sarif(path, tool="trivy", fallback_version="0.76.0", refine=TrivyHook().refine_finding)
    finding = refined[0]
    assert finding.package == "log4j-core"
    assert finding.installed_version == "2.14.1"
    assert finding.fixed_version == "2.15.0"
    assert finding.severity is Severity.CRITICAL
    assert finding.tool_version == "0.76.0"
    assert finding.fingerprint.startswith("dep:log4j-core:2.14.1:CVE-2021-44228")


def test_golden_files_are_json():
    for name in ("semgrep_eval.sarif.json", "trivy_cve.sarif.json"):
        json.loads((GOLDEN / name).read_text(encoding="utf-8"))
