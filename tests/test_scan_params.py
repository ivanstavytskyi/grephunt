"""Per-tool scan parameters from YAML descriptors."""
from __future__ import annotations

import pytest

from grephunt.scan_pipeline.options import ScanOptions
from grephunt.scanner_catalog.parameter_schema import validate_scan_params
from grephunt.scanner_catalog.registry import load_tools


def test_empty_trivy_scanners_falls_back_to_defaults():
    options = ScanOptions(params={"trivy": {"scanners": []}})
    assert options.trivy_scanners == ["vuln", "secret", "misconfig"]


def test_validate_trivy_rejects_empty_scanners():
    tools = load_tools()
    descriptors = {name: tool.descriptor for name, tool in tools.items()}
    with pytest.raises(ValueError, match="at least one"):
        validate_scan_params(["trivy"], descriptors, {"trivy": {"scanners": []}})


def test_validate_applies_yaml_defaults_for_semgrep():
    tools = load_tools()
    descriptors = {name: tool.descriptor for name, tool in tools.items()}
    validated = validate_scan_params(["semgrep"], descriptors, {})
    assert validated["semgrep"]["configs"] == ["p/default"]


def test_legacy_scan_options_fields_lift_into_params():
    options = ScanOptions(configs=["p/ci"], trivy_scanners=["vuln"])
    assert options.configs == ["p/ci"]
    assert options.trivy_scanners == ["vuln"]
