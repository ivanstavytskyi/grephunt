"""Noise filter, dependency alias merge, and development-only packages."""
from __future__ import annotations

import json
from pathlib import Path

from grephunt.finding_model.correlation import correlate, vulnerability_ids
from grephunt.finding_model.record import Category, Finding, Location, Severity
from grephunt.scan_pipeline.dependency_scope import suppressed_packages
from grephunt.scan_pipeline.noise import is_noise
from grephunt.scan_pipeline.options import ScanOptions
from grephunt.scan_pipeline.pipeline import accept_finding
from grephunt.scanner_catalog.registry import load_tools
from grephunt.scanner_hooks.semgrep import SemgrepHook


def _dep(tool: str, package: str, rule_id: str, **extra) -> Finding:
    return Finding(
        tool=tool,
        category=Category.DEPENDENCY,
        rule_id=rule_id,
        title=extra.pop("title", package),
        severity=extra.pop("severity", Severity.HIGH),
        package=package,
        installed_version=extra.pop("installed_version", "8.5.1"),
        cve=extra.pop("cve", []),
        message=extra.pop("message", ""),
        description=extra.pop("description", None),
        location=Location(path=extra.pop("path", "package-lock.json"), start_line=1),
        **extra,
    )


def _code(rule_id: str, path: str, category: Category = Category.CODE) -> Finding:
    return Finding(
        tool="devskim",
        category=category,
        rule_id=rule_id,
        title=rule_id,
        severity=Severity.HIGH,
        location=Location(path=path, start_line=1),
    )


def test_noise_drops_devskim_hashes_logger_leak_and_vendor_secrets():
    assert is_noise(_code("DS173237", "bom.json"))
    assert is_noise(_code("Microsoft.DevSkim.DS137138", "src/app.ts"))
    assert is_noise(_code("javascript_lang_logger_leak", "frontend/src/app.ts"))
    secret = _code("generic-api-key", "node_modules/leftpad/index.js", Category.SECRET)
    assert is_noise(secret)
    assert is_noise(_code("DS000000", "cyclonedx.sbom.json"))
    real = _code("javascript.lang.security.eval", "routes/app.ts")
    assert not is_noise(real)
    cve = _dep("grype", "jsonwebtoken", "CVE-2022-23529", cve=["CVE-2022-23529"], path="node_modules/jsonwebtoken/package.json")
    assert not is_noise(cve)


def test_dependency_aliases_collapse_to_one_finding():
    ghsa = _dep(
        "grype",
        "jsonwebtoken",
        "GHSA-hjrf-2m68-5959",
        cve=["GHSA-hjrf-2m68-5959"],
        message="alias CVE-2022-23529",
    )
    cve = _dep("osv-scanner", "JSONWebToken", "CVE-2022-23529", cve=["CVE-2022-23529"])
    snyk = _dep(
        "snyk-open-source",
        "jsonwebtoken",
        "SNYK-JS-JSONWEBTOKEN-2944537",
        description="This issue is CVE-2022-23529.",
    )
    other = _dep("grype", "jsonwebtoken", "CVE-2015-9235", cve=["CVE-2015-9235"], installed_version="8.5.1")
    merged = correlate([ghsa, cve, snyk, other])
    assert len(merged) == 2
    ids = {tuple(item.cve) for item in merged}
    assert ("CVE-2015-9235",) in ids or any("CVE-2015-9235" in item.cve and len(item.cve) == 1 for item in merged)
    combined = next(item for item in merged if "CVE-2022-23529" in item.cve)
    assert "GHSA-hjrf-2m68-5959".lower() in [value.lower() for value in combined.cve]
    assert "SNYK-JS-JSONWEBTOKEN-2944537" in combined.cve
    assert set(combined.tools) == {"grype", "osv-scanner", "snyk-open-source"}
    assert vulnerability_ids(snyk) == {"SNYK-JS-JSONWEBTOKEN-2944537", "CVE-2022-23529"}


def test_repeated_secret_in_one_file_is_one_finding():
    rows = [
        _code("hardcoded-password", "data/static/users.yml", Category.SECRET).model_copy(
            update={"location": Location(path="data/static/users.yml", start_line=line), "tool": "betterleaks", "tools": ["betterleaks"]}
        )
        for line in (150, 159, 168, 178)
    ]
    other = _code("private-key", "data/static/users.yml", Category.SECRET)
    merged = correlate([*rows, other])
    passwords = [item for item in merged if item.rule_id == "hardcoded-password"]
    assert len(passwords) == 1
    assert len(merged) == 2
    assert "4 occurrences" in passwords[0].message
    assert passwords[0].location.start_line == 150
    assert passwords[0].location.end_line == 178


def test_unrelated_packages_stay_separate():
    left = _dep("grype", "lodash", "CVE-2021-23337", cve=["CVE-2021-23337"])
    right = _dep("grype", "minimatch", "CVE-2022-3517", cve=["CVE-2022-3517"])
    assert len(correlate([left, right])) == 2


def test_unreferenced_npm_packages_are_excluded(tmp_path: Path):
    lock = {
        "packages": {
            "": {"name": "app"},
            "node_modules/tar": {"version": "6.1.11", "dev": True},
            "node_modules/minimatch": {"version": "3.0.4", "dev": True},
            "node_modules/jsonwebtoken": {"version": "8.5.1"},
            "node_modules/express": {"version": "4.18.2"},
            "node_modules/@scope/pkg": {"version": "1.0.0", "dev": True},
        }
    }
    (tmp_path / "package-lock.json").write_text(json.dumps(lock), encoding="utf-8")
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "dependencies": {"jsonwebtoken": "8.5.1"},
                "devDependencies": {"tar": "6.1.11"},
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "app.ts").write_text("import express from 'express'\n", encoding="utf-8")
    hidden = suppressed_packages(tmp_path)
    assert {"tar", "minimatch", "@scope/pkg"} <= hidden
    assert "jsonwebtoken" not in hidden
    assert "express" not in hidden
    options = ScanOptions(excludes=[])
    tar = _dep("grype", "tar", "CVE-2021-32803", cve=["CVE-2021-32803"])
    token = _dep("grype", "jsonwebtoken", "CVE-2022-23529", cve=["CVE-2022-23529"])
    assert not accept_finding(tar, options, hidden)
    assert accept_finding(token, options, hidden)


def test_semgrep_always_loads_bundled_javascript_rules():
    hook = SemgrepHook()
    descriptor = load_tools()["semgrep"].descriptor
    args = hook.build_args(descriptor, "/src", "/out/semgrep.sarif", ScanOptions(), True)
    assert "/rules/grephunt" in args
    mounts = dict((dest, host) for host, dest in hook.extra_mounts(ScanOptions(), True))
    assert mounts["/rules/grephunt"].name == "rules"
