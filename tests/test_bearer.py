"""Bearer: pinned rule pack, offline arguments, and JSON to SARIF."""
from __future__ import annotations

import asyncio
import io
import json
import tarfile
from pathlib import Path

import pytest

from grephunt.execution.request import RunOutcome
from grephunt.finding_model.correlation import correlate
from grephunt.finding_model.record import Category, Finding, Location, Severity
from grephunt.scan_pipeline.options import ScanOptions
from grephunt.scan_pipeline.pipeline import run_scan
from grephunt.scan_pipeline.sarif import parse_sarif
from grephunt.scanner_catalog import launch
from grephunt.scanner_catalog.descriptor import ToolDescriptor
from grephunt.scanner_catalog.registry import load_tools
from grephunt.scanner_hooks import bearer as bearer_hook
from grephunt.scanner_hooks.bearer import BearerHook, bearer_json_to_sarif, install_rules

ROOT = Path(__file__).resolve().parents[1]
GOLDEN = ROOT / "tests" / "golden" / "bearer_pickle.json"


def _descriptor() -> ToolDescriptor:
    return load_tools()["bearer"].descriptor


def _sarif(tmp_path: Path, report: dict) -> Path:
    path = tmp_path / "bearer.sarif"
    path.write_text(json.dumps(bearer_json_to_sarif(report, "2.1.2")), encoding="utf-8")
    return path


def _pack(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, data in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def test_descriptor_is_pinned_and_offline():
    descriptor = _descriptor()
    assert descriptor.image == "bearer/bearer:v2.1.2"
    assert descriptor.network is False
    assert descriptor.rules_version and not descriptor.rules_version.startswith("latest")
    assert descriptor.raw_output_filename == "bearer.json"
    rules = [volume for volume in descriptor.cache_volumes if volume.name == bearer_hook.RULES_CACHE]
    assert rules and rules[0].read_only is True


def test_latest_amd64_tag_is_not_a_pin():
    raw = _descriptor().model_dump()
    raw["image"] = "bearer/bearer:latest-amd64"
    with pytest.raises(ValueError):
        ToolDescriptor.model_validate(raw)
    raw["image"] = "bearer/bearer:v2.1.2"
    raw["rules_version"] = "latest"
    with pytest.raises(ValueError):
        ToolDescriptor.model_validate(raw)


def test_docker_arguments_use_the_mounted_rule_pack_and_no_registry():
    descriptor = _descriptor()
    args = BearerHook().build_args(
        descriptor, "/src", "/out/bearer.sarif", ScanOptions(excludes=["test", "*.spec.*", "a,b"]), True
    )
    assert args[:2] == ["scan", "/src"]
    assert args[args.index("--output") + 1] == "/out/bearer.json"
    assert args[args.index("--format") + 1] == "json"
    assert args[args.index("--external-rule-dir") + 1] == f"/rules/{descriptor.rules_version}"
    assert "--disable-default-rules" in args
    assert "--disable-version-check" in args
    assert args[args.index("--exit-code") + 1] == "0"
    skipped = args[args.index("--skip-path") + 1].split(",")
    assert {"test", "*.spec.*", "node_modules", "vendor"} <= set(skipped)
    assert "a" not in skipped


def test_local_arguments_use_host_paths(tmp_path: Path):
    descriptor = _descriptor()
    output = tmp_path / "bearer.sarif"
    args = BearerHook().build_args(descriptor, str(tmp_path), str(output), ScanOptions(excludes=[]), False)
    assert args[args.index("--output") + 1] == str(tmp_path / "bearer.json")
    assert Path(args[args.index("--external-rule-dir") + 1]) == bearer_hook.rules_dir(descriptor)


def test_applicable_only_to_supported_languages():
    hook = BearerHook()
    assert hook.is_applicable(ROOT / "samples" / "vuln_flask")
    assert not hook.is_applicable(ROOT / "samples" / "no_manifest")


def test_golden_report_becomes_a_finding(tmp_path: Path):
    report = json.loads(GOLDEN.read_text(encoding="utf-8"))
    findings = parse_sarif(_sarif(tmp_path, report), tool="bearer", refine=BearerHook().refine_finding)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "python_lang_avoid_pickle"
    assert finding.category is Category.CODE
    assert finding.severity is Severity.CRITICAL
    assert finding.severity_original == "critical"
    assert finding.cwe == ["CWE-502"]
    assert finding.location.path == "app.py"
    assert finding.location.start_line == 28
    assert finding.snippet == "return str(pickle.loads(request.data))"
    assert finding.tool_version == "2.1.2"
    assert finding.help_uri == "https://docs.bearer.com/reference/rules/python_lang_avoid_pickle"
    assert finding.description and finding.description.startswith("## Description")
    assert finding.fingerprint == "code:app.py:CWE-502"


def test_severity_mapping_and_empty_reports(tmp_path: Path):
    def item(rule: str, cwe: str) -> dict:
        return {"id": rule, "title": rule, "cwe_ids": [cwe], "filename": "a.js", "line_number": 3}

    report = {
        "high": [item("js_high", "79")],
        "medium": [item("js_medium", "601")],
        "low": [item("js_low", "1004")],
        "warning": [item("js_warning", "532")],
        "unknown": [item("js_unknown", "1")],
    }
    findings = parse_sarif(_sarif(tmp_path, report), tool="bearer", refine=BearerHook().refine_finding)
    by_rule = {finding.rule_id: finding for finding in findings}
    assert set(by_rule) == {"js_high", "js_medium", "js_low", "js_warning"}
    assert by_rule["js_high"].severity is Severity.HIGH
    assert by_rule["js_medium"].severity is Severity.MEDIUM
    assert by_rule["js_low"].severity is Severity.LOW
    assert by_rule["js_warning"].severity is Severity.INFO
    assert by_rule["js_warning"].severity_original == "warning"

    hook = BearerHook()
    for text in ("{}", "", "null"):
        raw = tmp_path / "bearer.json"
        raw.write_text(text, encoding="utf-8")
        hook.convert_output(raw, tmp_path / "empty.sarif", _descriptor())
        assert parse_sarif(tmp_path / "empty.sarif", tool="bearer") == []


def test_bearer_and_semgrep_confirm_each_other(tmp_path: Path):
    report = json.loads(GOLDEN.read_text(encoding="utf-8"))
    bearer = parse_sarif(_sarif(tmp_path, report), tool="bearer", refine=BearerHook().refine_finding)[0]
    semgrep = Finding(
        tool="semgrep",
        rule_id="insecure-pickle-loads",
        title="pickle",
        severity=Severity.HIGH,
        cwe=["CWE-502"],
        location=Location(path="app.py", start_line=28, end_line=28),
    )
    merged = correlate([semgrep, bearer])
    assert len(merged) == 1
    assert merged[0].tools == ["semgrep", "bearer"]
    assert merged[0].severity is Severity.CRITICAL


def test_rule_pack_is_installed_once(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(bearer_hook, "cache_dir", lambda name: tmp_path / name)
    calls: list[str] = []

    def fetch(url: str) -> bytes:
        calls.append(url)
        language = url.rsplit("/", 1)[-1].split(".")[0]
        return _pack({f"{language}/lang/rule.yml": b"metadata:\n  id: x\n", f"{language}/README.md": b"x"})

    descriptor = _descriptor()
    target = install_rules(descriptor, fetch=fetch)
    assert len(calls) == len(bearer_hook.LANGUAGES)
    assert all(descriptor.rules_version in url for url in calls)
    assert (target / "python" / "lang" / "rule.yml").is_file()
    assert not (target / "python" / "README.md").exists()
    install_rules(descriptor, fetch=fetch)
    assert len(calls) == len(bearer_hook.LANGUAGES)


def test_rule_pack_with_a_path_escape_is_rejected(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(bearer_hook, "cache_dir", lambda name: tmp_path / name)
    with pytest.raises(ValueError):
        install_rules(_descriptor(), fetch=lambda url: _pack({"../evil.yml": b"x"}))
    assert not (tmp_path / "evil.yml").exists()
    assert not bearer_hook.rules_dir(_descriptor()).exists()


def test_pipeline_converts_the_json_report(tmp_path: Path, monkeypatch):
    """Local mode with a fake binary: the raw JSON report turns into findings and a SARIF file."""
    tool = load_tools()["bearer"]
    monkeypatch.setattr(launch, "resolve_binary", lambda name: "/usr/bin/bearer")
    monkeypatch.setattr(bearer_hook, "install_rules", lambda descriptor: tmp_path)

    async def fake_run(self, request):
        output = Path(request.args[request.args.index("--output") + 1])
        output.write_text(GOLDEN.read_text(encoding="utf-8"), encoding="utf-8")
        return RunOutcome(returncode=0)

    monkeypatch.setattr(launch.LocalRunner, "run", fake_run)
    out = tmp_path / "out"
    out.mkdir()
    (out / "bearer.json").write_text('{"critical": []}', encoding="utf-8")
    result = asyncio.run(
        run_scan(ROOT / "samples" / "vuln_flask", out, [tool], ScanOptions(excludes=[], use_docker=False))
    )
    run = result.runs[0]
    assert run.status.value == "success", run.error
    assert (out / "bearer.sarif").is_file()
    assert [finding.rule_id for finding in result.findings] == ["python_lang_avoid_pickle"]


def test_a_failed_run_does_not_reuse_an_old_report(tmp_path: Path, monkeypatch):
    tool = load_tools()["bearer"]
    monkeypatch.setattr(launch, "resolve_binary", lambda name: "/usr/bin/bearer")
    monkeypatch.setattr(bearer_hook, "install_rules", lambda descriptor: tmp_path)

    async def failed_run(self, request):
        return RunOutcome(returncode=1, stderr="Error: something broke", error="exit code 1")

    monkeypatch.setattr(launch.LocalRunner, "run", failed_run)
    out = tmp_path / "out"
    out.mkdir()
    (out / "bearer.json").write_text(GOLDEN.read_text(encoding="utf-8"), encoding="utf-8")
    result = asyncio.run(
        run_scan(ROOT / "samples" / "vuln_flask", out, [tool], ScanOptions(excludes=[], use_docker=False))
    )
    assert result.runs[0].status.value == "failed"
    assert "something broke" in (result.runs[0].error or "")
    assert result.findings == []
