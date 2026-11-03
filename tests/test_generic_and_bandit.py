"""YAML-only scanners (the generic hook) and Bandit, the first tool built on it."""
from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path

import pytest
import yaml

from grephunt.execution.request import RunOutcome
from grephunt.finding_model.correlation import correlate
from grephunt.finding_model.record import Category, Finding, Location, Severity
from grephunt.scan_pipeline.converters import bandit_json
from grephunt.scan_pipeline.options import ScanOptions
from grephunt.scan_pipeline.pipeline import run_scan
from grephunt.scan_pipeline.sarif import parse_sarif
from grephunt.scanner_catalog import launch
from grephunt.scanner_catalog.descriptor import ToolDescriptor
from grephunt.scanner_catalog.registry import load_tools
from grephunt.scanner_hooks import generic
from grephunt.scanner_hooks.generic import GenericHook, expand, project_matches

ROOT = Path(__file__).resolve().parents[1]
GOLDEN = ROOT / "tests" / "golden" / "bandit_vuln_flask.json"
CATALOG = ROOT / "grephunt" / "scanner_catalog"


def _bandit() -> ToolDescriptor:
    return load_tools()["bandit"].descriptor


def _bandit_findings(tmp_path: Path) -> list[Finding]:
    sarif = tmp_path / "bandit.sarif"
    sarif.write_text(json.dumps(bandit_json(GOLDEN.read_text(encoding="utf-8"), _bandit())), encoding="utf-8")
    hook = GenericHook(_bandit())
    return parse_sarif(sarif, tool="bandit", project_root=Path("/src"), refine=hook.refine_finding)


def _descriptor(**changes) -> dict:
    raw = {
        "name": "fake",
        "binary": "fake",
        "image": "example/fake:1.0.0",
        "version": "1.0.0",
        "output_filename": "fake.sarif",
        "args": ["{src}", "{output}"],
    }
    raw.update(changes)
    return raw


def test_every_catalog_entry_loads_and_has_a_pinned_image():
    tools = load_tools()
    assert {"bandit", "bearer", "semgrep", "trivy"} <= set(tools)
    for tool in tools.values():
        tag = tool.descriptor.image.rsplit(":", 1)[-1]
        assert tag and not tag.startswith("latest"), tool.name


def test_descriptor_rejects_inconsistent_settings():
    with pytest.raises(ValueError):
        ToolDescriptor.model_validate(_descriptor(output_format="no-such-format", raw_output_filename="x.json"))
    with pytest.raises(ValueError):
        ToolDescriptor.model_validate(_descriptor(output_format="bandit-json"))
    with pytest.raises(ValueError):
        ToolDescriptor.model_validate(_descriptor(prepare={"args": ["update"], "cache": "missing"}))


def test_placeholders_are_filled_and_unknown_ones_fail():
    caches = {"db": "/cache/db"}
    filled = expand(["--db={cache:db}", "{src}", "{output}"], {"src": "/src", "output": "/out/x.json"}, caches)
    assert filled == ["--db=/cache/db", "/src", "/out/x.json"]
    with pytest.raises(ValueError):
        expand(["{nope}"], {}, caches)
    with pytest.raises(ValueError):
        expand(["{cache:other}"], {}, caches)


def test_project_matches_by_name_glob(tmp_path: Path):
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "Dockerfile.prod").write_text("FROM x", encoding="utf-8")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "a.py").write_text("x = 1", encoding="utf-8")
    assert project_matches(tmp_path, ["dockerfile*"])
    assert not project_matches(tmp_path, ["*.py"])
    assert project_matches(tmp_path, [])


def test_bandit_descriptor_pins_the_install():
    descriptor = _bandit()
    assert descriptor.network is False
    assert descriptor.prepare is not None and descriptor.prepare.network is True
    assert descriptor.version in descriptor.container_binary
    assert descriptor.environment["PYTHONPATH"].endswith(descriptor.version)
    assert f"{{cache:grephunt-bandit}}/{descriptor.version}" in descriptor.prepare.args
    lock = (CATALOG / "locks" / "bandit.txt").read_text(encoding="utf-8")
    assert f"bandit=={descriptor.version}" in lock
    assert "--hash=sha256:" in lock


def test_bandit_arguments_keep_project_excludes_out_of_the_substring_filter():
    descriptor = _bandit()
    args = GenericHook(descriptor).build_args(
        descriptor, "/src", "/out/bandit.sarif", ScanOptions(excludes=["test"]), True
    )
    assert args[args.index("--output") + 1] == "/out/bandit.json"
    assert args[args.index("-r") + 1] == "/src"
    assert "--exit-zero" in args
    excluded = args[args.index("-x") + 1].split(",")
    assert "test" not in excluded
    assert all(item.startswith("/") and item.endswith("/") for item in excluded)


def test_bandit_golden_report(tmp_path: Path):
    findings = _bandit_findings(tmp_path)
    by_rule = {finding.rule_id: finding for finding in findings}
    assert len(findings) == 9
    shell = by_rule["B602"]
    assert shell.severity is Severity.HIGH
    assert shell.severity_original == "HIGH, confidence HIGH"
    assert shell.cwe == ["CWE-78"]
    assert shell.location.path == "app.py"
    assert shell.location.start_line == 23
    assert shell.snippet == 'return subprocess.check_output("ping -c 1 " + host, shell=True)'
    assert shell.help_uri and "b602" in shell.help_uri
    assert by_rule["B105"].category is Category.SECRET
    assert by_rule["B403"].severity is Severity.LOW


def test_three_scanners_confirm_the_pickle_call(tmp_path: Path):
    bandit = {finding.rule_id: finding for finding in _bandit_findings(tmp_path)}["B301"]
    semgrep = Finding(
        tool="semgrep",
        rule_id="insecure-pickle-loads",
        title="pickle",
        severity=Severity.HIGH,
        cwe=["CWE-502"],
        location=Location(path="app.py", start_line=28, end_line=28),
    )
    bearer = semgrep.model_copy(update={"tool": "bearer", "tools": ["bearer"], "severity": Severity.CRITICAL})
    merged = correlate([semgrep, bandit, bearer])
    assert len(merged) == 1
    assert merged[0].tools == ["semgrep", "bandit", "bearer"]
    assert merged[0].severity is Severity.CRITICAL


class _Recorder:
    def __init__(self, returncode: int = 0) -> None:
        self.requests = []
        self.returncode = returncode

    async def run(self, request):
        self.requests.append(request)
        return RunOutcome(returncode=self.returncode, stderr="" if self.returncode == 0 else "pip failed")


def test_prepare_installs_once_in_the_image(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(generic, "cache_dir", lambda name: (tmp_path / name).mkdir(exist_ok=True) or tmp_path / name)
    descriptor = _bandit()
    hook = GenericHook(descriptor)
    runner = _Recorder()
    assert asyncio.run(hook.prepare(descriptor, runner, True)) is None
    request = runner.requests[0]
    assert request.binary == "python"
    assert request.network is True
    assert request.args[request.args.index("--target") + 1] == f"/opt/bandit/{descriptor.version}"
    assert request.args[-1] == f"{generic.CATALOG_MOUNT}/locks/bandit.txt"
    binds = {container: (host, read_only) for host, container, read_only in request.binds}
    assert binds["/opt/bandit"] == (str((tmp_path / "grephunt-bandit").resolve()), False)
    assert binds[generic.CATALOG_MOUNT] == (str(generic.CATALOG_DIR), True)
    assert asyncio.run(hook.prepare(descriptor, runner, True)) is None
    assert len(runner.requests) == 1
    assert asyncio.run(hook.prepare(descriptor, _Recorder(), False)) is None


def test_failed_refresh_keeps_old_data_but_a_first_failure_stops(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(generic, "cache_dir", lambda name: (tmp_path / name).mkdir(exist_ok=True) or tmp_path / name)
    raw = _descriptor(
        cache_volumes=[{"name": "db", "path": "/db"}],
        prepare={"args": ["update", "{cache:db}"], "cache": "db", "ttl_hours": 24},
    )
    descriptor = ToolDescriptor.model_validate(raw)
    hook = GenericHook(descriptor)
    error = asyncio.run(hook.prepare(descriptor, _Recorder(returncode=1), True))
    assert error and "pip failed" in error
    assert asyncio.run(hook.prepare(descriptor, _Recorder(), True)) is None
    marker = generic._marker(descriptor)
    marker.write_text(json.dumps({"at": time.time() - 25 * 3600}), encoding="utf-8")
    assert not generic.prepared_recently(descriptor)
    assert asyncio.run(hook.prepare(descriptor, _Recorder(returncode=1), True)) is None


def _sarif_text() -> str:
    return json.dumps(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "fake", "rules": [{"id": "R1", "properties": {"tags": ["CWE-79"]}}]}},
                    "results": [
                        {
                            "ruleId": "R1",
                            "level": "error",
                            "message": {"text": "bad"},
                            "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app.py"}, "region": {"startLine": 3}}}],
                        }
                    ],
                }
            ],
        }
    )


def test_stdout_report_is_saved_even_when_the_tool_exits_non_zero(tmp_path: Path, monkeypatch):
    catalog = tmp_path / "catalog"
    catalog.mkdir()
    (catalog / "fake.yaml").write_text(yaml.safe_dump(_descriptor(output_source="stdout", args=["{src}"])), encoding="utf-8")
    tool = load_tools(catalog)["fake"]
    monkeypatch.setattr(launch, "resolve_binary", lambda name: "/usr/bin/fake")

    async def fake_run(self, request):
        return RunOutcome(returncode=1, stdout=_sarif_text(), error="exit code 1")

    monkeypatch.setattr(launch.LocalRunner, "run", fake_run)
    result = asyncio.run(run_scan(ROOT / "samples" / "vuln_flask", tmp_path / "out", [tool], ScanOptions(excludes=[], use_docker=False)))
    assert result.runs[0].status.value == "success", result.runs[0].error
    assert [finding.rule_id for finding in result.findings] == ["R1"]


def test_bandit_pipeline_in_local_mode(tmp_path: Path, monkeypatch):
    tool = load_tools()["bandit"]
    monkeypatch.setattr(launch, "resolve_binary", lambda name: "/usr/bin/bandit")

    async def fake_run(self, request):
        output = Path(request.args[request.args.index("--output") + 1])
        report = GOLDEN.read_text(encoding="utf-8").replace("/src/", str(ROOT / "samples" / "vuln_flask").replace("\\", "/") + "/")
        output.write_text(report, encoding="utf-8")
        return RunOutcome(returncode=0)

    monkeypatch.setattr(launch.LocalRunner, "run", fake_run)
    result = asyncio.run(run_scan(ROOT / "samples" / "vuln_flask", tmp_path / "out", [tool], ScanOptions(excludes=[], use_docker=False)))
    assert result.runs[0].status.value == "success", result.runs[0].error
    assert len(result.findings) == 9
    assert {finding.location.path for finding in result.findings} == {"app.py"}
    assert load_tools()["bandit"].is_applicable(ROOT / "samples" / "vuln_flask")
    assert not load_tools()["bandit"].is_applicable(ROOT / "samples" / "no_manifest")
