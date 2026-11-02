"""Finding contract: two identity keys, correlation, and the example JSON."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

from grephunt.finding_model.correlation import correlate
from grephunt.finding_model.record import (
    Category,
    Finding,
    Location,
    Module,
    Severity,
    TaskRun,
    TaskStatus,
)
from grephunt.scan_pipeline.options import ScanOptions
from grephunt.scan_pipeline.pipeline import run_scan

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "grephunt" / "finding_model" / "example.json"


def _code(path: str, line: int, cwe: str, severity: Severity = Severity.HIGH, tool: str = "semgrep") -> Finding:
    return Finding(
        module=Module.SAST,
        category=Category.CODE,
        tool=tool,
        tool_version="1.180.0",
        rule_id="rule",
        title="title",
        message="message",
        severity=severity,
        severity_original="ERROR",
        cwe=[cwe],
        location=Location(path=path, start_line=line, end_line=line),
        evidence="SARIF region",
    )


def test_example_file_matches_constructed_finding():
    raw = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    finding = Finding(
        module=Module.SAST,
        category=Category.CODE,
        tool="semgrep",
        tool_version="1.180.0",
        rule_id="python.lang.security.audit.eval-detected",
        title="Use of eval",
        message="eval() on user input can execute arbitrary code.",
        severity=Severity.HIGH,
        severity_original="ERROR",
        cwe=["CWE-95"],
        location=Location(path="app.py", start_line=33, end_line=33),
        snippet='return str(eval(request.args.get("expr")))',
        evidence="SARIF region",
        raw_ref="semgrep.sarif#/runs/0/results/0",
    )
    dumped = finding.model_dump(mode="json")
    assert dumped["correlation_key"] == "code:app.py:33:CWE-95"
    assert dumped["fingerprint"] == "code:app.py:CWE-95"
    assert dumped["location"]["kind"] == "file"
    assert dumped == raw


def test_line_shift_changes_correlation_key_only():
    first = _code("app.py", 10, "CWE-89")
    shifted = _code("app.py", 40, "CWE-89")
    assert first.correlation_key != shifted.correlation_key
    assert first.fingerprint == shifted.fingerprint == "code:app.py:CWE-89"


def test_dependency_identity_ignores_line():
    def dep(line: int, cve: list[str]) -> Finding:
        return Finding(
            module=Module.SAST,
            category=Category.DEPENDENCY,
            tool="trivy",
            tool_version="0.76.0",
            rule_id=cve[0],
            title="vuln",
            severity=Severity.HIGH,
            cve=cve,
            package="Flask",
            installed_version="0.12.2",
            location=Location(path="requirements.txt", start_line=line),
        )

    left = dep(1, ["CVE-2018-1000656"])
    right = dep(9, ["CVE-2018-1000656"])
    assert left.correlation_key == right.correlation_key == right.fingerprint


def test_correlate_keeps_higher_severity_and_unions_cve():
    low = _code("app.py", 12, "CWE-89", severity=Severity.MEDIUM, tool="semgrep")
    high = low.model_copy(deep=True)
    high.tool = "bandit"
    high.tools = ["bandit"]
    high.severity = Severity.CRITICAL
    high.cve = ["CVE-2024-0001"]
    merged = correlate([low, high])
    assert len(merged) == 1
    assert merged[0].severity is Severity.CRITICAL
    assert merged[0].tools == ["semgrep", "bandit"]
    assert merged[0].cwe == ["CWE-89"]
    assert merged[0].cve == ["CVE-2024-0001"]


class _Ok:
    name = "semgrep"

    async def execute(self, project, out_dir, options, on_event):
        return TaskRun(tool=self.name, status=TaskStatus.SUCCESS, findings=[_code("app.py", 1, "CWE-78")])


class _Boom:
    name = "trivy"

    async def execute(self, project, out_dir, options, on_event):
        raise RuntimeError("scanner crashed")


def test_partial_task_failure_keeps_other_findings(tmp_path: Path):
    result = asyncio.run(run_scan(tmp_path, tmp_path / "out", [_Ok(), _Boom()], ScanOptions(excludes=[])))
    statuses = {run.tool: run.status for run in result.runs}
    assert statuses["semgrep"] is TaskStatus.SUCCESS
    assert statuses["trivy"] is TaskStatus.FAILED
    assert len(result.findings) == 1
    assert result.findings[0].fingerprint == "code:app.py:CWE-78"
