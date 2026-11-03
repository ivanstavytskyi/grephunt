"""Gitleaks, Betterleaks, TruffleHog, Kingfisher, Secretlint, and secret masking.

The golden reports come from real runs on secret_fixture.secret_project().
The fake values in them were replaced by placeholders like <fake-github>
before they were saved; _restore() puts the fake values back, so each test
sees what the tool really wrote and checks that it does not reach a finding.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from grephunt.finding_model.correlation import correlate
from grephunt.finding_model.record import Category, Finding, Severity
from grephunt.finding_model.redaction import mask_secrets
from grephunt.scan_pipeline.converters import secretlint_json, trufflehog_jsonl
from grephunt.scan_pipeline.options import ScanOptions
from grephunt.scan_pipeline.sarif import parse_sarif
from grephunt.scanner_catalog.registry import load_tools
from grephunt.scanner_hooks.generic import CATALOG_DIR, CATALOG_MOUNT

from secret_fixture import fake_tokens

ROOT = Path(__file__).resolve().parents[1]
GOLDEN = ROOT / "tests" / "golden" / "secrets"
PROJECT = Path("/tmp/sp")
SECRET_TOOLS = ("gitleaks", "betterleaks", "trufflehog", "kingfisher", "secretlint")


def _restore(name: str) -> str:
    text = (GOLDEN / name).read_text(encoding="utf-8")
    for key, value in fake_tokens().items():
        text = text.replace(f"<fake-{key}>", value)
    return text


def _findings(tool_name: str, tmp_path: Path) -> list[Finding]:
    tool = load_tools()[tool_name]
    sarif = tmp_path / f"{tool_name}.sarif"
    if tool_name == "trufflehog":
        sarif.write_text(json.dumps(trufflehog_jsonl(_restore("trufflehog.jsonl"), tool.descriptor)), encoding="utf-8")
    elif tool_name == "secretlint":
        sarif.write_text(json.dumps(secretlint_json(_restore("secretlint.json"), tool.descriptor)), encoding="utf-8")
    else:
        sarif.write_text(_restore(f"{tool_name}.sarif"), encoding="utf-8")
    return parse_sarif(
        sarif,
        tool=tool_name,
        project_root=PROJECT,
        fallback_version=tool.descriptor.version,
        refine=tool.hook.refine_finding,
        trust_reported_version=tool.descriptor.trust_reported_version,
    )


def _no_secret_values(findings: list[Finding]) -> None:
    values = list(fake_tokens().values())
    for finding in findings:
        text = json.dumps(finding.model_dump(mode="json"))
        leaked = [value for value in values if value in text]
        assert not leaked, (finding.tool, finding.rule_id, leaked)


@pytest.mark.parametrize("tool_name", SECRET_TOOLS)
def test_every_secret_scanner_reports_without_repeating_the_secret(tool_name: str, tmp_path: Path):
    findings = _findings(tool_name, tmp_path)
    assert findings, tool_name
    assert all(finding.category is Category.SECRET for finding in findings), tool_name
    assert {finding.location.path for finding in findings} <= {"config.py", "deploy.env"}
    assert any(finding.location.path == "config.py" and finding.location.start_line == 2 for finding in findings)
    _no_secret_values(findings)


def test_reported_versions_are_the_pinned_ones(tmp_path: Path):
    assert {finding.tool_version for finding in _findings("gitleaks", tmp_path)} == {"8.30.1"}
    assert {finding.tool_version for finding in _findings("betterleaks", tmp_path)} == {"1.9.0"}


def test_kingfisher_snippet_is_masked(tmp_path: Path):
    github = [finding for finding in _findings("kingfisher", tmp_path) if finding.location.start_line == 2][0]
    assert github.snippet is not None
    assert github.snippet.startswith("ghp_")
    assert "*" in github.snippet


def test_trufflehog_marks_verification_and_never_copies_raw(tmp_path: Path):
    tool = load_tools()["trufflehog"]
    sarif = json.dumps(trufflehog_jsonl(_restore("trufflehog.jsonl"), tool.descriptor))
    assert not any(value in sarif for value in fake_tokens().values())
    findings = _findings("trufflehog", tmp_path)
    assert {finding.severity_original for finding in findings} == {"unverified"}
    assert all(finding.severity is Severity.HIGH for finding in findings)


def test_secretlint_never_copies_the_file_content(tmp_path: Path):
    tool = load_tools()["secretlint"]
    sarif = json.dumps(secretlint_json(_restore("secretlint.json"), tool.descriptor))
    assert "sourceContent" not in sarif
    assert not any(value in sarif for value in fake_tokens().values())


def test_all_scanners_agree_on_the_github_token(tmp_path: Path):
    findings = [finding for name in SECRET_TOOLS for finding in _findings(name, tmp_path)]
    merged = correlate(findings)
    github = [finding for finding in merged if finding.location.path == "config.py" and finding.location.start_line == 2]
    assert len(github) == 1
    assert set(github[0].tools) == set(SECRET_TOOLS)


def test_secret_findings_from_any_tool_are_masked():
    token = fake_tokens()["github"]
    assert token not in mask_secrets(f'GITHUB_TOKEN = "{token}"')
    assert mask_secrets("found slack token: ******") == "found slack token: ******"
    assert mask_secrets("generic-api-key has detected secret for file deploy.env.") == (
        "generic-api-key has detected secret for file deploy.env."
    )


def test_a_code_scanner_secret_is_masked_too(tmp_path: Path):
    """Semgrep and Bandit also report secrets. Masking happens in the SARIF parser, for every tool."""
    token = fake_tokens()["github"]
    sarif = tmp_path / "semgrep.sarif"
    sarif.write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"name": "semgrep", "rules": [{"id": "hardcoded-secret", "properties": {"tags": ["CWE-798: Hard-coded"]}}]}},
                        "results": [
                            {
                                "ruleId": "hardcoded-secret",
                                "message": {"text": f"A secret is hard-coded: {token}"},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "config.py"},
                                            "region": {"startLine": 2, "snippet": {"text": f'GITHUB_TOKEN = "{token}"'}},
                                        }
                                    }
                                ],
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    finding = parse_sarif(sarif, tool="semgrep")[0]
    assert finding.category is Category.SECRET
    _no_secret_values([finding])
    assert finding.snippet.startswith('GITHUB_TOKEN = "ghp_')


def test_arguments_do_not_verify_keys_or_print_them():
    tools = load_tools()
    options = ScanOptions()
    for name, flag in (("gitleaks", "--redact"), ("betterleaks", "--redact"), ("trufflehog", "--no-verification"), ("kingfisher", "--no-validate")):
        args = tools[name].hook.build_args(tools[name].descriptor, "/src", f"/out/{name}.sarif", options, True)
        assert flag in args, name
        assert tools[name].descriptor.network is False, name
    secretlint = tools["secretlint"]
    args = secretlint.hook.build_args(secretlint.descriptor, "/src", "/out/secretlint.sarif", options, True)
    assert args[0] == "/src/**/*"
    assert args[args.index("--output") + 1] == "/out/secretlint.json"
    assert args[args.index("--secretlintignore") + 1] == f"{CATALOG_MOUNT}/config/secretlintignore"
    assert secretlint.hook.extra_mounts(options, True) == [(CATALOG_DIR, CATALOG_MOUNT)]
    trufflehog = tools["trufflehog"]
    image = trufflehog.hook.build_args(
        trufflehog.descriptor, "/image/image.tar", "/out/trufflehog.sarif", ScanOptions(target_kind="image"), True
    )
    assert image[:3] == ["docker", "--image", "file:///image/image.tar"]
