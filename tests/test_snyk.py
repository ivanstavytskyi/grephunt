"""Snyk: the login through the Snyk CLI, and Snyk Code / Snyk Open Source scans.

_CLI_OUTPUT is what Snyk CLI 1.1308.3 printed for `snyk auth --auth-type=oauth`
on a machine with no browser. snyk_code_sample.sarif.json is the Snyk CLI's
own Snyk Code SARIF fixture (test/fixtures/sast/sample-sarif.json).
"""
from __future__ import annotations

import asyncio
import hashlib
import io
import json
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from grephunt.execution.request import RunOutcome
from grephunt.finding_model.record import Category, Severity
from grephunt.integrations import snyk
from grephunt.scan_pipeline.options import ScanOptions
from grephunt.scan_pipeline.pipeline import run_scan
from grephunt.scan_pipeline.sarif import parse_sarif
from grephunt.scanner_catalog import launch
from grephunt.scanner_catalog.registry import load_tools
from grephunt.scanner_hooks import snyk as snyk_hook
from grephunt.web_console import app as console

ROOT = Path(__file__).resolve().parents[1]
GOLDEN = ROOT / "tests" / "golden"
AUTH_URL = (
    "https://app.snyk.io/oauth2/authorize?access_type=offline&client_id=b56d4c2e-b9e1-4d27-8773-ad47eafb0956"
    "&code_challenge=pH4KH9TfXHc8BbVA1lJeDDPQRy35o432ndkO1jVGtJY&code_challenge_method=S256&cross_region_routing=true"
    "&redirect_uri=http%3A%2F%2F127.0.0.1%3A8080%2Fauthorization-code%2Fcallback&response_type=code"
    "&scope=offline_access&state=StEQ~SovZNng-pY&version=2021-08-11~experimental"
)
_CLI_OUTPUT = f"""
Now redirecting you to our auth page, go ahead and log in,
and once the auth is complete, return to this prompt and you'll
be ready to start using snyk.

If you can't wait use this url:
{AUTH_URL}

"""
TOKEN = '{"access_token":"test-access","token_type":"bearer","refresh_token":"test-refresh","expiry":"2099-01-01T00:00:00Z"}'


@pytest.fixture
def snyk_home(tmp_path: Path, monkeypatch):
    def fake_cache_dir(name: str) -> Path:
        path = tmp_path / name
        path.mkdir(parents=True, exist_ok=True)
        return path

    monkeypatch.setattr(snyk, "cache_dir", fake_cache_dir)
    return tmp_path


def _connect(home: Path) -> None:
    config = home / snyk.HOME_CACHE / ".config" / "configstore" / "snyk.json"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(json.dumps({snyk.TOKEN_KEY: TOKEN, "snyk_api": "https://api.eu.snyk.io"}), encoding="utf-8")


class _FakeProcess:
    def __init__(self, on_exit, code: int = 0, output: str = _CLI_OUTPUT) -> None:
        self.stdout = io.StringIO(output)
        self._on_exit = on_exit
        self._code = code

    def wait(self) -> int:
        self._on_exit()
        return self._code

    def poll(self):
        return self._code

    def kill(self) -> None:
        pass


def _wait_for(login: snyk.SnykLogin, states: set[str]) -> dict:
    for _ in range(200):
        status = login.status()
        if status["login"] in states:
            return status
        time.sleep(0.01)
    raise AssertionError(login.status())


def test_platform_keys_match_the_release_assets():
    assets = snyk.cli_release()["assets"]
    assert snyk.platform_key("win32", "AMD64") == "windows-amd64"
    assert snyk.platform_key("darwin", "arm64") == "darwin-arm64"
    assert snyk.platform_key("linux", "aarch64") == "linux-arm64"
    assert snyk.platform_key("linux", "x86_64") == "linux-amd64"
    for key in ("windows-amd64", "darwin-arm64", "linux-arm64", "linux-amd64", "darwin-amd64"):
        assert len(assets[key]["sha256"]) == 64


def test_cli_download_is_checked_against_the_pinned_hash(snyk_home, monkeypatch):
    payload = b"fake snyk binary"
    release = {"version": "9.9.9", "url": "https://example.test/{version}/{file}",
               "assets": {"linux-amd64": {"file": "snyk-linux", "sha256": hashlib.sha256(payload).hexdigest()}}}
    monkeypatch.setattr(snyk, "cli_release", lambda: release)
    urls = []

    def fetch(url: str, target: Path) -> None:
        urls.append(url)
        target.write_bytes(payload)

    path = snyk.ensure_cli("linux-amd64", fetch=fetch)
    assert path.read_bytes() == payload
    assert urls == ["https://example.test/9.9.9/snyk-linux"]
    snyk.ensure_cli("linux-amd64", fetch=fetch)
    assert len(urls) == 1

    release["assets"]["linux-amd64"]["sha256"] = "0" * 64
    path.unlink()
    with pytest.raises(snyk.SnykError, match="does not match"):
        snyk.ensure_cli("linux-amd64", fetch=fetch)
    assert not path.exists()
    assert not path.with_name(path.name + ".part").exists()


def test_only_snyk_authorization_pages_are_accepted():
    assert snyk.is_snyk_auth_url(AUTH_URL)
    assert snyk.is_snyk_auth_url("https://app.eu.snyk.io/oauth2/authorize?x=1")
    assert not snyk.is_snyk_auth_url("http://app.snyk.io/oauth2/authorize")
    assert not snyk.is_snyk_auth_url("https://snyk.io.evil.test/oauth2/authorize")
    assert not snyk.is_snyk_auth_url("https://app.snyk.io/login")


def test_login_publishes_the_snyk_page_then_reports_connected(snyk_home):
    login = snyk.SnykLogin()
    started = []

    def popen(args, env, **kwargs):
        started.append((args, env))
        return _FakeProcess(on_exit=lambda: _connect(snyk_home))

    assert login.start(popen=popen, ensure=lambda key: snyk_home / "cli" / "snyk")["login"] in {"preparing", "waiting", "connected"}
    status = _wait_for(login, {"connected", "failed"})
    assert status["connected"] is True, status
    args, env = started[0]
    assert args[1:] == ["auth", "--auth-type=oauth"]
    assert env["PATH"] == str(snyk_home / "cli")
    assert env["HOME"] == env["USERPROFILE"] == str(snyk_home / snyk.HOME_CACHE)


def test_login_keeps_the_url_while_waiting_and_reports_a_timeout(snyk_home):
    login = snyk.SnykLogin()
    release = {}

    def popen(args, env, **kwargs):
        process = _FakeProcess(on_exit=lambda: None, code=2, output=_CLI_OUTPUT + "authentication failed: timed out\n")
        release["process"] = process
        return process

    login.start(popen=popen, ensure=lambda key: snyk_home / "snyk")
    status = _wait_for(login, {"failed"})
    assert status["url"] == AUTH_URL
    assert status["connected"] is False
    assert "not completed in time" in status["error"]


def test_cli_environment_hides_host_tokens_and_the_browser(snyk_home, monkeypatch):
    monkeypatch.setenv("SNYK_TOKEN", "host-token")
    env = snyk.cli_environment(snyk_home / "bin" / "snyk")
    assert "SNYK_TOKEN" not in env
    assert env["PATH"] == str(snyk_home / "bin")
    assert env["SNYK_DISABLE_ANALYTICS"] == "1"


def test_scan_environment_carries_the_token_and_region(snyk_home):
    with pytest.raises(snyk.SnykError):
        snyk.scan_environment()
    _connect(snyk_home)
    env = snyk.scan_environment()
    assert env[snyk.TOKEN_KEY] == TOKEN
    assert env["SNYK_API"] == "https://api.eu.snyk.io"


def test_scanners_need_a_connection_and_are_never_default(snyk_home, monkeypatch):
    from grephunt.cli import parse_scanners

    tools = load_tools()
    for name in ("snyk-code", "snyk-open-source"):
        assert tools[name].descriptor.cloud is True
        assert tools[name].descriptor.default_enabled is False
        assert tools[name].descriptor.network is True
    assert not {"snyk-code", "snyk-open-source"} & set(parse_scanners(None, tools))
    hook = tools["snyk-code"].hook
    message = asyncio.run(hook.prepare(tools["snyk-code"].descriptor, None, True))
    assert message and "not connected" in message

    _connect(snyk_home)
    calls = []
    monkeypatch.setattr(snyk, "ensure_cli", lambda key: calls.append(key) or snyk_home / key)
    monkeypatch.setattr(snyk, "refresh_token", lambda cli: calls.append(("refresh", cli)))
    assert asyncio.run(hook.prepare(tools["snyk-code"].descriptor, None, True)) is None
    assert calls[0] == snyk.platform_key()
    assert calls[1] == ("refresh", snyk_home / snyk.platform_key())
    assert calls[2] == snyk.container_platform_key()

    def expired(cli):
        raise snyk.SnykError("the Snyk login is no longer valid. Connect Snyk again.")

    monkeypatch.setattr(snyk, "refresh_token", expired)
    assert "no longer valid" in asyncio.run(hook.prepare(tools["snyk-code"].descriptor, None, True))
    assert hook.extra_mounts(ScanOptions(), True) == [(snyk.cli_path(snyk.container_platform_key()), snyk_hook.CLI_MOUNT)]
    assert hook.extra_environment(ScanOptions(), True)[snyk.TOKEN_KEY] == TOKEN


def test_snyk_code_sarif_reads_cwe_from_properties():
    tool = load_tools()["snyk-code"]
    findings = parse_sarif(GOLDEN / "snyk_code_sample.sarif.json", tool="snyk-code", refine=tool.hook.refine_finding)
    by_rule = {finding.rule_id: finding for finding in findings}
    assert by_rule["javascript/HttpToHttps"].cwe == ["CWE-319"]
    assert by_rule["javascript/HttpToHttps"].category is Category.CODE
    assert by_rule["javascript/Sqli"].severity is Severity.HIGH


def test_snyk_open_source_rule_text_gives_package_and_cve(tmp_path: Path):
    """The rule shape written by the Snyk CLI's open-source SARIF formatter."""
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Snyk Open Source",
                        "semanticVersion": "1.1308.3",
                        "rules": [
                            {
                                "id": "SNYK-PYTHON-FLASK-42185",
                                "shortDescription": {"text": "High severity - Improper Input Validation vulnerability in flask"},
                                "fullDescription": {"text": "(CVE-2018-1000656) flask@0.12.2"},
                                "properties": {"tags": ["security", "CWE-20", "pip"], "security-severity": "7.5"},
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "SNYK-PYTHON-FLASK-42185",
                        "level": "error",
                        "message": {"text": "This file introduces a vulnerable flask package with a high severity vulnerability."},
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "requirements.txt"}, "region": {"startLine": 1}}}],
                    }
                ],
            }
        ],
    }
    path = tmp_path / "snyk-open-source.sarif"
    path.write_text(json.dumps(sarif), encoding="utf-8")
    tool = load_tools()["snyk-open-source"]
    finding = parse_sarif(path, tool="snyk-open-source", refine=tool.hook.refine_finding)[0]
    assert finding.category is Category.DEPENDENCY
    assert (finding.package, finding.installed_version, finding.cve) == ("flask", "0.12.2", ["CVE-2018-1000656"])
    assert finding.severity is Severity.HIGH
    assert finding.cwe == ["CWE-20"]


def test_exit_code_3_means_nothing_to_scan(tmp_path: Path, snyk_home, monkeypatch):
    _connect(snyk_home)
    tool = load_tools()["snyk-open-source"]
    monkeypatch.setattr(launch, "resolve_binary", lambda name: "/usr/bin/snyk")
    monkeypatch.setattr(snyk, "ensure_cli", lambda key: snyk_home / key)
    monkeypatch.setattr(snyk, "refresh_token", lambda cli: None)

    async def no_projects(self, request):
        assert request.environment["HOME"] == str(snyk_home / snyk.HOME_CACHE)
        return RunOutcome(returncode=3, stderr="Could not detect supported target files")

    monkeypatch.setattr(launch.LocalRunner, "run", no_projects)
    result = asyncio.run(run_scan(ROOT / "samples" / "no_manifest", tmp_path / "out", [tool], ScanOptions(excludes=[], use_docker=False)))
    assert result.runs[0].status.value == "skipped"


def test_console_endpoints_and_cross_site_requests(snyk_home, monkeypatch):
    client = TestClient(console.app)
    assert client.get("/api/integrations/snyk").json()["connected"] is False
    started = []
    monkeypatch.setattr(snyk.LOGIN, "start", lambda: started.append(1) or snyk.LOGIN.status())
    blocked = client.post("/api/integrations/snyk/login", headers={"Origin": "https://evil.example"})
    assert blocked.status_code == 403
    assert started == []
    allowed = client.post("/api/integrations/snyk/login", headers={"Origin": "http://testserver"})
    assert allowed.status_code == 200
    assert started == [1]
    _connect(snyk_home)
    assert client.get("/api/integrations/snyk").json()["connected"] is True
    assert client.post("/api/integrations/snyk/logout").json()["connected"] is False
