"""Snyk account connection through the official Snyk CLI.

Login is the CLI's own OAuth flow, run on this machine:

1. `snyk auth --auth-type=oauth` starts with an isolated home directory
   (data/caches/grephunt-snyk-home) and a PATH without a browser launcher,
   so the CLI cannot open a browser itself.
2. It prints the app.snyk.io authorization URL and waits on
   127.0.0.1:8080 (or the next free callback port) for up to two minutes.
3. The console opens that URL in a popup. The person signs in on Snyk's
   own page; GrepHunt never sees the password.
4. Snyk redirects the browser to the CLI's callback, and the CLI stores the
   OAuth token in the isolated home.

The browser must run on the same machine as GrepHunt, because the callback
goes to 127.0.0.1. Scans get a freshly refreshed token through the
INTERNAL_OAUTH_TOKEN_STORAGE environment variable, read from that home.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.request
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

import yaml

from grephunt.execution.cache import cache_dir

_CONFIG = Path(__file__).resolve().parents[1] / "scanner_catalog" / "config" / "snyk-cli.yaml"
HOME_CACHE = "grephunt-snyk-home"
CLI_CACHE = "grephunt-snyk-cli"
TOKEN_KEY = "INTERNAL_OAUTH_TOKEN_STORAGE"
_URL = re.compile(r"https://\S+/oauth2/authorize\?\S+")
_LOGIN_TIMEOUT_SEC = 150


class SnykError(RuntimeError):
    pass


def cli_release() -> dict:
    return yaml.safe_load(_CONFIG.read_text(encoding="utf-8"))


def platform_key(system: str | None = None, machine: str | None = None) -> str:
    system = (system or sys.platform).lower()
    machine = (machine or platform.machine()).lower()
    arch = "arm64" if machine in {"arm64", "aarch64"} else "amd64"
    if system.startswith("win"):
        return "windows-amd64"
    if system == "darwin":
        return f"darwin-{arch}"
    return f"linux-{arch}"


def container_platform_key() -> str:
    """Docker Desktop runs Linux containers with the host's CPU architecture."""
    return f"linux-{platform_key().rsplit('-', 1)[-1]}"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def cli_path(key: str) -> Path:
    release = cli_release()
    asset = release["assets"][key]
    return cache_dir(CLI_CACHE) / str(release["version"]) / asset["file"]


_CLI_LOCKS: dict[str, threading.Lock] = {}
_CLI_LOCKS_GUARD = threading.Lock()


def _cli_lock(key: str) -> threading.Lock:
    with _CLI_LOCKS_GUARD:
        return _CLI_LOCKS.setdefault(key, threading.Lock())


def ensure_cli(key: str, fetch=None) -> Path:
    """Download the pinned Snyk CLI for a platform once and check its SHA-256.

    Snyk Code and Snyk Open Source prepare at the same time and need the same
    binary. A per-platform lock makes the second one wait for the first
    download instead of opening the same file (WinError 32 on Windows).
    """
    release = cli_release()
    asset = release["assets"].get(key)
    if asset is None:
        raise SnykError(f"no Snyk CLI build for {key}")
    with _cli_lock(key):
        return _ensure_cli_locked(key, release, asset, fetch)


def _ensure_cli_locked(key: str, release: dict, asset: dict, fetch) -> Path:
    target = cli_path(key)
    if target.is_file() and _sha256(target) == asset["sha256"]:
        return target
    target.parent.mkdir(parents=True, exist_ok=True)
    # A unique name per download, so another GrepHunt process cannot collide with it either.
    partial = target.with_name(f"{target.name}.{os.getpid()}-{uuid.uuid4().hex[:8]}.part")
    url = release["url"].format(version=release["version"], file=asset["file"])
    try:
        if fetch is not None:
            fetch(url, partial)
        else:
            request = urllib.request.Request(url, headers={"User-Agent": "GrepHunt"})
            with urllib.request.urlopen(request, timeout=600) as response, partial.open("wb") as sink:
                shutil.copyfileobj(response, sink, 1024 * 1024)
        actual = _sha256(partial)
        if actual != asset["sha256"]:
            raise SnykError(f"Snyk CLI download does not match the pinned SHA-256 ({actual})")
        try:
            os.replace(partial, target)
        except PermissionError:
            # Windows: another process already put the same file in place and has it open.
            if not (target.is_file() and _sha256(target) == asset["sha256"]):
                raise
    finally:
        partial.unlink(missing_ok=True)
    if os.name != "nt":
        target.chmod(0o755)
    return target


def home_dir() -> Path:
    return cache_dir(HOME_CACHE)


def _config_file() -> Path:
    return home_dir() / ".config" / "configstore" / "snyk.json"


def stored_config() -> dict:
    path = _config_file()
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8") or "{}")
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def is_connected() -> bool:
    return bool(stored_config().get(TOKEN_KEY))


def cli_environment(cli: Path) -> dict[str, str]:
    """Environment for the CLI on this machine: isolated home, and a PATH without a browser launcher."""
    env = {key: value for key, value in os.environ.items() if not key.upper().startswith("SNYK_")}
    home = str(home_dir())
    env.update(
        {
            "HOME": home,
            "USERPROFILE": home,
            "PATH": str(cli.parent),
            "SNYK_DISABLE_ANALYTICS": "1",
            "BROWSER": "none",
        }
    )
    env.pop("XDG_CONFIG_HOME", None)
    return env


def scan_environment() -> dict[str, str]:
    """What a scan container needs to act as the connected account."""
    config = stored_config()
    token = config.get(TOKEN_KEY)
    if not token:
        raise SnykError("Snyk is not connected. Use Connect Snyk in the console.")
    env = {TOKEN_KEY: token if isinstance(token, str) else json.dumps(token)}
    api = config.get("snyk_api") or config.get("endpoint")
    if isinstance(api, str) and api:
        env["SNYK_API"] = api
    org = config.get("org")
    if isinstance(org, str) and org:
        env["SNYK_CFG_ORG"] = org
    env["SNYK_DISABLE_ANALYTICS"] = "1"
    return env


def refresh_token(cli: Path, runner=subprocess.run) -> None:
    """Let the CLI on this machine refresh and store the OAuth token before a scan uses it."""
    result = runner(
        [str(cli), "whoami", "--experimental"],
        env=cli_environment(cli),
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if result.returncode != 0:
        tail = (result.stderr or result.stdout or "").strip().splitlines()[-1:] or ["no output"]
        raise SnykError(f"the Snyk login is no longer valid. Connect Snyk again. ({tail[0][:300]})")


def disconnect() -> None:
    path = _config_file()
    if path.is_file():
        path.unlink()


def is_snyk_auth_url(url: str) -> bool:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    return parsed.scheme == "https" and (host == "snyk.io" or host.endswith(".snyk.io")) and parsed.path.endswith("/oauth2/authorize")


@dataclass
class LoginState:
    state: str = "idle"
    """idle, preparing, waiting, connected, failed."""
    url: str | None = None
    error: str | None = None
    started_at: float = 0.0
    output: list[str] = field(default_factory=list)


class SnykLogin:
    """One login at a time. The CLI process and its callback port belong to it."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._state = LoginState()
        self._process: subprocess.Popen | None = None

    def status(self) -> dict:
        with self._lock:
            return self._public()

    def start(self, popen=subprocess.Popen, ensure=ensure_cli) -> dict:
        with self._lock:
            if self._state.state in {"preparing", "waiting"} and time.monotonic() - self._state.started_at < _LOGIN_TIMEOUT_SEC:
                return self._public()
            self._state = LoginState(state="preparing", started_at=time.monotonic())
        thread = threading.Thread(target=self._run, args=(popen, ensure), name="grephunt-snyk-login", daemon=True)
        thread.start()
        return self.status()

    def cancel(self) -> None:
        with self._lock:
            process = self._process
            self._state = LoginState()
        if process is not None and process.poll() is None:
            process.kill()

    def _public(self) -> dict:
        state = self._state
        return {"connected": is_connected(), "login": state.state, "url": state.url, "error": state.error,
                "cli_version": str(cli_release()["version"])}

    def _fail(self, message: str) -> None:
        with self._lock:
            self._state.state = "failed"
            self._state.error = message

    def _run(self, popen, ensure) -> None:
        try:
            cli = ensure(platform_key())
        except Exception as exc:  # download or hash failure
            self._fail(f"could not get the Snyk CLI: {exc}")
            return
        try:
            process = popen(
                [str(cli), "auth", "--auth-type=oauth"],
                env=cli_environment(cli),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
        except OSError as exc:
            self._fail(f"could not start the Snyk CLI: {exc}")
            return
        with self._lock:
            self._process = process
            self._state.state = "waiting"
        assert process.stdout is not None
        for line in process.stdout:
            with self._lock:
                self._state.output.append(line.rstrip())
                del self._state.output[:-40]
                match = _URL.search(line)
                if match and self._state.url is None:
                    url = match.group(0)
                    if is_snyk_auth_url(url):
                        self._state.url = url
                    else:
                        self._state.error = f"the Snyk CLI printed an unexpected login address: {url[:120]}"
        code = process.wait()
        with self._lock:
            self._process = None
            if code == 0 and is_connected():
                self._state.state = "connected"
                self._state.error = None
            elif self._state.state == "waiting":
                tail = " ".join(line for line in self._state.output[-3:] if line.strip())
                self._state.state = "failed"
                self._state.error = self._state.error or (
                    "login was not completed in time" if "timed out" in tail.lower() or code in {2, 124}
                    else f"Snyk CLI exited with {code}: {tail[:300]}"
                )


LOGIN = SnykLogin()
