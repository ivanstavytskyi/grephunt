"""Download a public GitHub repository as a zip archive."""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from pathlib import Path

MAX_UPLOAD = 500_000_000
MAX_UPLOAD_LABEL = f"{MAX_UPLOAD // 1_000_000} MB"

_REPO = re.compile(
    r"^https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?"
    r"(?:/tree/([A-Za-z0-9_./-]+))?/?$"
)
_HEADERS = {"User-Agent": "GrepHunt", "Accept": "application/vnd.github+json"}


def parse_github_url(raw: str) -> tuple[str, str, str | None]:
    url = raw.strip()
    if "@" in url or not url.startswith("https://github.com/"):
        raise ValueError("use a public link like https://github.com/owner/repo")
    match = _REPO.match(url)
    if not match:
        raise ValueError("use a public link like https://github.com/owner/repo")
    return match.group(1), match.group(2), match.group(3)


def download_github_zip(raw: str, destination: Path, max_bytes: int) -> tuple[str, str]:
    owner, repo, branch = parse_github_url(raw)
    branch_name = branch or _default_branch(owner, repo)
    archive_url = f"https://codeload.github.com/{owner}/{repo}/zip/refs/heads/{branch_name}"
    request = urllib.request.Request(archive_url, headers={"User-Agent": "GrepHunt"})
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        with urllib.request.urlopen(request, timeout=60) as response, destination.open("wb") as handle:
            total = 0
            while chunk := response.read(1024 * 1024):
                total += len(chunk)
                if total > max_bytes:
                    raise ValueError(f"repository archive is larger than {max_bytes // 1_000_000} MB")
                handle.write(chunk)
    except urllib.error.HTTPError as exc:
        raise ValueError("repository was not found, or it is private") from exc
    except urllib.error.URLError as exc:
        raise ValueError("could not download the repository") from exc
    return f"{owner}/{repo}", branch_name


def _default_branch(owner: str, repo: str) -> str:
    request = urllib.request.Request(
        f"https://api.github.com/repos/{owner}/{repo}",
        headers=_HEADERS,
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        raise ValueError("repository was not found, or it is private") from exc
    except urllib.error.URLError as exc:
        raise ValueError("could not reach GitHub") from exc
    branch = payload.get("default_branch")
    if not isinstance(branch, str) or not branch:
        raise ValueError("GitHub did not report a default branch")
    return branch
