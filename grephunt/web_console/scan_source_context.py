"""GitHub links and local source excerpts for AI scan reports."""
from __future__ import annotations

import re
from pathlib import Path

from grephunt.finding_model.redaction import mask_secrets

_LABEL_REPO = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_GITHUB = re.compile(r"^https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)")

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_MAX_EXCERPTS = 36
_CONTEXT_LINES = 10


def infer_github_from_label(label: str | None) -> str | None:
    text = (label or "").strip()
    if _LABEL_REPO.match(text):
        return f"https://github.com/{text}"
    return None


def normalize_github_url(raw: str | None) -> str | None:
    if not raw or not isinstance(raw, str):
        return None
    url = raw.strip().split("?", 1)[0].split("#", 1)[0]
    if not url.startswith("https://github.com/"):
        return None
    return url.rstrip("/")


def github_file_url(repository_url: str | None, ref: str | None, file_path: str | None, line: int | None) -> str | None:
    base = normalize_github_url(repository_url)
    if not base or not file_path:
        return None
    match = _GITHUB.match(base)
    if not match:
        return None
    branch = (ref or "main").strip() or "main"
    path = file_path.replace("\\", "/").lstrip("/")
    url = f"https://github.com/{match.group(1)}/{match.group(2)}/blob/{branch}/{path}"
    if isinstance(line, int) and line > 0:
        url = f"{url}#L{line}"
    return url


def resolve_scan_source(scan: dict) -> dict:
    repository_url = normalize_github_url(scan.get("source_repo_url")) or infer_github_from_label(
        scan.get("target_label")
    )
    ref = scan.get("source_ref")
    if not isinstance(ref, str) or not ref.strip():
        ref = "main"
    browse_url = None
    if repository_url:
        browse_url = f"{repository_url}/tree/{ref}"
    return {
        "repository_url": repository_url,
        "ref": ref,
        "browse_url": browse_url,
        "local_tree": scan.get("target_path"),
    }


def _safe_file(root: Path, relative: str) -> Path | None:
    rel = relative.replace("\\", "/").lstrip("/")
    if not rel or ".." in rel.split("/"):
        return None
    try:
        candidate = (root / rel).resolve()
        candidate.relative_to(root.resolve())
    except (ValueError, OSError):
        return None
    return candidate if candidate.is_file() else None


def _read_excerpt(path: Path, line: int | None) -> list[str]:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    if not lines:
        return []
    if line is None or line < 1:
        start, end = 0, min(len(lines), _CONTEXT_LINES)
    else:
        center = line - 1
        half = _CONTEXT_LINES // 2
        start = max(0, center - half)
        end = min(len(lines), start + _CONTEXT_LINES)
    excerpt = lines[start:end]
    return [mask_secrets(row) or "" for row in excerpt]


def build_source_excerpts(scan: dict, findings: list[dict]) -> list[dict]:
    source = resolve_scan_source(scan)
    root_text = source.get("local_tree")
    if not root_text or not isinstance(root_text, str):
        return []
    root = Path(root_text)
    if not root.is_dir():
        return []

    ranked = sorted(
        [item for item in findings if isinstance(item, dict)],
        key=lambda item: (
            _SEV_RANK.get(str(item.get("severity") or "info").lower(), 9),
            str((item.get("location") or {}).get("path") or ""),
        ),
    )

    seen: set[tuple[str, int | None]] = set()
    excerpts: list[dict] = []
    for finding in ranked:
        if len(excerpts) >= _MAX_EXCERPTS:
            break
        location = finding.get("location") if isinstance(finding.get("location"), dict) else {}
        rel_path = location.get("path")
        if not isinstance(rel_path, str) or not rel_path.strip():
            continue
        line = location.get("start_line")
        line_num = line if isinstance(line, int) else None
        key = (rel_path.replace("\\", "/"), line_num)
        if key in seen:
            continue
        file_path = _safe_file(root, rel_path)
        if file_path is None:
            continue
        seen.add(key)
        excerpt_lines = _read_excerpt(file_path, line_num)
        if not excerpt_lines:
            continue
        excerpts.append(
            {
                "severity": finding.get("severity"),
                "category": finding.get("category"),
                "tool": finding.get("tool"),
                "title": mask_secrets(finding.get("title")),
                "rule_id": finding.get("rule_id"),
                "path": rel_path.replace("\\", "/"),
                "start_line": line_num,
                "github_url": github_file_url(source.get("repository_url"), source.get("ref"), rel_path, line_num),
                "lines": excerpt_lines,
            }
        )
    return excerpts
