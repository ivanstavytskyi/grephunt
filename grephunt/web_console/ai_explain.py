"""Check a user-supplied model key and explain one finding from the scan."""
from __future__ import annotations

import json
import re
import socket

from grephunt.config import ai_scan_findings_max
from grephunt.finding_model.redaction import mask_secrets
from grephunt.web_console.scan_source_context import build_source_excerpts, resolve_scan_source
import time
import urllib.error
import urllib.request

GEMINI_MODELS = ("gemini-3.8-flash", "gemini-3.6-flash", "gemini-3.5-flash-lite", "gemini-2.5-flash")
DEEPSEEK_MODELS = ("deepseek-chat", "deepseek-reasoner")

GEMINI_BASE = "https://generativelanguage.googleapis.com/v1beta"
DEEPSEEK_URL = "https://api.deepseek.com/chat/completions"

TIMEOUT_SECONDS = 60
MAX_RETRY_WAIT = 20.0
MAX_ATTEMPTS = 2


class ProviderError(ValueError):
    def __init__(
        self,
        message: str,
        status: int | None = None,
        kind: str = "bad_request",
        retry_after: float | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.kind = kind
        self.retry_after = retry_after


_PROMPT = """You are reviewing a single result from a security scan.
Use only the finding below. Describe:
1. What is wrong, in plain language.
2. The exact file and line to open, and what to look at there.
3. Why this pattern is risky, using the snippet as evidence.
4. A minimal demonstration of the condition already present in that snippet: quote the unsafe lines and say what they allow. Do not write exploit code, payloads, or steps to attack a running system.
5. A corrected version of the same snippet.

Finding:
"""


def _parse_duration(value) -> float | None:
    if value is None:
        return None
    match = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*s?\s*", str(value))
    return float(match.group(1)) if match else None


def _parse_error(raw: str) -> tuple[str, str, float | None]:
    message, reason, retry_after = raw.strip(), "", None
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return message, reason, retry_after
    error = parsed.get("error") if isinstance(parsed, dict) else None
    if isinstance(error, dict):
        message = str(error.get("message") or message)
        reason = str(error.get("status") or error.get("type") or error.get("code") or "")
        for detail in error.get("details") or []:
            if not isinstance(detail, dict):
                continue
            if detail.get("reason"):
                reason = str(detail["reason"])
            if detail.get("retryDelay"):
                retry_after = _parse_duration(detail["retryDelay"])
    elif isinstance(error, str):
        message = error
    return message, reason, retry_after


def _classify(status: int, message: str, reason: str, retry_after: float | None) -> ProviderError:
    text = f"{message} {reason}".lower()
    short = message[:300] or f"HTTP {status}"

    if status == 401 or any(s in text for s in (
        "api_key_invalid", "api key not valid", "invalid api key",
        "incorrect api key", "authentication fails", "api key expired",
    )):
        return ProviderError(f"the provider rejected the key: {short}", status, "auth")
    if status == 402 or "insufficient balance" in text:
        return ProviderError(f"the account has no balance or billing: {short}", status, "billing")
    if status == 429:
        wait = f" Retry in about {round(retry_after)} s." if retry_after else ""
        return ProviderError(
            f"the key works, but the request quota for this model is used up.{wait} "
            f"Details: {short}",
            status, "rate_limit", retry_after,
        )
    if status == 403:
        return ProviderError(
            f"the key has no access to this model or API (check billing, region, or model availability): {short}",
            status, "access",
        )
    if status == 404:
        return ProviderError(f"not found: {short}", status, "not_found")
    if status >= 500:
        return ProviderError(f"the provider is temporarily unavailable: {short}", status, "server")
    return ProviderError(short, status, "bad_request")


def _post_once(url: str, payload: dict, headers: dict, *, timeout_sec: float | None = None) -> dict:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", **headers},
        method="POST",
    )
    timeout = TIMEOUT_SECONDS if timeout_sec is None else timeout_sec
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        message, reason, retry_after = _parse_error(raw)
        if retry_after is None and exc.headers is not None:
            retry_after = _parse_duration(exc.headers.get("Retry-After"))
        raise _classify(exc.code, message, reason, retry_after) from exc
    except (socket.timeout, TimeoutError) as exc:
        raise ProviderError("the provider did not answer in time", None, "network") from exc
    except urllib.error.URLError as exc:
        raise ProviderError(f"could not reach the provider: {exc.reason}", None, "network") from exc

    try:
        body = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ProviderError(f"the provider returned non-JSON: {raw[:200]}", None, "server") from exc
    if not isinstance(body, dict):
        raise ProviderError("the provider returned an unexpected response", None, "server")
    return body


def _post(url: str, payload: dict, headers: dict, *, timeout_sec: float | None = None) -> dict:
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            return _post_once(url, payload, headers, timeout_sec=timeout_sec)
        except ProviderError as exc:
            if attempt == MAX_ATTEMPTS:
                raise
            if exc.kind == "rate_limit" and exc.retry_after is not None and exc.retry_after <= MAX_RETRY_WAIT:
                time.sleep(exc.retry_after + 0.5)
            elif exc.kind == "server":
                time.sleep(2)
            else:
                raise
    raise AssertionError("unreachable")


_THOUGHT_TYPES = {"thought", "thinking", "thought_summary"}


def _gemini_text(body: dict) -> str:
    if isinstance(body.get("output_text"), str) and body["output_text"].strip():
        return body["output_text"].strip()

    steps = body.get("steps")
    if isinstance(steps, list):
        root = [s for s in steps if isinstance(s, dict) and s.get("type") in (None, "model_output")]
    else:
        root = body

    chunks: list[str] = []

    def walk(node) -> None:
        if isinstance(node, list):
            for item in node:
                walk(item)
            return
        if not isinstance(node, dict):
            return
        if node.get("thought") is True or node.get("type") in _THOUGHT_TYPES:
            return
        if isinstance(node.get("text"), str):
            chunks.append(node["text"])
        for key in ("outputs", "output", "content", "parts", "candidates"):
            if isinstance(node.get(key), (list, dict)):
                walk(node[key])

    walk(root)
    return "".join(chunks).strip()


def _gemini_empty_reason(body: dict) -> str:
    candidates = body.get("candidates") or [{}]
    first = candidates[0] if isinstance(candidates[0], dict) else {}
    reason = (
        first.get("finishReason")
        or (body.get("promptFeedback") or {}).get("blockReason")
        or body.get("status")
    )
    steps = body.get("steps")
    step_types = ", ".join(str(s.get("type")) for s in steps if isinstance(s, dict)) if isinstance(steps, list) else "-"
    return (
        f"Gemini returned an empty answer (reason: {reason or 'unknown'}; "
        f"steps: {step_types}; keys: {', '.join(sorted(body))})"
    )


def _gemini(api_key: str, model: str, text: str, require_text: bool = True, *, timeout_sec: float | None = None) -> str:
    if model not in GEMINI_MODELS:
        raise ValueError(f"unknown Gemini model: {model}")
    headers = {"x-goog-api-key": api_key}
    try:
        body = _post(
            f"{GEMINI_BASE}/interactions",
            {"model": model, "input": text},
            headers,
            timeout_sec=timeout_sec,
        )
    except ProviderError as exc:
        if exc.kind not in {"not_found", "bad_request"}:
            raise
        body = _post(
            f"{GEMINI_BASE}/models/{model}:generateContent",
            {"contents": [{"role": "user", "parts": [{"text": text}]}]},
            headers,
            timeout_sec=timeout_sec,
        )
    answer = _gemini_text(body)
    if not answer and require_text:
        raise ProviderError(_gemini_empty_reason(body), None, "server")
    return answer


def _deepseek(api_key: str, model: str, text: str, *, timeout_sec: float | None = None) -> str:
    if model not in DEEPSEEK_MODELS:
        raise ValueError(f"unknown DeepSeek model: {model}")
    body = _post(
        DEEPSEEK_URL,
        {"model": model, "messages": [{"role": "user", "content": text}], "stream": False},
        {"Authorization": f"Bearer {api_key}"},
        timeout_sec=timeout_sec,
    )
    choices = body.get("choices") or []
    if not choices or not isinstance(choices[0], dict):
        raise ProviderError("DeepSeek returned an empty answer", None, "server")
    answer = (choices[0].get("message") or {}).get("content") or ""
    if not answer.strip():
        reason = choices[0].get("finish_reason") or "unknown"
        raise ProviderError(f"DeepSeek returned an empty answer (reason: {reason})", None, "server")
    return answer.strip()


def _call(
    provider: str,
    api_key: str,
    model: str,
    text: str,
    require_text: bool = True,
    *,
    timeout_sec: float | None = None,
) -> str:
    key = (api_key or "").strip()
    if not key:
        raise ValueError("enter an API key")
    if provider == "gemini":
        return _gemini(key, model, text, require_text=require_text, timeout_sec=timeout_sec)
    if provider == "deepseek":
        return _deepseek(key, model, text, timeout_sec=timeout_sec)
    raise ValueError("choose Gemini or DeepSeek")


def check_key(provider: str, api_key: str, model: str) -> None:
    _call(provider, api_key, model, "Reply with the single word ok.", require_text=False)


_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_COMPACT_FINDINGS_THRESHOLD = 250


def _brief_finding(finding: dict, *, compact: bool = False) -> dict:
    location = finding.get("location") if isinstance(finding.get("location"), dict) else {}
    message = mask_secrets(finding.get("message")) or ""
    msg_limit = 200 if compact else 400
    if len(message) > msg_limit:
        message = message[: msg_limit - 3] + "..."
    row = {
        "title": mask_secrets(finding.get("title")),
        "severity": finding.get("severity"),
        "category": finding.get("category"),
        "tool": finding.get("tool"),
        "rule_id": finding.get("rule_id"),
        "message": message,
        "path": location.get("path"),
        "start_line": location.get("start_line"),
        "cwe": (finding.get("cwe") or [])[:3] if compact else finding.get("cwe"),
        "cve": (finding.get("cve") or [])[:3] if compact else finding.get("cve"),
        "package": finding.get("package"),
        "fixed_version": finding.get("fixed_version"),
    }
    if not compact:
        snippet = mask_secrets(finding.get("snippet"))
        if isinstance(snippet, str) and len(snippet) > 240:
            snippet = snippet[:237] + "..."
        row["snippet"] = snippet
    return row


def _scan_report_timeout(finding_count: int) -> float:
    """Scale wait time for large scans while keeping single-finding calls at 60s."""
    return min(300.0, max(float(TIMEOUT_SECONDS), 60.0 + finding_count * 0.2))


def explain_finding(provider: str, api_key: str, model: str, finding: dict) -> str:
    text = _PROMPT + json.dumps(_brief_finding(finding), ensure_ascii=False, indent=2)
    return _call(provider, api_key, model, text)


_SCAN_REPORT_PROMPT = """You are reviewing a full security scan of an application or infrastructure target.
The JSON lists summary counts and individual findings (secrets in snippets are already masked).

Write a report for developers. The UI renders your answer as markdown inside section cards.
It already shows severity and category totals separately — do NOT repeat a full count table.

Format rules (follow strictly):
- Start with one line: # Short title with the target name (plain text, no backticks in the title).
- Then one blank line, then sections only as level-2 headings: ## Section name
- Use ### only for subsections inside a section.
- Use bullet lists (- item) or numbered lists (1. item) for details; keep paragraphs short.
- Separate major sections with a blank line; do not use --- horizontal rules.
- Bold sparingly (**label:** value). Use `backticks` only for file paths, rule ids, and tool names.
- No HTML, no JSON, no code fences unless quoting a single line from a finding.

Required sections (exact ## titles, in this order):
## Overall risk posture
## Most critical issues to fix first
## Verified against source
## Recurring themes
## Likely real exposure vs lower-priority hygiene
## Remediation priority

When source.repository_url and/or source.code_excerpts are present, treat them as ground truth from the scanned tree.
Open the repository link mentally via source.browse_url; each excerpt includes github_url for the exact file/line.

In "Most critical issues to fix first", use a numbered list (top 5 max). Each item: title, severity, category, location, one sentence why it matters.
In "Verified against source", for the top issues (and any dependency/CVE flags such as nanoid), label each as:
**confirmed**, **likely false positive**, or **needs manual review**, with one sentence citing source.code_excerpts or explaining missing source.
In "Remediation priority", use a numbered list of concrete actions (5–8 items).

Do not invent findings. Do not write exploit code or attack steps.
If the JSON says truncated is true, mention it once in Overall risk posture.

Scan data:
"""


def explain_scan_report(provider: str, api_key: str, model: str, scan: dict, findings: list) -> str:
    rows = [item for item in findings if isinstance(item, dict)]
    rows.sort(
        key=lambda item: (
            _SEVERITY_RANK.get(str(item.get("severity") or "info").lower(), 5),
            str((item.get("location") or {}).get("path") or ""),
        )
    )
    total = len(rows)
    cap = ai_scan_findings_max()
    included = rows[:cap] if cap is not None else rows
    compact = len(included) >= _COMPACT_FINDINGS_THRESHOLD
    by_severity: dict[str, int] = {}
    by_category: dict[str, int] = {}
    for item in rows:
        sev = str(item.get("severity") or "info").lower()
        cat = str(item.get("category") or "unknown").lower()
        by_severity[sev] = by_severity.get(sev, 0) + 1
        by_category[cat] = by_category.get(cat, 0) + 1
    source = resolve_scan_source(scan)
    source_excerpts = build_source_excerpts(scan, rows)
    payload = {
        "target_label": scan.get("target_label"),
        "target_path": scan.get("target_path"),
        "finding_count": total,
        "included_in_prompt": len(included),
        "truncated": total > len(included),
        "compact_rows": compact,
        "counts_by_severity": by_severity,
        "counts_by_category": by_category,
        "scanners": scan.get("scanners"),
        "source": {
            **source,
            "code_excerpts": source_excerpts,
        },
        "findings": [_brief_finding(item, compact=compact) for item in included],
    }
    text = _SCAN_REPORT_PROMPT + json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    return _call(provider, api_key, model, text, timeout_sec=_scan_report_timeout(len(included)))