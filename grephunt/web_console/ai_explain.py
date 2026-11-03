"""Check a user-supplied model key and explain one finding from the scan."""
from __future__ import annotations

import json
import re
import socket

from grephunt.finding_model.redaction import mask_secrets
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


def _post_once(url: str, payload: dict, headers: dict) -> dict:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", **headers},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
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


def _post(url: str, payload: dict, headers: dict) -> dict:
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            return _post_once(url, payload, headers)
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


def _gemini(api_key: str, model: str, text: str, require_text: bool = True) -> str:
    if model not in GEMINI_MODELS:
        raise ValueError(f"unknown Gemini model: {model}")
    headers = {"x-goog-api-key": api_key}
    try:
        body = _post(f"{GEMINI_BASE}/interactions", {"model": model, "input": text}, headers)
    except ProviderError as exc:
        if exc.kind not in {"not_found", "bad_request"}:
            raise
        body = _post(
            f"{GEMINI_BASE}/models/{model}:generateContent",
            {"contents": [{"role": "user", "parts": [{"text": text}]}]},
            headers,
        )
    answer = _gemini_text(body)
    if not answer and require_text:
        raise ProviderError(_gemini_empty_reason(body), None, "server")
    return answer


def _deepseek(api_key: str, model: str, text: str) -> str:
    if model not in DEEPSEEK_MODELS:
        raise ValueError(f"unknown DeepSeek model: {model}")
    body = _post(
        DEEPSEEK_URL,
        {"model": model, "messages": [{"role": "user", "content": text}], "stream": False},
        {"Authorization": f"Bearer {api_key}"},
    )
    choices = body.get("choices") or []
    if not choices or not isinstance(choices[0], dict):
        raise ProviderError("DeepSeek returned an empty answer", None, "server")
    answer = (choices[0].get("message") or {}).get("content") or ""
    if not answer.strip():
        reason = choices[0].get("finish_reason") or "unknown"
        raise ProviderError(f"DeepSeek returned an empty answer (reason: {reason})", None, "server")
    return answer.strip()


def _call(provider: str, api_key: str, model: str, text: str, require_text: bool = True) -> str:
    key = (api_key or "").strip()
    if not key:
        raise ValueError("enter an API key")
    if provider == "gemini":
        return _gemini(key, model, text, require_text=require_text)
    if provider == "deepseek":
        return _deepseek(key, model, text)
    raise ValueError("choose Gemini or DeepSeek")


def check_key(provider: str, api_key: str, model: str) -> None:
    _call(provider, api_key, model, "Reply with the single word ok.", require_text=False)


_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_MAX_SCAN_FINDINGS = 180


def _brief_finding(finding: dict) -> dict:
    location = finding.get("location") if isinstance(finding.get("location"), dict) else {}
    message = mask_secrets(finding.get("message")) or ""
    if len(message) > 400:
        message = message[:397] + "..."
    snippet = mask_secrets(finding.get("snippet"))
    if isinstance(snippet, str) and len(snippet) > 240:
        snippet = snippet[:237] + "..."
    return {
        "title": mask_secrets(finding.get("title")),
        "severity": finding.get("severity"),
        "category": finding.get("category"),
        "tool": finding.get("tool"),
        "rule_id": finding.get("rule_id"),
        "message": message,
        "path": location.get("path"),
        "start_line": location.get("start_line"),
        "snippet": snippet,
        "cwe": finding.get("cwe"),
        "cve": finding.get("cve"),
        "package": finding.get("package"),
        "fixed_version": finding.get("fixed_version"),
    }


def explain_finding(provider: str, api_key: str, model: str, finding: dict) -> str:
    text = _PROMPT + json.dumps(_brief_finding(finding), ensure_ascii=False, indent=2)
    return _call(provider, api_key, model, text)


_SCAN_REPORT_PROMPT = """You are reviewing a full security scan of an application or infrastructure target.
The JSON lists summary counts and individual findings (secrets in snippets are already masked).

Write a clear report for a developer team. Use markdown headings and bullet lists where helpful.

Cover:
1. Overall risk posture — how serious is this target right now?
2. The most critical issues to fix first (severity, category, file/line, why it matters).
3. Recurring themes (dependency CVEs, secrets, misconfigurations, code patterns).
4. Likely real exposure vs lower-priority hygiene (only from the data given).
5. A short numbered remediation priority list.

Do not invent findings. Do not write exploit code or attack steps.
If findings were truncated, say so and use counts plus included rows.

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
    included = rows[:_MAX_SCAN_FINDINGS]
    by_severity: dict[str, int] = {}
    by_category: dict[str, int] = {}
    for item in rows:
        sev = str(item.get("severity") or "info").lower()
        cat = str(item.get("category") or "unknown").lower()
        by_severity[sev] = by_severity.get(sev, 0) + 1
        by_category[cat] = by_category.get(cat, 0) + 1
    payload = {
        "target_label": scan.get("target_label"),
        "target_path": scan.get("target_path"),
        "finding_count": total,
        "included_in_prompt": len(included),
        "truncated": total > len(included),
        "counts_by_severity": by_severity,
        "counts_by_category": by_category,
        "scanners": scan.get("scanners"),
        "findings": [_brief_finding(item) for item in included],
    }
    text = _SCAN_REPORT_PROMPT + json.dumps(payload, ensure_ascii=False, indent=2)
    return _call(provider, api_key, model, text)