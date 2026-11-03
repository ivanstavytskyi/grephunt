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
    if finding.get("impact_class"):
        row["impact_class"] = finding.get("impact_class")
    score = finding.get("exploitability")
    if isinstance(score, dict) and score.get("label"):
        row["exploitability"] = score.get("label")
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


_POC_PROMPT = '''You are a security engineer validating one finding from a scan of the user's OWN application.
This is the code the user scanned and controls. The goal is to confirm whether the finding is really
exploitable in this application and to help the owner fix it, the way a proof-of-concept in a
penetration-test report for one's own system does.

Scope rules (follow strictly):
- Everything you write targets ONLY this application, in a local or test environment the owner runs.
- Do NOT provide steps, tooling, or infrastructure for attacking any system the reader does not own,
  for scanning or finding other victims, or for evading detection, persistence, or covering tracks.
- No generic malware, botnet, or mass-exploitation guidance. Stay on this one finding in this code.

The UI renders your answer as markdown. Use these level-2 sections, in order:
## Is it reachable
Trace, from the finding and any provided context (route, request parameters, data flow, snippet),
how untrusted input could reach this line. If the map shows no route reaches it, say so and lower
your confidence. If you cannot tell from the given context, say what is missing.
## How to confirm it
Give the minimal way the owner can verify the finding against their own running instance: the
endpoint or entry point involved, and ONE representative input shaped to this finding (for example a
value in the vulnerable parameter), plus the observable result that distinguishes a real issue from a
false positive. Keep it to what proves the condition — not a weaponized or data-stealing payload.
## Impact if real
What an attacker who controls this input could do, in one short paragraph.
## Fix
The concrete change to this code (corrected snippet or precise instruction).
## Confidence
State your own confidence that this is genuinely exploitable in this app as: high, medium, or low,
with one sentence of reasoning. If context is thin, prefer medium or low.

Finding (secrets already masked):
'''


def poc_finding(provider: str, api_key: str, model: str, finding: dict) -> str:
    """A validation / proof-of-concept for one finding in the user's own scanned application."""
    text = _POC_PROMPT + json.dumps(_brief_finding(finding), ensure_ascii=False, indent=2)
    return _call(provider, api_key, model, text)


_SCAN_REPORT_PROMPT = """You are a senior application security engineer writing a bug bounty grade report.
The JSON holds findings that were already pre-filtered to classes that can cost the company money or
customer data: remote code execution (RCE), injections (SQL, NoSQL, XML/XXE, LDAP, XPath), LFR/LFI/RFI,
SSRF, memory leaks, business logic flaws, IDOR, access control flaws, account takeover,
authentication/authorization flaws, XSS and CSRF. Each finding has impact_class and an exploitability
estimate. Secrets in snippets are already masked. filter.dropped tells how many findings were left out.

Report ONLY vulnerabilities that an attacker can actually exploit to execute code, steal or change
customer data, take over accounts, bypass authentication or authorization, or cause financial loss.
Before including a finding, check it against the code excerpts and context:
- Leave it out if untrusted input clearly cannot reach it, it only runs in tests, build scripts or
  examples, the value is a constant, or the impact is cosmetic.
- Leave out hygiene issues entirely (weak hashes, missing headers, outdated packages without a reachable
  vulnerable path, debug flags, logging, linting) even if they slipped through the pre-filter.
- Do not list or count the findings you left out, and do not add a "lower priority" or "hygiene" section.
- Merge duplicates of the same issue at the same place into one item.

The UI renders your answer as markdown inside section cards.

Format rules (follow strictly):
- Start with one line: # Short title with the target name (plain text, no backticks in the title).
- Then one blank line, then sections only as level-2 headings: ## Section name
- Use ### only for subsections inside a section.
- Use bullet lists (- item) or numbered lists (1. item); keep paragraphs short.
- Separate major sections with a blank line; do not use --- horizontal rules.
- Bold sparingly (**label:** value). Use `backticks` only for file paths, rule ids, and tool names.
- No HTML, no JSON, no code fences unless quoting a single line from a finding.

Required sections (exact ## titles, in this order):
## Business impact summary
Two to four sentences: which exploitable vulnerabilities exist and what they put at risk (money,
customer data, accounts). If after review nothing is exploitable, say so plainly and stop after this
section and "Remediation priority".
## Exploitable vulnerabilities
One ### subsection per vulnerability class that has at least one exploitable finding, most damaging
class first (RCE, injections, LFR/LFI/RFI, SSRF, auth flaws, account takeover, IDOR, access control,
business logic, memory leaks, XSS/CSRF). Inside it, a numbered list; each item:
**title** — severity, `path:line`; **Entry point:** how attacker input reaches it;
**Impact:** what is lost (money, which customer data, which accounts);
**Verdict:** confirmed / needs manual review, with one sentence citing the code excerpt or what is missing.
## Remediation priority
A numbered list of concrete fixes (at most 8), most damaging first.

When source.repository_url and/or source.code_excerpts are present, treat them as ground truth from the scanned tree;
each excerpt includes github_url for the exact file/line.

Do not invent findings. Do not write exploit code or attack payloads.
If the JSON says truncated is true, mention it once in Business impact summary.

Scan data:
"""


_CHAT_FINDINGS_MAX = 80
_MAX_CHAT_MESSAGES = 40
_MAX_CHAT_MESSAGE_CHARS = 8000


_SCAN_REPORT_CHAT_PROMPT = """You are the security analyst who wrote the scan report below.
The user is asking follow-up questions about that report and the underlying scan.

Rules:
- Answer in markdown (short paragraphs, bullets when helpful).
- Ground answers in the report, scan summary, and reference findings when relevant.
- Do not invent findings or file paths not present in the context.
- Do not write exploit code, payloads, or step-by-step attack instructions.
- If you cannot verify from context, say what would need manual review.

Scan summary (JSON):
"""


def _scan_chat_digest(scan: dict, findings: list) -> dict:
    rows = [item for item in findings if isinstance(item, dict)]
    rows.sort(
        key=lambda item: (
            _SEVERITY_RANK.get(str(item.get("severity") or "info").lower(), 5),
            str((item.get("location") or {}).get("path") or ""),
        )
    )
    total = len(rows)
    included = rows[:_CHAT_FINDINGS_MAX]
    compact = len(included) >= _COMPACT_FINDINGS_THRESHOLD
    by_severity: dict[str, int] = {}
    by_category: dict[str, int] = {}
    for item in rows:
        sev = str(item.get("severity") or "info").lower()
        cat = str(item.get("category") or "unknown").lower()
        by_severity[sev] = by_severity.get(sev, 0) + 1
        by_category[cat] = by_category.get(cat, 0) + 1
    source = resolve_scan_source(scan)
    return {
        "target_label": scan.get("target_label"),
        "target_path": scan.get("target_path"),
        "finding_count": total,
        "included_in_prompt": len(included),
        "truncated": total > len(included),
        "counts_by_severity": by_severity,
        "counts_by_category": by_category,
        "scanners": scan.get("scanners"),
        "source": source,
        "findings": [_brief_finding(item, compact=compact) for item in included],
    }


def _normalize_chat_messages(messages: list) -> list[dict]:
    if not isinstance(messages, list) or not messages:
        raise ValueError("messages must be a non-empty list")
    if len(messages) > _MAX_CHAT_MESSAGES:
        raise ValueError(f"too many chat messages (max {_MAX_CHAT_MESSAGES})")
    out: list[dict] = []
    for item in messages:
        if not isinstance(item, dict):
            raise ValueError("each message must be an object")
        role = str(item.get("role") or "").strip().lower()
        if role not in {"user", "assistant"}:
            raise ValueError("message role must be user or assistant")
        content = str(item.get("content") or "").strip()
        if not content:
            raise ValueError("message content is empty")
        if len(content) > _MAX_CHAT_MESSAGE_CHARS:
            content = content[: _MAX_CHAT_MESSAGE_CHARS - 3] + "..."
        out.append({"role": role, "content": content})
    if out[-1]["role"] != "user":
        raise ValueError("the last message must be from the user")
    return out


def _gemini_chat(
    api_key: str,
    model: str,
    messages: list[dict],
    *,
    timeout_sec: float | None = None,
) -> str:
    if model not in GEMINI_MODELS:
        raise ValueError(f"unknown Gemini model: {model}")
    contents: list[dict] = []
    for item in messages:
        role = "model" if item["role"] == "assistant" else "user"
        contents.append({"role": role, "parts": [{"text": item["content"]}]})
    headers = {"x-goog-api-key": api_key}
    body = _post(
        f"{GEMINI_BASE}/models/{model}:generateContent",
        {"contents": contents},
        headers,
        timeout_sec=timeout_sec,
    )
    answer = _gemini_text(body)
    if not answer:
        raise ProviderError(_gemini_empty_reason(body), None, "server")
    return answer


def _deepseek_chat(
    api_key: str,
    model: str,
    messages: list[dict],
    *,
    timeout_sec: float | None = None,
) -> str:
    if model not in DEEPSEEK_MODELS:
        raise ValueError(f"unknown DeepSeek model: {model}")
    body = _post(
        DEEPSEEK_URL,
        {"model": model, "messages": messages, "stream": False},
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


def _call_chat(
    provider: str,
    api_key: str,
    model: str,
    messages: list[dict],
    *,
    timeout_sec: float | None = None,
) -> str:
    key = (api_key or "").strip()
    if not key:
        raise ValueError("enter an API key")
    if provider == "gemini":
        return _gemini_chat(key, model, messages, timeout_sec=timeout_sec)
    if provider == "deepseek":
        return _deepseek_chat(key, model, messages, timeout_sec=timeout_sec)
    raise ValueError("choose Gemini or DeepSeek")


def chat_scan_report(
    provider: str,
    api_key: str,
    model: str,
    scan: dict,
    findings: list,
    report: str,
    messages: list,
) -> str:
    report_text = (report or "").strip()
    if not report_text:
        raise ValueError("report text is missing")
    if len(report_text) > 120_000:
        report_text = report_text[:119_997] + "..."
    transcript = _normalize_chat_messages(messages)
    digest = _scan_chat_digest(scan, findings if isinstance(findings, list) else [])
    context = (
        _SCAN_REPORT_CHAT_PROMPT
        + json.dumps(digest, ensure_ascii=False, separators=(",", ":"))
        + "\n\n# Scan report you wrote\n\n"
        + report_text
    )
    if len(transcript) == 1:
        api_messages = [
            {
                "role": "user",
                "content": context + "\n\n## Follow-up question\n\n" + transcript[0]["content"],
            }
        ]
    else:
        api_messages = [
            {"role": "user", "content": context},
            {
                "role": "assistant",
                "content": "I have the report and scan context. I will answer your follow-up questions.",
            },
            *transcript,
        ]
    return _call_chat(provider, api_key, model, api_messages, timeout_sec=120.0)


NO_IMPACT_REPORT = """# {target}: no exploitable vulnerabilities

## Business impact summary
None of the {total} findings belongs to a class that can cost money or customer data (RCE, injections,
LFR/LFI/RFI, SSRF, memory leaks, business logic, IDOR, access control, account takeover,
authentication/authorization flaws, XSS/CSRF) at medium severity or above in production code.
{dropped}

## Remediation priority
1. Nothing urgent. Review the full findings table for hygiene work when convenient.
"""


def scan_report(provider: str, api_key: str, model: str, scan: dict, findings: list) -> dict:
    """The AI report over the impactful findings only, plus what the filter kept and dropped."""
    from grephunt.finding_model.impact_filter import filter_impactful

    kept, stats = filter_impactful(findings)
    keys = [
        {"fingerprint": item.get("fingerprint"), "correlation_key": item.get("correlation_key"), "impact_class": item["impact_class"]}
        for item in kept
    ]
    if not kept:
        reasons = ", ".join(f"{count} {reason}" for reason, count in stats["dropped_by_reason"].items())
        text = NO_IMPACT_REPORT.format(
            target=scan.get("target_label") or "Scan",
            total=stats["total"],
            dropped=f"Left out: {reasons}." if reasons else "",
        )
        return {"text": text, "filter": stats, "kept": keys}
    text = explain_scan_report(provider, api_key, model, scan, kept, filter_stats=stats)
    return {"text": text, "filter": stats, "kept": keys}


def explain_scan_report(
    provider: str, api_key: str, model: str, scan: dict, findings: list, filter_stats: dict | None = None
) -> str:
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
        "filter": filter_stats or {},
        "source": {
            **source,
            "code_excerpts": source_excerpts,
        },
        "findings": [_brief_finding(item, compact=compact) for item in included],
    }
    text = _SCAN_REPORT_PROMPT + json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    return _call(provider, api_key, model, text, timeout_sec=_scan_report_timeout(len(included)))

_TRIAGE_PROMPT = """You are triaging security findings. Decide if each one is a real issue in the shown code.
Reply with a JSON array only, no markdown. Each element:
{"id": "F-001", "verdict": "confirmed" | "likely" | "false_positive", "reason": "one sentence citing the file and line"}
"code" holds the whole enclosing function (code_kind "function"), the whole file when the code is not
inside a function ("file"), or the lines around the finding ("window"), each line prefixed with its number.
Before answering, read the path from the input to the reported line and look for anything that makes it safe:
escaping (mysqli_real_escape_string inside quotes, htmlspecialchars), hashing (md5, password_hash), casts and
type checks (intval, (int), is_numeric on every part, typeof x === 'string'), allowlists (in_array,
array_key_exists, a fixed map of choices), prepared statements. Name the line number of that check in the reason.
confirmed: input from outside the program reaches the reported line with no such check on the way.
likely: the pattern is dangerous but the shown code does not prove that an attacker controls the input.
false_positive: a check above makes it safe (cite its line), or it is a test, a comment, a safe API, generated code,
or a copied challenge file rather than the running application.
Use the map context when given: a route that reaches the code, and whether a query is built from variables.
Do not write exploit code, payloads, or attack steps. Do not invent files.

Findings:
"""

TRIAGE_BATCH = 24
TRIAGE_CODE_LIMIT = 3500


def _json_array(text: str) -> list:
    raw = text.strip()
    if raw.startswith("```"):
        raw = raw.split("\n", 1)[-1]
        raw = raw.rsplit("```", 1)[0]
    start, end = raw.find("["), raw.rfind("]")
    if start == -1 or end <= start:
        raise ValueError("the model did not return a JSON array")
    parsed = json.loads(raw[start : end + 1])
    if not isinstance(parsed, list):
        raise ValueError("the model did not return a JSON array")
    return parsed


def triage_findings(provider: str, api_key: str, model: str, findings: list) -> list[dict]:
    """Ask the model for a verdict per finding (one batch). Findings are never deleted."""
    rows = []
    for index, item in enumerate(findings[:TRIAGE_BATCH], start=1):
        if not isinstance(item, dict) or not item.get("fingerprint"):
            continue
        location = item.get("location") if isinstance(item.get("location"), dict) else {}
        context = item.get("context") if isinstance(item.get("context"), dict) else {}
        snippet = item.get("snippet") if isinstance(item.get("snippet"), str) else ""
        code = item.get("code_context") if isinstance(item.get("code_context"), str) else ""
        rows.append(
            {
                "id": f"F-{index:03d}",
                "fingerprint": str(item["fingerprint"]),
                "title": item.get("title"),
                "severity": item.get("severity"),
                "category": item.get("category"),
                "rule_id": item.get("rule_id"),
                "path": location.get("path"),
                "line": location.get("start_line"),
                "package": item.get("package"),
                "cve": (item.get("cve") or [])[:4],
                "routes": [route.get("label") for route in (context.get("routes") or [])[:3] if isinstance(route, dict)],
                "query_from_variables": bool((context.get("database") or {}).get("dynamic")) if isinstance(context.get("database"), dict) else False,
                "message": mask_secrets(str(item.get("message") or ""))[:300],
                "code_kind": item.get("code_kind") if code else "snippet",
                "code": mask_secrets(code)[:TRIAGE_CODE_LIMIT] if code else mask_secrets(snippet)[:500],
            }
        )
    if not rows:
        raise ValueError("findings list is missing")
    answer = _call(provider, api_key, model, _TRIAGE_PROMPT + json.dumps(rows, ensure_ascii=False), timeout_sec=90)
    by_id = {row["id"]: row["fingerprint"] for row in rows}
    verdicts = []
    for item in _json_array(answer):
        if not isinstance(item, dict):
            continue
        fingerprint = by_id.get(str(item.get("id") or ""))
        verdict = str(item.get("verdict") or "")
        if not fingerprint or verdict not in {"confirmed", "likely", "false_positive"}:
            continue
        verdicts.append({"fingerprint": fingerprint, "verdict": verdict, "reason": str(item.get("reason") or "")[:400]})
    return verdicts
