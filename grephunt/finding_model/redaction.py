"""Mask secret values before a finding is stored, shown, or sent to an AI provider.

A secret finding should say where a credential is, not repeat it. Some
scanners put the value in the snippet or the message (Kingfisher, Semgrep
rules, Bandit B105). This keeps the first four characters, which is enough
to tell two keys apart, and hides the rest.
"""
from __future__ import annotations

import re

# Long runs of token characters that mix letters and digits: keys, tokens, hashes.
_TOKEN = re.compile(r"[A-Za-z0-9_\-+/=.]{12,}")
# Quoted literals and values after = or : are secrets in a secret finding, even without digits.
_ASSIGNED = re.compile(r"""(?P<lead>[=:]\s*["']?|["'])(?P<value>[^\s"'`]{8,})""")
_KEEP = 4


def _mask(value: str) -> str:
    if value.startswith("<fake-") or set(value) <= {"*"}:
        return value
    return value[:_KEEP] + "*" * max(4, min(len(value) - _KEEP, 16))


def _looks_like_token(value: str) -> bool:
    return any(char.isdigit() for char in value) and any(char.isalpha() for char in value)


def mask_secrets(text: str | None) -> str | None:
    if not text:
        return text
    masked = _ASSIGNED.sub(lambda match: match.group("lead") + _mask(match.group("value")), text)
    return _TOKEN.sub(lambda match: _mask(match.group(0)) if _looks_like_token(match.group(0)) else match.group(0), masked)


def _mask_strings(node):
    if isinstance(node, str):
        return mask_secrets(node)
    if isinstance(node, list):
        return [_mask_strings(item) for item in node]
    if isinstance(node, dict):
        return {key: (value if key in {"ruleId", "uri", "ruleIndex"} else _mask_strings(value)) for key, value in node.items()}
    return node


def redact_sarif_file(path, result_refs: set[tuple[int, int]]) -> None:
    """Mask the strings of the given results (run index, result index) in a SARIF file on disk.

    The scan directory keeps each tool's SARIF and the merged SARIF. They are
    reports too, so a secret must not survive there either.
    """
    import json

    if not result_refs:
        return
    data = json.loads(path.read_text(encoding="utf-8"))
    for run_index, run in enumerate(data.get("runs") or []):
        for result_index, result in enumerate(run.get("results") or []):
            if (run_index, result_index) not in result_refs:
                continue
            # Every string in the result: tools also put the value in properties (Kingfisher writes
            # ready-made "validate" commands with the key in them).
            run["results"][result_index] = _mask_strings(result)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def secret_result_refs(findings) -> set[tuple[int, int]]:
    """Positions of secret findings in their SARIF file, from raw_ref "<file>#/runs/<i>/results/<j>"."""
    import re

    refs: set[tuple[int, int]] = set()
    for finding in findings:
        if getattr(finding.category, "value", finding.category) != "secret" or not finding.raw_ref:
            continue
        match = re.search(r"#/runs/(\d+)/results/(\d+)$", finding.raw_ref)
        if match:
            refs.add((int(match.group(1)), int(match.group(2))))
    return refs
