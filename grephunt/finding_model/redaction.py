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
