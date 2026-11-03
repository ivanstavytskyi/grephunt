"""Drop scanner noise that is not an application finding.

Secret hits inside dependency trees and SBOMs, DevSkim's generic hash rules,
and Bearer's logger leak rule dominate large JavaScript scans without pointing
at a vulnerability in the project itself.
"""
from __future__ import annotations

from grephunt.finding_model.record import Category, Finding

# DevSkim: generic cryptographic hash (DS173237) and weak-hash review (DS137138).
# They fire on every hash in bom.json / lockfiles.
_DENIED_RULES = {"DS173237", "DS137138"}
_VENDOR_DIRS = {"node_modules", "vendor", "bower_components"}
_INVENTORY_NAMES = {"bom.json", "sbom.json", "cyclonedx.json"}


def _rule_tokens(rule_id: str) -> set[str]:
    text = (rule_id or "").strip()
    if not text:
        return set()
    short = text.rsplit("/", 1)[-1]
    shorter = short.rsplit(".", 1)[-1]
    return {text, short, shorter}


def _parts(path: str) -> list[str]:
    return [part.lower() for part in path.replace("\\", "/").split("/") if part]


def _inventory_file(name: str) -> bool:
    if name in _INVENTORY_NAMES:
        return True
    if name.endswith((".cdx.json", ".spdx.json", ".spdx", "-bom.json", ".bom.json")):
        return True
    return "sbom" in name


def is_noise(finding: Finding) -> bool:
    """True when the finding should not be shown or correlated."""
    tokens = _rule_tokens(finding.rule_id)
    if tokens & _DENIED_RULES:
        return True
    if any("logger_leak" in token.lower() for token in tokens):
        return True
    if finding.category is Category.DEPENDENCY:
        return False
    parts = _parts(finding.location.path or "")
    if any(part in _VENDOR_DIRS for part in parts):
        return True
    if parts and _inventory_file(parts[-1]):
        return True
    return False
