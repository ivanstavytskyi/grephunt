"""Bundled Semgrep rules: structure checks that keep one bad rule from failing every scan.

Semgrep rejects the whole config when one rule is malformed, so these checks run
without Semgrep: unique ids, required fields, and every focus metavariable bound in
every pattern alternative of its sink.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

RULES = Path(__file__).resolve().parents[1] / "grephunt" / "scanner_catalog" / "rules"
FILES = sorted(RULES.glob("*.yaml"))
LANGUAGES = {"python", "javascript", "typescript", "php", "go", "java"}


def _rules() -> list[tuple[str, dict]]:
    return [(path.name, rule) for path in FILES for rule in yaml.safe_load(path.read_text(encoding="utf-8"))["rules"]]


def _patterns(node) -> list[str]:
    """Every pattern string below node (pattern, pattern-inside, pattern-either items)."""
    found: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key in {"pattern", "pattern-inside", "pattern-not", "pattern-not-inside"} and isinstance(value, str):
                found.append(value)
            else:
                found += _patterns(value)
    elif isinstance(node, list):
        for item in node:
            found += _patterns(item)
    return found


def test_every_language_has_a_rule_file():
    assert {path.stem for path in FILES} >= {"python", "javascript", "php", "go", "java"}


def test_rule_ids_are_unique_and_namespaced():
    ids = [rule["id"] for _, rule in _rules()]
    assert len(ids) == len(set(ids))
    assert all(rule_id.startswith("grephunt.") for rule_id in ids)


def test_no_yaml_anchors_left():
    for path in FILES:
        text = path.read_text(encoding="utf-8")
        assert not re.search(r"^\s*(- )?[\w-]+:\s*[&*][\w-]+\s*$", text, re.MULTILINE), f"{path.name} still uses YAML anchors"


@pytest.mark.parametrize("name,rule", _rules(), ids=lambda value: value if isinstance(value, str) else value["id"])
def test_rule_shape(name: str, rule: dict):
    assert set(rule["languages"]) <= LANGUAGES
    assert rule["severity"] in {"ERROR", "WARNING", "INFO"}
    assert len(rule["message"]) > 40
    cwe = rule["metadata"]["cwe"]
    assert cwe and all(re.fullmatch(r"CWE-\d+", item) for item in cwe)
    if rule.get("mode") == "taint":
        assert rule["pattern-sources"] and rule["pattern-sinks"]
        for sink in rule["pattern-sinks"]:
            steps = sink["patterns"]
            focus = [step["focus-metavariable"] for step in steps if "focus-metavariable" in step]
            assert len(focus) == 1, "each sink focuses on one argument"
            for step in steps:
                for alternative in _patterns(step.get("pattern-either", [])) + ([step["pattern"]] if "pattern" in step else []):
                    assert focus[0] in alternative, f"{rule['id']}: {focus[0]} is not bound in {alternative!r}"
    else:
        assert any(key in rule for key in ("pattern", "patterns", "pattern-either", "pattern-regex"))
    for regex_step in [step for step in _walk(rule) if "metavariable-regex" in step]:
        re.compile(regex_step["metavariable-regex"]["regex"])


def _walk(node):
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from _walk(value)
    elif isinstance(node, list):
        for item in node:
            yield from _walk(item)


def test_taint_rules_cover_sql_injection_for_each_language():
    by_language: dict[str, set[str]] = {}
    for _, rule in _rules():
        for language in rule["languages"]:
            by_language.setdefault(language, set()).update(rule["metadata"]["cwe"])
    for language in ("python", "javascript", "php", "go", "java"):
        assert {"CWE-89", "CWE-78"} <= by_language[language], language
