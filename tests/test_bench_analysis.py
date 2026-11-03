"""The honest benchmark measures: confirmation, AI triage, and the exploitability sweep."""
from grephunt.bench.analysis import (
    confirmation_curve,
    exploitability_curve,
    outcomes,
    triage_effect,
)
from grephunt.bench.owasp import OwaspTest
from grephunt.finding_model.record import Finding


def _finding(path, cwe, tool, severity="high", tools=None, verdict=None):
    data = {
        "tool": tool,
        "rule_id": "r",
        "title": "t",
        "severity": severity,
        "category": "code",
        "cwe": [f"CWE-{cwe}"],
        "location": {"path": path, "start_line": 10},
        "tools": tools or [tool],
    }
    if tools and len(tools) > 1:
        data["confirmations"] = [
            {"tool": name, "rule_id": "r", "title": "t", "line": 10, "severity": severity} for name in tools
        ]
    if verdict:
        data["ai_verdict"] = verdict
    return Finding.model_validate(data)


_TESTS = [
    OwaspTest(name="BenchmarkTest00001", category="sqli", real=True, cwe=89),
    OwaspTest(name="BenchmarkTest00002", category="sqli", real=False, cwe=89),
]


def test_confirmation_curve_drops_single_tool_false_positive():
    findings = [
        _finding("x/BenchmarkTest00001.java", 89, "semgrep", tools=["semgrep", "codeql"]),
        _finding("x/BenchmarkTest00002.java", 89, "semgrep"),
    ]
    points = {p.label: p for p in confirmation_curve(outcomes(findings, _TESTS))}
    assert points["≥1 tool"].fp == 1 and points["≥1 tool"].tp == 1
    # The second engine confirms only the real bug, so the false positive drops away.
    assert points["≥2 tools"].fp == 0 and points["≥2 tools"].tp == 1


def test_triage_removes_false_positive_marked_by_ai():
    findings = [
        _finding("x/BenchmarkTest00001.java", 89, "semgrep"),
        _finding("x/BenchmarkTest00002.java", 89, "semgrep", verdict="false_positive"),
    ]
    before, after, removed = triage_effect(outcomes(findings, _TESTS))
    assert removed == 1
    assert before.fp == 1 and after.fp == 0
    assert after.tp == before.tp  # recall is not harmed


def test_triage_effect_none_without_verdicts():
    findings = [_finding("x/BenchmarkTest00001.java", 89, "semgrep")]
    assert triage_effect(outcomes(findings, _TESTS)) is None


def test_exploitability_curve_picks_best_threshold():
    findings = [
        _finding("x/BenchmarkTest00001.java", 89, "semgrep", tools=["semgrep", "codeql"]),
        _finding("x/BenchmarkTest00002.java", 89, "semgrep", severity="low"),
    ]
    curve, best = exploitability_curve(outcomes(findings, _TESTS))
    assert curve and best in curve
    # The best cut scores at least as well as believing everything (≥0%).
    floor = next(p for p in curve if p.label == "≥0%")
    assert best.score >= floor.score
