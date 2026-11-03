"""Honest measures on top of an OWASP Benchmark run — no rule fitting.

Three questions the raw score cannot answer on its own:

- Confirmation: if we trust only findings a second engine also reported, how much
  of the recall survives and how far does the false-positive rate drop? This is
  the payoff of running CodeQL or Progpilot next to Semgrep.
- AI triage: the optional AI pass marks some findings a likely false positive.
  Applied to the benchmark, how many false positives does it remove, and at what
  cost in recall? Measured against ground truth, so it cannot be gamed.
- Exploitability threshold: the deterministic 0–99 exploitability score is a
  dial. Sweeping it gives a recall / false-positive curve; the best cut is the
  threshold that maximises recall minus false-positive rate.

Every measure re-derives the outcome from the same findings and the benchmark's
own expected-results, so none of it depends on tuning rules to the tests.
"""
from __future__ import annotations

from dataclasses import dataclass

from grephunt.bench.owasp import OwaspTest, _same_cwe, _test_name
from grephunt.finding_model.exploitability import exploitability
from grephunt.finding_model.record import Finding


@dataclass
class Outcome:
    """One benchmark test and the strongest finding that lands on it (if any)."""
    category: str
    real: bool
    hit: bool
    tools: int = 0
    exploit: int = 0
    verdict: str | None = None


def _tool_count(finding: Finding) -> int:
    names = {tool for tool in finding.tools if tool}
    names |= {item.tool for item in (finding.confirmations or []) if item.tool}
    if not names:
        names = {finding.tool} if finding.tool else set()
    return len(names)


def outcomes(findings: list[Finding], tests: list[OwaspTest]) -> list[Outcome]:
    """Per test: whether a finding of the right kind lands on it, and that finding's signals.

    When several findings match one test, the strongest wins — most tools, then
    highest exploitability — so a confirmed finding is not hidden by a weaker twin.
    """
    by_name: dict[str, list[Finding]] = {}
    for finding in findings:
        name = _test_name(finding.location.path or "")
        if name:
            by_name.setdefault(name, []).append(finding)

    result: list[Outcome] = []
    for test in tests:
        matches = [finding for finding in by_name.get(test.name, []) if _same_cwe(finding, test.cwe)]
        if not matches:
            result.append(Outcome(category=test.category, real=test.real, hit=False))
            continue
        scored = [(finding, _tool_count(finding), exploitability(finding.model_dump())["score"]) for finding in matches]
        finding, tools, exploit = max(scored, key=lambda row: (row[1], row[2]))
        result.append(
            Outcome(
                category=test.category,
                real=test.real,
                hit=True,
                tools=tools,
                exploit=exploit,
                verdict=finding.ai_verdict,
            )
        )
    return result


@dataclass
class Point:
    label: str
    tp: int
    fn: int
    fp: int
    tn: int

    @property
    def recall(self) -> float:
        total = self.tp + self.fn
        return self.tp / total if total else 1.0

    @property
    def fp_rate(self) -> float:
        total = self.fp + self.tn
        return self.fp / total if total else 0.0

    @property
    def score(self) -> float:
        return self.recall - self.fp_rate


def _tally(outcomes: list[Outcome], keep) -> Point:
    """keep(outcome) decides whether a hit is believed. A dropped hit becomes a miss / correct-ignore."""
    tp = fn = fp = tn = 0
    for item in outcomes:
        believed = item.hit and keep(item)
        if item.real and believed:
            tp += 1
        elif item.real:
            fn += 1
        elif believed:
            fp += 1
        else:
            tn += 1
    return Point(label="", tp=tp, fn=fn, fp=fp, tn=tn)


def confirmation_curve(outcomes: list[Outcome]) -> list[Point]:
    """Believe a finding only when at least N tools report it, for N = 1, 2, 3."""
    points = []
    for minimum in (1, 2, 3):
        point = _tally(outcomes, lambda item, m=minimum: item.tools >= m)
        point.label = f"≥{minimum} tool" + ("" if minimum == 1 else "s")
        points.append(point)
    return points


def triage_effect(outcomes: list[Outcome]) -> tuple[Point, Point, int] | None:
    """Before vs after dropping findings the AI called a false positive. None when no verdicts are present."""
    if not any(item.verdict for item in outcomes):
        return None
    before = _tally(outcomes, lambda item: True)
    after = _tally(outcomes, lambda item: item.verdict != "false_positive")
    removed = before.fp - after.fp
    before.label, after.label = "before AI triage", "after AI triage"
    return before, after, removed


def exploitability_curve(outcomes: list[Outcome], step: int = 5) -> tuple[list[Point], Point]:
    """Sweep the exploitability threshold; a finding is believed only at or above it.

    Returns the curve and the threshold that maximises recall minus false-positive rate.
    """
    points: list[Point] = []
    for threshold in range(0, 100, step):
        point = _tally(outcomes, lambda item, t=threshold: item.exploit >= t)
        point.label = f"≥{threshold}%"
        points.append(point)
    best = max(points, key=lambda point: (point.score, point.recall))
    return points, best


def format_analysis(outcomes: list[Outcome]) -> str:
    lines = ["", "confirmation (second engine):"]
    for point in confirmation_curve(outcomes):
        lines.append(
            f"  {point.label:<8} recall {point.recall:.0%} ({point.tp}/{point.tp + point.fn})"
            f"  false positives {point.fp_rate:.0%} ({point.fp}/{point.fp + point.tn})  score {point.score:.2f}"
        )

    triage = triage_effect(outcomes)
    if triage is None:
        lines += ["", "AI triage: no verdicts in these findings (run Sort with AI, then re-export to measure)"]
    else:
        before, after, removed = triage
        lines += [
            "",
            "AI triage (verdicts vs ground truth):",
            f"  before: recall {before.recall:.0%}  false positives {before.fp}",
            f"  after : recall {after.recall:.0%}  false positives {after.fp}",
            f"  removed {removed} false positive(s), recall cost {before.recall - after.recall:+.0%}",
        ]

    curve, best = exploitability_curve(outcomes)
    lines += ["", "exploitability threshold sweep:"]
    for point in curve:
        mark = "  <= best" if point is best else ""
        lines.append(
            f"  {point.label:<6} recall {point.recall:.0%}  false positives {point.fp_rate:.0%}  score {point.score:.2f}{mark}"
        )
    lines.append(f"  best threshold {best.label}: score {best.score:.2f} (recall {best.recall:.0%}, false positives {best.fp_rate:.0%})")
    return "\n".join(lines)
