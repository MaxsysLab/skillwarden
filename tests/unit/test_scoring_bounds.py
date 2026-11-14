"""The label is bounded by the evidence on both sides.

A CRITICAL finding floors the label at HIGH. And accumulated evidence can lift the label
one step above the most severe single finding, no further: many medium findings can
make a skill high, never critical, which says "treat as hostile" and needs at least one
high-severity finding behind it.
"""

from __future__ import annotations

from skillwarden.models import Category, Finding, Severity, Source
from skillwarden.report.scoring import score


def _f(rule: str, severity: Severity, confidence: float = 0.85) -> Finding:
    return Finding(
        rule_id=rule,
        category=Category.TOOL_MISUSE,
        severity=severity,
        title="t",
        description="d",
        source=Source.STATIC,
        confidence=confidence,
        file="x",
        line=1,
    )


def test_many_medium_findings_cannot_be_called_critical():
    mediums = [_f(f"M-{i:03}", Severity.MEDIUM) for i in range(30)]
    value, label, _ = score(mediums, has_executable=True)
    assert label is Severity.HIGH
    assert value <= 89  # the score stays inside the label's band


def test_many_low_findings_stop_at_medium():
    lows = [_f(f"L-{i:03}", Severity.LOW) for i in range(60)]
    value, label, _ = score(lows, has_executable=True)
    assert label is Severity.MEDIUM
    assert value <= 59


def test_one_high_finding_lets_the_pile_reach_critical():
    pile = [_f(f"M-{i:03}", Severity.MEDIUM) for i in range(30)]
    _, label, _ = score([*pile, _f("H-001", Severity.HIGH)], has_executable=True)
    assert label is Severity.CRITICAL


def test_a_high_finding_marked_unlikely_counts_one_step_lower():
    pile = [_f(f"M-{i:03}", Severity.MEDIUM) for i in range(30)]
    doubted = _f("H-001", Severity.HIGH, confidence=0.2)  # e.g. a confirmed false positive
    _, label, _ = score([*pile, doubted], has_executable=True)
    assert label is Severity.HIGH


def test_a_single_critical_finding_is_unaffected_by_the_ceiling():
    value, label, _ = score([_f("C-001", Severity.CRITICAL)], has_executable=False)
    assert label.weight >= Severity.HIGH.weight
    assert value >= 60


def test_a_confident_high_or_critical_finding_never_has_its_label_lowered():
    for severity in (Severity.HIGH, Severity.CRITICAL):
        for confidence in (0.5, 0.85, 1.0):
            pile = [_f(f"M-{i:03}", Severity.MEDIUM) for i in range(40)]
            _, label, _ = score([*pile, _f("X-001", severity, confidence)], has_executable=True)
            assert label is Severity.CRITICAL


def test_no_findings_is_still_a_clean_zero():
    assert score([], has_executable=True)[:2] == (0, Severity.INFO)
