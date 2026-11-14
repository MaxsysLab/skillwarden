"""Risk scoring: turn a finding list into a 0–100 score, a severity label, and
a recommendation. Confidence-weighted so low-confidence findings move the needle
less; executable skills carry a blast-radius multiplier. The label is bounded on both
sides by the evidence: a CRITICAL finding floors it at HIGH, and it never rises more
than one step above the most severe single finding."""

from __future__ import annotations

from skillwarden import constants
from skillwarden.models import Finding, ScanResult, Severity

# Beyond this many hits of the same rule, extra instances add nothing to the
# score — the rule's signal has saturated.
_MAX_HITS_PER_RULE = 3

_LABEL_THRESHOLDS = [
    (90, Severity.CRITICAL),
    (60, Severity.HIGH),
    (30, Severity.MEDIUM),
    (10, Severity.LOW),
    (0, Severity.INFO),
]

_RECOMMENDATIONS = {
    Severity.CRITICAL: "DO NOT INSTALL. Critical risk: treat as hostile until proven otherwise.",
    Severity.HIGH: "Do not install without remediation. High-risk findings need fixes and re-scan.",
    Severity.MEDIUM: "Review before installing. Medium-risk findings warrant human judgment.",
    Severity.LOW: "Likely acceptable. Review low-risk findings and proceed with awareness.",
    Severity.INFO: "No significant risk detected. Standard review still recommended.",
}


_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
# A finding counts at its full severity only at or above this confidence (the same line
# the CRITICAL floor below uses); under it, it counts one step lower.
_FULL_WEIGHT_CONFIDENCE = 0.5


def _ceiling(findings: list[Finding]) -> Severity:
    """The highest label the evidence can carry: one step above the most severe single
    finding. Many medium signals together can make a skill HIGH; they cannot make it
    CRITICAL, which says "treat as hostile" and needs at least one high-severity
    finding behind it. Likewise a pile of lows stops at MEDIUM."""
    top = 0
    for f in findings:
        rank = _ORDER.index(f.severity)
        if f.confidence < _FULL_WEIGHT_CONFIDENCE:
            rank = max(rank - 1, 0)
        top = max(top, rank)
    return _ORDER[min(top + 1, len(_ORDER) - 1)]


def _band_top(label: Severity) -> int:
    """The highest score that still reads as `label`."""
    above = [thresh for thresh, lbl in _LABEL_THRESHOLDS if lbl.weight > label.weight]
    return min(above) - 1 if above else 100


def score(findings: list[Finding], has_executable: bool) -> tuple[int, Severity, str]:
    # Noisy-OR: treat each finding as an independent risk probability and combine
    # them. The score saturates toward 100 as evidence accumulates, but a pile of
    # low-severity hits can't masquerade as critical the way a plain sum did — one
    # genuine critical outweighs a dozen low findings.
    #
    # Repeats of the SAME rule are correlated, not independent (9 `innerHTML`s are
    # one concern, not nine), so each rule contributes only its strongest few hits.
    by_rule: dict[str, list[float]] = {}
    for f in findings:
        p = (f.severity.weight / 100.0) * f.confidence
        by_rule.setdefault(f.rule_id, []).append(p)

    prob_safe = 1.0
    for probs in by_rule.values():
        for p in sorted(probs, reverse=True)[:_MAX_HITS_PER_RULE]:
            prob_safe *= 1.0 - p
    value = round(100 * (1.0 - prob_safe))

    if has_executable and value > 0:
        value = min(100, round(value * constants.EXECUTABLE_RISK_MULTIPLIER))

    label = next(lbl for thresh, lbl in _LABEL_THRESHOLDS if value >= thresh)
    # Accumulated evidence may lift the label one step above the most severe single
    # finding, no further. When the ceiling lowers the label, the score is held inside
    # that label's band so the two agree. (The CRITICAL floor below raises the label
    # only; there the score stays what the evidence adds up to.)
    ceiling = _ceiling(findings)
    if label.weight > ceiling.weight:
        label = ceiling
        value = min(value, _band_top(ceiling))
    # A single critical finding floors the label at HIGH regardless of math.
    has_critical = any(f.severity is Severity.CRITICAL and f.confidence >= 0.5 for f in findings)
    if has_critical and label.weight < Severity.HIGH.weight:
        label = Severity.HIGH
    return value, label, _RECOMMENDATIONS[label]


def apply_score(result: ScanResult) -> ScanResult:
    has_exec = any(c.executable for c in result.components)
    result.risk_score, result.severity_label, result.recommendation = score(
        result.findings, has_exec
    )
    if result.status == "incomplete":
        result.recommendation = (
            "Scan incomplete: do not treat partial findings or score as clearance. "
            "Resolve errors and re-scan."
        )
    return result
