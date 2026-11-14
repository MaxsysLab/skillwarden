"""Regression tests for false positives found by auditing real published skills
(the official Anthropic skills corpus). Each assertion pins a fix so a future
pattern change can't silently reintroduce the FP.
"""

from __future__ import annotations

from skillwarden.engine import scan
from skillwarden.models import Severity

# Rules that used to fire on the benign-docs fixture before tuning.
_REGRESSION_RULES = {
    "TA-003",  # matched every `if x == "literal":`
    "PI-004",  # matched TypeScript generics like Promise<User>
    "RA-003",  # matched "copy the skill to a writeable location"
    "HC-004",  # matched the prohibition "must not contain exploit code"
    "DX-005",  # matched ".toast.visible {" via a bad `oast.` substring
    "EA-002",  # matched the prose word "startup"
    "DX-003",  # matched `process.env.` and doc mentions of `.env`
}


def test_benign_docs_not_flagged(benign_docs_skill):
    result = scan(benign_docs_skill, use_llm=False)
    fired = {f.rule_id for f in result.findings}
    leaked = _REGRESSION_RULES & fired
    assert not leaked, f"false positives reintroduced: {leaked}"
    # A benign documentation skill must not land at HIGH/CRITICAL.
    assert result.severity_label.weight < Severity.HIGH.weight, (
        f"benign docs scored {result.risk_score}/{result.severity_label.value}: "
        f"{[(f.rule_id, f.file, f.line) for f in result.findings]}"
    )


def test_scoring_does_not_peg_on_finding_count():
    """Many low-severity hits of the same rule must not reach 'critical' — the
    pre-tuning additive model pegged anything with a few findings to 100."""
    from skillwarden.models import Category, Finding, Source
    from skillwarden.report.scoring import score

    lows = [
        Finding(
            rule_id="OH-003",
            category=Category.OUTPUT_HANDLING,
            severity=Severity.LOW,
            title="t",
            description="d",
            source=Source.STATIC,
            confidence=0.5,
            file="x.html",
            line=i,
        )
        for i in range(20)
    ]
    _value, label, _ = score(lows, has_executable=False)
    assert label.weight < Severity.HIGH.weight  # 20 lows ≠ critical
    # And one genuine critical outweighs the pile of lows.
    crit = lows[0].model_copy(update={"rule_id": "SC-001", "severity": Severity.CRITICAL})
    _value2, label2, _ = score([*lows, crit], has_executable=False)
    assert label2.weight >= Severity.HIGH.weight
