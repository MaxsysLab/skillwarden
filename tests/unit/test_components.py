"""Unit tests for the smaller pieces: scoring, suppression, AST analyzer."""

from __future__ import annotations

from skillwarden.analyzers.base import ScanContext
from skillwarden.analyzers.dangerous_code import DangerousCodeAnalyzer
from skillwarden.models import Category, Component, Finding, Severity
from skillwarden.report.scoring import score
from skillwarden.suppression import Baseline, partition


def _finding(rule_id="X-1", sev=Severity.HIGH, conf=1.0, file="a.py"):
    return Finding(
        rule_id=rule_id,
        category=Category.DANGEROUS_CODE,
        severity=sev,
        title="t",
        description="d",
        confidence=conf,
        file=file,
        snippet="s",
    )


def test_score_empty_is_zero():
    value, label, _ = score([], has_executable=False)
    assert value == 0 and label is Severity.INFO


def test_critical_floors_label_at_high():
    _value, label, _ = score([_finding(sev=Severity.CRITICAL)], has_executable=False)
    assert label.weight >= Severity.HIGH.weight


def test_confidence_weights_score():
    high_conf, _, _ = score([_finding(conf=1.0)], has_executable=False)
    low_conf, _, _ = score([_finding(conf=0.2)], has_executable=False)
    assert high_conf > low_conf


def test_executable_multiplier_increases_score():
    base, _, _ = score([_finding()], has_executable=False)
    boosted, _, _ = score([_finding()], has_executable=True)
    assert boosted >= base


def test_baseline_suppresses_by_fingerprint():
    f = _finding()
    bl = Baseline(fingerprints={f.fingerprint})
    active, suppressed = partition([f], bl)
    assert not active and suppressed == [f]


def test_baseline_suppresses_by_glob():
    f = _finding(rule_id="DC-001")
    bl = Baseline(rule_globs=["DC-*"])
    active, suppressed = partition([f], bl)
    assert not active and suppressed == [f]


def test_ast_detects_eval_not_in_string():
    ctx = ScanContext(
        target="t",
        components=[Component(path="x.py", type="python", lines=2, size_bytes=10, executable=True)],
        file_cache={"x.py": "y = eval('1+1')\nz = 'this mentions eval but is a string'\n"},
    )
    findings = DangerousCodeAnalyzer().run(ctx)
    eval_findings = [f for f in findings if f.rule_id == "DC-001"]
    assert len(eval_findings) == 1  # only the real call, not the string mention
    assert eval_findings[0].line == 1


def test_ast_handles_unparseable():
    ctx = ScanContext(
        target="t",
        components=[
            Component(path="bad.py", type="python", lines=1, size_bytes=5, executable=True)
        ],
        file_cache={"bad.py": "def (:\n"},
    )
    findings = DangerousCodeAnalyzer().run(ctx)
    assert any(f.rule_id == "DC-000" for f in findings)
