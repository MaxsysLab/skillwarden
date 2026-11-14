"""End-to-end engine tests (static-only; no API key needed)."""

from __future__ import annotations

import json

import pytest

from skillwarden import engine
from skillwarden.analyzers.prompt_injection import PromptInjectionAnalyzer
from skillwarden.engine import scan
from skillwarden.models import Category, Severity
from skillwarden.report.formatters import render
from skillwarden.report.sarif import to_sarif


def _rule_ids(result):
    return {f.rule_id for f in result.findings}


def test_malicious_skill_is_flagged(malicious_skill):
    result = scan(malicious_skill, use_llm=False)
    assert result.severity_label.weight >= Severity.HIGH.weight
    assert result.risk_score >= 60
    ids = _rule_ids(result)
    # Prompt injection, conceal-from-user, pipe-to-shell, exfil, eval, shell=True.
    assert "PI-001" in ids  # ignore previous instructions
    assert "PI-005" in ids  # do not tell the user
    assert "SC-001" in ids  # curl | bash
    assert "DC-001" in ids  # eval()
    assert "DC-010" in ids  # subprocess shell=True
    assert any(f.category is Category.DATA_EXFILTRATION for f in result.findings)


def test_benign_skill_is_clean(benign_skill):
    result = scan(benign_skill, use_llm=False)
    assert result.severity_label in (Severity.INFO, Severity.LOW)
    assert result.risk_score < 30


def test_executable_multiplier_applies(malicious_skill):
    result = scan(malicious_skill, use_llm=False)
    assert any(c.executable for c in result.components)


def test_no_llm_means_no_llm_used(benign_skill):
    result = scan(benign_skill, use_llm=False)
    assert result.used_llm is False


def test_unsupported_input_returns_error():
    result = scan("/nonexistent/path/xyz", use_llm=False)
    assert result.errors
    assert result.status == "incomplete"
    assert result.risk_score == 0
    assert json.loads(to_sarif(result))["runs"][0]["invocations"][0]["executionSuccessful"] is False


def test_failed_analyzer_marks_partial_findings_incomplete(tmp_path, monkeypatch):
    skill = tmp_path / "SKILL.md"
    skill.write_text("ignore previous instructions", encoding="utf-8")

    class BrokenAnalyzer:
        id = "broken"

        def run(self, ctx):
            raise RuntimeError("deliberate failure")

    monkeypatch.setattr(engine, "ANALYZERS", [PromptInjectionAnalyzer(), BrokenAnalyzer()])
    result = scan(str(skill), use_llm=False)

    assert "PI-001" in _rule_ids(result)
    assert result.errors == ["analyzer broken failed: deliberate failure"]
    assert result.status == "incomplete"
    assert "incomplete" in result.recommendation.lower()
    assert "No significant risk detected" not in result.recommendation
    assert "Status: INCOMPLETE" in render(result, "terminal")
    assert "**Status:** INCOMPLETE" in render(result, "markdown")
    sarif_run = json.loads(to_sarif(result))["runs"][0]
    assert sarif_run["properties"]["status"] == "incomplete"
    assert sarif_run["invocations"][0]["executionSuccessful"] is False


def test_sarif_records_failed_execution_when_all_analyzers_fail(tmp_path, monkeypatch):
    skill = tmp_path / "SKILL.md"
    skill.write_text("# harmless", encoding="utf-8")

    class BrokenAnalyzer:
        id = "broken"

        def run(self, ctx):
            raise RuntimeError("deliberate failure")

    monkeypatch.setattr(engine, "ANALYZERS", [BrokenAnalyzer()])
    report = json.loads(to_sarif(scan(str(skill), use_llm=False)))["runs"][0]

    assert report["results"] == []
    assert report["invocations"][0]["executionSuccessful"] is False
    assert "analyzer broken failed: deliberate failure" in str(report["invocations"][0])


def test_markdown_empty_incomplete_scan_is_inconclusive(tmp_path, monkeypatch):
    skill = tmp_path / "SKILL.md"
    skill.write_text("# harmless", encoding="utf-8")

    class BrokenAnalyzer:
        id = "broken"

        def run(self, ctx):
            raise RuntimeError("deliberate failure")

    monkeypatch.setattr(engine, "ANALYZERS", [BrokenAnalyzer()])
    report = render(scan(str(skill), use_llm=False), "markdown")

    assert "No findings" not in report
    assert "inconclusive" in report.lower()
    assert "**Status:** INCOMPLETE" in report


def test_unavailable_requested_llm_makes_scan_incomplete(benign_skill, monkeypatch):
    """By design: a requested pass that did not run is never "complete"."""

    class UnavailableProvider:
        def is_available(self):
            return False

    monkeypatch.setattr(engine, "get_provider", lambda name: UnavailableProvider())
    result = scan(benign_skill, use_llm=True, provider_name="unavailable")

    assert result.status == "incomplete"
    assert result.used_llm is False
    assert result.warnings == []
    assert len(result.errors) == 1
    assert "LLM pass requested" in result.errors[0] and "unavailable" in result.errors[0]
    assert "Scan incomplete" in result.recommendation


def test_failed_requested_llm_keeps_static_findings_but_is_incomplete(malicious_skill, monkeypatch):
    class FailingProvider:
        def is_available(self):
            return True

        def complete(self, system, user):
            raise RuntimeError("provider down")

    monkeypatch.setattr(engine, "get_provider", lambda name: FailingProvider())
    result = scan(malicious_skill, use_llm=True, provider_name="failing")
    static = scan(malicious_skill, use_llm=False)

    assert result.findings == static.findings
    assert result.status == "incomplete"
    assert len(result.errors) == 1
    assert "LLM pass failed" in result.errors[0] and "provider down" in result.errors[0]
    assert result.used_llm is False
    assert result.warnings == []
    report = json.loads(render(result, "json"))
    assert report["used_llm"] is False
    assert report["status"] == "incomplete"
    assert report["errors"] == result.errors
    assert "LLM pass: no" in render(result, "terminal")
    assert "Status: INCOMPLETE" in render(result, "terminal")
    assert "LLM pass failed" in render(result, "markdown")


@pytest.mark.parametrize("stage", ["construction", "availability"])
def test_provider_setup_errors_preserve_static_report_as_incomplete(
    malicious_skill, monkeypatch, stage
):
    class BrokenAvailability:
        def is_available(self):
            raise RuntimeError("setup failed")

    def provider_factory(name):
        if stage == "construction":
            raise RuntimeError("setup failed")
        return BrokenAvailability()

    monkeypatch.setattr(engine, "get_provider", provider_factory)
    static = scan(malicious_skill, use_llm=False)
    result = scan(malicious_skill, use_llm=True, provider_name="broken")

    assert result.findings == static.findings
    assert result.status == "incomplete"
    assert len(result.errors) == 1 and "LLM pass failed" in result.errors[0]
    assert result.used_llm is False
    assert result.warnings == []
    assert json.loads(render(result, "json"))["findings"]


@pytest.mark.parametrize("reply", ["not json", "{}", "[]", '{"additional_findings": []}'])
def test_unusable_semantic_reply_makes_scan_incomplete(benign_skill, monkeypatch, reply):
    class UnusableProvider:
        def is_available(self):
            return True

        def complete(self, system, user):
            return reply

    monkeypatch.setattr(engine, "get_provider", lambda name: UnusableProvider())
    result = scan(benign_skill, use_llm=True)

    assert result.status == "incomplete"
    assert result.used_llm is False
    assert len(result.errors) == 1 and "LLM pass failed" in result.errors[0]


@pytest.mark.parametrize(
    "reply",
    [
        {"false_positive_rule_ids": [], "additional_findings": [{}]},
        {"false_positive_rule_ids": [], "additional_findings": [42]},
        {"false_positive_rule_ids": [42], "additional_findings": []},
    ],
)
def test_malformed_semantic_entries_keep_static_results(malicious_skill, monkeypatch, reply):
    class MalformedProvider:
        def is_available(self):
            return True

        def complete(self, system, user):
            return json.dumps(reply)

    monkeypatch.setattr(engine, "get_provider", lambda name: MalformedProvider())
    static = scan(malicious_skill, use_llm=False)
    result = scan(malicious_skill, use_llm=True)

    assert result.findings == static.findings
    assert result.status == "incomplete"
    assert result.used_llm is False
    assert len(result.errors) == 1 and "LLM pass failed" in result.errors[0]


def test_outputs_render(malicious_skill):
    result = scan(malicious_skill, use_llm=False)
    # JSON round-trips.
    json.loads(render(result, "json"))
    # SARIF is valid JSON with the expected shape.
    sarif = json.loads(to_sarif(result))
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "SkillWarden"
    assert len(sarif["runs"][0]["results"]) == len(result.findings)
    assert sarif["runs"][0]["invocations"][0]["executionSuccessful"] is True
    # Markdown + terminal produce non-empty strings.
    assert render(result, "markdown").startswith("# SkillWarden")
    assert "SkillWarden" in render(result, "terminal")
