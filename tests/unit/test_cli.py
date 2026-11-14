"""CLI exit behavior for scans that cannot resolve their input."""

import json

import pytest
from typer.testing import CliRunner

from skillwarden import engine
from skillwarden.cli import app


@pytest.mark.parametrize("fail_on", ["none", "critical", "high"])
def test_input_resolution_error_exits_nonzero_regardless_of_threshold(tmp_path, fail_on):
    missing = tmp_path / "missing-skill"

    result = CliRunner().invoke(
        app, ["scan", str(missing), "--no-llm", "--format", "json", "--fail-on", fail_on]
    )

    assert result.exit_code == 2
    report = json.loads(result.stdout)
    assert report["errors"] == [f"Unsupported input: {str(missing)!r}"]
    assert report["input_error"] is True
    assert report["risk_score"] == 0
    assert report["severity_label"] == "info"


@pytest.mark.parametrize("fail_on", ["none", "high"])
def test_analyzer_failure_exits_nonzero_with_partial_report(tmp_path, monkeypatch, fail_on):
    skill = tmp_path / "SKILL.md"
    skill.write_text("# harmless", encoding="utf-8")

    class BrokenAnalyzer:
        id = "broken"

        def run(self, ctx):
            raise RuntimeError("deliberate failure")

    monkeypatch.setattr(engine, "ANALYZERS", [BrokenAnalyzer()])
    result = CliRunner().invoke(
        app, ["scan", str(skill), "--no-llm", "--format", "json", "--fail-on", fail_on]
    )

    assert result.exit_code == 2
    report = json.loads(result.stdout)
    assert report["status"] == "incomplete"
    assert report["input_error"] is False
    assert report["severity_label"] == "info"
    assert "Scan incomplete" in report["recommendation"]
    assert report["errors"] == ["analyzer broken failed: deliberate failure"]


def test_no_registered_analyzers_returns_incomplete_report(tmp_path, monkeypatch):
    skill = tmp_path / "SKILL.md"
    skill.write_text("# harmless", encoding="utf-8")
    monkeypatch.setattr(engine, "ANALYZERS", [])

    result = CliRunner().invoke(
        app, ["scan", str(skill), "--no-llm", "--format", "json", "--fail-on", "none"]
    )

    assert result.exit_code == 2
    report = json.loads(result.stdout)
    assert report["status"] == "incomplete"
    assert report["errors"] == ["no analyzers registered"]
    assert "Scan incomplete" in report["recommendation"]


@pytest.mark.parametrize("fail_on", ["none", "high"])
def test_requested_llm_unavailable_exits_nonzero_as_incomplete(benign_skill, monkeypatch, fail_on):
    """By design: a requested LLM pass that did not run is not a warning —
    the scan is incomplete and the process exits 2 regardless of --fail-on."""

    class UnavailableProvider:
        def is_available(self):
            return False

    monkeypatch.setattr(engine, "get_provider", lambda name: UnavailableProvider())
    result = CliRunner().invoke(
        app, ["scan", benign_skill, "--format", "json", "--fail-on", fail_on]
    )

    assert result.exit_code == 2
    report = json.loads(result.stdout)
    assert report["status"] == "incomplete"
    assert report["used_llm"] is False
    assert len(report["errors"]) == 1
    assert "LLM pass requested" in report["errors"][0] and "unavailable" in report["errors"][0]
    assert report["warnings"] == []
    assert "Scan incomplete" in report["recommendation"]


def test_successful_scan_with_fail_on_none_exits_zero(benign_skill):
    result = CliRunner().invoke(
        app, ["scan", benign_skill, "--no-llm", "--format", "json", "--fail-on", "none"]
    )

    assert result.exit_code == 0
    report = json.loads(result.stdout)
    assert report["errors"] == []
    assert report["input_error"] is False
    assert report["status"] == "complete"


@pytest.mark.parametrize(
    "content",
    [None, "fingerprints: [unclosed\n", "- just\n- a list\n", "fingerprints: 7\n"],
    ids=["missing", "bad-yaml", "not-a-mapping", "not-a-list"],
)
def test_unusable_baseline_is_a_clear_refusal_exit_2(tmp_path, content):
    skill = tmp_path / "SKILL.md"
    skill.write_text("# harmless", encoding="utf-8")
    (tmp_path / "bl[").mkdir()
    baseline = tmp_path / "bl[" / "x]baseline.yaml"  # the path contains "[/x]"
    if content is not None:
        baseline.write_text(content, encoding="utf-8")

    result = CliRunner().invoke(app, ["scan", str(skill), "--no-llm", "-b", str(baseline)])

    assert result.exit_code == 2, result.output
    assert not isinstance(result.exception, Exception) or isinstance(result.exception, SystemExit)
    assert "baseline" in result.output.lower()


def test_valid_baseline_still_loads_and_suppresses(tmp_path, malicious_skill):
    baseline = tmp_path / "baseline.yaml"
    baseline.write_text("rule_globs: ['*']\nfingerprints: []\n", encoding="utf-8")

    result = CliRunner().invoke(
        app, ["scan", malicious_skill, "--no-llm", "-f", "json", "-b", str(baseline)]
    )

    assert result.exit_code == 0, result.output
    report = json.loads(result.stdout)
    assert report["findings"] == [] and report["suppressed"]
