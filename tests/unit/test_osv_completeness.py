"""The live known-vulnerability (OSV) lookup follows the completeness contract.

A skill that pins dependencies asks for a lookup. If the lookup cannot be made, or its
answer cannot be read, the scan is incomplete (exit 2): it is never reported as a clean
pass that silently skipped the check. `--no-osv` / `use_osv=False` skips it on request,
and the report says so.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from typer.testing import CliRunner

from skillwarden.analyzers import osv_client
from skillwarden.analyzers.osv_client import OsvAnalyzer, OsvLookupError
from skillwarden.cli import app
from skillwarden.engine import scan

SKILL_MD = "---\nname: tidy\ndescription: Formats notes.\n---\n\n# Tidy\n\nFormat the notes.\n"


def _skill(tmp_path: Path, requirements: str | None = "requests==2.19.0\n") -> str:
    (tmp_path / "SKILL.md").write_text(SKILL_MD, encoding="utf-8")
    if requirements is not None:
        (tmp_path / "requirements.txt").write_text(requirements, encoding="utf-8")
    return str(tmp_path)


class _Reply:
    def __init__(self, payload: Any, status: int = 200, raw: str | None = None) -> None:
        self._payload, self._status, self._raw = payload, status, raw

    def raise_for_status(self) -> None:
        if self._status >= 400:
            request = httpx.Request("POST", "https://api.osv.dev/v1/querybatch")
            raise httpx.HTTPStatusError(
                f"status {self._status}",
                request=request,
                response=httpx.Response(self._status, request=request),
            )

    def json(self) -> Any:
        if self._raw is not None:
            return json.loads(self._raw)
        return self._payload


def _osv_answers(
    monkeypatch: pytest.MonkeyPatch, reply: _Reply | Exception
) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []

    def fake_post(url: str, **kwargs: Any) -> _Reply:
        calls.append({"url": url, **kwargs})
        if isinstance(reply, Exception):
            raise reply
        return reply

    monkeypatch.setattr(osv_client.httpx, "post", fake_post)
    return calls


def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*_a: Any, **_k: Any) -> None:
        raise AssertionError("the OSV lookup must not be called here")

    monkeypatch.setattr(osv_client.httpx, "post", refuse)


# --- a lookup that did not run is not a pass --------------------------------------


@pytest.mark.parametrize(
    "failure",
    [
        httpx.ConnectError("no route to host"),
        httpx.ReadTimeout("timed out"),
        _Reply({}, status=500),
        _Reply({}, status=429),
        _Reply(None, raw="not json"),
        _Reply({"results": []}),  # fewer answers than dependencies
        _Reply({"results": "nope"}),
        _Reply(["not", "a", "mapping"]),
        _Reply({"results": [{"vulns": "nope"}]}),
        _Reply({"results": [{"vulns": ["not-a-mapping"]}]}),
        _Reply({"results": [None]}),
        _Reply({"results": ["x"]}),
        _Reply({"results": [{"vulns": [], "next_page_token": "more"}]}),
    ],
    ids=[
        "offline",
        "timeout",
        "http-500",
        "rate-limited",
        "not-json",
        "short-answer",
        "results-not-a-list",
        "payload-not-a-mapping",
        "vulns-not-a-list",
        "vuln-not-a-mapping",
        "entry-is-null",
        "entry-not-a-mapping",
        "more-pages-not-fetched",
    ],
)
def test_failed_lookup_makes_the_scan_incomplete(tmp_path, monkeypatch, failure):
    _osv_answers(monkeypatch, failure)

    result = scan(_skill(tmp_path), use_llm=False)

    assert result.status == "incomplete"
    assert any("osv_lookup failed" in e and "did not run" in e for e in result.errors)
    assert any("--no-osv" in e for e in result.errors)  # the way out is named
    assert "incomplete" in result.recommendation.lower()


def test_failed_lookup_keeps_the_other_findings(malicious_skill, tmp_path, monkeypatch):
    import shutil

    skill = tmp_path / "skill"
    shutil.copytree(malicious_skill, skill)
    (skill / "requirements.txt").write_text("requests==2.19.0\n", encoding="utf-8")
    _no_network(monkeypatch)
    static = scan(str(skill), use_llm=False, use_osv=False)
    _osv_answers(monkeypatch, httpx.ConnectError("offline"))

    result = scan(str(skill), use_llm=False)

    assert result.status == "incomplete"
    assert {f.rule_id for f in result.findings} == {f.rule_id for f in static.findings}
    assert result.findings  # the static findings are reported, never dropped


def test_failed_lookup_exits_2_from_the_command_line(tmp_path, monkeypatch):
    _osv_answers(monkeypatch, httpx.ConnectError("offline"))

    result = CliRunner().invoke(
        app, ["scan", _skill(tmp_path), "--no-llm", "--format", "json", "--fail-on", "none"]
    )

    assert result.exit_code == 2
    report = json.loads(result.stdout)
    assert report["status"] == "incomplete"


# --- a lookup that ran ---------------------------------------------------------------


def test_lookup_with_advisories_reports_them_and_is_complete(tmp_path, monkeypatch):
    calls = _osv_answers(
        monkeypatch, _Reply({"results": [{"vulns": [{"id": "GHSA-x84v-xcm2-53pg"}]}]})
    )

    result = scan(_skill(tmp_path), use_llm=False)

    assert result.status == "complete"
    assert [f.rule_id for f in result.findings] == ["OSV-VULN"]
    assert "GHSA-x84v-xcm2-53pg" in result.findings[0].description
    sent = calls[0]["json"]["queries"]
    assert sent == [{"package": {"name": "requests", "ecosystem": "PyPI"}, "version": "2.19.0"}]


def test_lookup_with_no_advisories_is_complete_and_clean(tmp_path, monkeypatch):
    _osv_answers(monkeypatch, _Reply({"results": [{}]}))

    result = scan(_skill(tmp_path), use_llm=False)

    assert result.status == "complete"
    assert result.findings == []
    assert result.warnings == []


def test_answers_are_matched_to_dependencies_in_order(tmp_path, monkeypatch):
    _osv_answers(monkeypatch, _Reply({"results": [{}, {"vulns": [{"id": "PYSEC-1"}]}]}))

    result = scan(_skill(tmp_path, "safe-one==1.0.0\nold-two==0.1.0\n"), use_llm=False)

    assert [f.title for f in result.findings] == ["Known vulnerability in old-two==0.1.0"]


# --- skipped on request --------------------------------------------------------------


def test_no_osv_makes_no_call_and_says_what_was_not_checked(tmp_path, monkeypatch):
    _no_network(monkeypatch)

    result = scan(_skill(tmp_path, "a==1.0.0\nb==2.0.0\n"), use_llm=False, use_osv=False)

    assert result.status == "complete"  # a part skipped on request was not requested
    assert result.warnings == [
        "OSV lookup skipped (--no-osv): 2 pinned dependencies were not checked "
        "for known vulnerabilities"
    ]


def test_no_osv_flag_from_the_command_line(tmp_path, monkeypatch):
    _no_network(monkeypatch)

    result = CliRunner().invoke(
        app, ["scan", _skill(tmp_path), "--no-llm", "--no-osv", "--format", "json"]
    )

    assert result.exit_code == 0
    report = json.loads(result.stdout)
    assert report["status"] == "complete"
    assert report["warnings"] == [
        "OSV lookup skipped (--no-osv): 1 pinned dependency was not checked "
        "for known vulnerabilities"
    ]


def test_no_osv_still_runs_every_other_analyzer(malicious_skill, monkeypatch):
    _no_network(monkeypatch)

    with_lookup = scan(malicious_skill, use_llm=False)  # no pinned deps: no call either way
    without = scan(malicious_skill, use_llm=False, use_osv=False)

    assert {f.rule_id for f in without.findings} == {f.rule_id for f in with_lookup.findings}
    assert without.severity_label == with_lookup.severity_label


# --- nothing to look up --------------------------------------------------------------


@pytest.mark.parametrize("use_osv", [True, False])
def test_a_skill_without_pinned_dependencies_needs_no_lookup(tmp_path, monkeypatch, use_osv):
    _no_network(monkeypatch)

    result = scan(_skill(tmp_path, requirements=None), use_llm=False, use_osv=use_osv)

    assert result.status == "complete"
    assert result.warnings == []


def test_analyzer_raises_a_named_error():
    from skillwarden.analyzers.base import ScanContext
    from skillwarden.models import Component

    ctx = ScanContext(
        target="t",
        components=[
            Component(
                path="requirements.txt", type="other", lines=1, size_bytes=16, executable=False
            )
        ],
        file_cache={"requirements.txt": "requests==2.19.0\n"},
    )
    original = osv_client.httpx.post
    try:
        osv_client.httpx.post = lambda *a, **k: (_ for _ in ()).throw(httpx.ConnectError("x"))
        with pytest.raises(OsvLookupError, match="1 pinned dependency"):
            OsvAnalyzer().run(ctx)
    finally:
        osv_client.httpx.post = original
