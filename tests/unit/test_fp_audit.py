"""The audit gate must not turn incomplete scans into a clean corpus verdict."""

from __future__ import annotations

import hashlib
import struct
import subprocess
import sys
from pathlib import Path

from scripts import fp_audit
from skillwarden.models import Category, Finding, ScanResult, Severity, SkippedInput
from skillwarden.report.scoring import apply_score

GITLINK = 0o160000  # index mode of a submodule entry (a directory in the worktree)


def _fake_git(
    worktree: Path,
    paths: list[str],
    *,
    index_version: int = 2,
    modes: dict[str, int] | None = None,
) -> None:
    """Write the minimum of a *complete* clone: `.git/HEAD` plus a v2 index that lists
    ``paths`` (the same format `git clone` leaves behind, so the audit's offline
    completeness check has something real to verify)."""
    git = worktree / ".git"
    git.mkdir(parents=True, exist_ok=True)
    (git / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    body = b"DIRC" + struct.pack(">II", index_version, len(paths))
    for p in sorted(paths):
        name = p.encode()
        mode = (modes or {}).get(p, 0o100644)
        entry = struct.pack(">10I", 0, 0, 0, 0, 0, 0, mode, 0, 0, 0) + b"\0" * 20
        entry += struct.pack(">H", len(name)) + name + b"\0"
        entry += b"\0" * ((8 - (len(entry) % 8)) % 8)
        body += entry
    (git / "index").write_bytes(body + hashlib.sha1(body).digest())


def test_incomplete_scan_fails_audit_even_with_budget(tmp_path, monkeypatch, capsys):
    skill = tmp_path / "benign" / "SKILL.md"
    skill.parent.mkdir()
    skill.write_text("# harmless", encoding="utf-8")
    monkeypatch.setattr(
        fp_audit,
        "scan",
        lambda path, use_llm, use_osv: ScanResult(target=path, errors=["analyzer broken failed"]),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["fp_audit.py", "--corpus", str(tmp_path), "--no-fetch", "--max-critical", "99"],
    )

    assert fp_audit.main() != 0
    output = capsys.readouterr().out
    assert "FAIL" in output
    assert "benign" in output
    assert "analyzer broken failed" in output
    assert "OK:" not in output


def test_complete_static_scan_within_budget_passes_audit(tmp_path, monkeypatch, capsys):
    skill = tmp_path / "benign" / "SKILL.md"
    skill.parent.mkdir()
    skill.write_text("# harmless", encoding="utf-8")
    monkeypatch.setattr(fp_audit, "scan", lambda path, use_llm, use_osv: ScanResult(target=path))
    monkeypatch.setattr(sys, "argv", ["fp_audit.py", "--corpus", str(tmp_path), "--no-fetch"])

    assert fp_audit.main() == 0
    assert "OK:" in capsys.readouterr().out


def test_empty_corpus_fails_audit_without_fetching(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["fp_audit.py", "--corpus", str(tmp_path), "--no-fetch"])

    assert fp_audit.main() != 0
    output = capsys.readouterr().out
    assert "FAIL" in output
    assert "no skills found" in output
    assert "OK:" not in output


def test_failed_fetch_fails_audit_even_when_cached_skill_scans(tmp_path, monkeypatch, capsys):
    skill = tmp_path / "cached" / "benign" / "SKILL.md"
    skill.parent.mkdir(parents=True)
    skill.write_text("# harmless", encoding="utf-8")
    monkeypatch.setattr(fp_audit, "BENIGN_SOURCES", [("cached", "cached-url"), ("missing", "url")])

    def failed_clone(*args, **kwargs):
        raise subprocess.CalledProcessError(1, args[0])

    monkeypatch.setattr(fp_audit.subprocess, "run", failed_clone)
    scanned = []

    def scan_cached(path, use_llm, use_osv):
        scanned.append(path)
        return ScanResult(target=path)

    monkeypatch.setattr(fp_audit, "scan", scan_cached)
    monkeypatch.setattr(sys, "argv", ["fp_audit.py", "--corpus", str(tmp_path), "--fetch"])

    assert fp_audit.main() != 0
    assert scanned == [str(skill.parent)]
    output = capsys.readouterr().out
    assert "FAIL" in output and "missing" in output
    assert "OK:" not in output


# ── network is opt-in; a partial clone is never a corpus ─────────────────


def _no_network(*args, **kwargs):
    raise AssertionError("fp_audit made a network/subprocess call without --fetch")


def test_default_run_makes_no_network_call(tmp_path, monkeypatch, capsys):
    skill = tmp_path / "cached" / "SKILL.md"
    skill.parent.mkdir()
    skill.write_text("# harmless", encoding="utf-8")
    monkeypatch.setattr(fp_audit.subprocess, "run", _no_network)
    monkeypatch.setattr(fp_audit, "scan", lambda path, use_llm, use_osv: ScanResult(target=path))
    monkeypatch.setattr(sys, "argv", ["fp_audit.py", "--corpus", str(tmp_path)])

    assert fp_audit.main() == 0
    assert "OK:" in capsys.readouterr().out


def test_empty_default_corpus_fails_without_network(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(fp_audit.subprocess, "run", _no_network)
    monkeypatch.setattr(sys, "argv", ["fp_audit.py", "--corpus", str(tmp_path)])

    assert fp_audit.main() != 0
    assert "OK:" not in capsys.readouterr().out


def test_explicit_fetch_clones_into_place(tmp_path, monkeypatch, capsys):
    corpus = tmp_path / "corpus"
    monkeypatch.setattr(fp_audit, "BENIGN_SOURCES", [("src", "https://example.invalid/x")])
    calls = []

    def fake_clone(cmd, **kwargs):
        calls.append(cmd)
        target = Path(cmd[-1])
        (target / "s").mkdir(parents=True)
        (target / "s" / "SKILL.md").write_text("# ok", encoding="utf-8")
        _fake_git(target, ["s/SKILL.md"])

    monkeypatch.setattr(fp_audit.subprocess, "run", fake_clone)
    monkeypatch.setattr(fp_audit, "scan", lambda path, use_llm, use_osv: ScanResult(target=path))
    monkeypatch.setattr(sys, "argv", ["fp_audit.py", "--corpus", str(corpus), "--fetch"])

    assert fp_audit.main() == 0
    assert len(calls) == 1
    assert (corpus / "src" / "s" / "SKILL.md").is_file()
    assert "-c" in calls[0] and "http.followRedirects=false" in calls[0]  # item 6


def test_timed_out_clone_leaves_no_partial_corpus(tmp_path, monkeypatch, capsys):
    corpus = tmp_path / "corpus"
    monkeypatch.setattr(fp_audit, "BENIGN_SOURCES", [("src", "https://example.invalid/x")])

    def partial_then_timeout(cmd, **kwargs):
        target = Path(cmd[-1])
        (target / "half").mkdir(parents=True)
        (target / "half" / "SKILL.md").write_text("# partial", encoding="utf-8")
        raise subprocess.TimeoutExpired(cmd, 1)

    scanned = []
    monkeypatch.setattr(fp_audit.subprocess, "run", partial_then_timeout)
    monkeypatch.setattr(
        fp_audit,
        "scan",
        lambda path, use_llm, use_osv: scanned.append(path) or ScanResult(target=path),
    )
    monkeypatch.setattr(sys, "argv", ["fp_audit.py", "--corpus", str(corpus), "--fetch"])

    assert fp_audit.main() != 0
    output = capsys.readouterr().out
    assert "FAIL" in output and "OK:" not in output
    assert scanned == []  # the half-cloned skill was never audited as if it were the corpus
    assert not (corpus / "src").exists()

    # and a re-run must retry the clone rather than trust a leftover directory
    monkeypatch.setattr(fp_audit.subprocess, "run", partial_then_timeout)
    assert fp_audit.main() != 0


def test_preexisting_non_git_source_dir_is_not_trusted_on_fetch(tmp_path, monkeypatch, capsys):
    corpus = tmp_path / "corpus"
    leftover = corpus / "src" / "half"
    leftover.mkdir(parents=True)
    (leftover / "SKILL.md").write_text("# partial", encoding="utf-8")
    monkeypatch.setattr(fp_audit, "BENIGN_SOURCES", [("src", "https://example.invalid/x")])
    monkeypatch.setattr(fp_audit.subprocess, "run", _no_network)
    monkeypatch.setattr(fp_audit, "scan", lambda path, use_llm, use_osv: ScanResult(target=path))
    monkeypatch.setattr(sys, "argv", ["fp_audit.py", "--corpus", str(corpus), "--fetch"])

    assert fp_audit.main() != 0
    output = capsys.readouterr().out
    assert "src" in output and "FAIL" in output and "OK:" not in output


def test_fetch_and_no_fetch_together_stay_offline(tmp_path, monkeypatch, capsys):
    skill = tmp_path / "cached" / "SKILL.md"
    skill.parent.mkdir()
    skill.write_text("# harmless", encoding="utf-8")
    monkeypatch.setattr(fp_audit.subprocess, "run", _no_network)
    monkeypatch.setattr(fp_audit, "scan", lambda path, use_llm, use_osv: ScanResult(target=path))
    monkeypatch.setattr(
        sys, "argv", ["fp_audit.py", "--corpus", str(tmp_path), "--fetch", "--no-fetch"]
    )

    assert fp_audit.main() == 0


def _fetch_with(monkeypatch, tmp_path, run):
    monkeypatch.setattr(fp_audit, "BENIGN_SOURCES", [("src", "https://example.invalid/x")])
    monkeypatch.setattr(fp_audit.subprocess, "run", run)
    monkeypatch.setattr(fp_audit, "scan", lambda path, use_llm, use_osv: ScanResult(target=path))
    monkeypatch.setattr(sys, "argv", ["fp_audit.py", "--corpus", str(tmp_path), "--fetch"])


def test_missing_git_binary_is_a_reported_failure_not_a_traceback(tmp_path, monkeypatch, capsys):
    def no_git(cmd, **kwargs):
        raise FileNotFoundError("git")

    _fetch_with(monkeypatch, tmp_path, no_git)

    assert fp_audit.main() != 0
    output = capsys.readouterr().out
    assert "FAIL" in output and "src" in output and "OK:" not in output


def test_failure_moving_clone_into_place_is_reported_not_trusted(tmp_path, monkeypatch, capsys):
    def clone_ok(cmd, **kwargs):
        (Path(cmd[-1]) / "s").mkdir(parents=True)
        (Path(cmd[-1]) / "s" / "SKILL.md").write_text("# ok", encoding="utf-8")
        _fake_git(Path(cmd[-1]), ["s/SKILL.md"])

    def move_fails(src, dst):
        raise OSError("disk full")

    _fetch_with(monkeypatch, tmp_path, clone_ok)
    monkeypatch.setattr(fp_audit.shutil, "move", move_fails)

    assert fp_audit.main() != 0
    output = capsys.readouterr().out
    assert "disk full" in output and "OK:" not in output
    assert not (tmp_path / "src").exists()


def test_critical_skill_over_budget_fails_and_is_named(tmp_path, monkeypatch, capsys):
    skill = tmp_path / "evil" / "SKILL.md"
    skill.parent.mkdir()
    skill.write_text("# x", encoding="utf-8")
    critical = Finding(
        rule_id="PI-001",
        category=Category.PROMPT_INJECTION,
        severity=Severity.CRITICAL,
        title="t",
        description="d",
    )
    monkeypatch.setattr(
        fp_audit,
        "scan",
        lambda path, use_llm, use_osv: apply_score(ScanResult(target=path, findings=[critical])),
    )
    monkeypatch.setattr(sys, "argv", ["fp_audit.py", "--corpus", str(tmp_path)])

    assert fp_audit.main() == 1
    output = capsys.readouterr().out
    assert "rated CRITICAL" in output and "evil" in output and "OK:" not in output


# ── item 4: a half-clone with a `.git` dir is not a corpus ────────────────


def _half_clone_cases(corpus: Path) -> dict[str, Path]:
    """Each returns a `src` dir that LOOKS cloned (has `.git`) but is not complete."""
    cases: dict[str, Path] = {}

    d = corpus / "no-head" / "src"
    (d / "s").mkdir(parents=True)
    (d / "s" / "SKILL.md").write_text("# x", encoding="utf-8")
    (d / ".git").mkdir()  # the legacy shape: an empty .git dir
    cases["no-head"] = d

    d = corpus / "empty-head" / "src"
    _fake_git(d, ["s/SKILL.md"])
    (d / "s").mkdir()
    (d / "s" / "SKILL.md").write_text("# x", encoding="utf-8")
    (d / ".git" / "HEAD").write_text("", encoding="utf-8")
    cases["empty-head"] = d

    d = corpus / "index-lock" / "src"
    _fake_git(d, ["s/SKILL.md"])
    (d / "s").mkdir()
    (d / "s" / "SKILL.md").write_text("# x", encoding="utf-8")
    (d / ".git" / "index.lock").write_bytes(b"")  # interrupted checkout marker
    cases["index-lock"] = d

    d = corpus / "no-index" / "src"
    _fake_git(d, ["s/SKILL.md"])
    (d / "s").mkdir()
    (d / "s" / "SKILL.md").write_text("# x", encoding="utf-8")
    (d / ".git" / "index").unlink()
    cases["no-index"] = d

    d = corpus / "missing-worktree-file" / "src"
    _fake_git(d, ["s/SKILL.md", "s/run.py", "t/SKILL.md"])
    (d / "s").mkdir()
    (d / "s" / "SKILL.md").write_text("# x", encoding="utf-8")  # run.py and t/ never arrived
    cases["missing-worktree-file"] = d

    d = corpus / "empty-tree" / "src"
    _fake_git(d, [])
    cases["empty-tree"] = d

    d = corpus / "no-skill" / "src"
    _fake_git(d, ["README.md"])
    (d / "README.md").write_text("# no SKILL.md anywhere", encoding="utf-8")
    cases["no-skill"] = d

    d = corpus / "truncated-index" / "src"
    _fake_git(d, ["s/SKILL.md"])
    (d / "s").mkdir()
    (d / "s" / "SKILL.md").write_text("# x", encoding="utf-8")
    idx = d / ".git" / "index"
    idx.write_bytes(idx.read_bytes()[:-30])
    cases["truncated-index"] = d

    d = corpus / "unsupported-index-version" / "src"
    _fake_git(d, ["s/SKILL.md"], index_version=4)
    (d / "s").mkdir()
    (d / "s" / "SKILL.md").write_text("# x", encoding="utf-8")
    cases["unsupported-index-version"] = d
    return cases


def test_half_clone_cases_are_all_rejected_on_fetch(tmp_path, monkeypatch, capsys):
    cases = _half_clone_cases(tmp_path)
    assert len(cases) >= 9
    for name, src in cases.items():
        monkeypatch.setattr(fp_audit, "BENIGN_SOURCES", [("src", "https://example.invalid/x")])
        monkeypatch.setattr(fp_audit.subprocess, "run", _no_network)
        monkeypatch.setattr(
            fp_audit, "scan", lambda path, use_llm, use_osv: ScanResult(target=path)
        )
        monkeypatch.setattr(sys, "argv", ["fp_audit.py", "--corpus", str(src.parent), "--fetch"])

        rc = fp_audit.main()
        output = capsys.readouterr().out
        assert rc != 0, name
        assert "FAIL" in output and "src" in output and "OK:" not in output, name
        assert "incomplete" in output.lower() or "not a complete" in output, (name, output)
        assert "OK:" not in output, name


def test_half_clone_cases_are_all_rejected_offline(tmp_path, monkeypatch, capsys):
    # The default `make audit` (no --fetch) must not trust a cached half-clone either.
    cases = _half_clone_cases(tmp_path)
    for name, src in cases.items():
        monkeypatch.setattr(fp_audit.subprocess, "run", _no_network)
        monkeypatch.setattr(
            fp_audit, "scan", lambda path, use_llm, use_osv: ScanResult(target=path)
        )
        monkeypatch.setattr(sys, "argv", ["fp_audit.py", "--corpus", str(src.parent)])

        rc = fp_audit.main()
        output = capsys.readouterr().out
        assert rc != 0, (name, output)
        assert "FAIL" in output and "OK:" not in output, (name, output)
        assert "incomplete" in output.lower() or "not a complete" in output, (name, output)


def test_half_clone_nested_deeper_or_as_corpus_root_is_rejected_offline(
    tmp_path, monkeypatch, capsys
):
    cases = _half_clone_cases(tmp_path / "c")
    deep = tmp_path / "deep" / "group" / "team"
    deep.parent.mkdir(parents=True)
    cases["missing-worktree-file"].rename(deep)
    for corpus in (tmp_path / "deep", deep):
        monkeypatch.setattr(fp_audit.subprocess, "run", _no_network)
        monkeypatch.setattr(
            fp_audit, "scan", lambda path, use_llm, use_osv: ScanResult(target=path)
        )
        monkeypatch.setattr(sys, "argv", ["fp_audit.py", "--corpus", str(corpus)])

        assert fp_audit.main() != 0, corpus
        output = capsys.readouterr().out
        assert "s/run.py" in output and "OK:" not in output, output


def test_complete_clone_and_plain_skill_dirs_pass_offline(tmp_path, monkeypatch, capsys):
    src = tmp_path / "src"
    _fake_git(src, ["s/SKILL.md"])
    (src / "s").mkdir()
    (src / "s" / "SKILL.md").write_text("# x", encoding="utf-8")
    plain = tmp_path / "mine" / "skill"  # not a clone: a user's own skill directory
    plain.mkdir(parents=True)
    (plain / "SKILL.md").write_text("# y", encoding="utf-8")
    monkeypatch.setattr(fp_audit.subprocess, "run", _no_network)
    monkeypatch.setattr(fp_audit, "scan", lambda path, use_llm, use_osv: ScanResult(target=path))
    monkeypatch.setattr(sys, "argv", ["fp_audit.py", "--corpus", str(tmp_path)])

    assert fp_audit.main() == 0
    assert "OK:" in capsys.readouterr().out


def test_complete_clone_is_accepted_on_fetch_without_network(tmp_path, monkeypatch, capsys):
    src = tmp_path / "src"
    _fake_git(src, ["s/SKILL.md", "s/run.py"])
    (src / "s").mkdir()
    (src / "s" / "SKILL.md").write_text("# x", encoding="utf-8")
    (src / "s" / "run.py").write_text("print(1)\n", encoding="utf-8")
    monkeypatch.setattr(fp_audit, "BENIGN_SOURCES", [("src", "https://example.invalid/x")])
    monkeypatch.setattr(fp_audit.subprocess, "run", _no_network)
    monkeypatch.setattr(fp_audit, "scan", lambda path, use_llm, use_osv: ScanResult(target=path))
    monkeypatch.setattr(sys, "argv", ["fp_audit.py", "--corpus", str(tmp_path), "--fetch"])

    assert fp_audit.main() == 0
    assert "OK:" in capsys.readouterr().out


def test_clone_completeness_reasons_are_specific(tmp_path):
    cases = _half_clone_cases(tmp_path)
    reasons = {name: fp_audit.clone_incomplete_reason(src) for name, src in cases.items()}
    assert all(reasons.values()), reasons
    assert "HEAD" in reasons["no-head"]
    assert "HEAD" in reasons["empty-head"]
    assert "index.lock" in reasons["index-lock"]
    assert "index" in reasons["no-index"]
    assert "s/run.py" in reasons["missing-worktree-file"]
    assert "empty" in reasons["empty-tree"]
    assert "SKILL.md" in reasons["no-skill"]
    assert "index" in reasons["truncated-index"]
    assert "version" in reasons["unsupported-index-version"]


# ── item 6: the fetch path refuses redirects and non-https sources ─────────


def test_fetch_refuses_non_https_source_without_running_git(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(fp_audit, "BENIGN_SOURCES", [("src", "http://example.invalid/x")])
    monkeypatch.setattr(fp_audit.subprocess, "run", _no_network)
    monkeypatch.setattr(sys, "argv", ["fp_audit.py", "--corpus", str(tmp_path), "--fetch"])

    assert fp_audit.main() != 0
    output = capsys.readouterr().out
    assert "FAIL" in output and "https" in output and "OK:" not in output


def test_fetch_clone_command_disables_redirects(tmp_path, monkeypatch, capsys):
    calls = []

    def fake_clone(cmd, **kwargs):
        calls.append(cmd)
        target = Path(cmd[-1])
        (target / "s").mkdir(parents=True)
        (target / "s" / "SKILL.md").write_text("# ok", encoding="utf-8")
        _fake_git(target, ["s/SKILL.md"])

    _fetch_with(monkeypatch, tmp_path, fake_clone)
    assert fp_audit.main() == 0
    cmd = calls[0]
    assert cmd[:2] == ["git", "-c"]
    assert "http.followRedirects=false" in cmd
    assert cmd.index("http.followRedirects=false") < cmd.index("clone")


# ── items 1/2: any non-complete scan fails the audit, and skipped inputs are shown ──


def test_scan_with_skipped_input_fails_audit_and_names_the_file(tmp_path, monkeypatch, capsys):
    skill = tmp_path / "benign" / "SKILL.md"
    skill.parent.mkdir()
    skill.write_text("# harmless", encoding="utf-8")
    monkeypatch.setattr(
        fp_audit,
        "scan",
        lambda path, use_llm, use_osv: ScanResult(
            target=path, skipped=[SkippedInput(path="big.bin", reason="per-file limit")]
        ),
    )
    monkeypatch.setattr(sys, "argv", ["fp_audit.py", "--corpus", str(tmp_path)])

    assert fp_audit.main() != 0
    output = capsys.readouterr().out
    assert "FAIL" in output and "big.bin" in output and "OK:" not in output


def test_audit_never_requests_an_llm_pass(tmp_path, monkeypatch):
    skill = tmp_path / "benign" / "SKILL.md"
    skill.parent.mkdir()
    skill.write_text("# harmless", encoding="utf-8")
    seen = []
    monkeypatch.setattr(
        fp_audit,
        "scan",
        lambda path, use_llm, use_osv: seen.append(use_llm) or ScanResult(target=path),
    )
    monkeypatch.setattr(sys, "argv", ["fp_audit.py", "--corpus", str(tmp_path)])
    assert fp_audit.main() == 0
    assert seen == [False]


# ── submodule gitlinks and duplicate reasons ─────


def test_clone_with_submodule_gitlink_is_a_complete_clone(tmp_path):
    """A gitlink (mode 160000) is a directory in the worktree, not a file: a clone that
    contains a submodule must not be rejected as 'indexed file missing'."""
    src = tmp_path / "src"
    _fake_git(src, ["s/SKILL.md", "vendor/lib"], modes={"vendor/lib": GITLINK})
    (src / "s").mkdir()
    (src / "s" / "SKILL.md").write_text("# x", encoding="utf-8")
    (src / "vendor" / "lib").mkdir(parents=True)  # an un-initialised submodule: empty dir
    assert fp_audit.clone_incomplete_reason(src) is None


def test_clone_with_submodule_dir_missing_is_still_incomplete(tmp_path):
    src = tmp_path / "src"
    _fake_git(src, ["s/SKILL.md", "vendor/lib"], modes={"vendor/lib": GITLINK})
    (src / "s").mkdir()
    (src / "s" / "SKILL.md").write_text("# x", encoding="utf-8")
    reason = fp_audit.clone_incomplete_reason(src)
    assert reason is not None and "vendor/lib" in reason


def test_incomplete_reasons_are_not_printed_twice(tmp_path, monkeypatch, capsys):
    """The engine already lists every skipped input under ``errors``; the audit must not
    print the same reason a second time from ``skipped``."""
    skill = tmp_path / "benign" / "SKILL.md"
    skill.parent.mkdir()
    skill.write_text("# harmless", encoding="utf-8")
    monkeypatch.setattr(
        fp_audit,
        "scan",
        lambda path, use_llm, use_osv: ScanResult(
            target=path,
            errors=["input skipped: big.bin: per-file limit"],
            skipped=[SkippedInput(path="big.bin", reason="per-file limit")],
        ),
    )
    monkeypatch.setattr(sys, "argv", ["fp_audit.py", "--corpus", str(tmp_path)])

    assert fp_audit.main() != 0
    output = capsys.readouterr().out
    assert output.count("input skipped: big.bin: per-file limit") == 1, output


# --- a skill that cannot be scanned to completion, by design ----------------------


def _corpus_with(tmp_path: Path, *names: str) -> None:
    for name in names:
        skill = tmp_path / name / "SKILL.md"
        skill.parent.mkdir()
        skill.write_text("# harmless", encoding="utf-8")


def _incomplete(reason: str):
    def fake(path, use_llm, use_osv):
        return ScanResult(target=path, skipped=[SkippedInput(path="a.tar.gz", reason=reason)])

    return fake


def test_a_named_expected_incomplete_skill_is_reported_and_does_not_fail(
    tmp_path, monkeypatch, capsys
):
    _corpus_with(tmp_path, "web-artifacts-builder")
    monkeypatch.setattr(
        fp_audit, "scan", _incomplete("nested archive (gzip) not scanned; unpack it")
    )
    monkeypatch.setattr(sys, "argv", ["fp_audit.py", "--corpus", str(tmp_path)])

    assert fp_audit.main() == 0
    output = capsys.readouterr().out
    assert "cannot be scanned to completion, by design" in output
    assert "web-artifacts-builder" in output and "nested archive" in output
    assert "FAIL" not in output


def test_the_exception_covers_only_the_named_reason(tmp_path, monkeypatch, capsys):
    _corpus_with(tmp_path, "web-artifacts-builder")
    monkeypatch.setattr(fp_audit, "scan", _incomplete("unreadable: Permission denied"))
    monkeypatch.setattr(sys, "argv", ["fp_audit.py", "--corpus", str(tmp_path)])

    assert fp_audit.main() != 0
    assert "FAIL: 1 incomplete static scan(s)" in capsys.readouterr().out


def test_the_exception_covers_only_the_named_skill(tmp_path, monkeypatch, capsys):
    _corpus_with(tmp_path, "some-other-skill")
    monkeypatch.setattr(
        fp_audit, "scan", _incomplete("nested archive (gzip) not scanned; unpack it")
    )
    monkeypatch.setattr(sys, "argv", ["fp_audit.py", "--corpus", str(tmp_path)])

    assert fp_audit.main() != 0
    assert "FAIL: 1 incomplete static scan(s)" in capsys.readouterr().out


def test_one_unexpected_reason_among_expected_ones_still_fails(tmp_path, monkeypatch, capsys):
    _corpus_with(tmp_path, "web-artifacts-builder")

    def fake(path, use_llm, use_osv):
        return ScanResult(
            target=path,
            skipped=[
                SkippedInput(path="a.tar.gz", reason="nested archive (gzip) not scanned"),
                SkippedInput(path="b.py", reason="unreadable: Permission denied"),
            ],
        )

    monkeypatch.setattr(fp_audit, "scan", fake)
    monkeypatch.setattr(sys, "argv", ["fp_audit.py", "--corpus", str(tmp_path)])

    assert fp_audit.main() != 0


# --- the audit names the commit it measured -----------------------------------------


def test_commit_of_reads_a_detached_head(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "HEAD").write_text("2c5958ecac7c0000000000000000000000000000\n")
    assert fp_audit._commit_of(tmp_path) == "2c5958ecac7c"


def test_commit_of_follows_a_loose_ref(tmp_path):
    git = tmp_path / ".git"
    (git / "refs" / "heads").mkdir(parents=True)
    (git / "HEAD").write_text("ref: refs/heads/main\n")
    (git / "refs" / "heads" / "main").write_text("abcdef0123456789abcdef0123456789abcdef01\n")
    assert fp_audit._commit_of(tmp_path) == "abcdef012345"


def test_commit_of_follows_a_packed_ref(tmp_path):
    git = tmp_path / ".git"
    git.mkdir()
    (git / "HEAD").write_text("ref: refs/heads/main\n")
    (git / "packed-refs").write_text(
        "# pack-refs with: peeled fully-peeled sorted\n"
        "1111111111111111111111111111111111111111 refs/heads/other\n"
        "fedcba9876543210fedcba9876543210fedcba98 refs/heads/main\n"
    )
    assert fp_audit._commit_of(tmp_path) == "fedcba987654"


def test_commit_of_says_unknown_rather_than_guess(tmp_path):
    assert fp_audit._commit_of(tmp_path) == "unknown"
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    assert fp_audit._commit_of(tmp_path) == "unknown"


def test_audit_prints_the_commit_of_each_corpus_source(tmp_path, monkeypatch, capsys):
    source = tmp_path / "published"
    skill = source / "tidy" / "SKILL.md"
    skill.parent.mkdir(parents=True)
    skill.write_text("# harmless", encoding="utf-8")
    _fake_git(source, ["tidy/SKILL.md"])
    (source / ".git" / "HEAD").write_text("2c5958ecac7c0000000000000000000000000000\n")
    monkeypatch.setattr(fp_audit, "scan", lambda path, use_llm, use_osv: ScanResult(target=path))
    monkeypatch.setattr(sys, "argv", ["fp_audit.py", "--corpus", str(tmp_path)])

    assert fp_audit.main() == 0
    assert "corpus source published at commit 2c5958ecac7c" in capsys.readouterr().out


# --- benign skills the fixed rules are known to rate critical ---------------------

KNOWN = "anthropic-skills/skills/claude-api"


def _skill_at(tmp_path: Path, where: str) -> None:
    skill = tmp_path / where / "SKILL.md"
    skill.parent.mkdir(parents=True)
    skill.write_text("# harmless", encoding="utf-8")


def _rated_critical(*rules: str):
    def fake(path, use_llm, use_osv):
        findings = [
            Finding(
                rule_id=rule,
                category=Category.SUPPLY_CHAIN,
                severity=Severity.CRITICAL,
                title="t",
                description="d",
                file="SKILL.md",
                line=1,
            )
            for rule in rules
        ]
        return apply_score(ScanResult(target=path, findings=findings * 3))

    return fake


def _run_audit(tmp_path, monkeypatch, capsys, fake) -> tuple[int, str]:
    monkeypatch.setattr(fp_audit, "scan", fake)
    monkeypatch.setattr(sys, "argv", ["fp_audit.py", "--corpus", str(tmp_path)])
    return fp_audit.main(), capsys.readouterr().out


def test_a_known_false_alarm_is_reported_apart_and_does_not_fail(tmp_path, monkeypatch, capsys):
    _skill_at(tmp_path, KNOWN)

    code, output = _run_audit(tmp_path, monkeypatch, capsys, _rated_critical("SC-001", "TM-001"))

    assert code == 0
    assert "rated CRITICAL by the fixed rules, as known" in output
    assert f"{KNOWN}: documentation that discusses security" in output
    assert "OK: 0 CRITICAL" in output


def test_any_other_critical_skill_still_fails(tmp_path, monkeypatch, capsys):
    _skill_at(tmp_path, KNOWN)
    _skill_at(tmp_path, "anthropic-skills/skills/some-other-skill")

    code, output = _run_audit(tmp_path, monkeypatch, capsys, _rated_critical("SC-001"))

    assert code != 0
    assert "FAIL: 1 skill(s) rated CRITICAL (budget 0): some-other-skill" in output


def test_a_skill_with_the_same_name_somewhere_else_is_not_excused(tmp_path, monkeypatch, capsys):
    _skill_at(tmp_path, "another-source/claude-api")

    code, output = _run_audit(tmp_path, monkeypatch, capsys, _rated_critical("SC-001"))

    assert code != 0
    assert "FAIL: 1 skill(s) rated CRITICAL (budget 0): claude-api" in output
    assert "as known" not in output


def test_a_new_rule_firing_in_a_known_false_alarm_fails(tmp_path, monkeypatch, capsys):
    _skill_at(tmp_path, KNOWN)

    code, output = _run_audit(tmp_path, monkeypatch, capsys, _rated_critical("SC-001", "HC-003"))

    assert code != 0
    assert "FAIL: 1 known false alarm(s) gained a rule at high or critical" in output
    assert f"{KNOWN}: HC-003" in output
    assert "OK:" not in output


def test_a_known_false_alarm_that_no_longer_fires_is_pointed_out(tmp_path, monkeypatch, capsys):
    _skill_at(tmp_path, KNOWN)

    code, output = _run_audit(
        tmp_path, monkeypatch, capsys, lambda path, use_llm, use_osv: ScanResult(target=path)
    )

    assert code == 0
    assert f"remove from KNOWN_FALSE_ALARMS: {KNOWN}" in output


def test_a_listed_rule_that_stopped_firing_is_pointed_out(tmp_path, monkeypatch, capsys):
    _skill_at(tmp_path, KNOWN)

    code, output = _run_audit(tmp_path, monkeypatch, capsys, _rated_critical("SC-001"))

    assert code == 0
    assert f"No longer firing at high or critical in {KNOWN}; shorten its list:" in output
    assert "TM-001" in output and "SC-001" not in output.split("shorten its list:")[1]
