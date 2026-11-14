"""False-positive audit: scan a corpus of real *benign* published skills and
report how SkillWarden rates them.

A trusted skill should not score CRITICAL — so this doubles as a regression gate:
it exits non-zero if any corpus skill exceeds the allowed CRITICAL budget. Run it
whenever the pattern sets or scoring change. Skills the fixed rules are known to rate
CRITICAL wrongly are named in KNOWN_FALSE_ALARMS, by their place in the corpus and with
the rules known to fire there, and are reported apart; the gate is then about new
false alarms, in those skills and in every other. This audit measures false alarms on
harmless skills only. It cannot show a missed attack: `tests/unit/test_rule_coverage.py`
carries those.

Usage:
    make audit-fetch                # explicit opt-in: clone the default corpus, audit, gate
    make audit                      # offline: audit the cached corpus only (no network)
    python scripts/fp_audit.py --corpus path/to/skills --max-critical 0

Network access happens only with --fetch. Any fetch failure, empty corpus or incomplete
scan makes the run fail; it never reports OK on a partial corpus.

Corpus sources must be https:// git URLs; clones run with `http.followRedirects=false`
(a redirecting remote is refused, not followed). A cached source is trusted only when it
passes `clone_incomplete_reason()`: a valid `.git/HEAD`, no interrupted-operation lock, a
parseable index whose every entry exists in the worktree, and at least one `SKILL.md`.
"""

from __future__ import annotations

import argparse
import hashlib
import shutil
import struct
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

from skillwarden.engine import scan  # noqa: E402
from skillwarden.models import Severity  # noqa: E402

DEFAULT_CORPUS = REPO / ".audit-corpus"
# Known-benign, trusted sources. Add more (incl. community collections) over time.
BENIGN_SOURCES = [("anthropic-skills", "https://github.com/anthropics/skills")]
# Corpus skills that cannot be scanned to completion, by design, and why: every reason
# the scan gives must contain this text. Such a skill is reported and not counted as a
# failure; any other incomplete scan still fails the audit. Keep this list short and
# named: it is the only way a skill leaves the gate.
EXPECTED_INCOMPLETE = {
    # Bundles scripts/shadcn-components.tar.gz; nested archives are never unpacked.
    "web-artifacts-builder": "nested archive",
}
# Corpus skills that are harmless and that the fixed rules are known to rate CRITICAL:
# where each lives in the corpus, why, and which rules are known to fire there at high
# or critical severity. Such a skill is reported apart and does not count against
# --max-critical. The gate still fails when any other benign skill rates critical, and
# when a rule NOT listed here fires at high or critical in one of these: either way a
# new false alarm. Each entry is a false alarm waiting for a rule to be made more
# precise, with tests in both directions and a second pair of eyes. When an entry stops
# rating critical, or a listed rule stops firing, the audit says so; shorten the list.
# (Rules, not lines: the corpus is the skills as published that day, and lines move.)
KNOWN_FALSE_ALARMS: dict[str, tuple[str, frozenset[str]]] = {
    # 96 files of API documentation that discusses security: a comment that names
    # ~/.ssh/id_rsa, "never run curl | sh lines", "rm -rf /workspace/reports" in an
    # example of a tool call.
    "anthropic-skills/skills/claude-api": (
        "documentation that discusses security",
        frozenset(
            {
                "PI-005",
                "DX-003",
                "DX-004",
                "SC-001",
                "EA-002",
                "EA-005",
                "SPL-001",
                "TM-001",
                "RA-005",
            }
        ),
    ),
    # scripts/recalc.py hands a file name from the command line to LibreOffice, and
    # builds a regular expression from workbook names (`re.compile` read as `compile`).
    "anthropic-skills/skills/xlsx": (
        "a script that passes a file name to another program",
        frozenset({"TT-001"}),
    ),
}

GITLINK_MODE = 0o160000  # a submodule entry: a directory in the worktree, not a file


def _index_entries(index: Path) -> list[tuple[str, int]]:
    """(path, mode) pairs listed in a git index (v2/v3). Raises ValueError when it
    cannot be verified.

    Offline and git-free on purpose: the audit must not need the network or a git
    binary to decide whether a cached clone is whole. The trailing SHA-1 is checked, so
    a truncated index is detected. Index v4 (prefix-compressed paths) is unsupported.
    """
    data = index.read_bytes()
    if len(data) < 32 or data[:4] != b"DIRC":
        raise ValueError("index is not a git index")
    if hashlib.sha1(data[:-20]).digest() != data[-20:]:
        raise ValueError("index checksum mismatch (truncated or corrupt)")
    version, count = struct.unpack(">II", data[4:12])
    if version not in (2, 3):
        raise ValueError(f"index version {version} unsupported (only 2 and 3 are verified)")
    entries: list[tuple[str, int]] = []
    pos = 12
    body_end = len(data) - 20
    for _ in range(count):
        start = pos
        if pos + 62 > body_end:
            raise ValueError("index entry runs past the end of the file")
        mode = struct.unpack(">I", data[pos + 24 : pos + 28])[0]
        flags = struct.unpack(">H", data[pos + 60 : pos + 62])[0]
        pos += 62
        if version == 3 and flags & 0x4000:
            pos += 2
        end = data.find(b"\0", pos, body_end)
        if end < 0:
            raise ValueError("index entry path is not NUL-terminated")
        entries.append((data[pos:end].decode("utf-8", errors="surrogateescape"), mode))
        pos = end + 1
        pos += (8 - ((pos - start) % 8)) % 8  # entries are padded to 8 bytes
    return entries


def _worktree_entry_present(dest: Path, path: str, mode: int) -> bool:
    p = dest / path
    if (mode & 0o170000) == GITLINK_MODE:
        return p.is_dir()  # a submodule mount point (possibly un-initialised, so empty)
    return p.is_file() or p.is_symlink()


def clone_incomplete_reason(dest: Path) -> str | None:
    """Why ``dest`` is NOT a complete clone, or None when it looks whole."""
    git = dest / ".git"
    if not git.is_dir():
        return f"{dest} exists but is not a complete git clone (no .git directory)"
    head = git / "HEAD"
    if not head.is_file() or not head.read_bytes().strip():
        return f"{dest} is an incomplete clone: .git/HEAD missing or empty"
    locks = sorted(p.name for p in git.glob("*.lock"))
    if locks:
        return (
            f"{dest} is an incomplete clone: interrupted git operation "
            f"(found {', '.join(locks)} in .git)"
        )
    index = git / "index"
    if not index.is_file():
        return f"{dest} is an incomplete clone: .git/index missing (checkout never finished)"
    try:
        entries = _index_entries(index)
    except (ValueError, struct.error) as exc:
        return f"{dest} is an incomplete or unverifiable clone: {exc}"
    if not entries:
        return f"{dest} is an incomplete clone: empty tree (index lists no files)"
    missing = [p for p, mode in entries if not _worktree_entry_present(dest, p, mode)]
    if missing:
        shown = ", ".join(missing[:5]) + (" ..." if len(missing) > 5 else "")
        return (
            f"{dest} is an incomplete clone: {len(missing)} indexed file(s) missing from "
            f"the worktree ({shown})"
        )
    if not any(".git" not in p.parts for p in dest.rglob("SKILL.md")):
        return f"{dest} is an incomplete corpus source: no SKILL.md anywhere in the clone"
    return None


def ensure_corpus(corpus: Path, fetch: bool) -> tuple[list[Path], list[str]]:
    """Return (skill dirs, fetch failures). Network only happens when ``fetch`` is True.

    A clone is built in a scratch directory beside the corpus and moved into place only
    after git exits cleanly, so a timeout or crash can never leave a half-cloned source
    that a later run would mistake for a complete cached one. Every source that is used,
    cached or fresh, must pass `clone_incomplete_reason()`.
    """
    corpus.mkdir(parents=True, exist_ok=True)
    fetch_failures: list[str] = []
    if fetch:
        for name, url in BENIGN_SOURCES:
            dest = corpus / name
            if dest.exists():
                reason = clone_incomplete_reason(dest)
                if reason:
                    fetch_failures.append(f"{name}: {reason}")
                continue
            if not url.startswith("https://"):
                fetch_failures.append(
                    f"{name}: refusing to clone {url!r}: only https:// sources are supported"
                )
                continue
            print(f"fetching {url} -> {dest} ...")
            try:
                with tempfile.TemporaryDirectory(
                    prefix=".fp-audit-clone-", dir=corpus.parent
                ) as td:
                    staged = Path(td) / name
                    subprocess.run(
                        [
                            "git",
                            # A redirecting remote is refused, never followed to another host.
                            "-c",
                            "http.followRedirects=false",
                            "clone",
                            "--depth",
                            "1",
                            "--quiet",
                            url,
                            str(staged),
                        ],
                        check=True,
                        timeout=180,
                        env={"GIT_TERMINAL_PROMPT": "0", "PATH": "/usr/bin:/bin"},
                    )
                    reason = clone_incomplete_reason(staged)
                    if reason:
                        raise OSError(f"fresh clone failed verification: {reason}")
                    shutil.move(str(staged), str(dest))
            except (
                subprocess.CalledProcessError,
                subprocess.TimeoutExpired,
                FileNotFoundError,
                OSError,
            ) as exc:
                fetch_failures.append(f"{name}: {exc}")
    # Online or offline, any clone in the corpus (anything holding a `.git`, at any
    # depth, the corpus root included) is trusted only when it is complete: a legacy or
    # interrupted half-clone must fail the audit, not quietly shrink the corpus.
    reported = {f.split(":", 1)[0] for f in fetch_failures}
    for clone in _clones_in(corpus):
        reason = clone_incomplete_reason(clone)
        label = clone.relative_to(corpus).as_posix() if clone != corpus else str(corpus)
        if reason and label not in reported:
            fetch_failures.append(f"{label}: {reason}")
    skill_dirs = sorted({p.parent for p in corpus.rglob("SKILL.md") if ".git" not in p.parts})
    return skill_dirs, fetch_failures


def _corpus_path(skill_dir: Path, corpus: Path) -> str:
    """Where a skill sits in the corpus, as `source/path/to/skill`. A skill is known
    by this, never by its folder name alone: another source may use the same name."""
    try:
        return skill_dir.relative_to(corpus).as_posix()
    except ValueError:
        return skill_dir.as_posix()


def _commit_of(clone: Path) -> str:
    """The commit a corpus clone is at, for the record. Read from git's own files (a
    detached or symbolic HEAD, loose or packed ref); "unknown" if it cannot be read."""
    git = clone / ".git"
    try:
        head = (git / "HEAD").read_text(encoding="utf-8").strip()
        if not head.startswith("ref:"):
            return head[:12] or "unknown"
        ref = head.split(":", 1)[1].strip()
        loose = git / ref
        if loose.is_file():
            return loose.read_text(encoding="utf-8").strip()[:12] or "unknown"
        for line in (git / "packed-refs").read_text(encoding="utf-8").splitlines():
            sha, _, name = line.partition(" ")
            if name.strip() == ref:
                return sha[:12]
    except OSError:
        pass
    return "unknown"


def _clones_in(corpus: Path) -> list[Path]:
    """Every directory under ``corpus`` (itself included) that contains a `.git` entry."""
    found = {git.parent for git in corpus.rglob(".git") if ".git" not in git.parent.parts}
    if (corpus / ".git").exists():
        found.add(corpus)
    return sorted(found)


def main() -> int:
    parser = argparse.ArgumentParser(description="SkillWarden false-positive audit")
    parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    parser.add_argument(
        "--fetch",
        action="store_true",
        help="clone the BENIGN_SOURCES corpora (network). Without it the audit is offline.",
    )
    parser.add_argument(
        "--no-fetch", action="store_true", help="deprecated no-op: offline is the default"
    )
    parser.add_argument("--max-critical", type=int, default=0, help="allowed CRITICAL skills")
    args = parser.parse_args()

    skill_dirs, fetch_failures = ensure_corpus(args.corpus, fetch=args.fetch and not args.no_fetch)
    if fetch_failures:
        print(f"FAIL: {len(fetch_failures)} corpus source fetch(es) failed:")
        for failure in fetch_failures:
            print(f"  {failure}")
    if not skill_dirs:
        print(f"FAIL: no skills found under {args.corpus} (corpus empty; use --fetch to clone it)")
        return 1

    for clone in _clones_in(args.corpus):
        label = clone.relative_to(args.corpus).as_posix() if clone != args.corpus else "."
        print(f"corpus source {label} at commit {_commit_of(clone)}")

    rule_hits: Counter[str] = Counter()
    rule_sev: dict[str, str] = {}
    rows = []
    critical_skills = []
    known_false_alarms: list[str] = []
    new_in_known: list[tuple[str, list[str]]] = []
    gone_from_known: list[tuple[str, list[str]]] = []
    incomplete_skills: list[tuple[str, list[str]]] = []
    expected_incomplete: list[tuple[str, list[str]]] = []
    high_crit_findings = 0

    for d in skill_dirs:
        # Offline by contract: no LLM pass and no live OSV lookup (this gate is about
        # pattern false positives; it must not depend on, or call, the network).
        r = scan(str(d), use_llm=False, use_osv=False)
        if r.status != "complete":
            # The engine already lists skipped input under errors; keep each reason once.
            why = list(
                dict.fromkeys(
                    [*r.errors, *(f"input skipped: {s.path}: {s.reason}" for s in r.skipped)]
                )
            )
            expected = EXPECTED_INCOMPLETE.get(d.name)
            if expected and why and all(expected in reason for reason in why):
                expected_incomplete.append((str(d), why))
            else:
                incomplete_skills.append((str(d), why))
        hc = sum(1 for f in r.findings if f.severity.weight >= Severity.HIGH.weight)
        high_crit_findings += hc
        rows.append((d.name, r.risk_score, r.severity_label.value, len(r.findings), hc))
        where = _corpus_path(d, args.corpus)
        known = KNOWN_FALSE_ALARMS.get(where)
        if known is not None:
            fired = {f.rule_id for f in r.findings if f.severity.weight >= Severity.HIGH.weight}
            if fired - known[1]:
                new_in_known.append((where, sorted(fired - known[1])))
            if known[1] - fired:
                gone_from_known.append((where, sorted(known[1] - fired)))
        if r.severity_label is Severity.CRITICAL:
            if known is not None:
                known_false_alarms.append(where)
            else:
                critical_skills.append(d.name)
        for f in r.findings:
            rule_hits[f.rule_id] += 1
            rule_sev[f.rule_id] = f.severity.value

    print(f"\n=== {len(skill_dirs)} benign skills scanned ===\n")
    print(f"{'skill':30} {'score':>5} {'label':9} {'finds':>5} {'high+':>5}")
    for name, score, label, n, hc in sorted(rows, key=lambda x: -x[1]):
        print(f"{name:30} {score:5} {label:9} {n:5} {hc:5}")

    print(f"\nHIGH/CRITICAL findings on benign corpus: {high_crit_findings}")
    print("rule frequency (all false positives on a benign corpus):")
    for rid, n in rule_hits.most_common():
        print(f"  {rid:10} {rule_sev[rid]:9} x{n}")

    if known_false_alarms:
        print(
            f"\n{len(known_false_alarms)} benign skill(s) rated CRITICAL by the fixed rules, "
            "as known (KNOWN_FALSE_ALARMS); not counted against the budget:"
        )
        for where in known_false_alarms:
            print(f"  {where}: {KNOWN_FALSE_ALARMS[where][0]}")
    scanned = {_corpus_path(d, args.corpus) for d in skill_dirs}
    no_longer = sorted(
        w for w in KNOWN_FALSE_ALARMS if w in scanned and w not in known_false_alarms
    )
    if no_longer:
        print("\nNo longer rated CRITICAL; remove from KNOWN_FALSE_ALARMS: " + ", ".join(no_longer))
    for where, rules in gone_from_known:
        gone = ", ".join(rules)
        print(f"\nNo longer firing at high or critical in {where}; shorten its list: {gone}")
    if new_in_known:
        print(
            f"\nFAIL: {len(new_in_known)} known false alarm(s) gained a rule at high or critical:"
        )
        for where, rules in new_in_known:
            print(f"  {where}: {', '.join(rules)}")
    if expected_incomplete:
        print(
            f"\n{len(expected_incomplete)} skill(s) cannot be scanned to completion, by "
            "design (EXPECTED_INCOMPLETE); not counted as failures:"
        )
        for path, errors in expected_incomplete:
            print(f"  {path}: {'; '.join(errors)}")
    if incomplete_skills:
        print(f"\nFAIL: {len(incomplete_skills)} incomplete static scan(s):")
        for path, errors in incomplete_skills:
            print(f"  {path}: {'; '.join(errors) if errors else 'status incomplete'}")
    if len(critical_skills) > args.max_critical:
        print(
            f"\nFAIL: {len(critical_skills)} skill(s) rated CRITICAL "
            f"(budget {args.max_critical}): {', '.join(critical_skills)}"
        )
    if (
        fetch_failures
        or incomplete_skills
        or new_in_known
        or len(critical_skills) > args.max_critical
    ):
        return 1
    print(f"\nOK: {len(critical_skills)} CRITICAL (budget {args.max_critical}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
