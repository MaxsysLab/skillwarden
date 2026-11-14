"""A release whose own files disagree about what it is must not go out, and release
notes that cannot be written faithfully are refused, not guessed at."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

import skillwarden
from scripts import release_notes
from scripts.release_notes import ReleaseError

CHANGELOG = """\
# Changelog

## [Unreleased]

## [1.2.0] - 2026-12-01

A paragraph that was wrapped
for reading in an editor.

### Changed

- **A first item.** It runs on
  to a second line.
  - A nested item that also
    runs on.
- A second item.

```bash
uv run skillwarden scan .
  --no-llm
```

| Exit | Meaning |
|---|---|
| 0 | clean |

## [1.1.0] - 2026-11-20

- The release before.
"""


def _tree(root: Path, *, project: str = "1.2.0", package: str = "1.2.0") -> Path:
    (root / "src" / "skillwarden").mkdir(parents=True)
    (root / "pyproject.toml").write_text(
        f'[project]\nname = "skillwarden"\nversion = "{project}"\n', encoding="utf-8"
    )
    (root / "src" / "skillwarden" / "__init__.py").write_text(
        f'"""Package."""\n\n__version__ = "{package}"\n', encoding="utf-8"
    )
    (root / "CHANGELOG.md").write_text(CHANGELOG, encoding="utf-8")
    return root


def _notes(*lines: str) -> str:
    return release_notes.unwrap(list(lines))


# ---- the version, the package and the tag ------------------------------------


def test_the_repository_agrees_with_itself() -> None:
    """pyproject.toml, the package and the changelog name the same version, and the
    entry for it can be published as it stands."""
    version = release_notes.project_version()
    assert version == skillwarden.__version__
    notes = release_notes.release_notes(version)
    assert notes.strip()
    assert "Nothing has been tagged yet" not in notes


def test_the_package_and_pyproject_must_agree(tmp_path: Path) -> None:
    root = _tree(tmp_path, project="1.2.0", package="1.1.0")
    with pytest.raises(ReleaseError, match=re.escape("the package says 1.1.0")):
        release_notes.project_version(root)


def test_a_missing_version_line_is_an_error(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    (root / "src" / "skillwarden" / "__init__.py").write_text('"""Package."""\n', encoding="utf-8")
    with pytest.raises(ReleaseError, match="no __version__ line"):
        release_notes.project_version(root)


@pytest.mark.parametrize(
    "version", ["1.2.0", "1.2.0rc1", "1.2.0a2", "1.2.0b3", "1.2.0.post1", "10.20.30.dev4"]
)
def test_the_forms_a_version_may_take(tmp_path: Path, version: str) -> None:
    root = _tree(tmp_path, project=version, package=version)
    assert release_notes.project_version(root) == version
    assert release_notes.check_tag(f"v{version}", root) == version


@pytest.mark.parametrize(
    "version",
    [
        "1.2",
        "v1.2.0",
        "1.2.0-rc.1",
        "1.2.0rc",
        "1.2.0+local",
        "1.2.0 ",
        "1.2.0;id",
        "1.2.0/../x",
        "$(id)",
        "",
    ],
)
def test_any_other_form_of_version_is_refused(tmp_path: Path, version: str) -> None:
    root = _tree(tmp_path, project=version, package=version)
    with pytest.raises(ReleaseError, match="expected the form"):
        release_notes.project_version(root)


@pytest.mark.parametrize("version", ["1.0.\u0663", "\uff11.0.0", "1.0.0rc\u0661"])
def test_digits_of_other_scripts_are_not_digits_here(tmp_path: Path, version: str) -> None:
    root = _tree(tmp_path, project=version, package=version)
    with pytest.raises(ReleaseError, match="expected the form"):
        release_notes.project_version(root)


def test_the_tag_is_the_version_with_a_v(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    assert release_notes.check_tag("v1.2.0", root) == "1.2.0"


@pytest.mark.parametrize(
    "tag", ["1.2.0", "v1.2", "v1.2.1", "v1.2.0-rc.1", "v1.2.0 ", "V1.2.0", "release-1.2.0", ""]
)
def test_any_other_tag_is_refused(tmp_path: Path, tag: str) -> None:
    root = _tree(tmp_path)
    with pytest.raises(ReleaseError, match=re.escape("expected v1.2.0")):
        release_notes.check_tag(tag, root)


# ---- finding the entry -------------------------------------------------------


def test_the_entry_stops_at_the_next_version() -> None:
    body = release_notes.changelog_entry("1.2.0", CHANGELOG)
    text = "\n".join(body)
    assert "A paragraph that was wrapped" in text
    assert "The release before" not in text
    assert "## [" not in text


def test_a_version_without_an_entry_is_refused() -> None:
    with pytest.raises(ReleaseError, match=re.escape("no entry for 1.3.0")):
        release_notes.changelog_entry("1.3.0", CHANGELOG)


def test_unreleased_is_not_an_entry() -> None:
    with pytest.raises(ReleaseError, match="must read"):
        release_notes.changelog_entry("Unreleased", CHANGELOG)


@pytest.mark.parametrize(
    "heading",
    [
        "## [1.2.0]",
        "## [1.2.0] - soon",
        "## [1.2.0] 2026-12-01",
        "## [1.2.0] - 2026-12",
        "## [1.2.0] - 9999-99-99",
        "## [1.2.0] - 2026-02-30",
        "## [1.2.0] - 2026-12-01 [YANKED]",
        "## [1.2.0]  -  2026-12-01",
    ],
)
def test_the_heading_must_be_the_version_and_a_real_date(heading: str) -> None:
    changelog = CHANGELOG.replace("## [1.2.0] - 2026-12-01", heading)
    with pytest.raises(ReleaseError, match="must read"):
        release_notes.changelog_entry("1.2.0", changelog)


def test_two_entries_for_one_version_are_refused() -> None:
    changelog = CHANGELOG + "\n## [1.2.0] - 2026-10-01\n\n- An older text under the same number.\n"
    with pytest.raises(ReleaseError, match=re.escape("2 entries for 1.2.0")):
        release_notes.changelog_entry("1.2.0", changelog)


def test_a_second_level_heading_that_is_not_a_version_is_refused() -> None:
    changelog = CHANGELOG.replace("### Changed", "## Notes")
    with pytest.raises(ReleaseError, match="second-level heading that is not a version"):
        release_notes.changelog_entry("1.2.0", changelog)
    with pytest.raises(ReleaseError, match="second-level heading that is not a version"):
        release_notes.changelog_entry("1.1.0", changelog)


def test_an_empty_entry_is_refused() -> None:
    changelog = "## [1.2.0] - 2026-12-01\n\n\n## [1.1.0] - 2026-11-20\n\n- Before.\n"
    with pytest.raises(ReleaseError, match="is empty"):
        release_notes.changelog_entry("1.2.0", changelog)


def test_a_heading_inside_a_code_block_does_not_end_the_entry() -> None:
    example = "The format:\n\n```md\n## [Unreleased]\n## [1.2.0] - 2026-12-01\n```\n\n- After it.\n"
    changelog = "## [1.2.0] - 2026-12-01\n\n" + example + "\n## [1.1.0] - 2026-11-20\n\n- Before.\n"
    body = release_notes.changelog_entry("1.2.0", changelog)
    assert release_notes.unwrap(body) == example


def test_a_changelog_that_ends_inside_a_code_block_is_refused() -> None:
    with pytest.raises(ReleaseError, match="ends inside a fenced block"):
        release_notes.changelog_entry("1.2.0", "## [1.2.0] - 2026-12-01\n\n```\nnever closed\n")


def test_a_file_with_windows_line_endings_reads_the_same() -> None:
    body = release_notes.changelog_entry("1.2.0", CHANGELOG.replace("\n", "\r\n"))
    assert release_notes.unwrap(body) == release_notes.unwrap(
        release_notes.changelog_entry("1.2.0", CHANGELOG)
    )


# ---- one paragraph or item per line ------------------------------------------


def test_notes_have_one_paragraph_or_item_per_line() -> None:
    notes = release_notes.unwrap(release_notes.changelog_entry("1.2.0", CHANGELOG))
    assert notes == (
        "A paragraph that was wrapped for reading in an editor.\n"
        "\n"
        "### Changed\n"
        "\n"
        "- **A first item.** It runs on to a second line.\n"
        "  - A nested item that also runs on.\n"
        "- A second item.\n"
        "\n"
        "```bash\n"
        "uv run skillwarden scan .\n"
        "  --no-llm\n"
        "```\n"
        "\n"
        "| Exit | Meaning |\n"
        "|---|---|\n"
        "| 0 | clean |\n"
    )


def test_code_is_never_joined_whatever_the_fence() -> None:
    assert _notes("````md", "```", "line a", "line b", "```", "````", "after", "the block") == (
        "````md\n```\nline a\nline b\n```\n````\nafter the block\n"
    )
    assert _notes("~~~", "line a", "```", "line b", "~~~", "after") == (
        "~~~\nline a\n```\nline b\n~~~\nafter\n"
    )
    assert _notes("- An item with code:", "", "  ```bash", "  one", "", "  two", "  ```") == (
        "- An item with code:\n\n  ```bash\n  one\n\n  two\n  ```\n"
    )
    # Three backticks with more backticks after them are inline code, not a fence.
    assert _notes("```not a fence``` and", "more text") == "```not a fence``` and more text\n"


def test_a_number_and_a_dot_on_a_wrapped_line_is_text() -> None:
    assert _notes("It was first seen in", "2024. Nothing since.") == (
        "It was first seen in 2024. Nothing since.\n"
    )
    assert _notes("- It was first seen in", "  2024. Nothing since.") == (
        "- It was first seen in 2024. Nothing since.\n"
    )
    assert _notes("Steps:", "1. One", "   more", "2. Two", "10) Ten") == (
        "Steps:\n1. One more\n2. Two\n10) Ten\n"
    )
    # Inside an item, only "1." starts a list; the next item is where the markers are.
    assert _notes("1. Raise the limit to", "   10. Then run it.", "2. Check.") == (
        "1. Raise the limit to 10. Then run it.\n2. Check.\n"
    )
    assert _notes("1. Outer", "   1. Inner one", "   2. Inner two", "2. Outer two") == (
        "1. Outer\n   1. Inner one\n   2. Inner two\n2. Outer two\n"
    )
    assert _notes("The note is marked", "[x]: and it goes on.") == (
        "The note is marked [x]: and it goes on.\n"
    )


def test_rules_link_definitions_and_single_quotes_keep_their_lines() -> None:
    assert _notes(
        "Above",
        "",
        "---",
        "",
        "> One quoted line.",
        "",
        "[a]: https://example.com/a",
        "[b]: https://example.com/b",
    ) == (
        "Above\n\n---\n\n> One quoted line.\n\n[a]: https://example.com/a\n[b]: https://example.com/b\n"
    )
    assert (
        _notes("See <https://example.com> for", "the rest.")
        == "See <https://example.com> for the rest.\n"
    )
    assert (
        _notes("<https://example.com> has", "the rest.") == "<https://example.com> has the rest.\n"
    )


def test_blank_lines_are_kept_single_and_trimmed_at_the_ends() -> None:
    assert _notes("", "", "One.", "", "", "", "Two.", "", "") == "One.\n\nTwo.\n"


@pytest.mark.parametrize(
    ("lines", "what"),
    [
        (["A line that ends in two spaces  ", "and goes on."], "a hard line break"),
        (["A line that ends in a backslash\\", "and goes on."], "a hard line break"),
        (["Some text.", "", "    uv run skillwarden scan ."], "an indented block"),
        (["- An item.", "", "  Its second paragraph."], "an indented block"),
        (["A title", "======="], "a heading underlined"),
        (["A title", "---"], "a heading underlined"),
        (["Exit | Meaning", "--- | ---", "0 | clean"], "a table without leading pipes"),
        (["> A quote that", "> runs on."], "a quote over several lines"),
        (["> A quote that", "runs on lazily."], "a quote over several lines"),
        (["<details>", "<summary>More</summary>", "</details>"], "HTML"),
        (["<!-- a comment -->"], "HTML"),
    ],
)
def test_shapes_that_cannot_be_carried_are_refused(lines: list[str], what: str) -> None:
    with pytest.raises(ReleaseError, match=re.escape(what)):
        release_notes.unwrap(lines)


def test_an_entry_that_ends_inside_a_code_block_is_refused() -> None:
    with pytest.raises(ReleaseError, match="ends inside a fenced block"):
        release_notes.unwrap(["```", "never closed"])


# ---- the command -------------------------------------------------------------


def test_notes_are_refused_for_a_version_the_files_do_not_name(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    assert release_notes.release_notes("1.2.0", root).startswith("A paragraph")
    with pytest.raises(ReleaseError, match=re.escape("the files say 1.2.0")):
        release_notes.release_notes("1.1.0", root)


def test_the_command_exits_1_and_says_why(capsys: pytest.CaptureFixture[str]) -> None:
    assert release_notes.main(["check", "v0.0.0-not-this"]) == 1
    assert "release check failed" in capsys.readouterr().err
    assert release_notes.main(["version"]) == 0
    assert capsys.readouterr().out.strip() == skillwarden.__version__
