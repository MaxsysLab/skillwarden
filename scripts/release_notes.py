"""Release helper, used by .github/workflows/release.yml.

    python3 scripts/release_notes.py version        print the version in the files
    python3 scripts/release_notes.py check v1.2.3   the tag must name that version
    python3 scripts/release_notes.py notes 1.2.3    print the changelog entry as notes

The three agree or the command exits 1 and says why: the version in pyproject.toml,
the version the package reports, and, for a release, the tag and a dated entry in
CHANGELOG.md. A release whose own files disagree about what it is does not go out.

The notes are the changelog entry with one paragraph or list item per line. Markdown
this script does not rewrite safely is refused, not guessed at: the entry is fixed and
the release is cut from the fixed text.

Standard library only, so the workflow can run it before anything is installed.
"""

from __future__ import annotations

import argparse
import datetime
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# The forms a version may take here: 1.2.3, and 1.2.3rc1 / 1.2.3a1 / 1.2.3b1,
# 1.2.3.post1, 1.2.3.dev1. Anything else is refused, so that the tag, the file names
# and the version the package reports are the same string.
_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:(?:a|b|rc)[0-9]+|\.post[0-9]+|\.dev[0-9]+)?")
_VERSION_LINE = re.compile(r'^__version__\s*=\s*"([^"]+)"\s*$', re.MULTILINE)
_ENTRY_HEADING = re.compile(r"^## \[(?P<version>[^\]]+)\](?P<rest>.*)$")
_DATED = re.compile(r"^ - ([0-9]{4}-[0-9]{2}-[0-9]{2})$")

_FENCE = re.compile(r"^\s*(?P<marks>`{3,}|~{3,})(?P<info>.*)$")
_HEADING = re.compile(r"^#{1,6}(?:\s|$)")
_BULLET = re.compile(r"^\s*[-*+](?:\s+|$)")
_NUMBERED = re.compile(r"^\s*(?P<number>[0-9]{1,9})[.)](?:\s+|$)")
_RULE = re.compile(r"^(?:(?:\*\s*){3,}|(?:_\s*){3,}|(?:-\s*){3,})$")
_UNDERLINE = re.compile(r"^(?:=+|-+)$")
_TABLE_RULE = re.compile(r"^:?-+:?(?:\s*\|\s*:?-+:?)+\s*\|?$")
_LINK_DEFINITION = re.compile(r"^\s{0,3}\[[^\]]+\]:\s*\S")
_HTML = re.compile(r"^<(?:/?[A-Za-z][A-Za-z0-9-]*(?:\s|/?>|$)|!|\?)")


class ReleaseError(Exception):
    """The files do not agree on what is being released, or cannot be published."""


class _Fences:
    """Whether a line belongs to a fenced code block, by CommonMark's rules: a fence
    is closed only by the same character, at least as long, with nothing after it."""

    def __init__(self) -> None:
        self._open: tuple[str, int] | None = None

    @property
    def open(self) -> bool:
        return self._open is not None

    def feed(self, line: str) -> bool:
        """True when the line opens, closes or sits inside a fenced block."""
        fence = _FENCE.match(line)
        if self._open is None:
            if fence is None:
                return False
            marks, info = fence.group("marks"), fence.group("info")
            if marks[0] == "`" and "`" in info:
                return False  # inline code, not a fence
            self._open = (marks[0], len(marks))
            return True
        char, length = self._open
        if fence is not None:
            marks, info = fence.group("marks"), fence.group("info")
            if marks[0] == char and len(marks) >= length and not info.strip():
                self._open = None
        return True


def project_version(root: Path = ROOT) -> str:
    """The version in pyproject.toml, after checking the package reports the same."""
    with (root / "pyproject.toml").open("rb") as fh:
        version = tomllib.load(fh)["project"]["version"]
    if not isinstance(version, str) or not _VERSION.fullmatch(version):
        raise ReleaseError(
            f"the version in pyproject.toml is {version!r}: "
            "expected the form 1.2.3, 1.2.3rc1, 1.2.3.post1 or 1.2.3.dev1"
        )
    init = (root / "src" / "skillwarden" / "__init__.py").read_text(encoding="utf-8")
    found = _VERSION_LINE.search(init)
    if found is None:
        raise ReleaseError("src/skillwarden/__init__.py has no __version__ line")
    if found.group(1) != version:
        raise ReleaseError(f"pyproject.toml says {version} and the package says {found.group(1)}")
    return version


def check_tag(tag: str, root: Path = ROOT) -> str:
    """The version a tag releases. The tag must be exactly "v" + the version."""
    version = project_version(root)
    if tag != f"v{version}":
        raise ReleaseError(f"the tag is {tag} and the files say {version}: expected v{version}")
    return version


def changelog_entry(version: str, changelog: str) -> list[str]:
    """The lines under `## [version] - YYYY-MM-DD`, up to the next version heading.

    A `## ` line inside a fenced block is text, not a heading. Two entries for one
    version, a heading that is not exactly of that form, a date that is not a day,
    a second-level heading that is not a version, an empty entry and a fence left
    open are all refused.
    """
    lines = changelog.splitlines()
    fences = _Fences()
    headings = [
        n for n, line in enumerate(lines) if not fences.feed(line) and line.startswith("## ")
    ]
    if fences.open:
        raise ReleaseError("CHANGELOG.md ends inside a fenced block")
    for number in headings:
        if _ENTRY_HEADING.match(lines[number]) is None:
            raise ReleaseError(
                f"line {number + 1} of CHANGELOG.md is a second-level heading that is not "
                f"a version ('## [X.Y.Z] - YYYY-MM-DD'): {lines[number]!r}"
            )
    found = []
    for number in headings:
        heading = _ENTRY_HEADING.match(lines[number])
        if heading is not None and heading.group("version") == version:
            found.append((number, heading.group("rest").rstrip()))
    if not found:
        raise ReleaseError(f"CHANGELOG.md has no entry for {version}")
    if len(found) > 1:
        raise ReleaseError(f"CHANGELOG.md has {len(found)} entries for {version}")
    start, rest = found[0]
    dated = _DATED.match(rest)
    try:
        if dated is None:
            raise ValueError
        datetime.date.fromisoformat(dated.group(1))
    except ValueError:
        raise ReleaseError(
            f"the heading for {version} must read '## [{version}] - YYYY-MM-DD' "
            f"with a real date: {lines[start]!r}"
        ) from None
    end = next((n for n in headings if n > start), len(lines))
    body = lines[start + 1 : end]
    if not any(line.strip() for line in body):
        raise ReleaseError(f"the changelog entry for {version} is empty")
    return body


def unwrap(body: list[str]) -> str:
    """One paragraph or list item per line.

    The changelog is wrapped at a fixed width for reading in an editor. GitHub shows a
    single line break in a release body as a break on the page, so wrapped text would
    come out ragged. Paragraphs and list items are joined; headings, rules, table rows
    with a leading pipe, link definitions and fenced code keep their own lines.

    Shapes this cannot rewrite without changing their meaning raise ReleaseError: a
    hard line break, an indented block (indented code, or a second paragraph inside a
    list item), a heading underlined with = or -, a table without leading pipes, a
    quote that runs over several lines, and HTML.
    """
    out: list[str] = []
    current: str | None = None
    kind = ""  # "paragraph", "bullet" or "numbered" while `current` is being collected
    item_indent = 0  # where the marker of the item being collected starts
    fences = _Fences()

    def refuse(number: int, what: str, instead: str) -> ReleaseError:
        return ReleaseError(
            f"line {number} of the changelog entry is {what}, which the release notes "
            f"cannot carry: {instead}"
        )

    def flush() -> None:
        nonlocal current, kind
        if current is not None:
            out.append(current)
        current, kind = None, ""

    def alone(text: str) -> None:
        flush()
        out.append(text)

    for number, raw in enumerate(body, start=1):
        if fences.feed(raw):
            alone(raw.rstrip())
            continue
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped:
            flush()
            if out and out[-1] != "":
                out.append("")
            continue
        if raw.endswith("  ") or stripped.endswith("\\"):
            raise refuse(number, "a hard line break", "end the paragraph or join the lines")
        bullet = _BULLET.match(line)
        numbered = _NUMBERED.match(line)
        indent = len(line) - len(line.lstrip())
        # Markdown lets a numbered list start in the middle of other text only with
        # "1."; "2024. was a year" on a wrapped line is text. The next item of the
        # numbered list being collected starts where that list's markers start.
        starts_item = bool(bullet) or bool(
            numbered
            and (
                current is None
                or numbered["number"] == "1"
                or (kind == "numbered" and indent <= item_indent)
            )
        )
        after_quote = current is None and bool(out) and out[-1].lstrip().startswith(">")
        if _HEADING.match(stripped):
            alone(line)
        elif _UNDERLINE.match(stripped) and kind == "paragraph":
            raise refuse(number, "a heading underlined with = or -", "write it with #")
        elif _RULE.match(stripped) or stripped.startswith("|"):
            alone(line)
        elif _TABLE_RULE.match(stripped):
            raise refuse(number, "a table without leading pipes", "start each row with |")
        elif stripped.startswith(">"):
            if after_quote:
                raise refuse(number, "a quote over several lines", "write it on one line")
            alone(line)
        elif _LINK_DEFINITION.match(line) and current is None:
            alone(line)
        elif _HTML.match(stripped) and current is None:
            raise refuse(number, "HTML", "write it in Markdown")
        elif starts_item:
            flush()
            current, kind, item_indent = line, "bullet" if bullet else "numbered", indent
        elif after_quote:
            raise refuse(number, "a quote over several lines", "write it on one line")
        elif current is None:
            if line[0].isspace():
                raise refuse(
                    number,
                    "an indented block",
                    "use a fenced block for code, or a new item for a second paragraph",
                )
            current, kind = stripped, "paragraph"
        else:
            current = f"{current} {stripped}"
    flush()
    if fences.open:
        raise ReleaseError("the changelog entry ends inside a fenced block")
    while out and out[-1] == "":
        out.pop()
    while out and out[0] == "":
        out.pop(0)
    return "\n".join(out) + "\n"


def release_notes(version: str, root: Path = ROOT) -> str:
    """The changelog entry for the version in the files, ready to publish."""
    actual = project_version(root)
    if version != actual:
        raise ReleaseError(f"asked for the notes of {version} and the files say {actual}")
    changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    return unwrap(changelog_entry(version, changelog))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("version", help="print the version in the files")
    check = sub.add_parser("check", help="the tag must name the version in the files")
    check.add_argument("tag")
    notes = sub.add_parser("notes", help="print the changelog entry for a version")
    notes.add_argument("version")
    args = parser.parse_args(argv)
    try:
        if args.command == "version":
            print(project_version())
        elif args.command == "check":
            print(check_tag(args.tag))
        else:
            sys.stdout.write(release_notes(args.version))
    except (ReleaseError, OSError, KeyError, tomllib.TOMLDecodeError) as exc:
        print(f"release check failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
