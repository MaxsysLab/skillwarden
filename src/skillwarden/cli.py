"""SkillWarden CLI. `skillwarden scan <target> [--format ...] [--no-llm] [--no-osv] ...`"""

from __future__ import annotations

import sys

import typer
from rich.console import Console
from rich.text import Text

from skillwarden import __version__
from skillwarden.engine import scan
from skillwarden.models import Severity, printable
from skillwarden.report.formatters import FORMATS, render
from skillwarden.report.safe_text import visible
from skillwarden.suppression import Baseline, BaselineError

app = typer.Typer(
    add_completion=False, help="SkillWarden: vet AI agent skills before you install them."
)
# soft_wrap: Rich never inserts line breaks at the console width, so a path, a file name
# or an echoed option value always reaches stdout/stderr whole, on one line, whatever
# COLUMNS, the terminal width or the path length (a script capturing it gets the real
# value). Markup and control characters are still neutralised by `Text(visible(...))`.
console = Console(soft_wrap=True)
err = Console(stderr=True, soft_wrap=True)


def _version_cb(value: bool) -> None:
    if value:
        console.print(f"SkillWarden {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    _version: bool = typer.Option(False, "--version", callback=_version_cb, is_eager=True),
) -> None:
    pass


@app.command(name="scan")
def scan_cmd(
    target: str = typer.Argument(..., help="Directory, file, .zip, git URL, or https URL."),
    fmt: str = typer.Option("terminal", "--format", "-f", help="terminal|json|markdown|sarif"),
    output: str | None = typer.Option(None, "--output", "-o", help="Write report to FILE."),
    no_llm: bool = typer.Option(False, "--no-llm", help="Skip the semantic (LLM) pass."),
    no_osv: bool = typer.Option(
        False, "--no-osv", help="Skip the live known-vulnerability (OSV) lookup."
    ),
    baseline: str | None = typer.Option(
        None, "--baseline", "-b", help="Baseline YAML for suppression."
    ),
    fail_on: str = typer.Option(
        "high",
        "--fail-on",
        help="Exit non-zero at this severity (none to disable); incomplete scans always fail.",
    ),
) -> None:
    """Scan a skill and report its risk."""
    # Usage errors are refused before anything runs (exit 2): an unknown value is never
    # silently replaced by a default, which would hide a typo in a CI gate.
    if fmt not in FORMATS:
        err.print(Text(visible(f"Error: unknown --format {fmt!r}; use one of: "
                               f"{', '.join(FORMATS)}"), style="red"))
        raise typer.Exit(2)
    if fail_on != "none" and fail_on not in {s.value for s in Severity}:
        allowed = ", ".join(["none", *(s.value for s in Severity)])
        err.print(Text(visible(f"Error: unknown --fail-on {fail_on!r}; use one of: {allowed}"),
                       style="red"))
        raise typer.Exit(2)
    try:
        bl = Baseline.load(baseline) if baseline else None
    except BaselineError as exc:
        # A suppression list that cannot be applied means no scan ran: exit 2, like any
        # other unresolved input (never 1, which means "findings over the threshold").
        err.print(Text(visible(f"Error: {exc}"), style="red"))
        raise typer.Exit(2) from exc
    result = scan(target, use_llm=not no_llm, use_osv=not no_osv, baseline=bl)

    body = render(result, fmt)
    if output:
        with open(output, "w", encoding="utf-8") as fh:
            fh.write(body)
        # printable(): a non-UTF-8 path is shown backslash-escaped, never a crash.
        message = printable(f"Wrote {fmt} report to {output}")
        console.print(Text(visible(message), style="green"))
    else:
        # Printed verbatim: every format is already terminal-safe (see report.safe_text).
        # Re-rendering JSON through Rich would re-decode its \u escapes into raw C1/bidi
        # characters.
        print(body)

    exit_code = 2 if result.status == "incomplete" else _exit_code(result.severity_label, fail_on)
    raise typer.Exit(exit_code)


def _exit_code(label: Severity, fail_on: str) -> int:
    if fail_on == "none":
        return 0
    threshold = Severity(fail_on)  # validated in scan_cmd before the scan ran
    return 1 if label.weight >= threshold.weight else 0


if __name__ == "__main__":
    sys.exit(app())
