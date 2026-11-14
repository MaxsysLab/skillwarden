"""Human/machine output formats: terminal (Rich), JSON, Markdown.
SARIF lives in sarif.py. The CLI picks one via --format."""

from __future__ import annotations

import io
import re

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from skillwarden.models import Finding, ScanResult, Severity
from skillwarden.report.safe_text import json_safe, visible
from skillwarden.report.sarif import to_sarif

_SEV_COLOR = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def _location(f: Finding) -> str:
    if not f.file:
        return "-"
    return f"{f.file}:{f.line}" if f.line else f.file


FORMATS = ("terminal", "json", "markdown", "sarif")


def render(result: ScanResult, fmt: str) -> str:
    if fmt == "json":
        return json_safe(result.model_dump_json(indent=2))
    if fmt == "sarif":
        return json_safe(to_sarif(result))
    if fmt == "markdown":
        return _markdown(result)
    if fmt == "terminal":
        return _terminal(result)
    raise ValueError(f"unknown format {fmt!r}; use one of: {', '.join(FORMATS)}")


def _t(text: str, style: str = "") -> Text:
    """Untrusted text as a literal Rich `Text` (markup never parsed, controls escaped)."""
    return Text(visible(text), style=style)


# The terminal report is at least this wide; it grows so that no path is cut or folded.
_MIN_WIDTH = 100
# Room kept for the (wrappable, prose) Finding column next to the no-wrap columns.
_FINDING_MIN = 24
# A 4-column table: 5 borders + 2 padding cells per column.
_TABLE_CHROME = 5 + 4 * 2
# Panel title: 2 corners, 2 rule cells and 2 spaces around the title.
_PANEL_CHROME = 6


def _terminal(result: ScanResult) -> str:
    # Render into a buffer (don't emit here); the caller prints the returned text
    # exactly once and can also write it to --output. Every untrusted string goes in as
    # a `Text` object, never as markup (see safe_text).
    #
    # Paths are never wrapped, folded or cut with an ellipsis: the console is made wide
    # enough for the target title and for every Sev/Rule/Location cell (fixed, so the
    # report never depends on the user's terminal width), and the free-text lines below
    # the table are printed with soft_wrap (one logical line each, whatever its length).
    label = result.severity_label
    style = _SEV_COLOR[label]
    title = Text.assemble("SkillWarden: ", _t(result.target))
    findings = sorted(result.findings, key=lambda x: -x.severity.weight)
    rows = [
        (
            Text(f.severity.value, style=_SEV_COLOR[f.severity]),
            _t(f.rule_id),
            _t(f.title),
            _t(_location(f)),
        )
        for f in findings
    ]
    width = max(_MIN_WIDTH, title.cell_len + _PANEL_CHROME)
    if rows:
        sev_w = max(len("Sev"), *(r[0].cell_len for r in rows))
        rule_w = max(len("Rule"), *(r[1].cell_len for r in rows))
        loc_w = max(len("Location"), *(r[3].cell_len for r in rows))
        width = max(width, sev_w + rule_w + loc_w + _FINDING_MIN + _TABLE_CHROME)
    console = Console(record=True, width=width, file=io.StringIO())
    console.print(
        Panel(
            Text.assemble(
                (f" {label.value.upper()} ", style),
                "  risk score ",
                (f"{result.risk_score}/100", "bold"),
                "\n\n",
                _t(result.recommendation),
            ),
            title=title,
            border_style=style.split()[-1] if " " in style else style,
        )
    )

    if rows:
        table = Table(show_lines=False, expand=True)
        table.add_column("Sev", no_wrap=True)
        table.add_column("Rule", no_wrap=True)
        table.add_column("Finding")
        table.add_column("Location", no_wrap=True)
        for row in rows:
            table.add_row(*row)
        console.print(table)
    elif result.status == "incomplete":
        console.print(Text("No findings (scan incomplete).", style="yellow"))
    else:
        console.print(Text("No findings.", style="green"))

    console.print(
        Text(
            f"\nStatus: {result.status.upper()} · Scanned {len(result.components)} components · "
            + (f"Skipped {len(result.skipped)} inputs · " if result.skipped else "")
            + f"LLM pass: {'yes' if result.used_llm else 'no'}"
        ),
        soft_wrap=True,
    )
    if result.errors:
        console.print(
            Text.assemble(("Errors:", "red"), " ", _t("; ".join(result.errors))), soft_wrap=True
        )
    if result.skipped:
        console.print(
            Text.assemble(
                ("Skipped inputs (scan incomplete):", "red"),
                " ",
                _t("; ".join(f"{s.path} ({s.reason})" for s in result.skipped)),
            ),
            soft_wrap=True,
        )
    if result.warnings:
        console.print(
            Text.assemble(("Warnings:", "yellow"), " ", _t("; ".join(result.warnings))),
            soft_wrap=True,
        )
    return console.export_text()


def _md(text: str) -> str:
    """Untrusted text for a Markdown line or table cell: controls escaped, pipes escaped."""
    return visible(text).replace("|", "\\|")


def _md_code(text: str, *, in_table: bool = False) -> str:
    """Untrusted text as an inline code span that its own backticks cannot close."""
    body = _md(text) if in_table else visible(text)
    longest = max((len(run) for run in re.findall("`+", body)), default=0)
    fence = "`" * (longest + 1)
    pad = " " if body.startswith("`") or body.endswith("`") else ""
    return f"{fence}{pad}{body}{pad}{fence}"


def _markdown(result: ScanResult) -> str:
    c = result.counts
    out = [
        f"# SkillWarden Report: {_md_code(result.target)}",
        "",
        f"**Status:** {result.status.upper()} · **Risk:** {result.severity_label.value.upper()} "
        f"· **Score:** {result.risk_score}/100",
        "",
        f"> {_md(result.recommendation)}",
        "",
        f"Components: {len(result.components)} · "
        f"Critical: {c['critical']} · High: {c['high']} · Medium: {c['medium']} · "
        f"Low: {c['low']} · Info: {c['info']}",
        "",
        "## Findings",
        "",
        "| Severity | Rule | Category | Finding | Location |",
        "|----------|------|----------|---------|----------|",
    ]
    for f in sorted(result.findings, key=lambda x: -x.severity.weight):
        raw = _location(f)
        loc = _md_code(raw, in_table=True) if raw != "-" else raw
        out.append(
            f"| {f.severity.value} | {_md(f.rule_id)} | {f.category.value} | {_md(f.title)} "
            f"| {loc} |"
        )
    if not result.findings:
        summary = (
            "Inconclusive: scan incomplete" if result.status == "incomplete" else "No findings"
        )
        out.append(f"| – | – | – | {summary} | – |")
    if result.errors:
        out.extend(["", "## Errors", *[f"- {_md(error)}" for error in result.errors]])
    if result.skipped:
        out.extend(
            [
                "",
                "## Skipped inputs (scan incomplete)",
                *[f"- {_md_code(s.path)}: {_md(s.reason)}" for s in result.skipped],
            ]
        )
    if result.warnings:
        out.extend(["", "## Warnings", *[f"- {_md(warning)}" for warning in result.warnings]])
    return "\n".join(out)
