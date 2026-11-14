"""Align markdown table columns. Pure string manipulation, no side effects."""


def align_table(text: str) -> str:
    rows = [line.split("|") for line in text.strip().splitlines()]
    widths = [max(len(r[i].strip()) for r in rows) for i in range(len(rows[0]))]
    out = []
    for r in rows:
        cells = [c.strip().ljust(widths[i]) for i, c in enumerate(r)]
        out.append(" | ".join(cells))
    return "\n".join(out)
