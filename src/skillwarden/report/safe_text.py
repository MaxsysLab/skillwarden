"""Neutralise untrusted text before it reaches a report.

File names, finding text, LLM output and error messages are attacker-controlled. In a
terminal, ESC / C0 / C1 control characters can restyle or rewrite the screen, bidi
overrides can reorder what the reader sees, and a newline can forge a report line. Each
such character is shown as a visible escape (``\\x1b``, ``\\u202e``) instead. Rich markup
is never parsed from untrusted text: the terminal formatter builds `rich.text.Text`
objects, so ``[red]`` or ``[/x]`` are displayed literally.
"""

from __future__ import annotations

import re

# C0 + DEL + C1 controls, bidi embedding/override/isolate marks, line/paragraph separators.
_UNSAFE = re.compile("[\x00-\x1f\x7f-\x9f؜‎‏  ‪-‮⁦-⁩]")
# The subset JSON encoders leave raw (C0 is always escaped by JSON itself).
_JSON_RAW_UNSAFE = re.compile("[\x7f-\x9f؜‎‏  ‪-‮⁦-⁩]")


def _escape(match: re.Match[str]) -> str:
    code = ord(match.group())
    return f"\\x{code:02x}" if code <= 0xFF else f"\\u{code:04x}"


def visible(text: str) -> str:
    """`text` with every control / bidi / line-separator character shown as an escape."""
    return _UNSAFE.sub(_escape, text)


def json_safe(document: str) -> str:
    """A JSON document with the remaining raw terminal-unsafe characters \\u-escaped.

    Those characters can only occur inside JSON strings, where ``\\uXXXX`` is an exact,
    valid encoding, so the parsed document is unchanged.
    """
    return _JSON_RAW_UNSAFE.sub(lambda m: f"\\u{ord(m.group()):04x}", document)
