"""Output-handling patterns: ways a skill's output can attack the terminal, the
renderer, or the user — escape sequences, hidden unicode, injected markup."""

from __future__ import annotations

from typing import ClassVar

from skillwarden.analyzers.base import Pattern, PatternAnalyzer
from skillwarden.models import Category, Severity


class OutputHandlingAnalyzer(PatternAnalyzer):
    id = "static_output_handling"
    category = Category.OUTPUT_HANDLING

    patterns: ClassVar[list[Pattern]] = [
        Pattern(
            rule_id="OH-001",
            regex=r"\x1b\[|\\x1b\[|\\033\[|\\u001b\[|\\e\[",
            severity=Severity.MEDIUM,
            title="ANSI / terminal escape sequence",
            description="Emits raw terminal escapes: can spoof output, hide text, or alter the terminal.",
            remediation="Strip or escape control sequences before printing untrusted content.",
        ),
        Pattern(
            rule_id="OH-002",
            # Dropped U+FEFF (BOM) — it legitimately leads XML/text files and was
            # flagging every .xsd. Keep zero-width chars and the RTL override.
            regex=r"[​‌‍⁠‮]|\\u200[bcd]|\\u202e",
            severity=Severity.HIGH,
            title="Hidden / zero-width / bidi unicode",
            description="Contains invisible or right-to-left-override characters used to hide payloads.",
        ),
        Pattern(
            rule_id="OH-003",
            regex=r"dangerouslySetInnerHTML|\.innerHTML\s*=|document\.write\s*\(|v-html\b",
            # A code smell, not a definite vuln — frontend/HTML-asset skills use
            # these legitimately. Low + low confidence so it informs, not dominates.
            severity=Severity.LOW,
            title="Unsanitized HTML injection sink",
            description="Writes raw HTML to the DOM: an XSS sink if any input is untrusted.",
            confidence=0.5,
        ),
        Pattern(
            rule_id="OH-004",
            regex=r"!\[[^\]]*\]\(https?://[^)]+\)",
            severity=Severity.LOW,
            title="Remote image in output",
            description="An auto-loaded remote image can leak a render-time beacon (IP, timing).",
            confidence=0.6,
        ),
        Pattern(
            rule_id="OH-005",
            regex=r"\[[^\]]+\]\((javascript:|data:text/html)",
            severity=Severity.HIGH,
            title="Dangerous link scheme in output",
            description="Embeds a javascript:/data: link in rendered output.",
        ),
    ]
