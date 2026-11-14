"""System-prompt-leakage patterns: attempts to extract, reproduce, or exfiltrate
the host agent's system prompt / hidden instructions."""

from __future__ import annotations

from typing import ClassVar

from skillwarden.analyzers.base import Pattern, PatternAnalyzer
from skillwarden.models import Category, Severity


class SystemPromptLeakageAnalyzer(PatternAnalyzer):
    id = "static_system_prompt_leakage"
    category = Category.SYSTEM_PROMPT_LEAKAGE

    patterns: ClassVar[list[Pattern]] = [
        Pattern(
            rule_id="SPL-001",
            regex=r"\b(reveal|print|repeat|show|output|reproduce|display|recite)\b.{0,30}\b(system\s+prompt|initial\s+(instructions|prompt)|your\s+instructions|above\s+(text|instructions))",
            severity=Severity.HIGH,
            title="System-prompt extraction directive",
            description="Asks the agent to reproduce its system prompt or hidden instructions.",
        ),
        Pattern(
            rule_id="SPL-002",
            regex=r"\bwhat\s+(are|were)\s+your\s+(exact\s+)?(instructions|rules|system\s+prompt|guidelines)\b",
            severity=Severity.MEDIUM,
            title="Instruction-probing question",
            description="Probes the agent to disclose its configured instructions.",
        ),
        Pattern(
            rule_id="SPL-003",
            regex=r"\b(base64|rot13|encode|hex)\b.{0,30}\b(system\s+prompt|instructions|prompt)\b",
            severity=Severity.HIGH,
            title="Encoded instruction exfiltration",
            description="Requests the system prompt in an encoded form to slip past output filters.",
        ),
        Pattern(
            rule_id="SPL-004",
            regex=r"\b(everything\s+above|all\s+text\s+above|prior\s+messages?)\b.{0,30}\b(verbatim|word\s+for\s+word|exactly)",
            severity=Severity.MEDIUM,
            title="Verbatim context dump request",
            description="Asks for the full prior context verbatim: a common prompt-leak technique.",
        ),
    ]
