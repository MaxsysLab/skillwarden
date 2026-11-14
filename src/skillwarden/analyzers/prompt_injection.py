"""Prompt-injection patterns: instructions embedded in a skill that try to
override, exfiltrate, or hijack the host agent's behavior."""

from __future__ import annotations

from typing import ClassVar

from skillwarden.analyzers.base import Pattern, PatternAnalyzer
from skillwarden.models import Category, Severity


class PromptInjectionAnalyzer(PatternAnalyzer):
    id = "static_prompt_injection"
    category = Category.PROMPT_INJECTION

    patterns: ClassVar[list[Pattern]] = [
        Pattern(
            rule_id="PI-001",
            regex=r"\bignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|prompts?|rules?)\b",
            severity=Severity.HIGH,
            title="Instruction-override directive",
            description="Text instructs the agent to disregard prior instructions: a classic injection.",
            remediation="Remove override language; a skill should add capability, not rewrite the agent's rules.",
        ),
        Pattern(
            rule_id="PI-002",
            regex=r"\b(disregard|forget|override)\s+(your\s+)?(system\s+prompt|guidelines|safety|guardrails)\b",
            severity=Severity.HIGH,
            title="Safety/guardrail override directive",
            description="Attempts to disable the agent's safety or system constraints.",
        ),
        Pattern(
            rule_id="PI-003",
            regex=r"\byou\s+are\s+now\s+(a|an|in)\b|\bact\s+as\s+(if\s+you\s+are\s+)?(a\s+)?(dan|jailbroken|unrestricted)\b",
            severity=Severity.MEDIUM,
            title="Persona/role hijack",
            description="Reassigns the agent's identity to bypass its configured behavior.",
        ),
        Pattern(
            rule_id="PI-004",
            # Case-sensitive: real chat-template tags are lowercase. Avoids matching
            # TypeScript generics like `Promise<User>` / `Array<System>`.
            regex=r"</?(system|assistant|user)>|<\|(system|assistant|user)\|>|\[/?(INST|SYS)\]",
            flags=0,
            severity=Severity.MEDIUM,
            title="Chat-template injection markers",
            description="Embeds role/template delimiters that may be interpreted as conversation turns.",
        ),
        Pattern(
            rule_id="PI-005",
            regex=r"\bdo\s+not\s+(tell|inform|mention\s+to)\s+(the\s+)?(user|human|operator)\b",
            severity=Severity.HIGH,
            title="Conceal-from-user directive",
            description="Instructs the agent to hide actions from the user: a hallmark of covert behavior.",
        ),
    ]
