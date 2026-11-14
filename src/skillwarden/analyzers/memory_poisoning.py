"""Memory-poisoning patterns: a skill that writes durable instructions into the
agent's persistent memory/config so they take effect in future sessions."""

from __future__ import annotations

from typing import ClassVar

from skillwarden.analyzers.base import Pattern, PatternAnalyzer
from skillwarden.models import Category, Severity


class MemoryPoisoningAnalyzer(PatternAnalyzer):
    id = "static_memory_poisoning"
    category = Category.MEMORY_POISONING

    patterns: ClassVar[list[Pattern]] = [
        Pattern(
            rule_id="MP-001",
            regex=r"\b(CLAUDE\.md|AGENTS\.md|\.cursorrules|copilot-instructions|MEMORY\.md|\.github/copilot)",
            # Merely naming an instruction file (common in docs) is benign; the
            # danger is *writing* to one, which MP-002 catches. Keep this as a
            # low-confidence signal, not a high-severity hit.
            severity=Severity.LOW,
            title="Agent-memory / instruction file reference",
            description="References a file that durably steers agent behavior across sessions.",
            remediation="Confirm the skill only reads, never writes, agent-instruction files.",
            confidence=0.4,
        ),
        Pattern(
            rule_id="MP-002",
            regex=r"(>>|append|write_text|\.write\(|echo\s+.*>>)\s*.{0,40}(CLAUDE\.md|MEMORY\.md|\.claude|instructions|memory)",
            severity=Severity.CRITICAL,
            title="Write into persistent memory",
            description="Appends/writes content into a persistent memory or instruction store.",
        ),
        Pattern(
            rule_id="MP-003",
            regex=r"\bremember\s+(this|that|to|always)\b.{0,40}\b(always|forever|every\s+(time|session)|from\s+now\s+on)",
            severity=Severity.MEDIUM,
            title="Durable-instruction implant",
            description="Instructs the agent to permanently remember a behavior: memory poisoning.",
        ),
        Pattern(
            rule_id="MP-004",
            regex=r"\b(in|for)\s+(future|subsequent|all)\s+(sessions|conversations|chats)\b|\bnext\s+time\s+you\b",
            severity=Severity.MEDIUM,
            title="Future-session instruction",
            description="Plants an instruction intended to fire in later, unrelated sessions.",
        ),
        Pattern(
            rule_id="MP-005",
            regex=r"(~/\.config|settings\.json|\.claude/settings).{0,30}(write|append|modify|update|patch)",
            severity=Severity.HIGH,
            title="Persistent config modification",
            description="Modifies global agent/tool configuration that persists beyond this run.",
        ),
    ]
