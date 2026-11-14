"""Excessive-agency patterns: a skill that grants itself autonomy beyond its
stated job — persistence, self-modification, unattended approval, unbounded loops."""

from __future__ import annotations

from typing import ClassVar

from skillwarden.analyzers.base import Pattern, PatternAnalyzer
from skillwarden.models import Category, Severity


class ExcessiveAgencyAnalyzer(PatternAnalyzer):
    id = "static_excessive_agency"
    category = Category.EXCESSIVE_AGENCY

    patterns: ClassVar[list[Pattern]] = [
        Pattern(
            rule_id="EA-001",
            regex=r"\bcrontab\b|\bcron\.d\b|systemd.*\.timer|\blaunchctl\b|schtasks",
            severity=Severity.HIGH,
            title="Self-scheduling / persistence",
            description="Installs a scheduled task so the skill runs unattended later.",
            remediation="A skill should act when invoked, not schedule itself to run on its own.",
        ),
        Pattern(
            rule_id="EA-002",
            # Bare words "Startup"/"autostart" matched ordinary prose ("attached
            # at startup"). Keep only concrete persistence-file paths.
            regex=r"(\.bashrc|\.bash_profile|\.zshrc|\.profile\b|LaunchAgents|/etc/cron|\.config/autostart)",
            severity=Severity.HIGH,
            title="Autostart persistence target",
            description="Writes to a shell-init or autostart location to survive across sessions.",
        ),
        Pattern(
            rule_id="EA-003",
            regex=r"--yes\b|--force\b|\s-y\b|auto[_-]?approve|confirm\s*=\s*False|--no-confirm|--assume-yes",
            severity=Severity.MEDIUM,
            title="Approval / confirmation bypass",
            description="Suppresses confirmation prompts so destructive actions proceed unattended.",
            confidence=0.7,
        ),
        Pattern(
            rule_id="EA-004",
            regex=r"\bwhile\s+True\b.*\b(subprocess|spawn|fork|requests|httpx|os\.system)",
            severity=Severity.MEDIUM,
            title="Unbounded action loop",
            description="An open-ended loop driving side effects can run away without supervision.",
        ),
        Pattern(
            rule_id="EA-005",
            regex=r"(modify|rewrite|edit|patch)\s+(its|my|your|own)\s+(own\s+)?(code|source|file|instructions)",
            severity=Severity.HIGH,
            title="Self-modification directive",
            description="Instructs the skill/agent to alter its own code or instructions.",
        ),
        Pattern(
            rule_id="EA-006",
            regex=r"\bgit\s+push\b|\bgh\s+(pr|release)\b|\bnpm\s+publish\b|\btwine\s+upload\b|deploy\s+to\s+prod",
            severity=Severity.MEDIUM,
            title="Outbound publish/deploy action",
            description="Pushes code or publishes artifacts: high-impact action for a skill to take itself.",
            confidence=0.75,
            # Real deploy actions live in scripts/CI; in docs these are examples.
            skip_types=("markdown",),
        ),
    ]
