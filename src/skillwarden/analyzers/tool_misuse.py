"""Tool-misuse patterns: destructive or mass operations a skill can drive
through the agent's tools (bulk delete, history rewrite, secret dumps)."""

from __future__ import annotations

from typing import ClassVar

from skillwarden.analyzers.base import Pattern, PatternAnalyzer
from skillwarden.models import Category, Severity


class ToolMisuseAnalyzer(PatternAnalyzer):
    id = "static_tool_misuse"
    category = Category.TOOL_MISUSE

    patterns: ClassVar[list[Pattern]] = [
        Pattern(
            rule_id="TM-001",
            regex=r"\brm\s+-rf?\s+(/|~|\$HOME|\*)|shutil\.rmtree\s*\(|rmdir\s+/s",
            severity=Severity.CRITICAL,
            title="Recursive / destructive delete",
            description="Recursively deletes broad paths: catastrophic if the target is wrong.",
            remediation="Delete specific, validated paths; never rm -rf a root/home/glob.",
        ),
        Pattern(
            rule_id="TM-002",
            regex=r"\bgit\s+(push\s+--force|reset\s+--hard|clean\s+-[fd]+|filter-branch|push\s+-f)\b",
            severity=Severity.HIGH,
            title="Destructive git operation",
            description="Rewrites or discards history/working tree: irreversible data loss risk.",
        ),
        Pattern(
            rule_id="TM-003",
            regex=r"\b(DROP\s+(TABLE|DATABASE)|TRUNCATE\s+TABLE|DELETE\s+FROM\s+\w+\s*;?\s*$)",
            severity=Severity.HIGH,
            title="Destructive database statement",
            description="Drops/truncates/unfiltered-deletes database data.",
        ),
        Pattern(
            rule_id="TM-004",
            regex=r"\b(mkfs|dd\s+if=.*of=/dev/|>\s*/dev/sd[a-z]|fdisk|wipefs)\b",
            severity=Severity.CRITICAL,
            title="Disk / device-level write",
            description="Writes directly to block devices: can destroy a filesystem.",
        ),
        Pattern(
            rule_id="TM-005",
            regex=r"\b(printenv|env\s*\|\s*(curl|nc|mail)|os\.environ\b.*(post|send|dump)|dump.*secrets?)\b",
            severity=Severity.HIGH,
            title="Environment / secret dump",
            description="Reads and forwards the process environment, which often holds secrets.",
        ),
        Pattern(
            rule_id="TM-006",
            regex=r"\b(kill\s+-9\s+-1|killall|pkill\s+-9|taskkill\s+/F\s+/IM\s+\*)\b",
            severity=Severity.MEDIUM,
            title="Mass process termination",
            description="Kills broad sets of processes: can take down unrelated services.",
        ),
    ]
