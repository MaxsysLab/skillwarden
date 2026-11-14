"""Rogue-agent patterns: self-replication, agent spawning, and command-and-control
behavior — a skill trying to become an autonomous, networked actor."""

from __future__ import annotations

from typing import ClassVar

from skillwarden.analyzers.base import Pattern, PatternAnalyzer
from skillwarden.models import Category, Severity


class RogueAgentAnalyzer(PatternAnalyzer):
    id = "static_rogue_agent"
    category = Category.ROGUE_AGENT

    patterns: ClassVar[list[Pattern]] = [
        Pattern(
            rule_id="RA-001",
            regex=r"\b(reverse\s+shell|bind\s+shell|/dev/tcp/|nc\s+-e\b|ncat\s+.*-e|socket\.connect.*subprocess)",
            severity=Severity.CRITICAL,
            title="Reverse / bind shell",
            description="Establishes an interactive shell to or from a remote host: classic C2.",
        ),
        Pattern(
            rule_id="RA-002",
            # "check in with" / bare "poll" matched benign agent docs. Require
            # explicit command-and-control phrasing or polling-to-execute.
            regex=r"\b(c2\s+server|command\s+and\s+control|beacon\s+(to|back|interval))\b|poll\b.{0,30}\b(commands?|tasks?)\b.{0,20}\b(execute|run|exec)\b",
            severity=Severity.HIGH,
            title="C2 beacon / task polling",
            description="Polls a remote endpoint for commands to execute: command-and-control behavior.",
        ),
        Pattern(
            rule_id="RA-003",
            # "copy the skill to a writeable location" is benign; require true
            # self-replication / worm semantics.
            regex=r"\b(copies?|replicates?|propagates?)\s+(itself|themselves)\b|self[- ]?replicat|\bwormable\b|(propagate|spread)\s+(to\s+)?(other\s+)?(hosts?|machines?|systems?|networks?)\b",
            severity=Severity.CRITICAL,
            title="Self-replication",
            description="Copies itself to other locations/hosts: worm-like propagation.",
        ),
        Pattern(
            rule_id="RA-004",
            # "create agents" is ordinary in agent-framework docs. Require the
            # *uncontrolled* signal: recursion, unbounded counts, or self-spawning.
            regex=r"\brecursively\s+(spawn|invoke|create)\b|\bagent\s+swarm\b|\b(spawn|launch)\s+(unbounded|unlimited|infinite|countless)\b|self[- ]replicat",
            severity=Severity.MEDIUM,
            title="Uncontrolled agent spawning",
            description="Spawns further agents without bound or oversight.",
            confidence=0.7,
        ),
        Pattern(
            rule_id="RA-005",
            regex=r"\b(disable|kill|stop|uninstall)\b.{0,25}\b(antivirus|edr|defender|firewall|logging|audit)",
            severity=Severity.CRITICAL,
            title="Defense evasion",
            description="Attempts to disable security controls or logging.",
        ),
    ]
