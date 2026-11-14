"""Trigger-abuse patterns: logic that lies dormant and fires on a hidden
condition — time bombs, specific-date/host triggers, magic phrases."""

from __future__ import annotations

from typing import ClassVar

from skillwarden.analyzers.base import Pattern, PatternAnalyzer
from skillwarden.models import Category, Severity


class TriggerAbuseAnalyzer(PatternAnalyzer):
    id = "static_trigger_abuse"
    category = Category.TRIGGER_ABUSE

    patterns: ClassVar[list[Pattern]] = [
        Pattern(
            rule_id="TA-001",
            regex=r"\bif\b.{0,40}\b(datetime|date\.today|time\.time|now\(\))\b.{0,20}([<>=]=?|after|before)",
            severity=Severity.HIGH,
            title="Date/time-gated logic (time bomb)",
            description="Behavior is conditioned on a specific date/time: payload may lie dormant until then.",
        ),
        Pattern(
            rule_id="TA-002",
            regex=r"\bif\b.{0,30}\b(hostname|gethostname|platform\.node|getpass\.getuser|os\.getlogin)\b",
            severity=Severity.MEDIUM,
            title="Host/user-gated logic",
            description="Behavior depends on a specific host or user: targeted, environment-aware payload.",
        ),
        Pattern(
            rule_id="TA-003",
            # Was matching every `if x == "literal":`. Now requires explicit
            # secret-trigger language — an ordinary equality check is not a backdoor.
            regex=r"\b(magic|secret|hidden|activation)\s+(word|phrase|key|token|string)\b|\bkill\s*switch\b|\bbackdoor\b",
            severity=Severity.MEDIUM,
            title="Hidden trigger phrase",
            description="A secret phrase/token gates hidden behavior: a covert backdoor switch.",
            confidence=0.6,
        ),
        Pattern(
            rule_id="TA-004",
            regex=r"\bsleep\s*\(\s*\d{4,}\s*\)|time\.sleep\s*\(\s*\d{4,}|delay.{0,10}\d{4,}\s*(seconds|ms)",
            severity=Severity.LOW,
            title="Long dormancy delay",
            description="A very long sleep/delay can be used to evade short-lived sandboxes.",
            confidence=0.6,
        ),
        Pattern(
            rule_id="TA-005",
            regex=r"\bif\b.{0,30}\b(sandbox|virtual|vm|docker|ci|debugger|analysis)\b.{0,20}(detect|present|running)",
            severity=Severity.HIGH,
            title="Sandbox / analysis evasion",
            description="Changes behavior when it detects a sandbox/VM/CI: anti-analysis logic.",
        ),
    ]
