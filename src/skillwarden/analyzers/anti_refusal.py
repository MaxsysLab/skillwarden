"""Anti-refusal patterns: jailbreak framing that pressures the agent to bypass
its safety behavior (compliance demands, hypothetical wrappers, DAN-style)."""

from __future__ import annotations

from typing import ClassVar

from skillwarden.analyzers.base import Pattern, PatternAnalyzer
from skillwarden.models import Category, Severity


class AntiRefusalAnalyzer(PatternAnalyzer):
    id = "static_anti_refusal"
    category = Category.ANTI_REFUSAL

    patterns: ClassVar[list[Pattern]] = [
        Pattern(
            rule_id="AR-001",
            regex=r"\byou\s+(must|will|have\s+to|are\s+required\s+to)\s+(comply|obey|answer|never\s+refuse)\b",
            severity=Severity.MEDIUM,
            title="Compliance coercion",
            description="Pressures the agent to comply unconditionally and never refuse.",
        ),
        Pattern(
            rule_id="AR-002",
            regex=r"\b(do\s+not|don't|never)\s+(refuse|decline|say\s+no|add\s+(warnings?|disclaimers?|caveats?))\b",
            severity=Severity.MEDIUM,
            title="Refusal / warning suppression",
            description="Instructs the agent to drop refusals, warnings, or disclaimers.",
        ),
        Pattern(
            rule_id="AR-003",
            regex=r"\b(hypothetically|in\s+a\s+fictional|for\s+a\s+story|as\s+a\s+thought\s+experiment|pretend)\b.{0,40}\b(no\s+rules|without\s+restrictions|anything)",
            severity=Severity.MEDIUM,
            title="Hypothetical-framing jailbreak",
            description="Wraps a disallowed request in fiction/hypothesis to evade safety.",
            confidence=0.7,
        ),
        Pattern(
            rule_id="AR-004",
            regex=r"\b(DAN|do\s+anything\s+now|developer\s+mode|jailbreak|unfiltered\s+(mode|response)|no\s+(guardrails|filters))\b",
            severity=Severity.HIGH,
            title="Named jailbreak persona/mode",
            description="Invokes a well-known jailbreak persona or 'unfiltered' mode.",
        ),
        Pattern(
            rule_id="AR-005",
            regex=r"\bstay\s+in\s+character\b|\bnever\s+break\s+character\b|\bremain\s+(jailbroken|unrestricted)\b",
            severity=Severity.MEDIUM,
            title="Persona-lock directive",
            description="Tries to lock the agent into a bypassed persona for the session.",
        ),
    ]
