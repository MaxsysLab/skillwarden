"""Harmful-content patterns: a skill whose *purpose* is to produce malware,
exploits, credential theft, or other clearly malicious capability."""

from __future__ import annotations

from typing import ClassVar

from skillwarden.analyzers.base import Pattern, PatternAnalyzer
from skillwarden.models import Category, Severity


class HarmfulContentAnalyzer(PatternAnalyzer):
    id = "static_harmful_content"
    category = Category.HARMFUL_CONTENT

    patterns: ClassVar[list[Pattern]] = [
        Pattern(
            rule_id="HC-001",
            regex=r"\b(ransomware|keylogger|rootkit|botnet|cryptominer|coinminer|stealer\b|infostealer)\b",
            severity=Severity.CRITICAL,
            title="Malware capability keyword",
            description="Names a malware capability directly: strong signal of malicious intent.",
        ),
        Pattern(
            rule_id="HC-002",
            regex=r"\b(encrypt\s+(all\s+)?(the\s+)?files?|hold\s+.*ransom|ransom\s+note|\.locked\b|extension\s+to\s+encrypted)",
            severity=Severity.CRITICAL,
            title="Ransomware behavior",
            description="Mass file encryption / ransom behavior.",
        ),
        Pattern(
            rule_id="HC-003",
            regex=r"\b(steal|harvest|dump|exfiltrate)\s+(credentials|passwords?|cookies|tokens?|browser\s+data|wallet)",
            severity=Severity.HIGH,
            title="Credential / data theft",
            description="Describes harvesting credentials or sensitive user data.",
        ),
        Pattern(
            rule_id="HC-004",
            # Bare "exploit"/"rce" matched prose, incl. prohibitions ("must not
            # contain exploit code"). Require concrete offensive-tooling terms.
            # Keyword presence is weak signal — the LLM pass adjudicates intent.
            regex=r"\b(0day|zero-?day|shellcode|exploit\s+(kit|chain)|weaponized?|payload\s+delivery|metasploit|cobalt\s+strike|meterpreter)\b",
            severity=Severity.MEDIUM,
            title="Exploit / offensive payload",
            description="References exploit/shellcode tooling. Confirm authorized security context.",
            confidence=0.6,
        ),
        Pattern(
            rule_id="HC-005",
            regex=r"\b(phishing|spear-?phish|credential\s+harvesting\s+page|fake\s+login\s+page|clone\s+the\s+login)",
            severity=Severity.HIGH,
            title="Phishing capability",
            description="Describes building phishing or credential-harvesting lures.",
        ),
    ]
