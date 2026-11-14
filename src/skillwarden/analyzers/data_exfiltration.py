"""Data-exfiltration patterns: code or instructions that ship local data,
secrets, or conversation content to an external destination."""

from __future__ import annotations

from typing import ClassVar

from skillwarden import constants
from skillwarden.analyzers.base import Pattern, PatternAnalyzer
from skillwarden.models import Category, Severity


class DataExfiltrationAnalyzer(PatternAnalyzer):
    id = "static_data_exfiltration"
    category = Category.DATA_EXFILTRATION

    patterns: ClassVar[list[Pattern]] = [
        Pattern(
            rule_id="DX-001",
            regex=r"\b(curl|wget|requests\.(post|put)|httpx\.(post|put)|urllib)\b.*\b(http|https)://",
            severity=Severity.LOW,
            title="Outbound network call",
            description="Sends data to a remote endpoint. Review the destination and payload.",
            remediation="Confirm the endpoint is trusted and the payload contains no sensitive data.",
            confidence=0.5,
            # A bare HTTP call is weak signal and ubiquitous in docs; only flag in real code.
            only_types=constants.CODE_TYPES,
        ),
        Pattern(
            rule_id="DX-002",
            # Require the secret to be actually handed to a send call, not merely
            # near the word "http" (which matched docs constantly).
            regex=r"\b(AWS_SECRET|AWS_ACCESS_KEY|SECRET_KEY|PRIVATE_KEY)\b.*\b(requests\.|httpx\.|urllib|fetch\(|\.post\(|upload\()",
            severity=Severity.HIGH,
            title="Secret transmitted off-host",
            description="A credential value is passed to a transmission primitive.",
        ),
        Pattern(
            rule_id="DX-003",
            # `.env` only as a file reference — the lookbehind rejects `process.env`,
            # `os.environ`, etc. where the dot is preceded by an identifier char.
            regex=r"(\.ssh/id_|/etc/passwd|/etc/shadow|\.aws/credentials|\.netrc|(?<![\w.])\.env(?![\w]))",
            severity=Severity.HIGH,
            title="Sensitive file access",
            description="References a path that commonly holds credentials or secrets.",
            # In code/config a credential path is an access; in prose it's usually
            # a mention. Prompt-level threats in docs are caught by other analyzers.
            skip_types=("markdown",),
        ),
        Pattern(
            rule_id="DX-004",
            regex=r"\b(base64|b64encode|hexlify)\b.*\b(curl|post|send|requests|fetch|upload)\b|\b(curl|post|send)\b.*\bbase64\b",
            severity=Severity.HIGH,
            title="Encoded data transmission",
            description="Encoding combined with transmission is a common exfiltration-obfuscation tactic.",
        ),
        Pattern(
            rule_id="DX-005",
            regex=r"(webhook\.site|requestbin|pipedream\.net|ngrok\.io|burpcollaborator|interact\.sh|\boast\.(live|fun|online|site|pro|me)\b)",
            severity=Severity.CRITICAL,
            title="Known exfiltration/callback host",
            description="References a service frequently used as an exfiltration or OOB callback sink.",
        ),
    ]
