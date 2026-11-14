"""Privilege-escalation patterns: code or instructions that seek elevated
rights, weaken permissions, or break out of a sandbox/container."""

from __future__ import annotations

from typing import ClassVar

from skillwarden.analyzers.base import Pattern, PatternAnalyzer
from skillwarden.models import Category, Severity


class PrivilegeEscalationAnalyzer(PatternAnalyzer):
    id = "static_privilege_escalation"
    category = Category.PRIVILEGE_ESCALATION

    patterns: ClassVar[list[Pattern]] = [
        Pattern(
            rule_id="PE-001",
            regex=r"\bsudo\s+(-\w+\s+)*\S",
            severity=Severity.MEDIUM,
            title="Privilege elevation via sudo",
            description="Runs a command as root. Verify it is necessary and the command is safe.",
            remediation="Avoid sudo in skills; if required, scope it to a single, reviewed command.",
            confidence=0.7,
        ),
        Pattern(
            rule_id="PE-002",
            regex=r"\bchmod\s+([ug]\+s|[0-7]?[4267][0-7][0-7])\b|\bos\.set[ug]id\b|\bsetuid\b",
            severity=Severity.HIGH,
            title="Setuid / permission elevation",
            description="Sets setuid/setgid or grants elevated file permissions: a privilege-escalation vector.",
        ),
        Pattern(
            rule_id="PE-003",
            regex=r"\bchmod\s+(-R\s+)?0?777\b",
            severity=Severity.HIGH,
            title="World-writable permissions",
            description="chmod 777 makes a path writable by anyone: enables tampering and escalation.",
            remediation="Grant the narrowest permissions that work.",
        ),
        Pattern(
            rule_id="PE-004",
            regex=r"--privileged\b|\bcap_add\b|CAP_SYS_ADMIN|securityContext|--cap-add",
            severity=Severity.HIGH,
            title="Privileged container / added capabilities",
            description="Requests privileged mode or extra Linux capabilities: near-host-root access.",
        ),
        Pattern(
            rule_id="PE-005",
            regex=r"/etc/sudoers|\bvisudo\b|NOPASSWD",
            severity=Severity.CRITICAL,
            title="Sudoers modification",
            description="Edits sudoers / grants passwordless sudo: a persistent privilege backdoor.",
        ),
        Pattern(
            rule_id="PE-006",
            regex=r"/var/run/docker\.sock|\bnsenter\b|/proc/1/root|\b--pid=host\b",
            severity=Severity.CRITICAL,
            title="Container-escape primitive",
            description="References a known container-escape mechanism (docker socket, host PID, nsenter).",
        ),
    ]
