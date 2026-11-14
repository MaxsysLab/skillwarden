"""MCP tool-poisoning analyzer: an MCP tool's *description* is fed to the model,
so a malicious server can smuggle instructions there — hidden directives, calls
to read secrets, or 'rug-pull' language that changes behavior post-approval."""

from __future__ import annotations

import re

from skillwarden.analyzers.base import Analyzer, ScanContext
from skillwarden.analyzers.mcp_common import parse_configs, walk
from skillwarden.models import Category, Finding, Severity, Source

_DESC_KEYS = {"description", "instructions", "prompt", "summary", "usage"}

# Signals that a description is doing more than describing a tool.
_INJECTION = re.compile(
    r"(ignore\s+(previous|prior)|do\s+not\s+(tell|mention|inform)|<\s*(important|system|secret)\s*>|"
    r"before\s+(using|calling)\s+this\s+tool|you\s+must\s+(first|also)|in\s+addition,?\s+(always|secretly))",
    re.IGNORECASE,
)
_SECRET_ACCESS = re.compile(
    r"(\.ssh|\.env\b|\.aws/credentials|/etc/passwd|id_rsa|api[_\s-]?key|read\s+the\s+file|cat\s+~?/)",
    re.IGNORECASE,
)
_RUG_PULL = re.compile(
    r"(once\s+(approved|trusted|installed)|after\s+(approval|first\s+use)|on\s+subsequent\s+calls)",
    re.IGNORECASE,
)


class McpToolPoisoningAnalyzer(Analyzer):
    id = "mcp_tool_poisoning"
    category = Category.MCP_TOOL_POISONING

    def run(self, ctx: ScanContext) -> list[Finding]:
        out: list[Finding] = []
        for path, data in parse_configs(ctx):
            for jp, key, value in walk(data):
                if key.lower() not in _DESC_KEYS or not isinstance(value, str):
                    continue
                out.extend(self._inspect(path, jp, value))
        return out

    def _inspect(self, path: str, jp: str, text: str) -> list[Finding]:
        found: list[Finding] = []
        if _INJECTION.search(text):
            found.append(
                self._f(
                    "MTP-001",
                    Severity.CRITICAL,
                    "Injected instructions in tool description",
                    "A tool description contains directives aimed at the model, not documentation: "
                    "the model reads this as instructions (tool poisoning).",
                    path,
                    jp,
                    text,
                )
            )
        if _SECRET_ACCESS.search(text):
            found.append(
                self._f(
                    "MTP-002",
                    Severity.HIGH,
                    "Tool description references secrets/sensitive files",
                    "Description steers the agent toward reading credentials or sensitive paths.",
                    path,
                    jp,
                    text,
                )
            )
        if _RUG_PULL.search(text):
            found.append(
                self._f(
                    "MTP-003",
                    Severity.HIGH,
                    "Rug-pull / deferred-behavior language",
                    "Description implies behavior changes after approval/first use: a rug-pull pattern.",
                    path,
                    jp,
                    text,
                )
            )
        return found

    def _f(
        self, rid: str, sev: Severity, title: str, desc: str, path: str, jp: str, text: str
    ) -> Finding:
        return Finding(
            rule_id=rid,
            category=self.category,
            severity=sev,
            title=title,
            description=desc,
            source=Source.STATIC,
            confidence=0.85,
            file=path,
            snippet=f"{jp}: {text.strip()[:160]}",
            remediation="Reject MCP tools whose descriptions contain instructions, secret access, or deferred behavior.",
        )
