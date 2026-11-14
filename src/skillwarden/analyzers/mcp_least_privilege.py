"""MCP least-privilege analyzer: flags MCP server configs that grant more
authority than a skill should need — wildcard tool access, auto-approval,
root/home filesystem scope, blanket environment passthrough."""

from __future__ import annotations

from skillwarden.analyzers.base import Analyzer, ScanContext
from skillwarden.analyzers.mcp_common import parse_configs, walk
from skillwarden.models import Category, Finding, Severity, Source

_BROAD_PATHS = {"/", "~", "$HOME", "${HOME}", "/Users", "/home", "C:\\", "%USERPROFILE%"}
_AUTO_APPROVE_KEYS = {"autoapprove", "alwaysallow", "auto_approve", "always_allow"}
_TOOL_KEYS = {"allowedtools", "tools", "allowed_tools", "enabledtools"}


class McpLeastPrivilegeAnalyzer(Analyzer):
    id = "mcp_least_privilege"
    category = Category.MCP_LEAST_PRIVILEGE

    def run(self, ctx: ScanContext) -> list[Finding]:
        out: list[Finding] = []
        for path, data in parse_configs(ctx):
            for jp, key, value in walk(data):
                key_l = key.lower()
                out.extend(self._check(path, jp, key_l, value))
        return out

    def _check(self, path: str, jp: str, key: str, value: object) -> list[Finding]:
        found: list[Finding] = []

        if key in _AUTO_APPROVE_KEYS:
            broad = value is True or (isinstance(value, list) and ("*" in value or not value))
            found.append(
                self._f(
                    "MLP-001",
                    Severity.HIGH if broad else Severity.MEDIUM,
                    "MCP auto-approval enabled",
                    "Server auto-approves tool calls, removing the human-in-the-loop checkpoint."
                    + (" Approval is wildcard/unbounded." if broad else ""),
                    path,
                    jp,
                )
            )

        if key in _TOOL_KEYS and self._has_wildcard(value):
            found.append(
                self._f(
                    "MLP-002",
                    Severity.MEDIUM,
                    "Wildcard tool grant",
                    "Grants access to all tools ('*') rather than an explicit allowlist.",
                    path,
                    jp,
                )
            )

        if key in ("args", "command", "allowedpaths", "roots") and self._has_broad_path(value):
            found.append(
                self._f(
                    "MLP-003",
                    Severity.HIGH,
                    "Root/home filesystem scope",
                    "MCP server is scoped to a root or home directory: far broader than needed.",
                    path,
                    jp,
                )
            )

        if key == "env" and (value == "*" or (isinstance(value, str) and value.strip() == "*")):
            found.append(
                self._f(
                    "MLP-004",
                    Severity.MEDIUM,
                    "Blanket environment passthrough",
                    "Passes the entire process environment to the MCP server, exposing all secrets.",
                    path,
                    jp,
                )
            )
        return found

    @staticmethod
    def _has_wildcard(value: object) -> bool:
        if value == "*":
            return True
        return isinstance(value, list) and "*" in value

    @staticmethod
    def _has_broad_path(value: object) -> bool:
        items = value if isinstance(value, list) else [value]
        return any(isinstance(i, str) and i.strip() in _BROAD_PATHS for i in items)

    def _f(self, rid: str, sev: Severity, title: str, desc: str, path: str, jp: str) -> Finding:
        return Finding(
            rule_id=rid,
            category=self.category,
            severity=sev,
            title=title,
            description=desc,
            source=Source.STATIC,
            confidence=0.8,
            file=path,
            snippet=f"at config path: {jp}",
            remediation="Scope MCP servers to the minimum tools, paths, and env they require.",
        )
