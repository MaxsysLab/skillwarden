"""Supply-chain patterns: untrusted installs, pinned-to-nothing dependencies,
and pipe-to-shell bootstrapping."""

from __future__ import annotations

from typing import ClassVar

from skillwarden import constants
from skillwarden.analyzers.base import Pattern, PatternAnalyzer
from skillwarden.models import Category, Severity


class SupplyChainAnalyzer(PatternAnalyzer):
    id = "static_supply_chain"
    category = Category.SUPPLY_CHAIN

    patterns: ClassVar[list[Pattern]] = [
        Pattern(
            rule_id="SC-001",
            regex=r"\bcurl\b[^\n|]*\|\s*(sudo\s+)?(ba)?sh\b|\bwget\b[^\n|]*\|\s*(ba)?sh\b",
            severity=Severity.CRITICAL,
            title="Pipe-to-shell install",
            description="Downloads and executes a remote script in one step: no chance to inspect it.",
            remediation="Download, checksum-verify, and review before executing.",
        ),
        Pattern(
            rule_id="SC-002",
            regex=r"\bpip\s+install\b[^\n]*\bgit\+https?://|\bnpm\s+(install|i)\b[^\n]*\b(git\+|github:|http)",
            severity=Severity.HIGH,
            title="Install from VCS URL",
            description="Installs a dependency directly from a git/URL source rather than a pinned registry release.",
        ),
        Pattern(
            rule_id="SC-003",
            regex=r"\b(pip|pip3)\s+install\s+(--pre\s+|-U\s+|--upgrade\s+)*[a-z0-9_.\-]+(?![=<>~!])",
            severity=Severity.LOW,
            title="Unpinned dependency install",
            description="Installs a package without a version pin; resolved version can change underneath you.",
            remediation="Pin to an exact version and, ideally, a hash.",
            # `pip install <pkg>` appears in nearly every README; only flag in scripts.
            only_types=constants.CODE_TYPES,
        ),
        Pattern(
            rule_id="SC-004",
            regex=r"--trusted-host|--insecure|--no-check-certificate|verify\s*=\s*False",
            severity=Severity.HIGH,
            title="TLS verification disabled",
            description="Disables certificate verification during fetch/install: opens the door to MITM.",
        ),
        Pattern(
            rule_id="SC-005",
            regex=r"\b(http://)(?!localhost|127\.0\.0\.1)[a-z0-9.\-]+/[^\s\"']*\.(sh|py|exe|tar|zip|whl)\b",
            severity=Severity.MEDIUM,
            title="Artifact fetched over plaintext HTTP",
            description="Downloads an executable artifact over unencrypted HTTP.",
        ),
    ]
