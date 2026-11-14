"""SkillWarden: a security scanner for AI agent skills."""

from __future__ import annotations

__version__ = "1.0.0"

from skillwarden.engine import scan
from skillwarden.models import Category, Finding, ScanResult, Severity

__all__ = ["Category", "Finding", "ScanResult", "Severity", "__version__", "scan"]
