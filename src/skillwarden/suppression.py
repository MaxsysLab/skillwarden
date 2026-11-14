"""Baseline suppression: accept known findings so re-scans surface only *new*
issues. A baseline is a YAML file listing fingerprints and/or rule_id globs."""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from skillwarden.models import Finding


class BaselineError(ValueError):
    """The baseline file is missing, unreadable or malformed."""


@dataclass
class Baseline:
    fingerprints: set[str] = field(default_factory=set)
    rule_globs: list[str] = field(default_factory=list)

    @classmethod
    def load(cls, path: str | Path) -> Baseline:
        """Load a baseline; any unreadable or malformed file raises `BaselineError`."""
        try:
            data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
            raise BaselineError(f"cannot read baseline {str(path)!r}: {exc}") from exc
        if not isinstance(data, dict):
            raise BaselineError(f"baseline {str(path)!r} must be a YAML mapping")
        lists: dict[str, list[str]] = {}
        for key in ("fingerprints", "rule_globs"):
            value = data.get(key) or []
            if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
                raise BaselineError(f"baseline {str(path)!r}: {key!r} must be a list of strings")
            lists[key] = value
        return cls(fingerprints=set(lists["fingerprints"]), rule_globs=lists["rule_globs"])

    def matches(self, f: Finding) -> bool:
        if f.fingerprint in self.fingerprints:
            return True
        return any(fnmatch.fnmatch(f.rule_id, g) for g in self.rule_globs)


def partition(
    findings: list[Finding], baseline: Baseline | None
) -> tuple[list[Finding], list[Finding]]:
    """Split into (active, suppressed). Suppressed are excluded from scoring."""
    if baseline is None:
        return findings, []
    active: list[Finding] = []
    suppressed: list[Finding] = []
    for f in findings:
        (suppressed if baseline.matches(f) else active).append(f)
    return active, suppressed
