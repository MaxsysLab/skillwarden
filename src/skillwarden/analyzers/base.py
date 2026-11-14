"""Analyzer contract and the scan context passed to every analyzer.

An analyzer is a small, self-contained unit that inspects the skill and yields
Findings. Static analyzers are synchronous and fast; they run concurrently in
threads. This is intentionally simpler than a graph framework — we own it.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import ClassVar

from skillwarden.models import Category, Component, Finding, Severity, SkippedInput, Source


@dataclass
class ScanContext:
    """Everything an analyzer needs, built once by the engine."""

    target: str
    components: list[Component]
    file_cache: dict[str, str]  # path -> text content (text files only)
    manifest: dict[str, object] = field(default_factory=dict)  # parsed SKILL.md frontmatter
    # Files the input stage could not scan, with the reason. Non-empty ⇒ the scan is
    # incomplete: analyzers (static and LLM) saw partial input.
    skipped: list[SkippedInput] = field(default_factory=list)
    # Advisory notes from the input stage (e.g. a lossily decoded text file).
    warnings: list[str] = field(default_factory=list)

    @property
    def has_executable_scripts(self) -> bool:
        return any(c.executable for c in self.components)

    def text_files(self) -> dict[str, str]:
        return self.file_cache

    def iter_lines(self, path: str) -> Iterator[tuple[int, str]]:
        """Yield (1-based line number, line text) for a cached file."""
        yield from enumerate(self.file_cache.get(path, "").splitlines(), start=1)


class Analyzer(ABC):
    """Base for all analyzers. Subclasses set class attrs and implement run()."""

    id: str  # node id, e.g. "static_prompt_injection"
    category: Category
    requires_llm: bool = False

    @abstractmethod
    def run(self, ctx: ScanContext) -> list[Finding]: ...


@dataclass(frozen=True)
class Pattern:
    """A single regex rule. The building block of static analyzers."""

    rule_id: str
    regex: str
    severity: Severity
    title: str
    description: str
    remediation: str | None = None
    references: tuple[str, ...] = ()
    flags: int = re.IGNORECASE
    confidence: float = 0.85
    # Per-pattern file scoping. `only_types`: fire ONLY on these component types
    # (None = all). `skip_types`: never fire on these types. Lets a code-execution
    # rule ignore prose/docs without muting prompt-level rules.
    only_types: tuple[str, ...] | None = None
    skip_types: tuple[str, ...] = ()

    def compiled(self) -> re.Pattern[str]:
        return re.compile(self.regex, self.flags)

    def applies_to(self, ftype: str | None) -> bool:
        if self.only_types is not None and ftype not in self.only_types:
            return False
        return ftype not in self.skip_types


class PatternAnalyzer(Analyzer):
    """Static analyzer driven by a list of regex Patterns. Most categories are
    expressible this way; the AST and taint analyzers subclass Analyzer directly."""

    patterns: ClassVar[list[Pattern]] = []
    # Restrict matching to certain component types (None = all text files).
    file_types: ClassVar[set[str] | None] = None

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        compiled = [(p, p.compiled()) for p in self.patterns]
        types = self.file_types
        type_by_path = {c.path: c.type for c in ctx.components}

        for path, text in ctx.file_cache.items():
            ftype = type_by_path.get(path)
            if types is not None and ftype not in types:
                continue
            for lineno, line in enumerate(text.splitlines(), start=1):
                for pat, rx in compiled:
                    if not pat.applies_to(ftype):
                        continue
                    if rx.search(line):
                        findings.append(
                            Finding(
                                rule_id=pat.rule_id,
                                category=self.category,
                                severity=pat.severity,
                                title=pat.title,
                                description=pat.description,
                                source=Source.STATIC,
                                confidence=pat.confidence,
                                file=path,
                                line=lineno,
                                snippet=line.strip()[:200],
                                remediation=pat.remediation,
                                references=list(pat.references),
                            )
                        )
        return findings
