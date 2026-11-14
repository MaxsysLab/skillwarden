"""Core data models for SkillWarden.

Everything the pipeline produces flows through `Finding` and `ScanResult`.
These are the contract between analyzers, the scorer, and the reporters — keep
them stable and well-documented.
"""

from __future__ import annotations

import os
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field, model_validator


def printable(text: str) -> str:
    """A string safe for every report format: non-UTF-8 bytes are backslash-escaped."""
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return os.fsencode(text).decode("utf-8", errors="backslashreplace")
    return text


class Severity(StrEnum):
    """Ordered severity. Use `.weight` for scoring, not the string."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def weight(self) -> int:
        return _SEVERITY_WEIGHTS[self]

    @property
    def sarif_level(self) -> str:
        # SARIF 2.1.0 only defines: none, note, warning, error.
        return {
            Severity.INFO: "note",
            Severity.LOW: "note",
            Severity.MEDIUM: "warning",
            Severity.HIGH: "error",
            Severity.CRITICAL: "error",
        }[self]


_SEVERITY_WEIGHTS = {
    Severity.INFO: 0,
    Severity.LOW: 10,
    Severity.MEDIUM: 25,
    Severity.HIGH: 50,
    Severity.CRITICAL: 90,
}


class Category(StrEnum):
    """Vulnerability categories. The same taxonomy NVIDIA's SkillSpector uses, so
    findings map onto what people in the field expect; add to it as needs arise."""

    PROMPT_INJECTION = "prompt_injection"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SUPPLY_CHAIN = "supply_chain"
    EXCESSIVE_AGENCY = "excessive_agency"
    OUTPUT_HANDLING = "output_handling"
    SYSTEM_PROMPT_LEAKAGE = "system_prompt_leakage"
    MEMORY_POISONING = "memory_poisoning"
    TOOL_MISUSE = "tool_misuse"
    ROGUE_AGENT = "rogue_agent"
    ANTI_REFUSAL = "anti_refusal"
    TRIGGER_ABUSE = "trigger_abuse"
    DANGEROUS_CODE = "dangerous_code"
    TAINT = "taint"
    HARMFUL_CONTENT = "harmful_content"
    MCP_LEAST_PRIVILEGE = "mcp_least_privilege"
    MCP_TOOL_POISONING = "mcp_tool_poisoning"


class Source(StrEnum):
    STATIC = "static"
    SEMANTIC = "semantic"


class Finding(BaseModel):
    """A single issue discovered by an analyzer."""

    rule_id: str = Field(..., description="Stable rule identifier, e.g. 'PI-001'.")
    category: Category
    severity: Severity
    title: str
    description: str
    source: Source = Source.STATIC
    confidence: float = Field(1.0, ge=0.0, le=1.0)

    file: str | None = None
    line: int | None = None
    snippet: str | None = None

    remediation: str | None = None
    references: list[str] = Field(default_factory=list)

    # Suppression: stable fingerprint so baselines survive line drift.
    @property
    def fingerprint(self) -> str:
        return f"{self.rule_id}:{self.file or '-'}:{(self.snippet or self.title)[:80]}"


class Component(BaseModel):
    """A file inside the scanned skill."""

    path: str
    type: str  # markdown | python | shell | yaml | json | other | binary
    lines: int
    size_bytes: int
    executable: bool
    # True when the file was not valid UTF-8 and was decoded with replacement characters
    # so it could still be scanned. The scan stays complete, but the reader is told.
    lossy_decode: bool = False


class SkippedInput(BaseModel):
    """A file the scanner did NOT examine, and why. Any entry makes the scan incomplete:
    static and semantic analysis saw partial input, so no verdict is a clearance."""

    path: str
    reason: str


class ScanResult(BaseModel):
    """The complete output of a scan — what reporters render."""

    target: str
    findings: list[Finding] = Field(default_factory=list)
    components: list[Component] = Field(default_factory=list)

    risk_score: int = 0  # 0–100
    severity_label: Severity = Severity.INFO
    recommendation: str = ""

    suppressed: list[Finding] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)  # Advisory only; never affects status.
    skipped: list[SkippedInput] = Field(default_factory=list)  # Input dropped → incomplete.
    status: Literal["complete", "incomplete"] = "complete"
    input_error: bool = False  # Input could not be resolved; no scan took place.
    used_llm: bool = False

    @model_validator(mode="after")
    def mark_failed_scans_incomplete(self) -> ScanResult:
        # A scan is complete only when every requested part ran over every input. Errors
        # (analyzer failures, a requested LLM pass that did not run or returned malformed
        # output), unresolved input, or any dropped file all make it incomplete.
        if self.errors or self.input_error or self.skipped:
            self.status = "incomplete"
        # A target name that is not valid UTF-8 (surrogate-escaped by the OS) cannot be
        # serialised or printed; escape it so every report format still renders.
        self.target = printable(self.target)
        return self

    @property
    def counts(self) -> dict[str, int]:
        out = {s.value: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.value] += 1
        return out
