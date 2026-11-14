"""Semantic pass: a second-stage LLM review over the skill and the static
findings. It (a) flags false positives among static findings and (b) surfaces
semantic issues regexes can't see (intent, social engineering, subtle agency).

The static findings always stand on their own; the LLM only *adjusts confidence*
and *adds* findings — it can mark a static finding as a likely false positive
(we lower its confidence and tag it) but never silently deletes evidence.

**The two directions are not equally risky, and are not treated equally.**
Adding a finding costs review time.
Suppressing one costs a missed vulnerability — and the suppression path had a
demonstrable hole: `report.scoring.score()` floors the severity label at HIGH via
`any(f.severity is CRITICAL and f.confidence >= 0.5)`, while a false-positive call
multiplied confidence by 0.3. So **one unchallenged LLM opinion could take a
CRITICAL static finding from confidence 1.0 to 0.3 and drop it under the floor that
exists to stop exactly that.**

So suppression, and only suppression, is hardened:

* **A second, adversarial opinion is required.** Every false-positive claim faces a
  refuter prompted to show the finding is real. Only claims that survive are applied.
  It is an escalation on disagreement, aimed at the one direction that can hurt, so
  the cost is a single extra call and only when the LLM claims a false positive.
* **A confirmation must carry evidence, per finding.** The refuter names the exact
  finding (`rule_id`, `file`, `line`) and a non-empty rationale; the rationale is
  attached to the downgraded finding so a reader can check it. An entry without
  evidence, or that does not match a claimed finding, is malformed.
* **The refuter failing means the pass failed.** A provider error, an unusable reply
  or a malformed confirmation raises `SemanticPassError`; the engine keeps every static
  finding untouched and marks the scan incomplete. A security
  tool that cannot verify a suppression must not perform it — and must not report a
  complete scan either.
* **CRITICAL findings keep their floor.** Their confidence is never taken below
  `CRITICAL_CONFIDENCE_FLOOR`, so the label still floors at HIGH and the reader sees
  the false-positive note instead of the finding quietly evaporating.

**Every character is reviewed, and a suppression needs the whole skill in one view.**
The skill's text is shown to the model in full. A skill that fits in one call (the
backend's `max_prompt_chars`) gets the whole protocol above. A larger skill is reviewed
in parts, each a separate call, until every character of every file has been shown;
in that case the pass only *adds* findings. A false-positive call made from one part
is ignored, because what makes a line dangerous may sit in a part the reviewer was not
shown. A skill larger than `LLM_MAX_CHARS` cannot be reviewed whole: the engine
reports the scan incomplete, and nothing is suppressed.

Adding findings is deliberately left alone. For *this* tool it is the valuable
direction — prompt injection and social engineering are semantic by nature and a
regex genuinely cannot see a novel phrasing — and an added finding is already
structurally distinguishable (`rule_id="LLM-SEM"`, `source=SEMANTIC`), so it can
never be mistaken for deterministic evidence. The asymmetry that matters is between
the two directions, adding and suppressing, and only suppressing is constrained.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from skillwarden import constants
from skillwarden.analyzers.base import ScanContext
from skillwarden.models import Category, Finding, Severity, Source
from skillwarden.providers.base import LLMProvider

_SYSTEM = """You are a security reviewer for AI agent skills. You receive a skill's \
files and a list of static findings. Respond ONLY with JSON of the form:
{"false_positive_rule_ids": ["PI-001", ...],
 "additional_findings": [
   {"category": "prompt_injection", "severity": "high", "title": "...",
    "description": "...", "file": "...", "confidence": 0.0-1.0}
 ]}
Be conservative: only call a static finding a false positive when the context \
clearly makes it benign. Only add findings you are confident a regex would miss."""

_VALID_CATEGORIES = {c.value for c in Category}
_VALID_SEVERITIES = {s.value for s in Severity}

# The reply is validated strictly (`_coerce_finding`): an addition whose category or
# severity is not one of ours fails the whole pass and the scan is incomplete. So the
# model must be told the allowed values. They are generated from the enums here, so the
# prompt and the validator cannot drift apart.
_SYSTEM += (
    '\n\nIn each additional finding, "category" must be exactly one of: '
    + ", ".join(sorted(_VALID_CATEGORIES))
    + '. "severity" must be exactly one of: '
    + ", ".join(s.value for s in Severity)
    + ". Do not invent other values: if an issue fits none of the categories, use the "
    "closest one and say so in the description. Use only the fields shown."
)

_REFUTE_SYSTEM = """You are a security reviewer double-checking a colleague's claim that \
certain static findings are FALSE POSITIVES. Your job is to REFUTE that claim, not to agree \
with it. For each rule id, look at the skill's files and ask whether there is a real attack \
path — reachable input, a genuine sink, an instruction a model would actually follow.

A finding is only a false positive if the surrounding context CLEARLY makes it benign (a \
documented framework idiom, a constant, a build-time value, text that no agent would act on). \
If you cannot show it is clearly benign, it is NOT a false positive.

Respond ONLY with JSON of the form:
{"confirmed_false_positives": [
   {"rule_id": "PI-001", "file": "SKILL.md", "line": 12,
    "evidence": "why this exact location is clearly benign, quoting the text"}
 ]}
Every entry must name one finding exactly as listed (same rule_id, file and line) and give \
non-empty evidence; an entry without evidence is rejected. List only the findings you are \
confident are genuinely benign. Default to leaving a finding in place — omitting it keeps \
the finding, which is the safe outcome."""

# A false-positive call scales confidence by this much.
FALSE_POSITIVE_SCALE = 0.3
# ...but never below this for a CRITICAL finding. `report.scoring.score()` floors the
# severity label at HIGH when a CRITICAL finding still has confidence >= 0.5; letting
# an LLM opinion cross that line would silently disarm the floor.
CRITICAL_CONFIDENCE_FLOOR = 0.5


# A call that could show the model less skill text than this is not worth making: the
# backend's context window is too small for this skill's prompt, and the pass fails.
_MIN_CALL_CHARS = 1000
# Allowance, per call, for the headings and notes around the files.
_PROMPT_SLACK = 600
# Allowance, per file shown, for its header line and code fence.
_FILE_OVERHEAD = 120


class SemanticPassError(Exception):
    """The optional semantic review did not produce a usable result."""


# (rule_id, file, line) identifies one static finding for the refutation protocol.
_FindingKey = tuple[str, str | None, int | None]


def _key(f: Finding) -> _FindingKey:
    return (f.rule_id, f.file, f.line)


def _corroborate_false_positives(
    ctx: ScanContext,
    static_findings: list[Finding],
    claimed: set[str],
    provider: LLMProvider,
) -> dict[_FindingKey, str]:
    """Second, adversarial opinion on each false-positive claim.

    Returns {finding key: evidence} for the claims that survive. Fails CLOSED: if the
    refuter errors, returns nothing usable, or returns a confirmation without valid
    per-finding evidence, `SemanticPassError` is raised and the engine marks the scan
    incomplete with every static finding intact.
    """
    at_risk = [f for f in static_findings if f.rule_id in claimed]
    if not at_risk:
        return {}
    if not _view_is_complete(ctx, provider, static_findings):
        # The refuter would judge a partial skill; the part it is not shown may be
        # exactly where the attack lives. Keep every finding at full confidence.
        return {}
    listing = "\n".join(
        f"- {f.rule_id} [{f.severity.value}] {f.title} @ {f.file}:{f.line}"
        f"{chr(10)}  snippet: {(f.snippet or '')[:300]}"
        for f in at_risk
    )
    user = (
        f"## Skill files\n{_files_block(ctx)}\n\n"
        f"## Findings a colleague claims are FALSE POSITIVES\n{listing}\n\n"
        "Refute the claim wherever you can."
    )
    cap = _prompt_cap(provider)
    if cap is not None and _size(_REFUTE_SYSTEM, provider) + _size(user, provider) > cap:
        # The refuter's prompt (the whole skill plus the claims and their snippets) is
        # longer than this backend can read. A refuter that could not be shown all of
        # it cannot confirm anything, so nothing is lowered and no call is made.
        return {}
    try:
        raw = provider.complete(_REFUTE_SYSTEM, user)
    except Exception as exc:
        raise SemanticPassError("refuter call failed") from exc
    try:
        data = _extract_json(raw)
    except Exception as exc:
        raise SemanticPassError("refuter returned unparseable output") from exc
    if "confirmed_false_positives" not in data:
        raise SemanticPassError("refuter returned no confirmation list")
    confirmed = data["confirmed_false_positives"]
    # A malformed confirmation is a protocol violation, not a partial answer: validate
    # the WHOLE list before applying any of it, so one valid entry cannot ride along.
    if not isinstance(confirmed, list):
        raise SemanticPassError("refuter returned an invalid confirmation list")
    known = {_key(f) for f in static_findings}
    surviving: dict[_FindingKey, str] = {}
    for entry in confirmed:
        parsed = _coerce_confirmation(entry)
        if parsed is None or parsed[0] not in known:
            raise SemanticPassError(
                "refuter confirmation entry is malformed or lacks evidence for a known finding"
            )
        key, evidence = parsed
        if key[0] in claimed:  # it may only confirm claims already made — never widen them
            surviving[key] = evidence
    return surviving


def _coerce_confirmation(entry: Any) -> tuple[_FindingKey, str] | None:
    """One refuter entry → ((rule_id, file, line), evidence), or None if malformed.

    Nothing is defaulted: rule_id and file must be strings, line an int (or null for a
    finding that has no line), evidence a non-blank string.
    """
    if not isinstance(entry, dict):
        return None
    rule_id = entry.get("rule_id")
    file = entry.get("file")
    line = entry.get("line")
    evidence = entry.get("evidence")
    if not isinstance(rule_id, str) or not rule_id:
        return None
    if file is not None and not isinstance(file, str):
        return None
    if isinstance(line, bool) or (line is not None and not isinstance(line, int)):
        return None
    if not isinstance(evidence, str) or not evidence.strip():
        return None
    return (rule_id, file, line), evidence.strip()


def run_semantic(
    ctx: ScanContext, static_findings: list[Finding], provider: LLMProvider
) -> list[Finding]:
    """Return adjusted+augmented findings; raise on a failed primary review.

    The caller retains static findings and reports the optional pass failure.
    """
    batches, omitted = _plan(ctx, _call_budget(provider, static_findings), _in_bytes(provider))
    whole = _view_is_complete(ctx, provider, static_findings)
    cap = _prompt_cap(provider)
    additions: list[Finding] = []
    claimed: set[str] = set()
    # One call per part. A skill with no text still gets its one (empty) review.
    for number, batch in enumerate(batches or [[]], start=1):
        user = _build_prompt(
            batch,
            _findings_for(batch, static_findings, first=number == 1, ctx=ctx),
            part=number,
            parts=max(len(batches), 1),
            omitted=omitted,
        )
        if cap is not None and _size(_SYSTEM, provider) + _size(user, provider) > cap:
            # Never hand a backend more than it said it can read.
            raise SemanticPassError(
                "primary semantic review failed: the prompt is longer than this "
                "backend's context window allows"
            )
        try:
            raw = provider.complete(_SYSTEM, user)
            data = _extract_json(raw)
            if not (
                isinstance(data.get("false_positive_rule_ids"), list)
                and isinstance(data.get("additional_findings"), list)
            ):
                raise ValueError("semantic review response missing required lists")
            if not all(isinstance(rule_id, str) for rule_id in data["false_positive_rule_ids"]):
                raise ValueError("semantic review contains invalid false-positive rule IDs")
            for item in data["additional_findings"]:
                finding = _coerce_finding(item) if isinstance(item, dict) else None
                if finding is None:
                    raise ValueError("semantic review contains invalid additional findings")
                additions.append(finding)
        except Exception as exc:
            raise SemanticPassError("primary semantic review failed") from exc
        if whole:
            # Only a reviewer shown the whole skill may call a finding a false positive.
            claimed.update(data["false_positive_rule_ids"])

    # Suppression is the direction that can hide a vulnerability, so it needs a second
    # opinion before it is applied. Adding findings does not.
    confirmed = (
        _corroborate_false_positives(ctx, static_findings, claimed, provider) if claimed else {}
    )
    adjusted: list[Finding] = []
    for f in static_findings:
        evidence = confirmed.get(_key(f))
        if evidence is not None:
            lowered = round(f.confidence * FALSE_POSITIVE_SCALE, 2)
            if f.severity is Severity.CRITICAL:
                # Tag it, but keep the scoring floor armed — a critical that two
                # models think is benign is still a critical a human must look at.
                lowered = max(lowered, CRITICAL_CONFIDENCE_FLOOR)
            f = f.model_copy(
                update={
                    "confidence": lowered,
                    "title": f"{f.title} (LLM: likely false positive)",
                    "description": f"{f.description}\nLLM false-positive evidence: "
                    f"{evidence[:1000]}",
                }
            )
        adjusted.append(f)

    adjusted.extend(additions)
    return adjusted


def _view_is_complete(
    ctx: ScanContext, provider: object | None = None, findings: list[Finding] | None = None
) -> bool:
    """True only if one call shows the model every text byte of the skill.

    False when the skill needs more than one call or exceeds the total review budget,
    when a non-binary component never made it into the cache, or when the input stage
    skipped any file. (`build_context` records every dropped file in `ctx.skipped`, so
    partial input is visible here too.)
    """
    if ctx.skipped:
        return False
    batches, omitted = _plan(ctx, _call_budget(provider, findings), _in_bytes(provider))
    if omitted or len(batches) > 1:
        return False
    return all(c.path in ctx.file_cache or c.type == "binary" for c in ctx.components)


def unreviewed_files(
    ctx: ScanContext, provider: object | None = None, findings: list[Finding] | None = None
) -> list[str]:
    """Paths with text that no call will show the model: the skill is larger than the
    total review budget (`LLM_MAX_CHARS`). Empty when every character is reviewed."""
    return sorted(_plan(ctx, _call_budget(provider, findings), _in_bytes(provider))[1])


def _prompt_cap(provider: object | None) -> int | None:
    """The longest whole prompt this backend takes, or None if it names no limit."""
    declared = getattr(provider, "max_prompt_chars", None)
    if isinstance(declared, bool) or not isinstance(declared, int):
        return None
    return declared


def _listing(findings: list[Finding]) -> str:
    # File names are written here as they are, and a confirmation is matched on the
    # name as it is. Escaping them (as the file headers are) was tried and taken back:
    # the reply is JSON, decoding it undoes one level of escaping, and a confirmation
    # for one file could then be read as naming another. The clean fix is to give each
    # listed finding a short id and have the reply name the id.
    return "\n".join(
        f"- {f.rule_id} [{f.severity.value}] {f.title} @ {f.file}:{f.line}" for f in findings
    )


def _in_bytes(provider: object | None) -> bool:
    """True when the backend's limit is counted in bytes, not characters."""
    return getattr(provider, "prompt_limit_in_bytes", False) is True


def _size(text: str, provider: object | None) -> int:
    """The length of `text` in the unit the backend's limit is counted in."""
    return len(text.encode("utf-8")) if _in_bytes(provider) else len(text)


def _call_budget(provider: object | None, findings: list[Finding] | None = None) -> int:
    """Characters of skill text (with each file's header) shown to the model in one call.

    The default is `LLM_BATCH_CHARS`. A backend that names a limit for the whole prompt
    gets less: its limit, minus the system prompt, the list of static findings and the
    headings around them. If what is left is too little to be worth a call, the pass
    fails and the scan is incomplete: a backend that small cannot review this skill.
    """
    budget = constants.LLM_BATCH_CHARS
    cap = _prompt_cap(provider)
    if cap is not None:
        used = _size(_SYSTEM, provider) + _size(_listing(findings or []), provider)
        budget = min(budget, cap - used - _PROMPT_SLACK)
    if budget < _MIN_CALL_CHARS:
        raise SemanticPassError(
            "this backend's context window is too small for the review prompt "
            f"(room for {max(budget, 0)} characters of the skill per call)"
        )
    return budget


@dataclass(frozen=True)
class _Part:
    """A run of consecutive characters of one file. Most files are a single part."""

    path: str
    text: str
    number: int  # 1-based position among the file's parts
    of: int  # how many parts the file was cut into
    start: int  # offset of the first character in the file
    total: int  # characters in the whole file


def _measure(text: str, in_bytes: bool) -> int:
    return len(text.encode("utf-8")) if in_bytes else len(text)


def _cut(line: str, budget: int, in_bytes: bool) -> list[str]:
    """One line as consecutive pieces that each measure at most `budget`. A character
    is never cut in two; a budget smaller than one character yields that character."""
    if _measure(line, in_bytes) <= budget:
        return [line]
    if not in_bytes:
        return [line[i : i + budget] for i in range(0, len(line), budget)]
    raw = line.encode("utf-8")
    pieces: list[str] = []
    start = 0
    while start < len(raw):
        end = min(start + budget, len(raw))
        while end > start and end < len(raw) and (raw[end] & 0xC0) == 0x80:
            end -= 1  # back off to the start of a character
        if end == start:  # the budget is smaller than this character: take it whole
            end = start + 1
            while end < len(raw) and (raw[end] & 0xC0) == 0x80:
                end += 1
        pieces.append(raw[start:end].decode("utf-8"))
        start = end
    return pieces


def _split(text: str, budget: int, in_bytes: bool = False) -> list[str]:
    """Cut text into consecutive pieces that each measure at most `budget` (characters,
    or bytes of UTF-8 when `in_bytes`), at line ends where it can. Joined back together
    the pieces are exactly the text."""
    budget = max(budget, 1)
    if _measure(text, in_bytes) <= budget:
        return [text]
    pieces: list[str] = []
    current: list[str] = []
    size = 0
    for line in text.splitlines(keepends=True):
        for chunk in _cut(line, budget, in_bytes):
            cost = _measure(chunk, in_bytes)
            if current and size + cost > budget:
                pieces.append("".join(current))
                current, size = [], 0
            current.append(chunk)
            size += cost
    if current:
        pieces.append("".join(current))
    return pieces


def _plan(
    ctx: ScanContext, budget: int, in_bytes: bool = False
) -> tuple[list[list[_Part]], list[str]]:
    """Lay the skill's text out over calls.

    Returns (batches, omitted): each batch is the parts shown in one call, in file
    order; a batch's text plus the header of each of its files measures at most
    `budget` (characters, or bytes of UTF-8 when `in_bytes`). `omitted` names the files
    with text that falls beyond the total review budget and is shown in no call.
    """
    batches: list[list[_Part]] = []
    omitted: list[str] = []
    current: list[_Part] = []
    size = shown = 0
    for path, text in ctx.file_cache.items():
        header = _measure(_shown_path(path), in_bytes) + _FILE_OVERHEAD
        pieces = _split(text, budget - header, in_bytes)
        offset = 0
        for number, piece in enumerate(pieces, start=1):
            part = _Part(path, piece, number, len(pieces), offset, len(text))
            offset += len(piece)
            if shown + len(piece) > constants.LLM_MAX_CHARS:
                if path not in omitted:
                    omitted.append(path)
                continue
            cost = _measure(piece, in_bytes) + header
            if current and size + cost > budget:
                batches.append(current)
                current, size = [], 0
            current.append(part)
            size += cost
            shown += len(piece)
    if current:
        batches.append(current)
    return batches, omitted


def _shown_path(path: str) -> str:
    """A file name as it is written into a prompt. A name may hold newlines, backticks
    or control characters; shown raw, it could close a code fence or forge a heading.
    They are written as escapes, so the name stays on its header line."""
    return json.dumps(path)[1:-1].replace("`", "\\u0060")


def _fence(text: str) -> str:
    """A code fence longer than any run of backticks in `text`, so the text cannot close
    it and continue as if it were part of the prompt."""
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    return "`" * max(3, longest + 1)


def _block(parts: list[_Part]) -> str:
    blocks = []
    for p in parts:
        where = (
            ""
            if p.of == 1
            else f" (part {p.number} of {p.of}: characters {p.start + 1} to "
            f"{p.start + len(p.text)} of {p.total})"
        )
        fence = _fence(p.text)
        blocks.append(f"### {_shown_path(p.path)}{where}\n{fence}\n{p.text}\n{fence}")
    return "\n\n".join(blocks)


def _files_block(ctx: ScanContext) -> str:
    """Every file, whole. Used where the view is known to be complete."""
    return _block([_Part(path, text, 1, 1, 0, len(text)) for path, text in ctx.file_cache.items()])


def _findings_for(
    batch: list[_Part], findings: list[Finding], *, first: bool, ctx: ScanContext
) -> list[Finding]:
    """The static findings located in the files of this call. Findings that belong to
    no shown file (no location, or a file outside the text cache) go with the first."""
    here = {p.path for p in batch}
    out = [f for f in findings if f.file in here]
    if first:
        out += [f for f in findings if f.file is None or f.file not in ctx.file_cache]
    return out


def _build_prompt(
    batch: list[_Part],
    findings: list[Finding],
    *,
    part: int = 1,
    parts: int = 1,
    omitted: list[str] | None = None,
) -> str:
    fs = _listing(findings)
    notes = []
    if parts > 1:
        notes.append(
            f"[PART {part} OF {parts}] This skill is too large for one review. You are "
            "shown only this part. Add findings for what you see here, and leave "
            "false_positive_rule_ids empty: a false-positive call needs the whole skill "
            "in one view."
        )
    if omitted:
        notes.append(
            "[NOT SHOWN IN ANY PART: "
            + ", ".join(_shown_path(p) for p in sorted(omitted))
            + "] These files lie "
            "beyond the review budget. Leave false_positive_rule_ids empty."
        )
    head = "## Skill files" + ("\n" + "\n".join(notes) if notes else "")
    return f"{head}\n{_block(batch)}\n\n## Static findings\n{fs or '(none)'}"


def _extract_json(text: str) -> dict[str, Any]:
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        return {}
    parsed: dict[str, Any] = json.loads(match.group(0))
    return parsed


def _coerce_finding(item: dict[str, Any]) -> Finding | None:
    """Validate one semantic addition strictly. Nothing is defaulted or coerced: a
    malformed addition returns None and the caller fails the whole pass."""
    cat = item.get("category")
    sev = item.get("severity")
    title = item.get("title")
    description = item.get("description")
    confidence = item.get("confidence")
    file = item.get("file")
    if not isinstance(cat, str) or not isinstance(sev, str):
        return None
    if cat not in _VALID_CATEGORIES or sev not in _VALID_SEVERITIES:
        return None
    if not isinstance(title, str) or not title.strip() or not isinstance(description, str):
        return None
    # bool is an int subclass and float("0.9") accepts strings: check the type explicitly.
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
        return None
    if not 0.0 <= confidence <= 1.0:  # also rejects NaN
        return None
    if file is not None and not isinstance(file, str):
        return None
    return Finding(
        rule_id="LLM-SEM",
        category=Category(cat),
        severity=Severity(sev),
        title=title[:200],
        description=description,
        source=Source.SEMANTIC,
        confidence=float(confidence),
        file=file,
    )
