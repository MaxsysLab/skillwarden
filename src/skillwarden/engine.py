"""The scan engine: one plain pipeline, with no agent framework underneath.

Flow: resolve input → build context → run analyzers concurrently →
optional semantic (LLM) pass → suppress baseline → score → ScanResult.

It's plain, ownable code: a thread pool fans the static analyzers out (they're
CPU/IO-light and independent), then a single optional LLM call refines them.

Completeness contract: a result is ``complete`` only when
every requested part of the scan ran over every input. A requested LLM pass whose
provider is unavailable, errors, returns malformed output, or could not be shown the
whole skill; an analyzer failure (a known-vulnerability lookup that could not be made counts as
one); or any input file the input stage had to skip — each makes the result
``incomplete`` (the CLI then exits 2). A part skipped on request (``use_llm=False``,
``use_osv=False``) was not requested, so the rest can still be complete. Static
findings are still reported, but never as a clearance.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from skillwarden import constants
from skillwarden.analyzers import ANALYZERS
from skillwarden.analyzers.base import ScanContext
from skillwarden.analyzers.osv_client import OsvAnalyzer
from skillwarden.input_handler import InputError, build_context, is_zip_path, resolve
from skillwarden.models import Finding, ScanResult
from skillwarden.providers.base import get_provider
from skillwarden.report.scoring import apply_score
from skillwarden.semantic import run_semantic
from skillwarden.semantic.meta_analyzer import SemanticPassError, unreviewed_files
from skillwarden.suppression import Baseline, partition

_OSV_ONLY = frozenset({OsvAnalyzer.id})


def scan(
    input_path: str,
    *,
    use_llm: bool = True,
    use_osv: bool = True,
    baseline: Baseline | None = None,
    provider_name: str = constants.PROVIDER,
) -> ScanResult:
    errors: list[str] = []
    warnings: list[str] = []

    # 1. Resolve input to a local root (handles dir/zip/git/url).
    single_file: Path | None = None
    p = Path(input_path).expanduser()
    if p.is_file() and not is_zip_path(p):
        single_file = p
    try:
        resolved = resolve(input_path)
    except InputError as exc:
        return ScanResult(
            target=input_path, errors=[str(exc)], input_error=True, status="incomplete"
        )

    try:
        # 2. Build the shared context. Any file it could not scan is recorded, and makes
        #    the scan incomplete: every analyzer below saw partial input.
        ctx = build_context(input_path, resolved.root, single_file=single_file)
        warnings.extend(ctx.warnings)
        for skipped in ctx.skipped:
            errors.append(f"input skipped: {skipped.path}: {skipped.reason}")
        if not ctx.components and not ctx.skipped:
            # "Complete, no findings" over zero files would be a false clean pass.
            errors.append("nothing to scan: the target contains no files; scan incomplete")

        # 3. Fan out static analyzers concurrently. The live OSV lookup is a requested
        #    part of the scan unless it was skipped explicitly; then say so in the report.
        if not use_osv:
            unchecked = len(OsvAnalyzer()._collect_dependencies(ctx))
            if unchecked:
                warnings.append(
                    f"OSV lookup skipped (--no-osv): {unchecked} pinned "
                    f"dependenc{'y was' if unchecked == 1 else 'ies were'} not checked "
                    "for known vulnerabilities"
                )
        static = _run_analyzers(ctx, errors, skip=frozenset() if use_osv else _OSV_ONLY)

        # 4. Optional semantic pass. Requested but not (fully) run ⇒ incomplete.
        used_llm = False
        findings = static
        if use_llm:
            findings, used_llm = _run_llm_pass(ctx, static, provider_name, errors)

        # 5. Suppress baseline, then score.
        active, suppressed = partition(findings, baseline)
        result = ScanResult(
            target=input_path,
            findings=active,
            components=ctx.components,
            suppressed=suppressed,
            errors=errors,
            warnings=warnings,
            skipped=ctx.skipped,
            used_llm=used_llm,
        )
        return apply_score(result)
    finally:
        if resolved.temp_dir is not None:
            resolved.temp_dir.cleanup()


def _run_llm_pass(
    ctx: ScanContext, static: list[Finding], provider_name: str, errors: list[str]
) -> tuple[list[Finding], bool]:
    """Run the requested semantic pass; record why it did not (fully) run.

    Returns (findings, used_llm). Static findings are returned unchanged whenever the pass
    fails, and an error is appended so the result is incomplete. KeyboardInterrupt and
    SystemExit propagate.
    """
    try:
        provider = get_provider(provider_name)
        if not provider.is_available():
            errors.append(
                f"LLM pass requested but provider {provider_name!r} is unavailable "
                "(configure a provider or pass --no-llm); scan incomplete"
            )
            return static, False
        partial = unreviewed_files(ctx, provider, static)
        if partial:
            errors.append(
                "LLM pass could not review the whole skill: "
                + ", ".join(partial)
                + f" lie beyond the review budget of {constants.LLM_MAX_CHARS} characters "
                "(semantic review is partial; raise SKILLWARDEN_LLM_MAX_CHARS or pass "
                "--no-llm); scan incomplete"
            )
        findings = run_semantic(ctx, static, provider)
    except SemanticPassError as exc:
        cause = exc.__cause__
        detail = f"{exc}: {cause}" if cause else str(exc)
        errors.append(f"LLM pass failed ({detail}); static findings only; scan incomplete")
        return static, False
    except Exception as exc:  # provider setup/transport errors; static results survive
        errors.append(
            f"LLM pass failed ({type(exc).__name__}: {exc}); static findings only; scan incomplete"
        )
        return static, False
    return findings, True  # it ran (a partial review is already recorded above)


def _run_analyzers(
    ctx: ScanContext, errors: list[str], skip: frozenset[str] = frozenset()
) -> list[Finding]:
    findings: list[Finding] = []
    if not ANALYZERS:
        errors.append("no analyzers registered")
        return findings
    selected = [a for a in ANALYZERS if a.id not in skip]
    if not selected:
        return findings
    max_workers = min(len(selected), 8)
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(a.run, ctx): a for a in selected}
        for fut in futures:
            analyzer = futures[fut]
            try:
                findings.extend(fut.result())
            except Exception as exc:  # one bad analyzer must not sink the scan
                errors.append(f"analyzer {analyzer.id} failed: {exc}")
    return findings
