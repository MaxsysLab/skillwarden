"""OSV live vulnerability lookups. Extracts pinned dependencies a skill declares
(requirements.txt, package.json) and queries https://osv.dev for known CVEs.

The lookup is a requested part of the scan, so it follows the completeness contract:
when a skill pins dependencies and the lookup cannot be made or its answer cannot be
read (offline, timeout, rate limit, malformed reply), the analyzer raises
``OsvLookupError``. The engine records that as a failed analyzer and the scan is
reported incomplete, never as a clean pass that silently skipped the check. Static
findings from the other analyzers are unaffected. To scan without the lookup (an
air-gapped machine, an offline audit), skip it explicitly with ``--no-osv``; the
report then carries a warning that the pinned dependencies were not checked.
"""

from __future__ import annotations

import json
import re

import httpx

from skillwarden import constants
from skillwarden.analyzers.base import Analyzer, ScanContext
from skillwarden.models import Category, Finding, Severity, Source

_OSV_BATCH = "https://api.osv.dev/v1/querybatch"
_OSV_WEB = "https://osv.dev/vulnerability/"
_REQ_LINE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*==\s*([0-9][A-Za-z0-9_.\-]*)")
_VER_CLEAN = re.compile(r"^[\^~>=<\s]*")


class OsvLookupError(RuntimeError):
    """The known-vulnerability lookup was needed and did not (fully) run."""


class OsvAnalyzer(Analyzer):
    id = "osv_lookup"
    category = Category.SUPPLY_CHAIN

    def run(self, ctx: ScanContext) -> list[Finding]:
        deps = self._collect_dependencies(ctx)
        if not deps:
            return []
        results = self._query(deps)  # raises OsvLookupError; never a silent skip

        out: list[Finding] = []
        for (name, version, ecosystem, path), vulns in zip(deps, results, strict=True):
            if not vulns:
                continue
            ids = [str(v.get("id", "?")) for v in vulns][:8]
            out.append(
                Finding(
                    rule_id="OSV-VULN",
                    category=self.category,
                    severity=Severity.HIGH,
                    title=f"Known vulnerability in {name}=={version}",
                    description=(
                        f"{ecosystem} package {name} {version} has {len(vulns)} known "
                        f"advisory/advisories: {', '.join(ids)}."
                    ),
                    source=Source.STATIC,
                    confidence=0.95,
                    file=path,
                    references=[f"{_OSV_WEB}{i}" for i in ids],
                    remediation=f"Upgrade {name} to a patched version (see OSV links).",
                )
            )
        return out

    def _collect_dependencies(self, ctx: ScanContext) -> list[tuple[str, str, str, str]]:
        deps: list[tuple[str, str, str, str]] = []
        for path, text in ctx.file_cache.items():
            base = path.rsplit("/", 1)[-1].lower()
            if base == "requirements.txt" or base.endswith(".requirements.txt"):
                for line in text.splitlines():
                    m = _REQ_LINE.match(line)
                    if m:
                        deps.append((m.group(1), m.group(2), "PyPI", path))
            elif base == "package.json":
                deps.extend(self._npm_deps(text, path))
        return deps

    def _npm_deps(self, text: str, path: str) -> list[tuple[str, str, str, str]]:
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return []
        out: list[tuple[str, str, str, str]] = []
        for section in ("dependencies", "devDependencies"):
            for name, spec in (data.get(section) or {}).items():
                if isinstance(spec, str):
                    version = _VER_CLEAN.sub("", spec).strip()
                    if re.match(r"^\d", version):
                        out.append((name, version, "npm", path))
        return out

    def _query(self, deps: list[tuple[str, str, str, str]]) -> list[list[dict[str, object]]]:
        """Ask OSV about every pinned dependency: one list of advisories per dependency,
        in order. Raises OsvLookupError when the lookup did not fully run."""
        queries = [
            {"package": {"name": n, "ecosystem": eco}, "version": v} for (n, v, eco, _path) in deps
        ]
        try:
            resp = httpx.post(
                _OSV_BATCH, json={"queries": queries}, timeout=constants.NETWORK_TIMEOUT
            )
            resp.raise_for_status()
            payload = resp.json()
        except (httpx.HTTPError, json.JSONDecodeError) as exc:
            raise OsvLookupError(self._not_run(deps, f"{type(exc).__name__}: {exc}")) from exc

        results = payload.get("results") if isinstance(payload, dict) else None
        if not isinstance(results, list) or len(results) != len(deps):
            # A short or malformed answer would leave some dependencies unchecked.
            raise OsvLookupError(self._not_run(deps, "malformed reply from osv.dev"))
        out: list[list[dict[str, object]]] = []
        for entry in results:
            if not isinstance(entry, dict):
                # An answer that is not a mapping says nothing about the dependency.
                raise OsvLookupError(self._not_run(deps, "malformed reply from osv.dev"))
            if entry.get("next_page_token"):
                # More advisories exist than this page holds; we do not fetch them, so
                # the list for this dependency would be partial.
                raise OsvLookupError(self._not_run(deps, "osv.dev returned a partial list"))
            vulns = entry.get("vulns")
            if vulns is None:
                out.append([])
            elif isinstance(vulns, list) and all(isinstance(v, dict) for v in vulns):
                out.append(vulns)
            else:
                raise OsvLookupError(self._not_run(deps, "malformed reply from osv.dev"))
        return out

    @staticmethod
    def _not_run(deps: list[tuple[str, str, str, str]], why: str) -> str:
        return (
            f"known-vulnerability lookup did not run for {len(deps)} pinned "
            f"dependenc{'y' if len(deps) == 1 else 'ies'} ({why}); "
            "re-run with network access or pass --no-osv to skip it"
        )
