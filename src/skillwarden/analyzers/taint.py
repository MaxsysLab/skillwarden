"""Lightweight intraprocedural taint tracking for Python components.

Tracks data flowing from an untrusted *source* (user input, environment,
request params, argv, file reads) into a dangerous *sink* (eval/exec/compile,
os.system, subprocess, SQL execute). A regex can see `eval(x)`; only dataflow
can tell you `x` came from `input()`. This is deliberately simple — assignment
propagation to a fixpoint, not full SSA — but it catches the common injection
shapes the static pattern pass misses.
"""

from __future__ import annotations

import ast

from skillwarden.analyzers.base import Analyzer, ScanContext
from skillwarden.models import Category, Finding, Severity, Source

# Function calls / attributes that introduce untrusted data.
_SOURCE_CALLS = {"input", "raw_input", "getenv", "recv", "read", "readline"}
# Attribute chains that are sources without a call (e.g. sys.argv, request.args).
_SOURCE_ATTRS = {"argv", "environ", "args", "form", "values", "json", "data", "cookies", "headers"}
# Sinks: code/command execution where tainted input means injection.
_SINK_CALLS = {
    "eval": "DC-001",
    "exec": "DC-002",
    "compile": "compile",
    "system": "os.system",
    "popen": "os.popen",
    "run": "subprocess",
    "call": "subprocess",
    "Popen": "subprocess",
    "check_output": "subprocess",
    "execute": "sql",
    "executescript": "sql",
}


class TaintAnalyzer(Analyzer):
    id = "behavioral_taint"
    category = Category.TAINT

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for c in ctx.components:
            if c.type != "python":
                continue
            src = ctx.file_cache.get(c.path, "")
            try:
                tree = ast.parse(src)
            except SyntaxError:
                continue  # dangerous_code already reports unparseable files
            findings.extend(self._analyze(tree, c.path, src.splitlines()))
        return findings

    def _analyze(self, tree: ast.AST, path: str, lines: list[str]) -> list[Finding]:
        tainted = self._propagate(tree)
        out: list[Finding] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            sink = self._sink_name(node.func)
            if sink is None:
                continue
            if any(self._refs_tainted(arg, tainted) for arg in node.args):
                ln = getattr(node, "lineno", None)
                snippet = lines[ln - 1].strip()[:200] if ln and ln <= len(lines) else None
                out.append(
                    Finding(
                        rule_id="TT-001",
                        category=self.category,
                        severity=Severity.HIGH,
                        title=f"Untrusted input reaches {sink}",
                        description=(
                            "Data from an untrusted source (input/env/request/argv/file) flows "
                            f"into {sink}: a code/command/SQL injection path."
                        ),
                        source=Source.STATIC,
                        confidence=0.8,
                        file=path,
                        line=ln,
                        snippet=snippet,
                        remediation="Validate/allowlist the value, or avoid passing untrusted data to this sink.",
                    )
                )
        return out

    def _propagate(self, tree: ast.AST) -> set[str]:
        """Collect tainted variable names, iterating to a fixpoint for chains."""
        tainted: set[str] = set()
        for _ in range(4):  # small bound; chains deeper than this are rare
            changed = False
            for node in ast.walk(tree):
                if isinstance(node, ast.Assign) and self._expr_tainted(node.value, tainted):
                    for tgt in node.targets:
                        for name in self._assigned_names(tgt):
                            if name not in tainted:
                                tainted.add(name)
                                changed = True
            if not changed:
                break
        return tainted

    def _expr_tainted(self, node: ast.expr, tainted: set[str]) -> bool:
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call) and self._is_source_call(sub.func):
                return True
            if isinstance(sub, ast.Attribute) and sub.attr in _SOURCE_ATTRS:
                return True
            if isinstance(sub, ast.Name) and sub.id in tainted:
                return True
            # sys.argv[1], request.args['x'] etc.
            if isinstance(sub, ast.Subscript) and self._attr_is_source(sub.value):
                return True
        return False

    def _refs_tainted(self, node: ast.expr, tainted: set[str]) -> bool:
        return self._expr_tainted(node, tainted)

    @staticmethod
    def _assigned_names(target: ast.expr) -> set[str]:
        return {n.id for n in ast.walk(target) if isinstance(n, ast.Name)}

    def _is_source_call(self, func: ast.expr) -> bool:
        if isinstance(func, ast.Name):
            return func.id in _SOURCE_CALLS
        if isinstance(func, ast.Attribute):
            return func.attr in _SOURCE_CALLS
        return False

    @staticmethod
    def _attr_is_source(node: ast.expr) -> bool:
        return isinstance(node, ast.Attribute) and node.attr in _SOURCE_ATTRS

    @staticmethod
    def _sink_name(func: ast.expr) -> str | None:
        if isinstance(func, ast.Name) and func.id in _SINK_CALLS:
            return func.id
        if isinstance(func, ast.Attribute) and func.attr in _SINK_CALLS:
            return func.attr
        return None
