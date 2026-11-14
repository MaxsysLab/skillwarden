"""AST-based dangerous-code analyzer for Python components.

Regexes miss structure; this walks the Python AST so we flag real calls
(eval, exec, os.system, subprocess with shell=True, pickle.loads, dynamic
import) rather than mentions of those words in prose or strings.
"""

from __future__ import annotations

import ast

from skillwarden.analyzers.base import Analyzer, ScanContext
from skillwarden.models import Category, Finding, Severity, Source

# call name (dotted) -> (rule_id, severity, title, description)
_DANGEROUS_CALLS = {
    "eval": ("DC-001", Severity.HIGH, "Use of eval()", "Evaluates arbitrary code at runtime."),
    "exec": ("DC-002", Severity.HIGH, "Use of exec()", "Executes arbitrary code at runtime."),
    "os.system": (
        "DC-003",
        Severity.HIGH,
        "os.system() shell call",
        "Runs a command through the shell.",
    ),
    "pickle.loads": (
        "DC-004",
        Severity.HIGH,
        "pickle.loads()",
        "Deserializing pickle data can execute arbitrary code.",
    ),
    "pickle.load": (
        "DC-004",
        Severity.HIGH,
        "pickle.load()",
        "Deserializing pickle data can execute arbitrary code.",
    ),
    "__import__": (
        "DC-005",
        Severity.MEDIUM,
        "Dynamic __import__()",
        "Imports a module chosen at runtime.",
    ),
    "compile": ("DC-006", Severity.MEDIUM, "compile()", "Compiles code from a string at runtime."),
    "marshal.loads": (
        "DC-007",
        Severity.HIGH,
        "marshal.loads()",
        "Deserializes code objects; unsafe on untrusted input.",
    ),
}


class DangerousCodeAnalyzer(Analyzer):
    id = "behavioral_ast"
    category = Category.DANGEROUS_CODE

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        py_files = [c.path for c in ctx.components if c.type == "python"]
        for path in py_files:
            src = ctx.file_cache.get(path, "")
            try:
                tree = ast.parse(src, filename=path)
            except SyntaxError as exc:
                findings.append(
                    Finding(
                        rule_id="DC-000",
                        category=self.category,
                        severity=Severity.LOW,
                        title="Unparseable Python",
                        description=f"Could not parse {path}: {exc.msg}. Obfuscation or corruption?",
                        source=Source.STATIC,
                        file=path,
                        line=exc.lineno,
                        confidence=0.5,
                    )
                )
                continue
            findings.extend(self._walk(tree, path, src))
        return findings

    def _walk(self, tree: ast.AST, path: str, src: str) -> list[Finding]:
        lines = src.splitlines()
        out: list[Finding] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = self._call_name(node.func)
            if name in _DANGEROUS_CALLS:
                rid, sev, title, desc = _DANGEROUS_CALLS[name]
                out.append(self._finding(rid, sev, title, desc, path, node, lines))
            elif name in (
                "subprocess.run",
                "subprocess.call",
                "subprocess.Popen",
                "subprocess.check_output",
            ):
                if self._has_shell_true(node):
                    out.append(
                        self._finding(
                            "DC-010",
                            Severity.HIGH,
                            "subprocess with shell=True",
                            "Shell invocation is injectable if any argument is attacker-influenced.",
                            path,
                            node,
                            lines,
                        )
                    )
        return out

    def _finding(
        self,
        rid: str,
        sev: Severity,
        title: str,
        desc: str,
        path: str,
        node: ast.AST,
        lines: list[str],
    ) -> Finding:
        ln = getattr(node, "lineno", None)
        snippet = lines[ln - 1].strip()[:200] if ln and ln <= len(lines) else None
        return Finding(
            rule_id=rid,
            category=self.category,
            severity=sev,
            title=title,
            description=desc,
            source=Source.STATIC,
            file=path,
            line=ln,
            snippet=snippet,
            confidence=0.9,
        )

    @staticmethod
    def _call_name(func: ast.expr) -> str:
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            parts = []
            cur: ast.expr | None = func
            while isinstance(cur, ast.Attribute):
                parts.append(cur.attr)
                cur = cur.value
            if isinstance(cur, ast.Name):
                parts.append(cur.id)
            return ".".join(reversed(parts))
        return ""

    @staticmethod
    def _has_shell_true(node: ast.Call) -> bool:
        for kw in node.keywords:
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                return True
        return False
