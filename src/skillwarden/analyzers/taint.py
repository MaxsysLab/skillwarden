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
_REGEX_MODULES = frozenset({"re", "regex"})
_RESERVED_BUILTINS = frozenset({"builtins", "__builtins__"})
_CODE_COMPILE_KWARGS = frozenset(
    {"source", "filename", "mode", "dont_inherit", "optimize", "_feature_version"}
)
_MODULE_SUFFIXES = (".py", ".pyc", ".pyo", ".pyw", ".pyd", ".so", ".dll", ".dylib")


class _RegexScope:
    """Names in one AST that safely refer to `re`/`regex` rather than `builtins`."""

    def __init__(self, tree: ast.AST, allowed_modules: frozenset[str] = _REGEX_MODULES) -> None:
        self.allowed_modules = allowed_modules
        self.mod_aliases: set[str] = set()
        self.func_aliases: set[str] = set()
        self.builtin_sinks: dict[str, str] = {}
        self.other_bindings: set[str] = set()
        self.escaped_loads: set[str] = set()
        self.compile_attr_mutated = False
        self.dynamic_attr_mutator = False
        self.sys_modules_tampered = False
        self.namespace_tampered = False
        self.safe_compile_scopes: list[tuple[ast.AST, tuple[int, int]]] = []
        self._scan(tree)

    def _scan(self, tree: ast.AST) -> None:
        none_fallback_ids: set[int] = set()
        attr_load_ids: set[int] = set()

        for node in ast.walk(tree):
            if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef)):
                for stmt in node.body:
                    if (
                        isinstance(stmt, ast.ImportFrom)
                        and stmt.level == 0
                        and stmt.module in self.allowed_modules
                    ):
                        for alias in stmt.names:
                            if (
                                alias.name == "compile"
                                and (alias.asname or alias.name) == "compile"
                            ):
                                end_pos = (
                                    stmt.end_lineno or stmt.lineno,
                                    stmt.end_col_offset or 0,
                                )
                                self.safe_compile_scopes.append((node, end_pos))
            elif (
                isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id not in _SINK_CALLS
                and isinstance(node.value, ast.Constant)
                and node.value.value is None
            ):
                none_fallback_ids.add(id(node.targets[0]))
            elif isinstance(node, ast.Attribute):
                if isinstance(node.ctx, (ast.Store, ast.Del)):
                    if node.attr == "compile":
                        self.compile_attr_mutated = True
                    if node.attr == "modules":
                        self.sys_modules_tampered = True
                        self.namespace_tampered = True
                    root = self._root_name(node.value)
                    if root is not None:
                        self.escaped_loads.add(root)
                        if root in _RESERVED_BUILTINS:
                            self.sys_modules_tampered = True
                            self.namespace_tampered = True
                elif (
                    isinstance(node.ctx, ast.Load)
                    and node.attr not in {"__dict__", "__setattr__", "__delattr__", "__class__"}
                    and isinstance(node.value, ast.Name)
                ):
                    attr_load_ids.add(id(node.value))
                if node.attr in {"__dict__", "__setattr__", "__delattr__"}:
                    self.dynamic_attr_mutator = True
            elif isinstance(node, ast.Subscript) and isinstance(node.ctx, (ast.Store, ast.Del)):
                if isinstance(node.value, ast.Attribute) and node.value.attr == "modules":
                    self.sys_modules_tampered = True
                    self.namespace_tampered = True
                root = self._root_name(node.value)
                if root is not None:
                    self.escaped_loads.add(root)
                    if root in _RESERVED_BUILTINS:
                        self.sys_modules_tampered = True
                        self.namespace_tampered = True

        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                if isinstance(node.ctx, (ast.Store, ast.Del)):
                    if id(node) not in none_fallback_ids:
                        self.other_bindings.add(node.id)
                elif isinstance(node.ctx, ast.Load) and id(node) not in attr_load_ids:
                    self.escaped_loads.add(node.id)
            elif isinstance(
                node,
                (
                    ast.FunctionDef,
                    ast.AsyncFunctionDef,
                    ast.ClassDef,
                    ast.TypeVar,
                    ast.ParamSpec,
                    ast.TypeVarTuple,
                ),
            ):
                self.other_bindings.add(node.name)
            elif isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)):
                if node.name is not None:
                    self.other_bindings.add(node.name)
            elif isinstance(node, ast.MatchMapping):
                if node.rest is not None:
                    self.other_bindings.add(node.rest)
            elif isinstance(node, ast.arg):
                self.other_bindings.add(node.arg)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    bound = alias.asname or alias.name.split(".", 1)[0]
                    if alias.name in self.allowed_modules:
                        self.mod_aliases.add(bound)
                    else:
                        self.other_bindings.add(bound)
            elif isinstance(node, ast.ImportFrom):
                if any(a.name == "*" for a in node.names):
                    self.namespace_tampered = True
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    bound = alias.asname or alias.name
                    if (
                        node.level == 0
                        and node.module in self.allowed_modules
                        and alias.name == "compile"
                    ):
                        self.func_aliases.add(bound)
                    else:
                        self.other_bindings.add(bound)
                        if (
                            node.level == 0
                            and node.module == "builtins"
                            and alias.name in _SINK_CALLS
                        ):
                            self.builtin_sinks[bound] = alias.name
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    if node.func.id in {"globals", "locals"}:
                        self.namespace_tampered = True
                    elif node.func.id in {"setattr", "delattr", "vars"}:
                        self.dynamic_attr_mutator = True
                elif (
                    isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Attribute)
                    and node.func.value.attr == "modules"
                    and node.func.attr
                    in {"update", "setdefault", "pop", "clear", "__setitem__", "__delitem__"}
                ):
                    self.sys_modules_tampered = True
                    self.namespace_tampered = True

    def is_regex_compile(
        self,
        call: ast.Call,
        *,
        skill_compile_mutated: bool = False,
        skill_dynamic_mutator: bool = False,
        skill_namespace_tampered: bool = False,
    ) -> bool:
        if (
            self.namespace_tampered
            or skill_namespace_tampered
            or self.compile_attr_mutated
            or skill_compile_mutated
            or self._looks_like_code_compile(call)
        ):
            return False
        has_mutator = self.dynamic_attr_mutator or skill_dynamic_mutator
        func = call.func
        if isinstance(func, ast.Attribute) and func.attr == "compile":
            if not isinstance(func.value, ast.Name):
                return False
            mod = func.value.id
            if (
                mod in _RESERVED_BUILTINS
                or mod in self.other_bindings
                or mod in self.func_aliases
                or (has_mutator and mod in self.escaped_loads)
            ):
                return False
            return mod in self.mod_aliases or mod in self.allowed_modules
        if isinstance(func, ast.Name):
            name = func.id
            if (
                name in _RESERVED_BUILTINS
                or name in self.other_bindings
                or name in self.mod_aliases
                or name not in self.func_aliases
                or (has_mutator and name in self.escaped_loads)
            ):
                return False
            if name == "compile":
                call_pos = (getattr(call, "lineno", 0), getattr(call, "col_offset", 0))
                return any(
                    cutoff < call_pos and any(sub is call for sub in ast.walk(owner))
                    for owner, cutoff in self.safe_compile_scopes
                )
            return True
        return False

    @staticmethod
    def _looks_like_code_compile(call: ast.Call) -> bool:
        if len(call.args) >= 3 or any(isinstance(arg, ast.Starred) for arg in call.args):
            return True
        return any(kw.arg is None or kw.arg in _CODE_COMPILE_KWARGS for kw in call.keywords)

    @staticmethod
    def _root_name(node: ast.expr) -> str | None:
        cur = node
        while isinstance(cur, (ast.Attribute, ast.Subscript)):
            cur = cur.value
        return cur.id if isinstance(cur, ast.Name) else None


class TaintAnalyzer(Analyzer):
    id = "behavioral_taint"
    category = Category.TAINT

    def run(self, ctx: ScanContext) -> list[Finding]:
        allowed_modules = _REGEX_MODULES - self._shadowed_regex_modules(ctx)
        parsed: list[tuple[str, ast.Module, list[str], _RegexScope]] = []
        for c in ctx.components:
            if c.type != "python":
                continue
            src = ctx.file_cache.get(c.path, "")
            try:
                tree = ast.parse(src)
            except SyntaxError:
                continue  # dangerous_code already reports unparseable files
            parsed.append((c.path, tree, src.splitlines(), _RegexScope(tree, allowed_modules)))

        skill_compile_mutated = any(s.compile_attr_mutated for *_, s in parsed)
        skill_dynamic_mutator = any(s.dynamic_attr_mutator for *_, s in parsed)
        skill_sys_modules_tampered = any(s.sys_modules_tampered for *_, s in parsed)

        findings: list[Finding] = []
        for path, tree, lines, scope in parsed:
            findings.extend(
                self._analyze(
                    tree,
                    path,
                    lines,
                    scope=scope,
                    skill_compile_mutated=skill_compile_mutated,
                    skill_dynamic_mutator=skill_dynamic_mutator,
                    skill_namespace_tampered=skill_sys_modules_tampered,
                )
            )
        return findings

    def _analyze(
        self,
        tree: ast.AST,
        path: str,
        lines: list[str],
        *,
        scope: _RegexScope | None = None,
        skill_compile_mutated: bool = False,
        skill_dynamic_mutator: bool = False,
        skill_namespace_tampered: bool = False,
    ) -> list[Finding]:
        regex_scope = scope or _RegexScope(tree)
        tainted = self._propagate(tree)
        out: list[Finding] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            sink = self._call_sink(
                node,
                regex_scope,
                skill_compile_mutated=skill_compile_mutated,
                skill_dynamic_mutator=skill_dynamic_mutator,
                skill_namespace_tampered=skill_namespace_tampered,
            )
            if sink is None:
                continue
            checked_args = [
                *node.args,
                *(
                    kw.value
                    for kw in node.keywords
                    if sink == "compile" and kw.arg in (None, "source")
                ),
            ]
            if any(self._refs_tainted(arg, tainted) for arg in checked_args):
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

    def _call_sink(
        self,
        call: ast.Call,
        scope: _RegexScope,
        *,
        skill_compile_mutated: bool = False,
        skill_dynamic_mutator: bool = False,
        skill_namespace_tampered: bool = False,
    ) -> str | None:
        func = call.func
        sink = self._sink_name(func)
        if sink is None and isinstance(func, ast.Name):
            sink = scope.builtin_sinks.get(func.id)
        if sink == "compile" and scope.is_regex_compile(
            call,
            skill_compile_mutated=skill_compile_mutated,
            skill_dynamic_mutator=skill_dynamic_mutator,
            skill_namespace_tampered=skill_namespace_tampered,
        ):
            return None
        return sink

    @staticmethod
    def _sink_name(func: ast.expr) -> str | None:
        if isinstance(func, ast.Name) and func.id in _SINK_CALLS:
            return func.id
        if isinstance(func, ast.Attribute) and func.attr in _SINK_CALLS:
            return func.attr
        return None

    @staticmethod
    def _shadowed_regex_modules(ctx: ScanContext) -> set[str]:
        shadowed: set[str] = set()
        for c in ctx.components:
            parts = [p for p in c.path.replace("\\", "/").split("/") if p]
            if not parts:
                continue
            fname = parts[-1].lower()
            if fname.endswith(_MODULE_SUFFIXES):
                stem = fname.split(".", 1)[0]
                if stem in _REGEX_MODULES:
                    shadowed.add(stem)
                for parent in parts[:-1]:
                    if parent.lower() in _REGEX_MODULES:
                        shadowed.add(parent.lower())
        for s in ctx.skipped:
            for part in s.path.replace("\\", "/").split("/"):
                stem = part.split(".", 1)[0].lower()
                if stem in _REGEX_MODULES:
                    shadowed.add(stem)
        return shadowed
