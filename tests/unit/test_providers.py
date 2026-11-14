"""Provider resolution: name aliases and the 'auto' detection order."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest

from skillwarden.providers.anthropic_provider import AnthropicProvider
from skillwarden.providers.base import get_provider
from skillwarden.providers.claude_cli_provider import ClaudeCliProvider


def test_named_providers():
    assert isinstance(get_provider("anthropic"), AnthropicProvider)
    assert isinstance(get_provider("claude"), AnthropicProvider)
    assert isinstance(get_provider("claude_cli"), ClaudeCliProvider)
    assert isinstance(get_provider("subscription"), ClaudeCliProvider)


def test_unknown_provider_raises():
    with pytest.raises(ValueError, match="Unknown provider"):
        get_provider("definitely-not-a-provider")


def test_auto_prefers_api_key(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-xxx")
    assert isinstance(get_provider("auto"), AnthropicProvider)


def test_auto_falls_back_to_cli_when_no_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    # CLI is installed on this machine; auto should resolve to it without a key.
    provider = get_provider("auto")
    if ClaudeCliProvider().is_available():
        assert isinstance(provider, ClaudeCliProvider)
    else:
        assert isinstance(provider, AnthropicProvider)  # neither available; reports unavailable


def test_cli_provider_unavailable_complete_raises(monkeypatch):
    p = ClaudeCliProvider()
    monkeypatch.setattr(p, "_bin", None)
    assert p.is_available() is False
    with pytest.raises(RuntimeError, match="claude CLI not found"):
        p.complete("sys", "user")


# --- claude_cli: the model that reads hostile text is given nothing to act with ---


class _FakeRun:
    """Stands in for subprocess.run and records how the CLI was invoked."""

    def __init__(self, returncode: int = 0, stdout: str = "reply", stderr: str = "") -> None:
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr
        self.cmd: list[str] = []
        self.kwargs: dict[str, Any] = {}

    def __call__(self, cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        self.cmd, self.kwargs = list(cmd), kwargs
        return subprocess.CompletedProcess(cmd, self.returncode, self.stdout, self.stderr)


def _cli_provider(monkeypatch: pytest.MonkeyPatch, fake: _FakeRun) -> ClaudeCliProvider:
    p = ClaudeCliProvider()
    monkeypatch.setattr(p, "_bin", "/usr/bin/claude")
    monkeypatch.setattr(subprocess, "run", fake)
    return p


def _value_after(cmd: list[str], flag: str) -> str:
    return cmd[cmd.index(flag) + 1]


def test_cli_call_gives_the_model_no_tools(monkeypatch):
    fake = _FakeRun()
    _cli_provider(monkeypatch, fake).complete("SYSTEM", "hostile skill text")
    # No built-in tools, no MCP servers, none of this machine's settings.
    assert _value_after(fake.cmd, "--tools") == ""
    assert "--strict-mcp-config" in fake.cmd
    assert "--mcp-config" not in fake.cmd
    assert _value_after(fake.cmd, "--setting-sources") == ""
    # Nothing that widens what the model may do.
    for flag in ("--allowedTools", "--allowed-tools", "--dangerously-skip-permissions",
                 "--permission-mode", "--add-dir"):
        assert flag not in fake.cmd


def test_cli_call_keeps_hostile_text_off_the_command_line(monkeypatch):
    fake = _FakeRun()
    out = _cli_provider(monkeypatch, fake).complete("SYSTEM", "hostile skill text")
    assert out == "reply"
    assert "-p" in fake.cmd
    assert _value_after(fake.cmd, "--system-prompt") == "SYSTEM"
    # The skill text travels on stdin, never as an argument.
    assert fake.kwargs["input"] == "hostile skill text"
    assert "hostile skill text" not in fake.cmd
    # And the CLI runs in a throwaway directory, not in the caller's project.
    assert Path(fake.kwargs["cwd"]).name.startswith("skillwarden-cli-")
    assert Path(fake.kwargs["cwd"]).resolve() != Path.cwd().resolve()


def test_cli_that_rejects_the_flags_fails_the_pass(monkeypatch):
    # An older CLI that does not know a flag exits non-zero: the provider raises, the
    # engine records a failed pass, and the scan is incomplete. Never a retry with
    # tools on.
    fake = _FakeRun(returncode=1, stdout="", stderr="error: unknown option '--tools'")
    with pytest.raises(RuntimeError, match="claude CLI failed"):
        _cli_provider(monkeypatch, fake).complete("SYSTEM", "text")
