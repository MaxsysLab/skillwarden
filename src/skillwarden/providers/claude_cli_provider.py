"""Claude CLI provider: uses the installed Claude Code CLI (`claude -p`) and its
sign-in, in place of an API key.

On a developer's machine the `claude` CLI is usually signed in already, so the
semantic pass gets a Claude backend with no API key to provision. A server or CI job
uses the API-key provider instead. Both sit behind the same LLMProvider interface.

Notes:
- We invoke a *normal* `claude -p` (not `--bare`): `--bare` forces ANTHROPIC_API_KEY
  and never reads OAuth, which would defeat the purpose here.
- The prompt is piped on stdin (no ARG_MAX limit on large skills); the system
  prompt goes via --system-prompt; output is plain text.
- We run in a throwaway temp dir so the CLI's CLAUDE.md auto-discovery can't pull
  the current project's context into the scan.
- The prompt carries the text of the skill under review, which may be hostile. The
  model is therefore given nothing to act with: no built-in tools (`--tools ""`), no
  MCP servers (`--strict-mcp-config` with no `--mcp-config`), and none of this
  machine's settings (`--setting-sources ""`: no hooks, plugins or permission rules).
  It reads the prompt and answers in text. Without these flags, what injected text
  could make the model do would depend on the permission settings of whichever
  machine runs the scan. A CLI too old to know the flags exits non-zero, the pass
  fails, and the scan is reported incomplete: never a silent run with tools on.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile

from skillwarden import constants
from skillwarden.providers.base import LLMProvider

# The model reviews hostile text; it must have nothing to act with. Order matters only
# in that each flag is followed by its own value.
_NO_TOOLS_ARGS: tuple[str, ...] = (
    "--tools",
    "",
    "--strict-mcp-config",
    "--setting-sources",
    "",
)


class ClaudeCliProvider(LLMProvider):
    name = "claude_cli"

    def __init__(self) -> None:
        self._bin = shutil.which("claude")
        self._model = constants.CLI_MODEL

    def is_available(self) -> bool:
        return self._bin is not None

    @staticmethod
    def _base_args(system: str) -> list[str]:
        """Arguments for one text-only call. See the module notes on the last three."""
        return [
            "-p",
            "--output-format",
            "text",
            "--system-prompt",
            system,
            *_NO_TOOLS_ARGS,
        ]

    def complete(self, system: str, user: str) -> str:
        if self._bin is None:
            raise RuntimeError("claude CLI not found on PATH")
        cmd = [self._bin, *self._base_args(system)]
        if self._model:
            cmd += ["--model", self._model]
        with tempfile.TemporaryDirectory(prefix="skillwarden-cli-") as workdir:
            proc = subprocess.run(
                cmd,
                input=user,
                capture_output=True,
                text=True,
                timeout=constants.CLI_TIMEOUT,
                cwd=workdir,
            )
        if proc.returncode != 0:
            detail = proc.stderr.strip()[:300]
            raise RuntimeError(f"claude CLI failed ({proc.returncode}): {detail}")
        return proc.stdout
