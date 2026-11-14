"""Provider interface for the semantic (LLM) analysis pass.

Kept deliberately small and swappable: a provider takes a prompt and returns text.
Claude is the default; another backend implements this one method. No framework and
no MCP: a thin call that is easy to read.
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod


class LLMProvider(ABC):
    name: str

    @abstractmethod
    def is_available(self) -> bool:
        """True when credentials/config are present so the engine can skip cleanly."""

    @abstractmethod
    def complete(self, system: str, user: str) -> str:
        """Return the model's text response."""

    @property
    def max_prompt_chars(self) -> int | None:
        """The longest whole prompt (system and user text together) this backend can
        take in one call, in characters; None when it sets no limit of its own.

        The semantic pass sizes each call to fit and never sends a longer one, so the
        model is never handed more than it can read. A backend with a small context
        window overrides this.
        """
        return None

    @property
    def prompt_limit_in_bytes(self) -> bool:
        """True when `max_prompt_chars` is to be compared with the prompt's size in
        bytes of UTF-8, not in characters. A backend with no tokenizer of its own uses
        bytes, the one bound that cannot under-count."""
        return False


def get_provider(name: str) -> LLMProvider:
    """Resolve a provider by name.

    "auto" (the default) prefers an explicit API key when one is set, the usual way
    on a server or in CI, and otherwise falls back to the Claude Code CLI, which
    uses the sign-in already on a developer's machine. Forcing a name
    (anthropic | claude_cli | ollama) bypasses detection.
    """
    if name == "auto":
        return _auto_provider()
    if name in ("anthropic", "claude", "api"):
        from skillwarden.providers.anthropic_provider import AnthropicProvider

        return AnthropicProvider()
    if name in ("claude_cli", "cli", "subscription"):
        from skillwarden.providers.claude_cli_provider import ClaudeCliProvider

        return ClaudeCliProvider()
    if name in ("ollama", "local"):
        from skillwarden.providers.ollama_provider import OllamaProvider

        return OllamaProvider()
    raise ValueError(f"Unknown provider: {name!r}")


def _auto_provider() -> LLMProvider:
    """Detection order: API key (prod) → subscription CLI (dev) → local Ollama
    (offline/air-gapped) → report unavailable."""
    from skillwarden.providers.anthropic_provider import AnthropicProvider
    from skillwarden.providers.claude_cli_provider import ClaudeCliProvider
    from skillwarden.providers.ollama_provider import OllamaProvider

    if os.getenv("ANTHROPIC_API_KEY"):
        return AnthropicProvider()
    cli = ClaudeCliProvider()
    if cli.is_available():
        return cli
    ollama = OllamaProvider()
    if ollama.is_available():
        return ollama
    return AnthropicProvider()  # unavailable; engine surfaces the "set a key" notice
