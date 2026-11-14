"""Claude (Anthropic) provider — the default semantic backend."""

from __future__ import annotations

import os
from typing import Any

from skillwarden import constants
from skillwarden.providers.base import LLMProvider


class AnthropicProvider(LLMProvider):
    name = "anthropic"

    def __init__(self) -> None:
        self._model = constants.ANTHROPIC_MODEL
        self._client: Any = None

    def is_available(self) -> bool:
        return bool(os.getenv("ANTHROPIC_API_KEY"))

    def _ensure_client(self) -> Any:
        if self._client is None:
            from anthropic import Anthropic

            self._client = Anthropic()  # reads ANTHROPIC_API_KEY from env
        return self._client

    def complete(self, system: str, user: str) -> str:
        client = self._ensure_client()
        resp = client.messages.create(
            model=self._model,
            max_tokens=constants.LLM_MAX_TOKENS,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return "".join(block.text for block in resp.content if block.type == "text")
