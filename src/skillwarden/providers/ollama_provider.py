"""Ollama provider — local / air-gapped LLMs.

For scanning on machines with no subscription and no API key (offline, secure
enclaves), or when a team prefers a self-hosted model. Talks to an Ollama server
over its HTTP API; the model is pulled and served by Ollama itself.

Config: SKILLWARDEN_OLLAMA_URL (default http://localhost:11434),
SKILLWARDEN_OLLAMA_MODEL (default llama3.1), SKILLWARDEN_OLLAMA_NUM_CTX (the context
window in tokens, default 8192).

Ollama cuts a prompt that is longer than the model's context window without reporting
it, which would leave the model reviewing part of a skill while the scan claimed the
whole. So the window is set explicitly on every call; the semantic pass is told how
long a prompt may be (`max_prompt_chars`); a prompt whose size in bytes could exceed
the window is refused before it is sent (a token is at least one byte, so this cannot
under-count); and a reply whose prompt filled the window is refused as possibly cut.
The default window is small. Raise SKILLWARDEN_OLLAMA_NUM_CTX to what your model
allows, or most skills will be reviewed in many small parts.
"""

from __future__ import annotations

import httpx

from skillwarden import constants
from skillwarden.providers.base import LLMProvider


def _normalize_url(url: str) -> str:
    # OLLAMA_HOST is sometimes set as "host:port" with no scheme.
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"
    return url.rstrip("/")


# Tokens kept back from the context window for the reply and the chat template.
_RESERVED_TOKENS = 2048


class OllamaProvider(LLMProvider):
    name = "ollama"

    def __init__(self) -> None:
        self._url = _normalize_url(constants.OLLAMA_URL)
        self._model = constants.OLLAMA_MODEL
        self._num_ctx = constants.OLLAMA_NUM_CTX

    @property
    def _prompt_tokens(self) -> int:
        """Tokens of the context window left for the prompt."""
        return max(self._num_ctx - _RESERVED_TOKENS, 0)

    @property
    def max_prompt_chars(self) -> int:
        # No tokenizer here, so the size is bounded the only safe way: a token is at
        # least one byte, so a prompt of N bytes is at most N tokens. One character per
        # token is the figure, counted in bytes (`prompt_limit_in_bytes`); `complete`
        # checks the same bytes again before it sends anything.
        return self._prompt_tokens

    @property
    def prompt_limit_in_bytes(self) -> bool:
        return True

    def is_available(self) -> bool:
        try:
            resp = httpx.get(f"{self._url}/api/tags", timeout=2.0)
            return resp.status_code == 200
        except httpx.HTTPError:
            return False

    def complete(self, system: str, user: str) -> str:
        size = len((system + user).encode("utf-8"))
        if size > self._prompt_tokens:
            # Refused here, before the call: Ollama would cut it and not say so.
            raise RuntimeError(
                f"prompt of {size} bytes may not fit Ollama's context window "
                f"({self._num_ctx} tokens, {_RESERVED_TOKENS} kept for the reply); raise "
                "SKILLWARDEN_OLLAMA_NUM_CTX"
            )
        resp = httpx.post(
            f"{self._url}/api/chat",
            json={
                "model": self._model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                "stream": False,
                "options": {"num_ctx": self._num_ctx},
            },
            timeout=constants.OLLAMA_TIMEOUT,
        )
        resp.raise_for_status()
        body = resp.json()
        # Ollama reports how many prompt tokens it evaluated. A prompt that filled the
        # window may have been cut to fit; a review of a cut prompt is not a review.
        evaluated = body.get("prompt_eval_count")
        counted = isinstance(evaluated, int) and not isinstance(evaluated, bool)
        if counted and evaluated >= self._num_ctx:
            raise RuntimeError(
                f"Ollama evaluated {evaluated} prompt tokens with a context window of "
                f"{self._num_ctx}: the prompt may have been cut; raise "
                "SKILLWARDEN_OLLAMA_NUM_CTX"
            )
        message = body.get("message", {})
        content = message.get("content", "")
        if not isinstance(content, str):
            raise RuntimeError("Ollama returned a non-text response")
        return content
