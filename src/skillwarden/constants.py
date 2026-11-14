"""Tunable constants. Env vars override where noted (per-deployment config)."""

from __future__ import annotations

import os

# --- LLM / provider -------------------------------------------------------
# "auto" resolves at runtime: an API key if one is set, else the Claude Code CLI if it
# is installed (it uses that machine's sign-in), else a local Ollama server, else
# unavailable. Force one with SKILLWARDEN_PROVIDER = anthropic | claude_cli | ollama.
PROVIDER = os.getenv("SKILLWARDEN_PROVIDER", "auto")
# The semantic pass renders a security judgment, and judging is where a weaker model
# costs the most. So this defaults to a top-tier model and is not a setting to lower
# for cost. Ollama stays available for air-gapped work, where a weaker local model is
# a deliberate, stated trade and not a silent downgrade.
ANTHROPIC_MODEL = os.getenv("SKILLWARDEN_MODEL", "claude-opus-5")
# The ceiling on one reply. The model may think before it answers and that thinking
# counts against this ceiling, so it is set well above the size of the JSON we expect.
LLM_MAX_TOKENS = int(os.getenv("SKILLWARDEN_LLM_MAX_TOKENS", "16000"))
# How much skill text the model is shown in one call, and in all calls together. Every
# character of every text file is shown in some call: a skill that fits in one call
# gets the full protocol (added findings, and refuted false-positive calls); a larger
# one is reviewed in parts, for added findings only. A skill larger than LLM_MAX_CHARS
# cannot be reviewed whole, and the scan is reported incomplete.
LLM_BATCH_CHARS = int(os.getenv("SKILLWARDEN_LLM_BATCH_CHARS", "200000"))
LLM_MAX_CHARS = int(os.getenv("SKILLWARDEN_LLM_MAX_CHARS", "3000000"))

# claude_cli provider (subscription / OAuth via the installed Claude Code CLI).
CLI_MODEL = os.getenv("SKILLWARDEN_CLI_MODEL", "opus")  # alias: opus | sonnet | haiku
CLI_TIMEOUT = float(os.getenv("SKILLWARDEN_CLI_TIMEOUT", "180"))

# ollama provider (local / air-gapped LLMs).
OLLAMA_URL = os.getenv("SKILLWARDEN_OLLAMA_URL", os.getenv("OLLAMA_HOST", "http://localhost:11434"))
OLLAMA_MODEL = os.getenv("SKILLWARDEN_OLLAMA_MODEL", "llama3.1")
OLLAMA_TIMEOUT = float(os.getenv("SKILLWARDEN_OLLAMA_TIMEOUT", "120"))
# Ollama cuts a prompt that is longer than the model's context window without saying
# so. The window is therefore set explicitly on every call, and each prompt is sized
# and checked to fit inside it (see OllamaProvider).
OLLAMA_NUM_CTX = int(os.getenv("SKILLWARDEN_OLLAMA_NUM_CTX", "8192"))

# --- Scanning limits (defensive; a hostile skill should not exhaust us) ---
MAX_FILE_BYTES = int(os.getenv("SKILLWARDEN_MAX_FILE_BYTES", str(2 * 1024 * 1024)))
MAX_TOTAL_BYTES = int(os.getenv("SKILLWARDEN_MAX_TOTAL_BYTES", str(50 * 1024 * 1024)))
MAX_COMPONENTS = int(os.getenv("SKILLWARDEN_MAX_COMPONENTS", "2000"))
# Zip-bomb guard: an archive (or any member) whose uncompressed size is more than
# MAX_ZIP_RATIO times its compressed size is refused before extraction, once the
# uncompressed size passes ZIP_RATIO_FLOOR_BYTES (small repetitive files are normal).
MAX_ZIP_RATIO = int(os.getenv("SKILLWARDEN_MAX_ZIP_RATIO", "100"))
ZIP_RATIO_FLOOR_BYTES = int(os.getenv("SKILLWARDEN_ZIP_RATIO_FLOOR_BYTES", str(1024 * 1024)))
NETWORK_TIMEOUT = float(os.getenv("SKILLWARDEN_NETWORK_TIMEOUT", "20"))

# --- Risk scoring ---------------------------------------------------------
# A skill that ships executable scripts is inherently higher-blast-radius.
EXECUTABLE_RISK_MULTIPLIER = 1.25

EXECUTABLE_EXTENSIONS = {".py", ".sh", ".bash", ".js", ".ts", ".rb", ".pl", ".ps1"}
TYPE_BY_EXTENSION = {
    ".md": "markdown",
    ".py": "python",
    ".sh": "shell",
    ".bash": "shell",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".jsx": "javascript",
    ".rb": "ruby",
    ".pl": "perl",
    ".ps1": "powershell",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".json": "json",
}
# Component types that hold executable code (vs prose/data). Used by patterns
# that should only fire on real code, not documentation examples.
CODE_TYPES = ("python", "shell", "javascript", "typescript", "ruby", "perl", "powershell")

LOG_LEVEL = os.getenv("SKILLWARDEN_LOG_LEVEL", "WARNING")
