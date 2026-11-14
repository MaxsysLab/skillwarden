"""Shared helpers for the MCP analyzers: locate and parse MCP server configs
that a skill may ship, regardless of exact filename/schema."""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

import yaml

from skillwarden.analyzers.base import ScanContext

_MCP_HINTS = ("mcpservers", "mcp_servers", '"command"', "tools", "allowedtools", "autoapprove")


def parse_configs(ctx: ScanContext) -> Iterator[tuple[str, Any]]:
    """Yield (path, parsed_object) for files that look like MCP/tool configs."""
    for path, text in ctx.file_cache.items():
        lower = path.lower()
        is_struct = lower.endswith((".json", ".yaml", ".yml"))
        looks_mcp = "mcp" in lower or any(h in text.lower() for h in _MCP_HINTS)
        if not (is_struct and looks_mcp):
            continue
        data = _load(path, text)
        if data is not None:
            yield path, data


def _load(path: str, text: str) -> Any | None:
    try:
        if path.lower().endswith(".json"):
            return json.loads(text)
        return yaml.safe_load(text)
    except (json.JSONDecodeError, yaml.YAMLError):
        return None


def walk(obj: Any, _path: str = "") -> Iterator[tuple[str, str, Any]]:
    """Walk a parsed structure, yielding (json_path, key, value) for every dict key."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            jp = f"{_path}.{k}" if _path else str(k)
            yield jp, str(k), v
            yield from walk(v, jp)
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            yield from walk(item, f"{_path}[{i}]")
