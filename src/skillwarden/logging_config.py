"""Internal logging. User-facing output goes through Rich in the reporters;
this is for operational/diagnostic logging only."""

from __future__ import annotations

import logging

from skillwarden import constants

_configured = False


def _configure() -> None:
    global _configured
    if not _configured:
        logging.basicConfig(
            level=getattr(logging, constants.LOG_LEVEL.upper(), logging.WARNING),
            format="%(asctime)s %(name)s %(levelname)s %(message)s",
        )
        _configured = True


def get_logger(name: str) -> logging.Logger:
    _configure()
    return logging.getLogger(name)
