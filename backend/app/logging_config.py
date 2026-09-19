"""Structured logging setup shared across the whole application."""
from __future__ import annotations

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

from app.config import get_settings


def configure_logging() -> None:
    settings = get_settings()
    log_path = Path(settings.LOG_DIR) / "bugbounty-copilot.log"

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    root = logging.getLogger()
    root.setLevel(settings.LOG_LEVEL)

    if root.handlers:
        # Avoid duplicate handlers on reload
        root.handlers.clear()

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    root.addHandler(stream_handler)

    file_handler = RotatingFileHandler(log_path, maxBytes=5_000_000, backupCount=5)
    file_handler.setFormatter(formatter)
    root.addHandler(file_handler)

    # Quiet noisy third-party loggers
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)

    # Dedicated audit trail for the Scope-Aware Request Firewall: every
    # allow/block decision, on its own rotating file, separate from the
    # general application log so it's easy to review/export on its own.
    # Never propagates secrets -- ScopeDecision objects never carry
    # headers/cookies/tokens, only URL/host/port/scheme/rule/reason.
    audit_path = Path(settings.LOG_DIR) / "scope_decisions.log"
    audit_logger = logging.getLogger("scope_firewall.audit")
    audit_logger.setLevel(logging.INFO)
    audit_logger.propagate = True  # still shows up in the main log/console too
    if not any(isinstance(h, RotatingFileHandler) and getattr(h, "_scope_audit", False)
               for h in audit_logger.handlers):
        audit_handler = RotatingFileHandler(audit_path, maxBytes=5_000_000, backupCount=5)
        audit_handler.setFormatter(formatter)
        audit_handler._scope_audit = True  # marker to avoid duplicate handlers on reload
        audit_logger.addHandler(audit_handler)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
