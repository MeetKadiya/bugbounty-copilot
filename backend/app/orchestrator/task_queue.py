"""
Lightweight asyncio-based background task runner.

Deliberately simple (no Celery/Redis dependency required) so `docker-compose up`
just works out of the box. The interface is intentionally Celery-shaped
(`enqueue_scan`) so swapping in Celery/Redis later is a drop-in change if the
project needs true multi-worker horizontal scaling.
"""
from __future__ import annotations

import asyncio

from app.database import AsyncSessionLocal
from app.logging_config import get_logger
from app.orchestrator.pipeline import run_pipeline

logger = get_logger(__name__)

_running_tasks: dict[str, asyncio.Task] = {}


def enqueue_scan(scan_id: str, target_domain: str) -> None:
    """Fire-and-forget an asyncio task for this scan. Survives for the lifetime
    of the FastAPI process; for true durability across restarts, swap this
    module's internals for a Celery task without touching any caller."""
    task = asyncio.create_task(_run_and_cleanup(scan_id, target_domain))
    _running_tasks[scan_id] = task


async def _run_and_cleanup(scan_id: str, target_domain: str) -> None:
    try:
        await run_pipeline(scan_id, target_domain, AsyncSessionLocal)
    finally:
        _running_tasks.pop(scan_id, None)


def cancel_scan(scan_id: str) -> bool:
    task = _running_tasks.get(scan_id)
    if task and not task.done():
        task.cancel()
        return True
    return False


def is_running(scan_id: str) -> bool:
    task = _running_tasks.get(scan_id)
    return bool(task and not task.done())
