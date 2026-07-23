"""Base class every scanner module implements -- keeps the pipeline pluggable."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from app.logging_config import get_logger


class BaseScanner(ABC):
    name: str = "base"

    def __init__(self) -> None:
        self.logger = get_logger(f"scanner.{self.name}")

    @abstractmethod
    async def run(self, target_domain: str, context: dict[str, Any]) -> dict[str, Any]:
        """Execute the scan stage. `context` carries results from prior stages.

        Must return a dict of new/updated results to merge into the pipeline
        context. Must never raise on recoverable errors -- log and return
        partial/empty results instead so one failing stage doesn't kill the scan.
        """
        raise NotImplementedError
