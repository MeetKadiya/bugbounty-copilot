"""Pipeline stage: turn raw discovered endpoints + parameters into structured
Endpoint Intelligence (see app.intelligence.endpoint_intelligence). Runs after
API extraction and parameter discovery so it has both inputs available."""
from __future__ import annotations

from typing import Any

from app.intelligence.endpoint_intelligence import build_endpoint_intelligence
from app.scanners.base import BaseScanner


class EndpointIntelligenceScanner(BaseScanner):
    name = "endpoint_intelligence"

    async def run(self, target_domain: str, context: dict[str, Any]) -> dict[str, Any]:
        endpoints = context.get("endpoints", [])
        parameters = context.get("parameters", [])
        try:
            records = build_endpoint_intelligence(endpoints, parameters)
        except Exception:  # noqa: BLE001
            self.logger.exception("Endpoint intelligence build failed; returning no records")
            records = []
        self.logger.info("Derived intelligence for %d normalized endpoint group(s)", len(records))
        return {"endpoint_intelligence": records}
