"""Classify crawled URLs / discovered paths into API endpoints vs regular pages."""
from __future__ import annotations

import re
from typing import Any

from app.scanners.base import BaseScanner

API_HINTS_RE = re.compile(
    r"(/api/|/v[0-9]+/|/graphql|/rest/|\.json$|/rpc/|/gateway/|/service/)",
    re.IGNORECASE,
)


class APIExtractorScanner(BaseScanner):
    name = "api_extractor"

    async def run(self, target_domain: str, context: dict[str, Any]) -> dict[str, Any]:
        endpoints: list[dict] = []
        seen: set[str] = set()

        for url in context.get("crawled_urls", []):
            if url in seen:
                continue
            seen.add(url)
            endpoints.append({
                "url": url,
                "method": "GET",
                "status_code": None,
                "content_type": None,
                "source": "crawler",
                "is_api": bool(API_HINTS_RE.search(url)),
            })

        for path_info in context.get("discovered_paths", []):
            if path_info["url"] in seen:
                continue
            seen.add(path_info["url"])
            path_info["is_api"] = path_info.get("is_api") or bool(API_HINTS_RE.search(path_info["url"]))
            endpoints.append(path_info)

        api_count = sum(1 for e in endpoints if e["is_api"])
        self.logger.info("Classified %d endpoints (%d look like API endpoints)", len(endpoints), api_count)
        return {"endpoints": endpoints}
