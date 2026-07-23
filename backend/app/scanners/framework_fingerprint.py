"""
Framework fingerprinting from static assets and crawled URL patterns.

Complements headers_tech.py by looking at *paths* discovered during crawling
(e.g. '/wp-content/', '/_next/', '/static/django_extensions/') rather than
just headers/cookies.
"""
from __future__ import annotations

from typing import Any

from app.scanners.base import BaseScanner

PATH_SIGNATURES = {
    "/wp-content/": ("WordPress", "cms"),
    "/wp-includes/": ("WordPress", "cms"),
    "/_next/": ("Next.js", "frontend"),
    "/static/rest_framework/": ("Django REST Framework", "framework"),
    "/umbraco/": ("Umbraco CMS", "cms"),
    "/sites/default/": ("Drupal", "cms"),
    "/typo3/": ("TYPO3", "cms"),
    "/magento/": ("Magento", "cms"),
    "/administrator/": ("Joomla", "cms"),
    "/laravel-": ("Laravel", "framework"),
    "/webpack": ("Webpack Bundled App", "build-tool"),
    "/angular": ("Angular", "frontend"),
    "/vue": ("Vue.js", "frontend"),
    "/react": ("React", "frontend"),
}


class FrameworkFingerprintScanner(BaseScanner):
    name = "framework_fingerprint"

    async def run(self, target_domain: str, context: dict[str, Any]) -> dict[str, Any]:
        technologies: list[dict] = list(context.get("technologies", []))
        seen = {(t["hostname"], t["name"]) for t in technologies}

        all_urls = context.get("crawled_urls", []) + context.get("js_files", [])
        for url in all_urls:
            for pattern, (label, category) in PATH_SIGNATURES.items():
                if pattern in url:
                    hostname = url.split("/")[2] if "//" in url else target_domain
                    key = (hostname, label)
                    if key not in seen:
                        seen.add(key)
                        technologies.append({
                            "hostname": hostname, "name": label, "category": category,
                            "evidence": f"Path pattern '{pattern}' seen in {url}",
                        })

        self.logger.info("Total technology signals after framework fingerprinting: %d", len(technologies))
        return {"technologies": technologies}
