"""
Centralized configuration for Bug Bounty Copilot.

All tunables live here and are overridable via environment variables / .env file.
This keeps the "assistant only, never intrusive" posture configurable but
defaults are intentionally conservative.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any, List

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent

_CORS_DEFAULTS = ["http://localhost:5173", "http://localhost:3000"]


def _parse_str_list(value: Any, default: list) -> list:
    """
    Robustly coerce an environment variable to List[str].

    Handles all formats that deployment platforms (Render, Railway, Fly.io)
    may produce:
      - Already a list  → returned as-is
      - Empty / blank   → ``default`` is returned
      - JSON array str  → parsed with json.loads
      - Comma-separated → split on commas, values stripped
    """
    if isinstance(value, list):
        return value or default
    if not isinstance(value, str):
        return default
    value = value.strip()
    if not value:
        return default
    # Try JSON first (e.g. '["https://foo.com"]')
    if value.startswith("["):
        try:
            parsed = json.loads(value)
            return parsed if parsed else default
        except json.JSONDecodeError:
            pass
    # Fall back to comma-separated (e.g. "https://foo.com,https://bar.com")
    return [item.strip() for item in value.split(",") if item.strip()] or default


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        # Treat empty-string env vars as unset so the field default is used.
        # Without this, platforms like Render that set an env var to "" cause
        # pydantic-settings to call json.loads("") on List fields → crash.
        env_ignore_empty=True,
    )

    # --- App ---
    APP_NAME: str = "Bug Bounty Copilot"
    ENV: str = "development"
    DEBUG: bool = True
    API_V1_PREFIX: str = "/api/v1"

    # --- Server ---
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    # Stored as a plain str to avoid pydantic-settings calling json.loads("") on
    # a List[str] field when the env var is blank (crashes before any validator
    # or env_ignore_empty flag can intercept it).
    # main.py calls get_cors_origins() to get the parsed List[str].
    CORS_ORIGINS: str = '["http://localhost:5173","http://localhost:3000"]'

    # --- Database ---
    DATABASE_URL: str = f"sqlite+aiosqlite:///{BASE_DIR / 'data' / 'bugbounty.db'}"

    # --- Safety / Scope ---
    # Hard safety switch. This tool NEVER exploits. This flag cannot enable exploitation;
    # it only gates whether "active" (rate-limited, non-destructive) checks like httpx
    # probing / directory discovery are allowed vs. passive-only (OSINT/CT-log) recon.
    ALLOW_ACTIVE_RECON: bool = True
    MAX_CONCURRENT_REQUESTS: int = 20
    REQUEST_TIMEOUT_SECONDS: int = 10
    RATE_LIMIT_PER_HOST_RPS: float = 5.0
    RESPECT_ROBOTS_TXT: bool = True

    # --- Scope-Aware Request Firewall ---
    # Every outbound request the scanners make is checked here first. This
    # is deny-by-default: anything ambiguous, unresolvable, or not
    # explicitly matched by scope is blocked rather than allowed.
    SCOPE_FIREWALL_ENABLED: bool = True
    ALLOWED_SCHEMES: List[str] = ["http", "https"]
    ALLOWED_PORTS: List[int] = [80, 443]
    ALLOW_PRIVATE_NETWORKS: bool = False
    MAX_REDIRECTS: int = 5
    # DNS rebinding guard: resolve fresh at request time and re-check the
    # resolved IP, never trust a hostname-only decision made earlier.
    SCOPE_FIREWALL_DNS_TIMEOUT_SECONDS: float = 5.0

    @field_validator("ALLOWED_SCHEMES", mode="before")
    @classmethod
    def parse_allowed_schemes(cls, v: Any) -> Any:
        return _parse_str_list(v, ["http", "https"])

    @field_validator("ALLOWED_PORTS", mode="before")
    @classmethod
    def parse_allowed_ports(cls, v: Any) -> Any:
        raw = _parse_str_list(v, ["80", "443"])
        try:
            return [int(p) for p in raw]
        except (ValueError, TypeError):
            return [80, 443]

    # --- Recon tuning ---
    SUBDOMAIN_WORDLIST: str = str(BASE_DIR / "wordlists" / "subdomains.txt")
    DIRECTORY_WORDLIST: str = str(BASE_DIR / "wordlists" / "directories.txt")
    MAX_JS_FILES_PER_TARGET: int = 60
    MAX_URLS_PER_TARGET: int = 500
    MAX_SUBDOMAINS_TO_PROBE: int = 300

    # --- External tool binaries (optional; graceful fallback if missing) ---
    SUBFINDER_BIN: str = "subfinder"
    ASSETFINDER_BIN: str = "assetfinder"
    HTTPX_BIN: str = "httpx"
    KATANA_BIN: str = "katana"
    GAU_BIN: str = "gau"
    WAYBACKURLS_BIN: str = "waybackurls"
    HAKRAWLER_BIN: str = "hakrawler"
    NUCLEI_BIN: str = "nuclei"
    EXTERNAL_TOOL_TIMEOUT_SECONDS: int = 120
    ENABLE_NUCLEI_EXECUTION: bool = False  # template *suggestions* only by default

    # --- AI ---
    ANTHROPIC_API_KEY: str = Field(default="")
    AI_MODEL: str = "claude-sonnet-4-6"
    AI_MAX_TOKENS: int = 4000

    # --- Logging ---
    LOG_LEVEL: str = "INFO"
    LOG_DIR: str = str(BASE_DIR / "logs")


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    Path(settings.LOG_DIR).mkdir(parents=True, exist_ok=True)
    (BASE_DIR / "data").mkdir(parents=True, exist_ok=True)
    return settings


def get_cors_origins() -> List[str]:
    """Return CORS_ORIGINS as a parsed list, safe for any input format."""
    return _parse_str_list(get_settings().CORS_ORIGINS, _CORS_DEFAULTS)
