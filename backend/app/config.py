"""
Centralized configuration for Bug Bounty Copilot.

All tunables live here and are overridable via environment variables / .env file.
This keeps the "assistant only, never intrusive" posture configurable but
defaults are intentionally conservative.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import List

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # --- App ---
    APP_NAME: str = "Bug Bounty Copilot"
    ENV: str = "development"
    DEBUG: bool = True
    API_V1_PREFIX: str = "/api/v1"

    # --- Server ---
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    CORS_ORIGINS: List[str] = ["http://localhost:5173", "http://localhost:3000"]

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
