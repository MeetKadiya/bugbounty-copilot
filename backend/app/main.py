"""FastAPI application entrypoint."""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import (
    routes_endpoint_intelligence, routes_export, routes_findings, routes_scans, routes_targets,
)
from app.config import get_settings
from app.database import init_db
from app.logging_config import configure_logging, get_logger

settings = get_settings()
configure_logging()
logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting %s (env=%s)", settings.APP_NAME, settings.ENV)
    await init_db()
    yield
    logger.info("Shutting down %s", settings.APP_NAME)


app = FastAPI(
    title=settings.APP_NAME,
    description=(
        "An AI-powered Bug Bounty Copilot. Passive/active reconnaissance assistant "
        "for authorized security research. This tool NEVER exploits vulnerabilities "
        "-- it only collects, correlates, and explains publicly observable data, "
        "keeping a human researcher fully in control of every decision."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(routes_targets.router, prefix=settings.API_V1_PREFIX)
app.include_router(routes_scans.router, prefix=settings.API_V1_PREFIX)
app.include_router(routes_findings.router, prefix=settings.API_V1_PREFIX)
app.include_router(routes_endpoint_intelligence.router, prefix=settings.API_V1_PREFIX)
app.include_router(routes_export.router, prefix=settings.API_V1_PREFIX)


@app.get("/")
async def root():
    return {"app": settings.APP_NAME, "status": "ok", "docs": "/docs"}


@app.get("/health")
async def health():
    return {"status": "healthy"}
