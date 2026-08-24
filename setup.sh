#!/usr/bin/env bash
# Bug Bounty Copilot -- first-run setup for Linux / macOS.
#
# What this does:
#   1. Checks that Docker and the Docker Compose plugin are available and
#      that the Docker daemon is actually running.
#   2. Creates backend/.env from backend/.env.example if it doesn't exist yet
#      (never overwrites an existing .env).
#   3. Runs `docker compose up --build`.
#
# Safe to re-run any time -- it never touches an existing backend/.env and
# `docker compose up --build` is idempotent.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

BOLD="\033[1m"
GREEN="\033[32m"
YELLOW="\033[33m"
RED="\033[31m"
RESET="\033[0m"

info()  { echo -e "${BOLD}==>${RESET} $1"; }
ok()    { echo -e "${GREEN}[OK]${RESET} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${RESET} $1"; }
fail()  { echo -e "${RED}[ERROR]${RESET} $1"; exit 1; }

echo "Bug Bounty Copilot -- setup"
echo "==========================="
echo
# 1. Docker present?
info "Checking for Docker..."
if ! command -v docker >/dev/null 2>&1; then
  fail "Docker was not found on PATH. Install Docker Desktop (macOS) or Docker Engine (Linux) from https://docs.docker.com/get-docker/ and re-run this script."
fi
ok "Docker is installed ($(docker --version))."

# 2. Docker Compose v2 plugin present?
info "Checking for Docker Compose..."
if ! docker compose version >/dev/null 2>&1; then
  fail "The 'docker compose' plugin (Compose v2) is required but was not found. Update Docker Desktop / Docker Engine, then re-run this script."
fi
ok "Docker Compose is available ($(docker compose version --short 2>/dev/null || echo 'v2'))."

# 3. Daemon actually running?
info "Checking that the Docker daemon is running..."
if ! docker info >/dev/null 2>&1; then
  fail "Docker is installed but the daemon isn't running. Start Docker Desktop (or 'sudo systemctl start docker' on Linux) and re-run this script."
fi
ok "Docker daemon is running."

# 4. Create backend/.env if missing (never overwrite an existing one)
info "Checking backend/.env..."
if [ -f "backend/.env" ]; then
  ok "backend/.env already exists -- leaving it untouched."
else
  if [ ! -f "backend/.env.example" ]; then
    fail "backend/.env.example is missing from the repository -- cannot create backend/.env."
  fi
  cp "backend/.env.example" "backend/.env"
  ok "Created backend/.env from backend/.env.example (safe defaults; no secrets)."
  warn "Edit backend/.env if you want to add an ANTHROPIC_API_KEY for AI-powered analysis. Not required to run the app."
fi

echo
info "Building and starting containers (this can take a few minutes on first run)..."
echo

if docker compose up --build; then
  :
else
  echo
  fail "docker compose up --build failed. Run 'docker compose logs' for details, and see the Troubleshooting section in README.md."
fi
