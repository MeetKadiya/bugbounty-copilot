<#
.SYNOPSIS
    Bug Bounty Copilot -- first-run setup for Windows (PowerShell).

.DESCRIPTION
    1. Checks that Docker Desktop / the Docker Compose plugin are available
       and that the Docker daemon is actually running.
    2. Creates backend\.env from backend\.env.example if it doesn't exist yet
       (never overwrites an existing .env).
    3. Runs `docker compose up --build`.

    Safe to re-run any time.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\setup.ps1
#>

$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

function Write-Info($msg)  { Write-Host "==> $msg" -ForegroundColor Cyan }
function Write-Ok($msg)    { Write-Host "[OK] $msg" -ForegroundColor Green }
function Write-WarnMsg($msg) { Write-Host "[WARN] $msg" -ForegroundColor Yellow }
function Write-Fail($msg)  { Write-Host "[ERROR] $msg" -ForegroundColor Red; exit 1 }

Write-Host "Bug Bounty Copilot -- setup"
Write-Host "==========================="
Write-Host ""
# 1. Docker present?
Write-Info "Checking for Docker..."
$dockerCmd = Get-Command docker -ErrorAction SilentlyContinue
if (-not $dockerCmd) {
    Write-Fail "Docker was not found on PATH. Install Docker Desktop from https://www.docker.com/products/docker-desktop/ and re-run this script."
}
$dockerVersion = (docker --version)
Write-Ok "Docker is installed ($dockerVersion)."

# 2. Docker Compose v2 plugin present?
Write-Info "Checking for Docker Compose..."
docker compose version *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Fail "The 'docker compose' plugin (Compose v2) is required but was not found. Update Docker Desktop, then re-run this script."
}
Write-Ok "Docker Compose is available."

# 3. Daemon actually running?
Write-Info "Checking that the Docker daemon is running..."
docker info *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Fail "Docker is installed but the daemon isn't running. Start Docker Desktop and re-run this script."
}
Write-Ok "Docker daemon is running."

# 4. Create backend\.env if missing (never overwrite an existing one)
Write-Info "Checking backend\.env..."
$envPath = Join-Path $PSScriptRoot "backend\.env"
$envExamplePath = Join-Path $PSScriptRoot "backend\.env.example"

if (Test-Path $envPath) {
    Write-Ok "backend\.env already exists -- leaving it untouched."
} else {
    if (-not (Test-Path $envExamplePath)) {
        Write-Fail "backend\.env.example is missing from the repository -- cannot create backend\.env."
    }
    Copy-Item -Path $envExamplePath -Destination $envPath
    Write-Ok "Created backend\.env from backend\.env.example (safe defaults; no secrets)."
    Write-WarnMsg "Edit backend\.env if you want to add an ANTHROPIC_API_KEY for AI-powered analysis. Not required to run the app."
}

Write-Host ""
Write-Info "Building and starting containers (this can take a few minutes on first run)..."
Write-Host ""

docker compose up --build
if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Fail "docker compose up --build failed. Run 'docker compose logs' for details, and see the Troubleshooting section in README.md."
}
