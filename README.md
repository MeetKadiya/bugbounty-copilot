# 🛡️ Bug Bounty Copilot

An **AI-powered reconnaissance assistant** for authorized security researchers.
It automates the tedious parts of recon — subdomain enumeration, live-host
probing, endpoint/parameter/secret discovery, tech fingerprinting — then uses
an AI analysis layer to summarize the attack surface and suggest **where a
human should look next**.

> ⚠️ **This is an assistant, not an autonomous hacker.** It never exploits
> vulnerabilities or performs intrusive/destructive actions. Every output is a
> *suggestion* for a human researcher to manually verify. Only use this against
> domains you own or are explicitly authorized to test (bug bounty programs,
> owned assets, lab environments).

---
## ✨ Features

- **Target input & scope validation** — accepts a domain or wildcard (`*.example.com`), rejects raw IPs/localhost/internal ranges before any request is made.
- **Modular recon pipeline** (11 stages, each independently swappable):
  1. Subdomain enumeration (subfinder / assetfinder / crt.sh / DNS brute-force fallback)
  2. Live host probing
  3. WAF/CDN detection
  4. HTTP headers & technology collection
  5. Directory/endpoint discovery
  6. JavaScript crawling (katana / gau / waybackurls / hakrawler / pure-Python fallback)
  7. API endpoint extraction
  8. Framework fingerprinting
  9. Parameter extraction
  10. Endpoint Intelligence Engine (see below)
  11. Secret detection (AWS, GCP, Firebase, JWT, Slack, Stripe, GitHub tokens, private keys, basic-auth URLs — all redacted)
- **Endpoint Intelligence Engine** — turns raw discovered URLs/endpoints into structured, security-relevant intelligence for manual triage:
  - **Normalization**: collapses endpoints that only differ by an identifier into one path template, e.g. `/api/users/1`, `/api/users/2`, `/api/users/100` → `/api/users/{id}` (numeric, UUID, Mongo-style, hex, and alphanumeric-slug IDs all recognized).
  - **Parameter classifier**: token-based heuristics group parameters into Object Identifier, URL-Related, Privilege-Related, File-Related, and Sensitive categories, each labeled `interesting`, `potentially sensitive`, or `requires review` — never a confirmed vulnerability.
  - **OWASP-oriented signals** (all `potential...`, all heuristic): BOLA/IDOR, broken function-level authorization, excessive data exposure, SSRF-related input, open redirect, mass-assignment input, and file-upload surface.
  - **Confidence score (0–100) + risk level (High/Medium/Low) + human-readable reasons** for every normalized endpoint.
  - Retrieval API: `GET /api/v1/scans/{scan_id}/endpoint-intelligence`, filterable by `hostname`, `method`, `category`, `risk`, `min_confidence`, `parameter`, and `vulnerability_class`.
  - Does not perform exploitation, brute forcing, or authentication bypass, and never issues a network request itself.
- **AI analysis** — Claude-powered (or a deterministic heuristic fallback with zero API key needed) vulnerability-class suggestions (IDOR, XSS, SSRF, SQLi, Open Redirect, SSTI, XXE, File Upload, CSRF, CORS…) with confidence + reasoning + a safe manual next step.
- **Explainable Attack Surface Risk Score** (0–100) — a transparent heuristic, not a black box.
- **Dark cyber-themed dashboard**: overview cards, live scan progress, asset graph, subdomain table, endpoint/parameter explorers, Endpoint Intelligence panel, secrets panel, tech stack, AI recommendations, risk gauge, JSON/Markdown export.
- **Every external recon tool is optional.** If a binary (`subfinder`, `httpx`, `katana`, etc.) isn't installed, the app transparently falls back to a pure-Python implementation — nothing ever breaks because a tool is missing.
- **Subdomain takeover detection** — passive CNAME + HTTP-fingerprint checks against 30+ known de-provisioned-service patterns. Never claims a resource — flags it for manual verification only.
- **Program scope upload** — paste a bug bounty program's official scope doc and every discovered asset gets checked against it.
- **Historical diffing** — every scan of a target is compared against its predecessor: new/removed subdomains, new/removed endpoints, tech stack changes, rotated secrets, new takeover candidates, plus a risk-score delta.

---
## 🏗️ Architecture

```
BUGBOUNTY-COPILOT/
├── backend/                 FastAPI + SQLite + asyncio background pipeline
│   ├── app/
│   │   ├── api/              REST routes (targets, scans, findings, endpoint-intelligence, export)
│   │   ├── core/              scope validation, risk scoring
│   │   ├── scanners/          11 modular scanner classes (BaseScanner subclasses)
│   │   ├── intelligence/      Endpoint Intelligence Engine (normalizer, parameter_classifier, endpoint_intelligence)
│   │   ├── ai/                Claude analysis + prompts + heuristic fallback
│   │   ├── orchestrator/      pipeline.py (stage runner) + task_queue.py (asyncio)
│   │   ├── models.py           SQLAlchemy ORM models
│   │   ├── schemas.py          Pydantic schemas
│   │   ├── config.py           centralized settings (env-driven, safe defaults)
│   │   ├── database.py, logging_config.py, main.py
│   ├── tests/                 pytest unit tests (scope, risk score, secrets, API, endpoint intelligence)
│   ├── wordlists/              subdomain & directory wordlists
│   ├── requirements.txt, Dockerfile, Dockerfile.full, .env.example, .dockerignore, pytest.ini
├── frontend/                 React 18 + TypeScript + Tailwind (Vite)
│   ├── src/
│   │   ├── components/         Dashboard building blocks
│   │   ├── pages/Dashboard.tsx
│   │   ├── api/client.ts       typed axios client (relative /api/v1 base URL)
│   │   ├── types/index.ts
│   ├── Dockerfile, nginx.conf, package-lock.json, .dockerignore
├── docker-compose.yml
├── setup.sh                  first-run setup for Linux / macOS
├── setup.ps1                 first-run setup for Windows (PowerShell)
├── README.md / LICENSE / .gitignore
```

**Why this design:**
- **Modular scanners** — each stage is a `BaseScanner` subclass with one job. Add a new one, append it to `STAGES` in `orchestrator/pipeline.py`, done.
- **Graceful degradation** — every optional binary has a real Python fallback, so the tool works identically inside Docker (with tools installed) or on a bare `pip install` (without them).
- **Safety by construction** — `core/scope.py` is the single choke point every scanner passes through; `config.ALLOW_ACTIVE_RECON` lets you switch to passive-only OSINT; rate limiting + bounded concurrency in `utils/http_client.py` keep active checks non-intrusive; the AI system prompt explicitly forbids suggesting exploitation.
- **Zero required configuration** — every setting in `app/config.py` has a safe default (via `pydantic-settings`). The app starts and runs fully without a `.env` file at all; `.env` only lets you *override* a default (e.g. add an API key), it is never required.
- **asyncio background pipeline** — no Redis/Celery dependency required to run end-to-end.

---
## ✅ Requirements

| Platform | You need |
|---|---|
| Windows 10/11 | [Docker Desktop](https://www.docker.com/products/docker-desktop/) (includes Compose v2), Git, PowerShell (built in) |
| macOS | [Docker Desktop](https://www.docker.com/products/docker-desktop/) (includes Compose v2), Git |
| Linux | [Docker Engine](https://docs.docker.com/engine/install/) + the [Compose plugin](https://docs.docker.com/compose/install/linux/), Git |

Docker Desktop on Windows/macOS bundles Compose v2 automatically. On Linux, `docker compose version` should print a v2.x version — if it prints "command not found", install the `docker-compose-plugin` package.

No local Python or Node.js install is required for the Docker workflow — everything runs inside containers. Python 3.11+ and Node.js 20+ are only needed for the [local (non-Docker) dev workflow](#-local-dev-without-docker).

---

## 🚀 Quick Start (Docker — recommended)

This works identically on a machine that has **nothing installed except Docker and Git**. No manual `.env` file is required — the app ships with safe defaults and starts without one.

**Linux / macOS:**
```bash
git clone https://github.com/MeetKadiya/bugbounty-copilot.git
cd bugbounty-copilot
./setup.sh
```

**Windows (PowerShell):**
```powershell
git clone https://github.com/MeetKadiya/bugbounty-copilot.git
cd bugbounty-copilot
powershell -ExecutionPolicy Bypass -File .\setup.ps1
```

Both scripts: verify Docker is installed and running, create `backend/.env` from `backend/.env.example` **only if it doesn't already exist** (never overwrites your settings), then run `docker compose up --build`.

**Don't want to use the script?** It's just a convenience wrapper — this works everywhere too:
```bash
git clone https://github.com/MeetKadiya/bugbounty-copilot.git
cd bugbounty-copilot
docker compose up --build
```
You can skip the `.env` copy step entirely — the app runs with safe development defaults out of the box. Only create `backend/.env` (copied from `backend/.env.example`) if you want to override something, e.g. add an `ANTHROPIC_API_KEY`.

Once it's up:
- **Frontend:** http://localhost:5173
- **Backend API docs (Swagger):** http://localhost:8000/docs
- **Backend health check:** http://localhost:8000/health

Press `Ctrl+C` to stop. Run `docker compose up --build` again any time to restart — your scan history persists in a named Docker volume (see [SQLite / Data Persistence](#-sqlite--data-persistence)).

---

## 🧑‍💻 Local Dev (without Docker)

Useful for fast iteration on backend or frontend code. Requires Python 3.11+ and Node.js 20+ installed locally.

**Backend:**
```bash
cd backend
python -m venv .venv

# activate the venv:
source .venv/bin/activate        # Linux / macOS
.venv\Scripts\Activate.ps1       # Windows PowerShell
.venv\Scripts\activate.bat       # Windows cmd.exe

pip install -r requirements.txt
uvicorn app.main:app --reload
```
No `.env` file is required to run the backend — it starts with safe defaults. Copy `backend/.env.example` to `backend/.env` only if you want to change a setting (e.g. add an `ANTHROPIC_API_KEY`).

**Frontend:**
```bash
cd frontend
npm install
npm run dev
```
The Vite dev server proxies `/api` requests to `http://localhost:8000`, so run the backend first (or alongside).

---
## 🧪 Running Tests

```bash
cd backend
pip install -r requirements.txt   # if not already installed
pytest
```
All 61 backend tests should pass with no `.env` file present — the suite runs entirely against safe defaults.

---

## ⚙️ Environment Variables

All settings live in `backend/.env` (copied from `backend/.env.example`) and every single one has a working default — **none are required to launch the app**.

| Variable | Default | Purpose |
|---|---|---|
| `ENV` | `development` | Environment label, logged at startup. |
| `DEBUG` | `true` | FastAPI debug behavior. |
| `HOST` / `PORT` | `0.0.0.0` / `8000` | Backend bind address. |
| `CORS_ORIGINS` | `["http://localhost:5173","http://localhost:3000"]` | Allowed frontend origins. |
| `DATABASE_URL` | `sqlite+aiosqlite:///./data/bugbounty.db` | SQLite connection string; auto-created on first run. |
| `ALLOW_ACTIVE_RECON` | `true` | `false` = passive OSINT only (crt.sh, no probing/brute-force). |
| `MAX_CONCURRENT_REQUESTS` / `RATE_LIMIT_PER_HOST_RPS` | `20` / `5.0` | Bound request volume against any single host. |
| `REQUEST_TIMEOUT_SECONDS` | `10` | Per-request HTTP timeout. |
| `ANTHROPIC_API_KEY` | *(blank)* | **Genuinely optional.** Leave blank to use the built-in deterministic heuristic analysis engine — the app is fully functional without this. Set it to enable Claude-powered analysis. |
| `AI_MODEL` | `claude-sonnet-4-6` | Model used when `ANTHROPIC_API_KEY` is set. |
| `ENABLE_NUCLEI_EXECUTION` | `false` | Stays `false` by default — nuclei is used for template *suggestions* only, never auto-executed. |
| `LOG_LEVEL` | `INFO` | Logging verbosity. |

**Never commit `backend/.env`** — it's gitignored on purpose. Only `backend/.env.example` (which contains no real secrets) is tracked in Git.

---
## 🛠️ Optional Recon Tools

Several scanner stages can optionally shell out to native Go-based recon binaries (`subfinder`, `httpx`, `katana`, `nuclei`, `assetfinder`, `gau`, `waybackurls`, `hakrawler`) for higher-fidelity results. **None of them are required.** Every scanner detects tool availability at runtime (`shutil.which`) and transparently falls back to a pure-Python implementation if a binary is missing — the backend never crashes or fails to start because a tool is absent.

- **`docker compose up --build`** (default) builds the backend from `backend/Dockerfile`, which **skips** these native tools entirely and relies purely on the Python fallbacks. This keeps the image build under a minute and is what most users want.
- **Need the native binaries** (e.g. for a closer-to-production deployment)? Build from `backend/Dockerfile.full` instead, which best-effort compiles all 8 Go tools (10–20+ min build, network-dependent, never fails the build if a tool can't compile):
  ```bash
  docker build -f backend/Dockerfile.full -t bugbounty-copilot-backend:full ./backend
  ```
  Then either run that image directly, or point `docker-compose.yml`'s `backend.build.dockerfile` at `Dockerfile.full` and rebuild.

---

## 💾 SQLite / Data Persistence

- The backend uses SQLite (`aiosqlite`), stored at `/app/data/bugbounty.db` inside the container.
- `docker-compose.yml` mounts two **named Docker volumes** — `backend_data` (the database) and `backend_logs` — so your scan history and logs **survive container restarts and rebuilds** (`docker compose down` + `docker compose up --build` will not delete your data).
- To wipe all data and start completely fresh:
  ```bash
  docker compose down -v
  ```
  (the `-v` flag removes the named volumes — omit it to keep your data).
- The database schema is created automatically on backend startup (`init_db()` in `app/database.py`) — no manual migration step is needed on a fresh install.

---

## 🔒 Security Notes

- No secrets, API keys, or credentials are committed to this repository. `backend/.env` is gitignored; only `backend/.env.example` (blank/placeholder values) is tracked.
- CORS is restricted to explicit origins (`CORS_ORIGINS`), not a wildcard.
- All external recon tool invocations use `asyncio.create_subprocess_exec` with an argument list (never `shell=True`, never string-interpolated shell commands) — command injection is not possible through this path.
- `core/scope.py` rejects raw IPs, `localhost`, and internal/reserved hostnames before any scan request is made.
- Containers run the official `python:3.11-slim` and `nginx:alpine` base images with no added privileged flags, capabilities, or host mounts beyond the two named data volumes above.
- `ENABLE_NUCLEI_EXECUTION` defaults to `false` — nuclei is used for template suggestions only, never auto-executed against a target.

---
## 🔒 Responsible Use

This tool is built for the **reconnaissance and triage** phase of authorized
security testing only:

- It never sends exploit payloads.
- It never attempts authentication bypass, brute-force login, or data exfiltration.
- Secrets are always redacted before storage/display.
- All AI-generated "findings" are **suggestions requiring manual human verification** — never treat them as confirmed vulnerabilities.
- Always follow the scope and rules of engagement defined by the bug bounty program or written authorization you're operating under.

---

## 🧯 Troubleshooting

**Docker daemon isn't running**
> `Cannot connect to the Docker daemon...` — Start Docker Desktop (Windows/macOS) or `sudo systemctl start docker` (Linux), then retry.

**Port already in use (`5173` or `8000`)**
> Another process is using the port. Stop it, or change the host-side port in `docker-compose.yml`, e.g. `"5174:80"` for the frontend.

**Missing `backend/.env`**
> Not an error — the app runs with safe defaults without it. Run `./setup.sh` / `setup.ps1`, or manually copy `backend/.env.example` to `backend/.env` if you want to customize settings.

**Frontend can't reach the backend**
> Confirm both containers are healthy: `docker compose ps`. In Docker, the frontend's nginx proxies `/api/` to `http://backend:8000` using the Compose service name — never `localhost` (container-to-container traffic can't use `localhost`). If you're running the frontend outside Docker (`npm run dev`), make sure the backend is running on `localhost:8000` (the Vite dev proxy target).

**Backend container exits immediately**
> Check the logs: `docker compose logs backend`. Common causes: a syntax error in a manually-edited `backend/.env`, or a port conflict on 8000.

**Dependency installation failure during build**
> Usually a transient network issue reaching PyPI/npm. Retry with `docker compose build --no-cache backend` or `... frontend`.

**Database initialization failure**
> Delete the volume and let it re-create: `docker compose down -v && docker compose up --build`.

**Docker build cache problems / stale build**
> `docker compose build --no-cache` forces a clean rebuild of both images.

**Permission problems (Linux)**
> If Docker requires `sudo` on your system, either run commands with `sudo` or add your user to the `docker` group: `sudo usermod -aG docker $USER` (log out/in afterward).

**Optional recon tool unavailable**
> Expected with the default `backend/Dockerfile` — see [Optional Recon Tools](#-optional-recon-tools). The affected scanner stage automatically falls back to its Python implementation; nothing crashes.

**Windows PowerShell issues (script won't run)**
> If you see `... cannot be loaded because running scripts is disabled`, run:
> ```powershell
> powershell -ExecutionPolicy Bypass -File .\setup.ps1
> ```
> This does not change your system-wide execution policy.

**Windows: `npm run build` fails locally with a `tsc` error even though the project is fine**
> If your global npm config has `omit=dev` set (check with `npm config list -l`), `npm install` silently skips `devDependencies` — including `typescript` and `vite` — so `tsc`/`vite` won't be found. This does **not** affect the Docker build (the container's `npm ci` never sees your host's global npm config). To build locally anyway: `npm install --include=dev`, or find and remove `omit=dev` from your `.npmrc` (`npm config get globalconfig` shows its location).

**Useful diagnostic commands:**
```bash
docker compose ps
docker compose logs
docker compose logs backend
docker compose logs frontend
docker compose down -v && docker compose up --build   # full reset
```

---

## 🗺️ Extending

Add a new scanner in three steps:
1. Create `backend/app/scanners/my_scanner.py` subclassing `BaseScanner`.
2. Implement `async def run(self, target_domain, context) -> dict`.
3. Add `("My Stage Label", MyScanner())` to `STAGES` in `orchestrator/pipeline.py`.

---

## 📄 License

MIT — see [LICENSE](./LICENSE). Includes a responsible-use notice.
