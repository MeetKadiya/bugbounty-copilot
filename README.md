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
  - **Parameter classifier**: token-based heuristics (not naive substring matching, so `hourly` is never mistaken for containing `url`) group parameters into Object Identifier, URL-Related, Privilege-Related, File-Related, and Sensitive categories, each labeled `interesting`, `potentially sensitive`, or `requires review` — never a confirmed vulnerability.
  - **OWASP-oriented signals** (all `potential...`, all heuristic): BOLA/IDOR, broken function-level authorization, excessive data exposure, SSRF-related input, open redirect, mass-assignment input, and file-upload surface.
  - **Confidence score (0–100) + risk level (High/Medium/Low) + human-readable reasons** for every normalized endpoint, so a researcher can sort and triage instead of reading a raw endpoint dump.
  - Retrieval API: `GET /api/v1/scans/{scan_id}/endpoint-intelligence`, filterable by `hostname`, `method`, `category`, `risk`, `min_confidence`, `parameter`, and `vulnerability_class`.
  - Frontend: an **Endpoint Intelligence** panel on the dashboard with filters and an expandable card per normalized endpoint (parameters, categories, potential concerns, confidence, reasons).
  - Does not perform exploitation, brute forcing, or authentication bypass, and never issues a network request itself — it's pure analysis over data the existing scanners already collected under the existing scope/rate-limit controls.
- **AI analysis** — Claude-powered (or a deterministic heuristic fallback with zero API key needed) vulnerability-class suggestions (IDOR, XSS, SSRF, SQLi, Open Redirect, SSTI, XXE, File Upload, CSRF, CORS…) with confidence + reasoning + a safe manual next step.
- **Explainable Attack Surface Risk Score** (0–100) — a transparent heuristic, not a black box.
- **Dark cyber-themed dashboard**: overview cards, live scan progress, asset graph, subdomain table, endpoint/parameter explorers, **Endpoint Intelligence panel**, secrets panel, tech stack, AI recommendations, risk gauge, JSON/Markdown export.
- **Every external recon tool is optional.** If a binary (`subfinder`, `httpx`, `katana`, etc.) isn't installed, the app transparently falls back to a pure-Python implementation — nothing ever breaks because a tool is missing.
- **Subdomain takeover detection** — passive CNAME + HTTP-fingerprint checks against 30+ known de-provisioned-service patterns (S3, Azure, Heroku, GitHub Pages, Shopify, Netlify, and more). Never claims a resource — flags it for manual verification only.
- **Program scope upload** — paste a bug bounty program's official scope doc (one rule per line, `*.example.com` / `!internal.example.com` supported) and every discovered asset gets checked against it and flagged in/out of scope instead of a loose root-domain guess.
- **Historical diffing** — every scan of a target is compared against its predecessor: new/removed subdomains, new/removed endpoints, tech stack changes, rotated secrets, and new takeover candidates, plus a risk-score delta. This is what turns one-off recon into ongoing bug-bounty monitoring.

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
│   │   ├── config.py           centralized settings (.env driven)
│   │   ├── database.py, logging_config.py, main.py
│   ├── tests/                 pytest unit tests (scope, risk score, secrets, API, endpoint intelligence)
│   ├── wordlists/              subdomain & directory wordlists
│   ├── requirements.txt, Dockerfile, .env.example, pytest.ini
├── frontend/                 React 18 + TypeScript + Tailwind (Vite)
│   ├── src/
│   │   ├── components/         Dashboard building blocks
│   │   ├── pages/Dashboard.tsx
│   │   ├── api/client.ts       typed axios client
│   │   ├── types/index.ts
│   ├── Dockerfile, nginx.conf
├── docker-compose.yml
├── README.md / LICENSE / .gitignore
```

**Why this design:**
- **Modular scanners** — each stage is a `BaseScanner` subclass with one job. Add a new one, append it to `STAGES` in `orchestrator/pipeline.py`, done.
- **Graceful degradation** — every optional binary has a real Python fallback, so the tool works identically inside Docker (with tools installed) or on a bare `pip install` (without them).
- **Safety by construction** — `core/scope.py` is the single choke point every scanner passes through; `config.ALLOW_ACTIVE_RECON` lets you switch to passive-only OSINT; rate limiting + bounded concurrency in `utils/http_client.py` keep active checks non-intrusive; the AI system prompt explicitly forbids suggesting exploitation.
- **asyncio background pipeline** — no Redis/Celery dependency required to run end-to-end; the task-queue interface is Celery-shaped so it's a drop-in swap later if you need multi-worker scaling.

---

## 🚀 Quick Start (Docker — recommended)

```bash
cd I:\BUGBOUNTY-COPILOT
cp backend/.env.example backend/.env
# (optional) edit backend/.env and add ANTHROPIC_API_KEY for AI-powered analysis
docker compose up --build
```

- Frontend: http://localhost:5173
- Backend API docs: http://localhost:8000/docs

## 🧑‍💻 Local Dev (without Docker)

**Backend:**
```bash
cd backend
python -m venv .venv
.venv\Scripts\activate        # Windows
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload
```

**Frontend:**
```bash
cd frontend
npm install
npm run dev
```

## 🧪 Running Tests
```bash
cd backend
pytest
```

---

## ⚙️ Configuration

All settings live in `backend/.env` (see `.env.example`). Key safety flags:

| Variable | Purpose |
|---|---|
| `ALLOW_ACTIVE_RECON` | `false` = passive OSINT only (crt.sh, no probing/brute-force) |
| `MAX_CONCURRENT_REQUESTS` / `RATE_LIMIT_PER_HOST_RPS` | bound request volume against any single host |
| `ANTHROPIC_API_KEY` | enables Claude-powered analysis; leave blank to use the built-in heuristic engine |
| `ENABLE_NUCLEI_EXECUTION` | stays `false` by default — nuclei is used for **template suggestions only** |

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

## 🗺️ Extending

Add a new scanner in three steps:
1. Create `backend/app/scanners/my_scanner.py` subclassing `BaseScanner`.
2. Implement `async def run(self, target_domain, context) -> dict`.
3. Add `("My Stage Label", MyScanner())` to `STAGES` in `orchestrator/pipeline.py`.

---

## 📄 License

MIT — see [LICENSE](./LICENSE). Includes a responsible-use notice.
