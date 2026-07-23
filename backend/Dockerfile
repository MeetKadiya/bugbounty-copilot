# --- Backend Dockerfile (fast local dev) ---
# Skips the optional Go-based recon tools (subfinder, httpx, katana, nuclei,
# assetfinder, gau, waybackurls, hakrawler) entirely. The app's pure-Python
# fallbacks / heuristic engine cover everything needed for local development,
# and this cuts the image build from 10-20+ minutes down to well under a
# minute on a warm pip cache.
#
# Need the native recon binaries for a real deployment? Build from
# Dockerfile.full instead:
#   docker build -f backend/Dockerfile.full -t bugbounty-copilot-backend:full ./backend

FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install Python deps first so this layer is cached unless requirements.txt changes
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/data /app/logs

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
