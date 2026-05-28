FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app \
    PORT=8000

WORKDIR /app

# System deps — curl for healthcheck, ca-certificates for TLS
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && adduser --disabled-password --gecos "" --home /home/ironclaw ironclaw

# ── Layer 1: install metadata only ──────────────────────────────────────────
# Copy only the files pip needs to resolve dependencies.
# This layer is cached until pyproject.toml or README.md changes,
# not on every source-code edit.
COPY pyproject.toml README.md ./

# ── Layer 2: install dependencies ───────────────────────────────────────────
# Install the package in editable mode with the docker extras group.
# --no-build-isolation keeps the build inside the image without extra tooling.
RUN python -m pip install --upgrade pip \
    && python -m pip install -e ".[docker]"

# ── Layer 3: application source ─────────────────────────────────────────────
# Copied last so dependency layers are not invalidated on code changes.
COPY . /app

# Export OpenAPI schema at build time so the locked schema is present in the image.
# Failure is non-fatal — an empty placeholder is written so startup does not break.
RUN python3 scripts/export_openapi.py --output /app/openapi.json \
    && echo "[docker-build] OpenAPI schema exported successfully" \
    || (echo "[docker-build] WARNING: OpenAPI export failed, continuing build" && touch /app/openapi.json)

RUN chown -R ironclaw:ironclaw /app

USER ironclaw

# Port must match uvicorn bind port in CMD below.
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl --fail --silent http://127.0.0.1:8000/api/health \
    || curl --fail --silent http://127.0.0.1:8000/api/health/liveness \
    || exit 1

# No secrets are accepted here. All runtime configuration is injected
# via environment variables at container start (see .env.example).
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]