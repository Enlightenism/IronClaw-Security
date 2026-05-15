FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app \
    PORT=8000

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && adduser --disabled-password --gecos "" --home /home/ironclaw ironclaw

COPY requirements.txt /app/requirements.txt
RUN python -m pip install --upgrade pip \
    && python -m pip install -r /app/requirements.txt

COPY . /app

# Export OpenAPI schema during build to ensure locked schema is present in container
RUN python3 scripts/export_openapi.py --output /app/openapi.json \
    && echo "[docker-build] OpenAPI schema exported successfully" \
    || (echo "[docker-build] WARNING: OpenAPI export failed, continuing build" && touch /app/openapi.json)

RUN chown -R ironclaw:ironclaw /app

USER ironclaw

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl --fail --silent http://127.0.0.1:8000/health \
    || curl --fail --silent http://127.0.0.1:8000/health/liveness \
    || exit 1

CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]