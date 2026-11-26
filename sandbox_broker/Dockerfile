# Scanner image run once per agent return by the host sandbox broker.
# Pinned to the python:3.12-slim index digest. Refresh the digest deliberately, never by tag alone.
FROM python:3.12-slim@sha256:b18b261e1b4974b4f321451ad5251ded85abb22c2b8b262da527dda1d031ab30

ARG SCANNER_VERSION=1
ARG PROMPT_GUARD_MODEL_VERSION=86m

LABEL org.ironclaw.scanner-version="${SCANNER_VERSION}" \
      org.ironclaw.prompt-guard-model="prompt-guard-${PROMPT_GUARD_MODEL_VERSION}" \
      org.ironclaw.prompt-guard-min-model="${PROMPT_GUARD_MODEL_VERSION}" \
      org.ironclaw.fail-closed="true"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN python -m pip install --no-cache-dir \
    "torch==2.6.0" \
    "transformers==4.51.3" \
    "tokenizers==0.21.1" \
    "sentencepiece==0.2.0" \
    "safetensors==0.5.3" \
    "numpy==2.2.4"

WORKDIR /opt/scanner
COPY sandbox_broker/scanner.py /opt/scanner/scanner.py
COPY sandbox_broker/security_rules.json /opt/scanner/security_rules.json
COPY sandbox_broker/policy_snapshot.json /opt/scanner/policy_snapshot.json
COPY models/prompt-guard-86m /opt/ironclaw/models/prompt-guard-86m

USER 65532:65532

ENTRYPOINT ["python", "-I", "/opt/scanner/scanner.py"]
