# Scanner image run once per agent return by the host sandbox broker.
# Pinned to the python:3.12-slim index digest. Refresh the digest deliberately, never by tag alone.
FROM python:3.12-slim@sha256:b18b261e1b4974b4f321451ad5251ded85abb22c2b8b262da527dda1d031ab30

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /opt/scanner
COPY scanner.py /opt/scanner/scanner.py

USER 65532:65532

ENTRYPOINT ["python", "-I", "/opt/scanner/scanner.py"]
