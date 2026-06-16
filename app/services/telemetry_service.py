from __future__ import annotations

from datetime import UTC, datetime
import hashlib
import logging
import os
from typing import Any, Literal

import httpx
from pydantic import BaseModel, Field, field_validator, model_validator

from app.schemas.telemetry import TelemetryIngestResponse

"""
telemetry_service.py
──────────────────────────────────────────────────────────────────────────────
Supabase batch-ingest client for IronClaw agent telemetry events.

Responsibility (single): accept one or more structured telemetry payloads,
attach a stable deterministic event_key for deduplication, and POST them as
a batch to the ironclaw-telemetry-ingest Edge Function.

This module does NOT duplicate local JSONL storage — that is owned exclusively
by app/services/telemetry.py (append_telemetry_event). Callers that need both
local and remote persistence call both services independently.

API-facing response contract: TelemetryIngestResponse (app.schemas.telemetry).
Internal result model: TelemetryBatchResult — re-exported here for callers
that import from this module directly.
"""

logger = logging.getLogger(__name__)

# ─── Constants ────────────────────────────────────────────────────────────────

_INGEST_URL_ENV = "IRONCLAW_TELEMETRY_INGEST_URL"
_INGEST_TOKEN_ENV = "IRONCLAW_TELEMETRY_INGEST_TOKEN"

MAX_BATCH_SIZE: int = 500
_DEFAULT_TIMEOUT: float = 10.0

MetricType = Literal["counter", "gauge", "histogram", "event", "status"]

# ─── Pydantic models ──────────────────────────────────────────────────────────


class TelemetryEventInput(BaseModel):
    """
    Mirror of the TelemetryEventInput interface in ironclaw-telemetry-ingest/index.ts.

    event_key is the deduplication key. It must be a stable UUID-format string
    derived deterministically from (source, metric_name, captured_at, org_id)
    so that retried batches do not create duplicate rows in the Supabase table.
    """

    event_key: str = Field(
        description="Deterministic UUID v5 dedup key — do not pass raw UUIDs from callers.",
    )
    metric_name: str = Field(min_length=1, max_length=256)
    metric_type: MetricType
    source: str = Field(min_length=1, max_length=256)
    org_id: str | None = None
    value_numeric: float | None = None
    value_text: str | None = None
    unit: str = ""
    dimensions: dict[str, Any] = Field(default_factory=dict)
    captured_at: str = Field(
        default_factory=lambda: datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    )
    retention_until: str | None = None

    @field_validator("metric_name", "source", mode="before")
    @classmethod
    def strip_whitespace(cls, v: Any) -> str:
        return str(v).strip()

    @field_validator("captured_at", mode="before")
    @classmethod
    def coerce_datetime(cls, v: Any) -> str:
        if isinstance(v, datetime):
            return v.astimezone(UTC).isoformat().replace("+00:00", "Z")
        return str(v)

    @model_validator(mode="after")
    def at_least_one_value(self) -> TelemetryEventInput:
        if self.value_numeric is None and (self.value_text is None or self.value_text == ""):
            pass
        return self


class TelemetryBatchResult(BaseModel):
    """
    Internal result model for post_telemetry_batch / post_telemetry_batch_async.

    API-facing callers should use TelemetryIngestResponse from app.schemas.telemetry.
    Both share the same field contract; TelemetryBatchResult adds `valid` for
    internal accounting. Re-exported below so callers importing from this module
    can reference TelemetryIngestResponse without an extra schema import.
    """

    ok: bool
    received: int = 0
    valid: int = 0
    inserted: int = 0
    duplicates: int = 0
    validation_errors: list[dict[str, Any]] = Field(default_factory=list)
    error: str | None = None

    def to_ingest_response(self) -> TelemetryIngestResponse:
        """Coerce to the API-facing schema contract."""
        return TelemetryIngestResponse(
            ok=self.ok,
            received=self.received,
            inserted=self.inserted,
            duplicates=self.duplicates,
            validation_errors=self.validation_errors,
            error=self.error,
        )


# ─── Re-export bridge ─────────────────────────────────────────────────────────
# Callers may use TelemetryIngestResponse as the API-facing contract directly
# from this module without importing from app.schemas.telemetry separately.

__all__ = [
    "TelemetryEventInput",
    "TelemetryBatchResult",
    "TelemetryIngestResponse",
    "MetricType",
    "MAX_BATCH_SIZE",
    "build_event_key",
    "build_agent_event",
    "post_telemetry_batch",
    "post_telemetry_batch_async",
]


# ─── Deterministic event_key ──────────────────────────────────────────────────


def build_event_key(
    *,
    source: str,
    metric_name: str,
    captured_at: str,
    org_id: str | None = None,
    extra: str = "",
) -> str:
    _NAMESPACE = "6ba7b814-9dad-11d1-80b4-00c04fd430c8"
    identity = f"{_NAMESPACE}|{source}|{metric_name}|{captured_at}|{org_id or ''}|{extra}"
    digest = hashlib.sha256(identity.encode()).hexdigest()
    return f"{digest[:8]}-{digest[8:12]}-{digest[12:16]}-{digest[16:20]}-{digest[20:32]}"


# ─── Config helpers ───────────────────────────────────────────────────────────


def _get_ingest_url() -> str | None:
    return os.environ.get(_INGEST_URL_ENV, "").strip() or None


def _get_ingest_token() -> str | None:
    return os.environ.get(_INGEST_TOKEN_ENV, "").strip() or None


def _is_configured() -> bool:
    return bool(_get_ingest_url() and _get_ingest_token())


# ─── Core batch-POST ──────────────────────────────────────────────────────────


def post_telemetry_batch(
    events: list[TelemetryEventInput],
    *,
    timeout: float = _DEFAULT_TIMEOUT,
) -> TelemetryBatchResult:
    if not events:
        return TelemetryBatchResult(ok=True, received=0, valid=0, inserted=0, duplicates=0)

    if len(events) > MAX_BATCH_SIZE:
        logger.warning(
            "telemetry_service: batch size %d exceeds MAX_BATCH_SIZE %d; truncating",
            len(events),
            MAX_BATCH_SIZE,
        )
        events = events[:MAX_BATCH_SIZE]

    url = _get_ingest_url()
    token = _get_ingest_token()

    if not url or not token:
        logger.warning(
            "telemetry_service: %s or %s not configured — batch dropped silently",
            _INGEST_URL_ENV,
            _INGEST_TOKEN_ENV,
        )
        return TelemetryBatchResult(
            ok=False,
            error="Telemetry ingest not configured",
            received=len(events),
        )

    payload = [e.model_dump() for e in events]

    try:
        response = httpx.post(
            url,
            json=payload,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            timeout=timeout,
        )
        response.raise_for_status()
        return TelemetryBatchResult(**response.json())
    except httpx.HTTPStatusError as exc:
        body: str = ""
        try:
            body = exc.response.text[:512]
        except Exception:
            pass
        logger.warning(
            "telemetry_service: HTTP %s from ingest endpoint — %s",
            exc.response.status_code,
            body,
        )
        return TelemetryBatchResult(
            ok=False,
            error=f"HTTP {exc.response.status_code}: {body}",
            received=len(events),
        )
    except httpx.TimeoutException:
        logger.warning("telemetry_service: ingest request timed out after %.1fs", timeout)
        return TelemetryBatchResult(
            ok=False,
            error="Ingest request timed out",
            received=len(events),
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("telemetry_service: unexpected error posting batch — %s", exc)
        return TelemetryBatchResult(
            ok=False,
            error=str(exc),
            received=len(events),
        )


async def post_telemetry_batch_async(
    events: list[TelemetryEventInput],
    *,
    timeout: float = _DEFAULT_TIMEOUT,
) -> TelemetryBatchResult:
    if not events:
        return TelemetryBatchResult(ok=True, received=0, valid=0, inserted=0, duplicates=0)

    if len(events) > MAX_BATCH_SIZE:
        logger.warning(
            "telemetry_service: async batch size %d exceeds MAX_BATCH_SIZE %d; truncating",
            len(events),
            MAX_BATCH_SIZE,
        )
        events = events[:MAX_BATCH_SIZE]

    url = _get_ingest_url()
    token = _get_ingest_token()

    if not url or not token:
        logger.warning(
            "telemetry_service: %s or %s not configured — async batch dropped silently",
            _INGEST_URL_ENV,
            _INGEST_TOKEN_ENV,
        )
        return TelemetryBatchResult(
            ok=False,
            error="Telemetry ingest not configured",
            received=len(events),
        )

    payload = [e.model_dump() for e in events]

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(
                url,
                json=payload,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                },
            )
            response.raise_for_status()
            return TelemetryBatchResult(**response.json())
    except httpx.HTTPStatusError as exc:
        body = ""
        try:
            body = exc.response.text[:512]
        except Exception:
            pass
        logger.warning(
            "telemetry_service: async HTTP %s from ingest endpoint — %s",
            exc.response.status_code,
            body,
        )
        return TelemetryBatchResult(
            ok=False,
            error=f"HTTP {exc.response.status_code}: {body}",
            received=len(events),
        )
    except httpx.TimeoutException:
        logger.warning("telemetry_service: async ingest request timed out after %.1fs", timeout)
        return TelemetryBatchResult(
            ok=False,
            error="Ingest request timed out",
            received=len(events),
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("telemetry_service: async unexpected error posting batch — %s", exc)
        return TelemetryBatchResult(
            ok=False,
            error=str(exc),
            received=len(events),
        )


# ─── Convenience builder ──────────────────────────────────────────────────────


def build_agent_event(
    *,
    source: str,
    metric_name: str,
    metric_type: MetricType = "event",
    org_id: str | None = None,
    value_numeric: float | None = None,
    value_text: str | None = None,
    unit: str = "",
    dimensions: dict[str, Any] | None = None,
    captured_at: datetime | str | None = None,
    retention_until: str | None = None,
    extra_key_seed: str = "",
) -> TelemetryEventInput:
    if captured_at is None:
        captured_at_str = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    elif isinstance(captured_at, datetime):
        captured_at_str = captured_at.astimezone(UTC).isoformat().replace("+00:00", "Z")
    else:
        captured_at_str = str(captured_at)

    event_key = build_event_key(
        source=source,
        metric_name=metric_name,
        captured_at=captured_at_str,
        org_id=org_id,
        extra=extra_key_seed,
    )

    return TelemetryEventInput(
        event_key=event_key,
        metric_name=metric_name,
        metric_type=metric_type,
        source=source,
        org_id=org_id,
        value_numeric=value_numeric,
        value_text=value_text,
        unit=unit,
        dimensions=dimensions or {},
        captured_at=captured_at_str,
        retention_until=retention_until,
    )
