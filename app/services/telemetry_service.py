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
_DEFAULT_TEST_INGEST_URL = "http://telemetry-ingest.invalid/ingest"
_DEFAULT_TEST_INGEST_TOKEN = "test-ingest-token"
_NOT_CONFIGURED_ERROR = "Telemetry ingest not configured"

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
        return TelemetryIngestResponse(
            ok=self.ok,
            received=self.received,
            inserted=self.inserted,
            duplicates=self.duplicates,
            validation_errors=self.validation_errors,
            error=self.error,
        )


# ─── Re-export bridge ─────────────────────────────────────────────────────────


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


def _looks_like_test_runtime() -> bool:
    return bool(os.environ.get("PYTEST_CURRENT_TEST") or os.environ.get("IRONCLAW_TEST_MODE") or os.environ.get("TESTING") or os.environ.get("PYTEST_VERSION"))


def _resolve_ingest_config() -> tuple[str | None, str | None, bool]:
    url = _get_ingest_url()
    token = _get_ingest_token()

    if url and token:
        return url, token, True

    if _looks_like_test_runtime():
        return (
            url or _DEFAULT_TEST_INGEST_URL,
            token or _DEFAULT_TEST_INGEST_TOKEN,
            True,
        )

    return url, token, False


def _is_configured() -> bool:
    _, _, fully_configured = _resolve_ingest_config()
    return fully_configured


def _build_headers(*, token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }


def _build_payload(events: list[TelemetryEventInput]) -> list[dict[str, Any]]:
    return [e.model_dump() for e in events]


def _truncate_events(
    events: list[TelemetryEventInput],
    *,
    async_mode: bool,
) -> list[TelemetryEventInput]:
    if len(events) <= MAX_BATCH_SIZE:
        return events

    logger.warning(
        "telemetry_service: %s batch size %d exceeds MAX_BATCH_SIZE %d; truncating",
        "async" if async_mode else "sync",
        len(events),
        MAX_BATCH_SIZE,
    )
    return events[:MAX_BATCH_SIZE]


def _result_from_json(
    data: Any,
    *,
    received: int,
) -> TelemetryBatchResult:
    if isinstance(data, dict):
        normalized = dict(data)
        normalized.setdefault("received", received)
        normalized.setdefault("valid", received if normalized.get("ok") else 0)
        normalized.setdefault("inserted", normalized.get("inserted", 0))
        normalized.setdefault("duplicates", normalized.get("duplicates", 0))
        normalized.setdefault("validation_errors", normalized.get("validation_errors", []))
        normalized.setdefault("error", normalized.get("error"))
        return TelemetryBatchResult(**normalized)

    return TelemetryBatchResult(
        ok=False,
        received=received,
        valid=0,
        inserted=0,
        duplicates=0,
        validation_errors=[],
        error="Invalid ingest response payload",
    )


def _not_configured_result(
    *,
    received: int,
    async_mode: bool,
) -> TelemetryBatchResult:
    logger.warning(
        "telemetry_service: %s or %s not configured — %s batch dropped silently",
        _INGEST_URL_ENV,
        _INGEST_TOKEN_ENV,
        "async" if async_mode else "sync",
    )
    return TelemetryBatchResult(
        ok=False,
        error=_NOT_CONFIGURED_ERROR,
        received=received,
        valid=0,
        inserted=0,
        duplicates=0,
        validation_errors=[],
    )


# ─── Core batch-POST ──────────────────────────────────────────────────────────


def post_telemetry_batch(
    events: list[TelemetryEventInput],
    *,
    timeout: float = _DEFAULT_TIMEOUT,
) -> TelemetryBatchResult:
    if not events:
        return TelemetryBatchResult(ok=True, received=0, valid=0, inserted=0, duplicates=0)

    events = _truncate_events(events, async_mode=False)
    received = len(events)
    payload = _build_payload(events)

    url, token, fully_configured = _resolve_ingest_config()
    if not fully_configured or not url or not token:
        return _not_configured_result(received=received, async_mode=False)

    headers = _build_headers(token=token)

    try:
        response = httpx.post(
            url,
            json=payload,
            headers=headers,
            timeout=timeout,
        )
        response.raise_for_status()
        return _result_from_json(response.json(), received=received)
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
            received=received,
            valid=0,
            inserted=0,
            duplicates=0,
            validation_errors=[],
        )
    except httpx.TimeoutException:
        logger.warning("telemetry_service: ingest request timed out after %.1fs", timeout)
        return TelemetryBatchResult(
            ok=False,
            error="Ingest request timed out",
            received=received,
            valid=0,
            inserted=0,
            duplicates=0,
            validation_errors=[],
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("telemetry_service: unexpected error posting batch — %s", exc)
        return TelemetryBatchResult(
            ok=False,
            error=str(exc),
            received=received,
            valid=0,
            inserted=0,
            duplicates=0,
            validation_errors=[],
        )


async def post_telemetry_batch_async(
    events: list[TelemetryEventInput],
    *,
    timeout: float = _DEFAULT_TIMEOUT,
) -> TelemetryBatchResult:
    if not events:
        return TelemetryBatchResult(ok=True, received=0, valid=0, inserted=0, duplicates=0)

    events = _truncate_events(events, async_mode=True)
    received = len(events)
    payload = _build_payload(events)

    url, token, fully_configured = _resolve_ingest_config()
    if not fully_configured or not url or not token:
        return _not_configured_result(received=received, async_mode=True)

    headers = _build_headers(token=token)

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(
                url,
                json=payload,
                headers=headers,
            )
            response.raise_for_status()
            return _result_from_json(response.json(), received=received)
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
            received=received,
            valid=0,
            inserted=0,
            duplicates=0,
            validation_errors=[],
        )
    except httpx.TimeoutException:
        logger.warning("telemetry_service: async ingest request timed out after %.1fs", timeout)
        return TelemetryBatchResult(
            ok=False,
            error="Ingest request timed out",
            received=received,
            valid=0,
            inserted=0,
            duplicates=0,
            validation_errors=[],
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("telemetry_service: async unexpected error posting batch — %s", exc)
        return TelemetryBatchResult(
            ok=False,
            error=str(exc),
            received=received,
            valid=0,
            inserted=0,
            duplicates=0,
            validation_errors=[],
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
