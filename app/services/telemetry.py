from __future__ import annotations

from collections import deque
from datetime import UTC, datetime
import json
from pathlib import Path
from threading import Lock
from typing import Any, Final, Literal

TELEMETRY_DIR: Final[Path] = Path.home() / ".ironclaw"
TELEMETRY_PATH: Final[Path] = TELEMETRY_DIR / "telemetry_events.jsonl"
TELEMETRY_SCHEMA_VERSION: Final[int] = 1
DEFAULT_READ_LIMIT: Final[int] = 50
MAX_READ_LIMIT: Final[int] = 10_000

TELEMETRY_DIR.mkdir(parents=True, exist_ok=True)

_TELEMETRY_LOCK = Lock()
_COERCE_MAX_DEPTH = 32

# ---------------------------------------------------------------------------
# Canonical event type registry
# Any service that emits telemetry must register its event types here.
# External consumers and tests use KNOWN_EVENT_TYPES for contract validation.
# ---------------------------------------------------------------------------

KnownEventType = Literal[
    # Core scan / action guard
    "scan_completed",
    "action_guard_decision",
    "prompt_injection_detected",
    # Quarantine / incidents
    "quarantine_created",
    "quarantine_released",
    "incident_created",
    "incident_updated",
    # Policy
    "policy_changed",
    "policy_violation",
    # Alerts
    "alert_dispatched",
    "alert_failed",
    # Audit
    "audit_entry_created",
    # Trust
    "trust_score_updated",
    "trust_collapse_detected",
    # Phase 9 — Behavioral Baseline & Agent Profiling
    "behavioral_drift_detected",
    "behavioral_baseline_updated",
    "behavioral_baseline_suspended",
    "agent_observation_recorded",
    # System
    "system_startup",
    "system_shutdown",
    "telemetry_cleared",
]

KNOWN_EVENT_TYPES: Final[frozenset[str]] = frozenset(KnownEventType.__args__)  # type: ignore[attr-defined]


def is_known_event_type(event_type: str) -> bool:
    """Return True if event_type is in the canonical registry."""
    return event_type in KNOWN_EVENT_TYPES


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _utc_now_iso() -> str:
    return _utc_now().isoformat().replace("+00:00", "Z")


def _is_pydantic_model(value: Any) -> bool:
    """Return True only for real Pydantic BaseModel instances, not Mocks."""
    try:
        from pydantic import BaseModel

        return isinstance(value, BaseModel)
    except ImportError:
        return False


def _coerce_json_safe(value: Any, _depth: int = 0) -> Any:
    if _depth > _COERCE_MAX_DEPTH:
        return str(value)

    if value is None or isinstance(value, (str, int, float, bool)):
        return value

    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")

    if isinstance(value, Path):
        return str(value)

    if isinstance(value, dict):
        return {str(k): _coerce_json_safe(v, _depth + 1) for k, v in value.items()}

    if isinstance(value, (list, tuple, set, frozenset)):
        return [_coerce_json_safe(item, _depth + 1) for item in value]

    if _is_pydantic_model(value):
        return _coerce_json_safe(value.model_dump(), _depth + 1)

    type_name = type(value).__name__
    if "Mock" not in type_name and hasattr(value, "dict") and callable(value.dict) and hasattr(value, "__fields__") is not False:
        try:
            dumped = value.dict()
            if isinstance(dumped, dict):
                return _coerce_json_safe(dumped, _depth + 1)
        except Exception:
            pass

    if hasattr(value, "__dict__") and "Mock" not in type(value).__name__:
        return _coerce_json_safe(vars(value), _depth + 1)

    return str(value)


def _safe_limit(limit: int | str | None, default: int = DEFAULT_READ_LIMIT) -> int:
    try:
        resolved = int(limit if limit is not None else default)
    except (TypeError, ValueError):
        resolved = default
    return max(1, min(resolved, MAX_READ_LIMIT))


def _ensure_parent_dir() -> None:
    TELEMETRY_PATH.parent.mkdir(parents=True, exist_ok=True)


def _build_event_record(event_type: str, payload: dict[str, Any] | None) -> dict[str, Any]:
    safe_event_type = str(event_type).strip() or "unknown"
    safe_payload = _coerce_json_safe(payload if payload is not None else {})
    if not isinstance(safe_payload, dict):
        safe_payload = {"value": safe_payload}

    now = _utc_now()
    return {
        "event_id": f"telem_{now.strftime('%Y%m%d%H%M%S%f')}",
        "schema_version": TELEMETRY_SCHEMA_VERSION,
        "timestamp": now.isoformat().replace("+00:00", "Z"),
        "event_type": safe_event_type,
        "payload": safe_payload,
    }


def _normalize_event(event: Any) -> dict[str, Any] | None:
    if not isinstance(event, dict):
        return None

    normalized = dict(event)
    normalized["event_id"] = str(normalized.get("event_id") or "").strip() or None
    normalized["schema_version"] = int(normalized.get("schema_version") or TELEMETRY_SCHEMA_VERSION)
    normalized["timestamp"] = str(normalized.get("timestamp") or "").strip() or None
    normalized["event_type"] = str(normalized.get("event_type") or "unknown").strip() or "unknown"

    payload = _coerce_json_safe(normalized.get("payload"))
    normalized["payload"] = payload if isinstance(payload, dict) else {"value": payload}
    return normalized


def _parse_iso_timestamp(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def append_telemetry_event(
    event_type: str,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    record = _build_event_record(event_type, payload)

    with _TELEMETRY_LOCK:
        _ensure_parent_dir()
        with TELEMETRY_PATH.open("a", encoding="utf-8", newline="\n") as file_handle:
            file_handle.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")

    return record


def read_telemetry_events(
    limit: int = DEFAULT_READ_LIMIT,
    *,
    event_type: str | None = None,
    since: str | datetime | None = None,
    until: str | datetime | None = None,
    agent_id: str | None = None,
) -> list[dict[str, Any]]:
    """Read telemetry events in reverse-chronological order.

    Args:
        limit:      Maximum number of matching events to return.
        event_type: Optional exact-match filter on event_type field.
        since:      Optional ISO timestamp or datetime lower bound (inclusive).
        until:      Optional ISO timestamp or datetime upper bound (inclusive).
        agent_id:   Optional filter on payload.agent_id for behavioral events.
    """
    safe_limit = _safe_limit(limit)
    expected_type = str(event_type).strip() if event_type is not None else None
    expected_agent = str(agent_id).strip() if agent_id is not None else None

    since_dt: datetime | None = None
    until_dt: datetime | None = None

    if since is not None:
        since_dt = since if isinstance(since, datetime) else _parse_iso_timestamp(str(since))
    if until is not None:
        until_dt = until if isinstance(until, datetime) else _parse_iso_timestamp(str(until))

    with _TELEMETRY_LOCK:
        if not TELEMETRY_PATH.exists():
            return []

        with TELEMETRY_PATH.open("r", encoding="utf-8", newline="") as file_handle:
            lines = deque(file_handle, maxlen=MAX_READ_LIMIT)

    events: list[dict[str, Any]] = []

    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue

        try:
            raw_event = json.loads(line)
        except json.JSONDecodeError:
            continue

        event = _normalize_event(raw_event)
        if event is None:
            continue

        if expected_type is not None and event.get("event_type") != expected_type:
            continue

        if since_dt is not None or until_dt is not None:
            event_ts = _parse_iso_timestamp(event.get("timestamp"))
            if event_ts is not None:
                if since_dt is not None and event_ts < since_dt:
                    continue
                if until_dt is not None and event_ts > until_dt:
                    continue

        if expected_agent is not None:
            event_payload = event.get("payload") or {}
            if isinstance(event_payload, dict):
                if str(event_payload.get("agent_id") or "").strip() != expected_agent:
                    continue

        events.append(event)
        if len(events) >= safe_limit:
            break

    return events


def get_events_by_agent(
    agent_id: str,
    *,
    limit: int = DEFAULT_READ_LIMIT,
    event_type: str | None = None,
    since: str | datetime | None = None,
) -> list[dict[str, Any]]:
    """Return telemetry events scoped to a specific agent_id.

    Convenience wrapper for the behavioral baseline router and drift audit queries.
    """
    return read_telemetry_events(
        limit=limit,
        event_type=event_type,
        since=since,
        agent_id=agent_id,
    )


def summarize_telemetry_events(limit: int = 500) -> dict[str, Any]:
    events = read_telemetry_events(limit=limit)
    counts: dict[str, int] = {}

    for event in events:
        event_type = str(event.get("event_type") or "unknown")
        counts[event_type] = counts.get(event_type, 0) + 1

    unknown_types = [et for et in counts if et not in KNOWN_EVENT_TYPES]

    return {
        "path": str(TELEMETRY_PATH),
        "schema_version": TELEMETRY_SCHEMA_VERSION,
        "event_count": len(events),
        "event_type_counts": dict(sorted(counts.items())),
        "unknown_event_types": sorted(unknown_types),
        "latest_timestamp": events[0].get("timestamp") if events else None,
    }


def clear_telemetry_events() -> None:
    with _TELEMETRY_LOCK:
        _ensure_parent_dir()
        TELEMETRY_PATH.write_text("", encoding="utf-8")


def telemetry_file_exists() -> bool:
    with _TELEMETRY_LOCK:
        return TELEMETRY_PATH.exists()


def get_telemetry_path() -> str:
    return str(TELEMETRY_PATH)
