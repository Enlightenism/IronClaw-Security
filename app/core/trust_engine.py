from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import logging
import threading
import time
from typing import Any, Literal
import uuid

from app.core.logging import get_logger
from app.core.supabase_persistence import _T_AGENT_TRUST_PROFILES, _T_TRUST_EVENTS

_logger: logging.Logger = get_logger("ironclaw.trust_engine")

# ---------------------------------------------------------------------------
# Trust event types
# ---------------------------------------------------------------------------

TrustEventType = Literal[
    "anomaly_detected",
    "policy_violation",
    "prompt_injection_attempt",
    "tool_call_blocked",
    "sandbox_escape_attempt",
    "data_exfiltration_attempt",
    "role_hijack_attempt",
    "review_escalation",
    "trust_restored",
    "trust_reset",
    "manual_adjustment",
]

# ---------------------------------------------------------------------------
# Decay weights per event type — how much each event reduces trust_score
# ---------------------------------------------------------------------------

_DECAY_WEIGHTS: dict[str, float] = {
    "anomaly_detected": 0.05,
    "policy_violation": 0.08,
    "prompt_injection_attempt": 0.15,
    "tool_call_blocked": 0.10,
    "sandbox_escape_attempt": 0.20,
    "data_exfiltration_attempt": 0.20,
    "role_hijack_attempt": 0.15,
    "review_escalation": 0.07,
    "trust_restored": -0.10,
    "trust_reset": 0.0,
    "manual_adjustment": 0.0,
}

# Restore amount applied for "trust_restored" event (negative decay = score gain)
_RESTORE_AMOUNT: float = 0.10

# Floor below which a trust_score cannot decay further without an explicit reset
_SCORE_FLOOR: float = 0.0
_SCORE_CEILING: float = 1.0

# Default trust score for an agent with no profile
_DEFAULT_SCORE: float = 0.75

# TTL for in-process profile cache (seconds)
_CACHE_TTL_SECONDS: float = 60.0

# ---------------------------------------------------------------------------
# TrustProfile — the public data structure returned to callers
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class TrustProfile:
    agent_id: str
    trust_score: float
    event_count: int
    last_event_type: str | None
    last_event_at: str | None
    created_at: str
    updated_at: str
    is_suspended: bool
    suspension_reason: str | None
    metadata: dict[str, Any]


@dataclass(frozen=True, slots=True)
class TrustEvent:
    event_id: str
    agent_id: str
    event_type: TrustEventType
    previous_score: float
    new_score: float
    delta: float
    metadata: dict[str, Any]
    recorded_at: str


# ---------------------------------------------------------------------------
# In-process profile cache — keyed by agent_id
# ---------------------------------------------------------------------------

_lock: threading.RLock = threading.RLock()
_profile_cache: dict[str, tuple[TrustProfile, float]] = {}


def _get_cached(agent_id: str) -> TrustProfile | None:
    entry = _profile_cache.get(agent_id)
    if entry is None:
        return None
    profile, expires_at = entry
    if time.monotonic() > expires_at:
        del _profile_cache[agent_id]
        return None
    return profile


def _set_cached(agent_id: str, profile: TrustProfile) -> None:
    _profile_cache[agent_id] = (profile, time.monotonic() + _CACHE_TTL_SECONDS)


def _evict_cached(agent_id: str) -> None:
    _profile_cache.pop(agent_id, None)


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------


def _now_utc() -> str:
    return datetime.now(UTC).isoformat()


def _clamp(value: float) -> float:
    return max(_SCORE_FLOOR, min(_SCORE_CEILING, value))


def _get_client():
    from app.core.supabase import get_supabase_service_client  # noqa: PLC0415

    return get_supabase_service_client()


def _supabase_errors():
    from app.supabaseclient import SupabaseAPIError, SupabaseClientError  # noqa: PLC0415

    return SupabaseAPIError, SupabaseClientError


# ---------------------------------------------------------------------------
# DB read — agent_trust_profiles
# ---------------------------------------------------------------------------


def _fetch_profile_from_db(agent_id: str) -> dict[str, Any] | None:
    try:
        client = _get_client()
        resp = client.table(_T_AGENT_TRUST_PROFILES).select("*").eq("agent_id", agent_id).maybe_single().execute()
        data = resp.data
        if isinstance(data, dict) and data:
            return data
        if isinstance(data, list):
            return data[0] if data else None
        return None
    except Exception as exc:  # noqa: BLE001
        _logger.error("trust_engine: failed to fetch profile for agent %r: %s", agent_id, exc)
        return None


def _row_to_profile(row: dict[str, Any]) -> TrustProfile:
    return TrustProfile(
        agent_id=str(row.get("agent_id") or ""),
        trust_score=_clamp(float(row.get("trust_score") or _DEFAULT_SCORE)),
        event_count=int(row.get("event_count") or 0),
        last_event_type=row.get("last_event_type"),
        last_event_at=row.get("last_event_at"),
        created_at=str(row.get("created_at") or _now_utc()),
        updated_at=str(row.get("updated_at") or _now_utc()),
        is_suspended=bool(row.get("is_suspended") or False),
        suspension_reason=row.get("suspension_reason"),
        metadata=dict(row.get("metadata") or {}),
    )


def _default_profile(agent_id: str) -> TrustProfile:
    now = _now_utc()
    return TrustProfile(
        agent_id=agent_id,
        trust_score=_DEFAULT_SCORE,
        event_count=0,
        last_event_type=None,
        last_event_at=None,
        created_at=now,
        updated_at=now,
        is_suspended=False,
        suspension_reason=None,
        metadata={},
    )


# ---------------------------------------------------------------------------
# DB write — agent_trust_profiles
# ---------------------------------------------------------------------------


def _upsert_profile_to_db(profile: TrustProfile) -> None:
    record: dict[str, Any] = {
        "agent_id": profile.agent_id,
        "trust_score": round(profile.trust_score, 6),
        "event_count": profile.event_count,
        "last_event_type": profile.last_event_type,
        "last_event_at": profile.last_event_at,
        "updated_at": _now_utc(),
        "is_suspended": profile.is_suspended,
        "suspension_reason": profile.suspension_reason,
        "metadata": profile.metadata,
    }
    try:
        client = _get_client()
        client.table(_T_AGENT_TRUST_PROFILES).upsert(record, on_conflict="agent_id", returning="minimal").execute()
    except Exception as exc:  # noqa: BLE001
        _logger.error("trust_engine: failed to upsert profile for agent %r: %s", profile.agent_id, exc)
        raise


# ---------------------------------------------------------------------------
# DB write — trust_events
# ---------------------------------------------------------------------------


def _insert_trust_event_to_db(event: TrustEvent) -> None:
    record: dict[str, Any] = {
        "event_id": event.event_id,
        "agent_id": event.agent_id,
        "event_type": event.event_type,
        "previous_score": round(event.previous_score, 6),
        "new_score": round(event.new_score, 6),
        "delta": round(event.delta, 6),
        "metadata": event.metadata,
        "recorded_at": event.recorded_at,
    }
    try:
        client = _get_client()
        client.table(_T_TRUST_EVENTS).insert(record, returning="minimal").execute()
    except Exception as exc:  # noqa: BLE001
        _logger.error("trust_engine: failed to insert trust_event for agent %r: %s", event.agent_id, exc)


# ---------------------------------------------------------------------------
# Score computation
# ---------------------------------------------------------------------------


def _apply_decay(
    current_score: float,
    event_type: str,
    metadata: dict[str, Any],
) -> float:
    if event_type == "trust_reset":
        return _DEFAULT_SCORE

    if event_type == "manual_adjustment":
        adjustment = float(metadata.get("adjustment") or 0.0)
        return _clamp(current_score + adjustment)

    if event_type == "trust_restored":
        restore_amount = float(metadata.get("restore_amount") or _RESTORE_AMOUNT)
        return _clamp(current_score + restore_amount)

    decay = _DECAY_WEIGHTS.get(event_type, 0.05)
    return _clamp(current_score - decay)


def _should_suspend(profile: TrustProfile, event_type: str) -> tuple[bool, str | None]:
    critical_events = {
        "sandbox_escape_attempt",
        "data_exfiltration_attempt",
    }
    if event_type in critical_events:
        return True, f"Auto-suspended on critical event: {event_type}"
    if profile.trust_score <= 0.10 and not profile.is_suspended:
        return True, "Auto-suspended: trust_score at or below critical threshold (0.10)"
    return profile.is_suspended, profile.suspension_reason


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def get_trust(agent_id: str) -> TrustProfile:
    """Return the TrustProfile for agent_id.

    Resolution order:
      1. In-process TTL cache.
      2. Supabase agent_trust_profiles table.
      3. Default profile (trust_score=0.75) — never fails.

    This function is safe to call from policy_engine.evaluate() on every
    request. It is read-only and never mutates DB state.
    """
    if not agent_id or not agent_id.strip():
        return _default_profile("unknown")

    agent_id = agent_id.strip()

    with _lock:
        cached = _get_cached(agent_id)
        if cached is not None:
            return cached

    row = _fetch_profile_from_db(agent_id)
    if row:
        profile = _row_to_profile(row)
    else:
        profile = _default_profile(agent_id)

    with _lock:
        _set_cached(agent_id, profile)

    return profile


def record_event(
    agent_id: str,
    event_type: TrustEventType,
    metadata: dict[str, Any] | None = None,
) -> TrustEvent:
    """Record a trust event for agent_id and apply score decay.

    Steps:
      1. Load the current TrustProfile (cache → DB → default).
      2. Compute the new trust_score via _apply_decay.
      3. Evaluate suspension criteria.
      4. Upsert the updated profile to Supabase.
      5. Insert a trust_events row.
      6. Invalidate the cache for this agent.
      7. Return a TrustEvent with before/after scores and delta.

    This is the single mutation entry point for trust state.
    No other module may directly write to agent_trust_profiles or trust_events.
    """
    if not agent_id or not agent_id.strip():
        raise ValueError("agent_id is required and must be non-empty")

    agent_id = agent_id.strip()
    meta: dict[str, Any] = metadata or {}
    recorded_at = _now_utc()

    current_profile = get_trust(agent_id)
    previous_score = current_profile.trust_score

    new_score = _apply_decay(previous_score, event_type, meta)
    delta = round(new_score - previous_score, 6)

    is_suspended, suspension_reason = _should_suspend(
        TrustProfile(
            agent_id=agent_id,
            trust_score=new_score,
            event_count=current_profile.event_count + 1,
            last_event_type=event_type,
            last_event_at=recorded_at,
            created_at=current_profile.created_at,
            updated_at=recorded_at,
            is_suspended=current_profile.is_suspended,
            suspension_reason=current_profile.suspension_reason,
            metadata=current_profile.metadata,
        ),
        event_type,
    )

    updated_profile = TrustProfile(
        agent_id=agent_id,
        trust_score=new_score,
        event_count=current_profile.event_count + 1,
        last_event_type=event_type,
        last_event_at=recorded_at,
        created_at=current_profile.created_at,
        updated_at=recorded_at,
        is_suspended=is_suspended,
        suspension_reason=suspension_reason,
        metadata=current_profile.metadata,
    )

    try:
        _upsert_profile_to_db(updated_profile)
    except Exception:  # noqa: BLE001
        pass

    event = TrustEvent(
        event_id=str(uuid.uuid4()),
        agent_id=agent_id,
        event_type=event_type,
        previous_score=previous_score,
        new_score=new_score,
        delta=delta,
        metadata=meta,
        recorded_at=recorded_at,
    )

    _insert_trust_event_to_db(event)

    with _lock:
        _evict_cached(agent_id)

    _logger.info(
        "trust_engine.event",
        extra={
            "event_id": event.event_id,
            "agent_id": agent_id,
            "event_type": event_type,
            "previous_score": previous_score,
            "new_score": new_score,
            "delta": delta,
            "is_suspended": is_suspended,
        },
    )

    return event


def suspend_agent(
    agent_id: str,
    reason: str,
    *,
    metadata: dict[str, Any] | None = None,
) -> TrustProfile:
    """Immediately suspend an agent and record a manual_adjustment event.

    Sets is_suspended=True and trust_score to floor (0.0).
    Callers: admin endpoints, automated escalation workflows.
    """
    agent_id = agent_id.strip()
    meta: dict[str, Any] = {**(metadata or {}), "adjustment": -1.0, "reason": reason}
    record_event(agent_id, "manual_adjustment", meta)

    profile = get_trust(agent_id)
    suspended = TrustProfile(
        agent_id=profile.agent_id,
        trust_score=_SCORE_FLOOR,
        event_count=profile.event_count,
        last_event_type="manual_adjustment",
        last_event_at=_now_utc(),
        created_at=profile.created_at,
        updated_at=_now_utc(),
        is_suspended=True,
        suspension_reason=reason,
        metadata=profile.metadata,
    )
    try:
        _upsert_profile_to_db(suspended)
    except Exception:  # noqa: BLE001
        pass
    with _lock:
        _set_cached(agent_id, suspended)
    _logger.warning(
        "trust_engine.agent_suspended",
        extra={"agent_id": agent_id, "reason": reason},
    )
    return suspended


def restore_agent(
    agent_id: str,
    *,
    restore_score: float = _DEFAULT_SCORE,
    metadata: dict[str, Any] | None = None,
) -> TrustProfile:
    """Lift suspension and restore trust_score for an agent.

    Callers: admin endpoints, manual review resolution.
    """
    agent_id = agent_id.strip()
    meta: dict[str, Any] = {
        **(metadata or {}),
        "restore_amount": restore_score - _clamp(get_trust(agent_id).trust_score),
    }
    profile = get_trust(agent_id)
    restored = TrustProfile(
        agent_id=profile.agent_id,
        trust_score=_clamp(restore_score),
        event_count=profile.event_count + 1,
        last_event_type="trust_restored",
        last_event_at=_now_utc(),
        created_at=profile.created_at,
        updated_at=_now_utc(),
        is_suspended=False,
        suspension_reason=None,
        metadata=profile.metadata,
    )
    try:
        _upsert_profile_to_db(restored)
    except Exception:  # noqa: BLE001
        pass
    with _lock:
        _set_cached(agent_id, restored)

    event = TrustEvent(
        event_id=str(uuid.uuid4()),
        agent_id=agent_id,
        event_type="trust_restored",
        previous_score=profile.trust_score,
        new_score=restored.trust_score,
        delta=round(restored.trust_score - profile.trust_score, 6),
        metadata=meta,
        recorded_at=_now_utc(),
    )
    _insert_trust_event_to_db(event)

    _logger.info(
        "trust_engine.agent_restored",
        extra={
            "agent_id": agent_id,
            "new_score": restored.trust_score,
        },
    )
    return restored


def reset_trust(agent_id: str, *, metadata: dict[str, Any] | None = None) -> TrustEvent:
    """Reset an agent's trust_score to the default (0.75) and clear suspension.

    Records a trust_reset event. Use for onboarding re-evaluation or
    post-investigation clearance.
    """
    return record_event(agent_id, "trust_reset", metadata)


def list_trust_events(
    agent_id: str,
    *,
    limit: int = 50,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """Return trust_events rows for agent_id ordered by recorded_at desc.

    Read-only. Does not mutate cache or profile state.
    """
    try:
        client = _get_client()
        resp = client.table(_T_TRUST_EVENTS).select("*").eq("agent_id", agent_id).order("recorded_at", desc=True).range(offset, offset + limit - 1).execute()
        data = resp.data
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return [data]
        return []
    except Exception as exc:  # noqa: BLE001
        _logger.error("trust_engine: failed to list trust_events for agent %r: %s", agent_id, exc)
        return []


def invalidate_cache(agent_id: str | None = None) -> None:
    """Invalidate the in-process trust profile cache.

    When agent_id is None, clears the entire cache.
    Call after direct Supabase mutations to agent_trust_profiles.
    """
    with _lock:
        if agent_id is None:
            _profile_cache.clear()
        else:
            _evict_cached(agent_id.strip())


def trust_stats() -> dict[str, Any]:
    """Return a snapshot of trust engine cache state for health/diagnostic use."""
    with _lock:
        cached_count = len(_profile_cache)
        agents = list(_profile_cache.keys())
    return {
        "cached_profiles": cached_count,
        "cached_agent_ids": agents,
        "cache_ttl_seconds": _CACHE_TTL_SECONDS,
        "default_score": _DEFAULT_SCORE,
        "score_floor": _SCORE_FLOOR,
        "score_ceiling": _SCORE_CEILING,
    }


# ---------------------------------------------------------------------------
# Public surface
# ---------------------------------------------------------------------------

__all__ = [
    "TrustEventType",
    "TrustProfile",
    "TrustEvent",
    "get_trust",
    "record_event",
    "suspend_agent",
    "restore_agent",
    "reset_trust",
    "list_trust_events",
    "invalidate_cache",
    "trust_stats",
]
