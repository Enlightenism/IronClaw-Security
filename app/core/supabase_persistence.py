from __future__ import annotations

from datetime import UTC, datetime
import logging
from typing import Any

from app.core.logging import get_logger
from app.core.supabase import get_supabase_service_client
from app.supabaseclient import SupabaseAPIError, SupabaseClientError

_logger: logging.Logger = get_logger("ironclaw.persistence")


# ---------------------------------------------------------------------------
# Table names
# ---------------------------------------------------------------------------
_T_SCAN_HISTORY = "scan_history"
_T_AUDIT_EVENTS = "audit_events"
_T_TELEMETRY = "telemetry_events"
_T_QUARANTINE = "quarantine_items"
_T_REVIEW_QUEUE = "review_queue"
_T_IOCS = "iocs"
_T_THREAT_DETECTIONS = "threat_detections"
_T_POLICY_SETS = "policy_sets"
_T_POLICY_RULES = "policy_rules"
_T_POLICY_SET_MEMBERSHIPS = "policy_set_memberships"
_T_TOOL_CALL_LOG = "tool_call_log"
_T_SANDBOX_EXECUTION_LOG = "sandbox_execution_log"
_T_AGENT_TRUST_PROFILES = "agent_trust_profiles"
_T_TRUST_EVENTS = "trust_events"
_T_SCAN_PATTERNS = "scan_patterns"
_T_RATE_LIMIT_STATE = "rate_limit_state"
_T_WEBHOOK_SUBSCRIPTIONS = "webhook_subscriptions"
_T_WEBHOOK_DELIVERIES = "webhook_deliveries"
_T_WEBHOOK_DELIVERY_LOG = "webhook_delivery_log"


_COL_POLICY_RULE_ID = "policy_rule_id"


# ---------------------------------------------------------------------------
# PersistenceError
# ---------------------------------------------------------------------------


class PersistenceError(RuntimeError):
    """Raised when any Supabase persistence operation fails."""

    def __init__(self, operation: str, message: str = "", *, cause: BaseException | None = None) -> None:
        super().__init__(f"[{operation}] {message}" if message else operation)
        self.operation = operation
        self.cause = cause


def _now_utc() -> str:
    return datetime.now(UTC).isoformat()


def _wrap(operation: str, exc: BaseException) -> PersistenceError:
    _logger.error(
        "persistence_error",
        extra={"operation": operation, "error": str(exc)},
        exc_info=exc,
    )
    return PersistenceError(operation, str(exc), cause=exc)


# ---------------------------------------------------------------------------
# Scan History
# ---------------------------------------------------------------------------


def upsert_scan(record: dict[str, Any]) -> dict[str, Any]:
    operation = "upsert_scan"
    try:
        client = get_supabase_service_client()
        resp = client.table(_T_SCAN_HISTORY).upsert(record, on_conflict="scan_id", returning="representation").execute()
        data = resp.data
        if isinstance(data, list):
            return data[0] if data else record
        if isinstance(data, dict):
            return data
        return record
    except (SupabaseAPIError, SupabaseClientError) as exc:
        raise _wrap(operation, exc) from exc


def get_scan_by_id(scan_id: str) -> dict[str, Any] | None:
    operation = "get_scan_by_id"
    try:
        client = get_supabase_service_client()
        resp = client.table(_T_SCAN_HISTORY).select("*").eq("scan_id", scan_id).maybe_single().execute()
        data = resp.data
        if isinstance(data, dict):
            return data
        if isinstance(data, list):
            return data[0] if data else None
        return None
    except (SupabaseAPIError, SupabaseClientError) as exc:
        raise _wrap(operation, exc) from exc


def list_scans(
    *,
    agent_id: str | None = None,
    verdict: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[dict[str, Any]]:
    operation = "list_scans"
    try:
        client = get_supabase_service_client()
        q = client.table(_T_SCAN_HISTORY).select("*")
        if agent_id:
            q = q.eq("agent_id", agent_id)
        if verdict:
            q = q.eq("verdict", verdict)
        q = q.order("created_at", desc=True).range(offset, offset + limit - 1)
        resp = q.execute()
        data = resp.data
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return [data]
        return []
    except (SupabaseAPIError, SupabaseClientError) as exc:
        raise _wrap(operation, exc) from exc


# ---------------------------------------------------------------------------
# Audit Events
# ---------------------------------------------------------------------------


def upsert_audit_event(record: dict[str, Any]) -> dict[str, Any]:
    operation = "upsert_audit_event"
    try:
        client = get_supabase_service_client()
        if "created_at" not in record:
            record = {**record, "created_at": _now_utc()}
        if "event_id" in record:
            resp = client.table(_T_AUDIT_EVENTS).upsert(record, on_conflict="event_id", returning="representation").execute()
        else:
            resp = client.table(_T_AUDIT_EVENTS).insert(record, returning="representation").execute()
        data = resp.data
        if isinstance(data, list):
            return data[0] if data else record
        if isinstance(data, dict):
            return data
        return record
    except (SupabaseAPIError, SupabaseClientError) as exc:
        raise _wrap(operation, exc) from exc


# ---------------------------------------------------------------------------
# Telemetry
# ---------------------------------------------------------------------------


def upsert_telemetry(record: dict[str, Any]) -> dict[str, Any]:
    operation = "upsert_telemetry"
    try:
        client = get_supabase_service_client()
        if "recorded_at" not in record:
            record = {**record, "recorded_at": _now_utc()}
        resp = client.table(_T_TELEMETRY).upsert(record, on_conflict="telemetry_id", returning="representation").execute()
        data = resp.data
        if isinstance(data, list):
            return data[0] if data else record
        if isinstance(data, dict):
            return data
        return record
    except (SupabaseAPIError, SupabaseClientError) as exc:
        raise _wrap(operation, exc) from exc


# ---------------------------------------------------------------------------
# Quarantine
# ---------------------------------------------------------------------------


def upsert_quarantine_item(record: dict[str, Any]) -> dict[str, Any]:
    operation = "upsert_quarantine_item"
    try:
        client = get_supabase_service_client()
        if "quarantined_at" not in record:
            record = {**record, "quarantined_at": _now_utc()}
        resp = client.table(_T_QUARANTINE).upsert(record, on_conflict="quarantine_id", returning="representation").execute()
        data = resp.data
        if isinstance(data, list):
            return data[0] if data else record
        if isinstance(data, dict):
            return data
        return record
    except (SupabaseAPIError, SupabaseClientError) as exc:
        raise _wrap(operation, exc) from exc


# ---------------------------------------------------------------------------
# Review Queue
# ---------------------------------------------------------------------------


def get_review_queue(
    *,
    status: str | None = None,
    agent_id: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[dict[str, Any]]:
    operation = "get_review_queue"
    try:
        client = get_supabase_service_client()
        q = client.table(_T_REVIEW_QUEUE).select("*")
        if status:
            q = q.eq("status", status)
        if agent_id:
            q = q.eq("agent_id", agent_id)
        q = q.order("created_at", desc=False).range(offset, offset + limit - 1)
        resp = q.execute()
        data = resp.data
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return [data]
        return []
    except (SupabaseAPIError, SupabaseClientError) as exc:
        raise _wrap(operation, exc) from exc


# ---------------------------------------------------------------------------
# IOCs
# ---------------------------------------------------------------------------


def upsert_ioc(record: dict[str, Any]) -> dict[str, Any]:
    operation = "upsert_ioc"
    try:
        client = get_supabase_service_client()
        if "detected_at" not in record:
            record = {**record, "detected_at": _now_utc()}
        resp = client.table(_T_IOCS).upsert(record, on_conflict="ioc_id", returning="representation").execute()
        data = resp.data
        if isinstance(data, list):
            return data[0] if data else record
        if isinstance(data, dict):
            return data
        return record
    except (SupabaseAPIError, SupabaseClientError) as exc:
        raise _wrap(operation, exc) from exc


# ---------------------------------------------------------------------------
# Threat Detections
# ---------------------------------------------------------------------------


def upsert_threat_detection(record: dict[str, Any]) -> dict[str, Any]:
    operation = "upsert_threat_detection"
    try:
        client = get_supabase_service_client()
        if "detected_at" not in record:
            record = {**record, "detected_at": _now_utc()}
        resp = client.table(_T_THREAT_DETECTIONS).upsert(record, on_conflict="detection_id", returning="representation").execute()
        data = resp.data
        if isinstance(data, list):
            return data[0] if data else record
        if isinstance(data, dict):
            return data
        return record
    except (SupabaseAPIError, SupabaseClientError) as exc:
        raise _wrap(operation, exc) from exc


# ---------------------------------------------------------------------------
# Policy Sets
# ---------------------------------------------------------------------------


def get_policy_set(set_key: str) -> dict[str, Any] | None:
    operation = "get_policy_set"
    if not set_key or not set_key.strip():
        raise PersistenceError(operation, "set_key is required")
    try:
        client = get_supabase_service_client()
        set_resp = client.table(_T_POLICY_SETS).select("*").eq("set_key", set_key).maybe_single().execute()
        set_data = set_resp.data
        if not set_data:
            return None

        policy_set_id: str | None = None
        if isinstance(set_data, dict):
            policy_set_id = set_data.get("id") or set_data.get("policy_set_id")

        rules: list[dict[str, Any]] = []
        if policy_set_id:
            membership_resp = client.table(_T_POLICY_SET_MEMBERSHIPS).select(_COL_POLICY_RULE_ID).eq("policy_set_id", str(policy_set_id)).execute()
            memberships = membership_resp.data or []
            if isinstance(memberships, dict):
                memberships = [memberships]
            rule_ids: list[str] = [str(m[_COL_POLICY_RULE_ID]) for m in memberships if isinstance(m, dict) and m.get(_COL_POLICY_RULE_ID)]
            if rule_ids:
                rules_resp = client.table(_T_POLICY_RULES).select("*").in_("id", rule_ids).execute()
                raw_rules = rules_resp.data or []
                rules = raw_rules if isinstance(raw_rules, list) else [raw_rules]

        return {"policy_set": set_data, "rules": rules}
    except (SupabaseAPIError, SupabaseClientError) as exc:
        raise _wrap(operation, exc) from exc


# ---------------------------------------------------------------------------
# Scan Patterns
# ---------------------------------------------------------------------------


def get_scan_patterns(
    *,
    is_active: bool | None = True,
    pattern_type: str | None = None,
) -> list[dict[str, Any]]:
    operation = "get_scan_patterns"
    try:
        client = get_supabase_service_client()
        q = client.table(_T_SCAN_PATTERNS).select("*")
        if is_active is not None:
            q = q.eq("is_active", is_active)
        if pattern_type:
            q = q.eq("pattern_type", pattern_type)
        resp = q.execute()
        data = resp.data
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return [data]
        return []
    except (SupabaseAPIError, SupabaseClientError) as exc:
        raise _wrap(operation, exc) from exc


# ---------------------------------------------------------------------------
# Rate Limit State
# ---------------------------------------------------------------------------


def get_rate_limit_state(key: str) -> dict[str, Any] | None:
    operation = "get_rate_limit_state"
    if not key or not key.strip():
        raise PersistenceError(operation, "key is required")
    try:
        client = get_supabase_service_client()
        resp = client.table(_T_RATE_LIMIT_STATE).select("*").eq("key", key.strip()).maybe_single().execute()
        data = resp.data
        if isinstance(data, dict) and data:
            return data
        if isinstance(data, list):
            return data[0] if data else None
        return None
    except (SupabaseAPIError, SupabaseClientError) as exc:
        raise _wrap(operation, exc) from exc


def delete_rate_limit_state(key: str) -> None:
    operation = "delete_rate_limit_state"
    if not key or not key.strip():
        raise PersistenceError(operation, "key is required")
    try:
        client = get_supabase_service_client()
        client.table(_T_RATE_LIMIT_STATE).delete().eq("key", key.strip()).execute()
    except (SupabaseAPIError, SupabaseClientError) as exc:
        raise _wrap(operation, exc) from exc


# ---------------------------------------------------------------------------
# Tool Call Log
# ---------------------------------------------------------------------------


def log_tool_call(record: dict[str, Any]) -> dict[str, Any]:
    operation = "log_tool_call"
    try:
        client = get_supabase_service_client()
        if "called_at" not in record:
            record = {**record, "called_at": _now_utc()}
        if "tool_call_id" in record:
            resp = client.table(_T_TOOL_CALL_LOG).upsert(record, on_conflict="tool_call_id", returning="representation").execute()
        else:
            resp = client.table(_T_TOOL_CALL_LOG).insert(record, returning="representation").execute()
        data = resp.data
        if isinstance(data, list):
            return data[0] if data else record
        if isinstance(data, dict):
            return data
        return record
    except (SupabaseAPIError, SupabaseClientError) as exc:
        raise _wrap(operation, exc) from exc


# ---------------------------------------------------------------------------
# Sandbox Execution Log
# ---------------------------------------------------------------------------


def log_sandbox_execution(record: dict[str, Any]) -> dict[str, Any]:
    operation = "log_sandbox_execution"
    try:
        client = get_supabase_service_client()
        if "executed_at" not in record:
            record = {**record, "executed_at": _now_utc()}
        if "execution_id" in record:
            resp = client.table(_T_SANDBOX_EXECUTION_LOG).upsert(record, on_conflict="execution_id", returning="representation").execute()
        else:
            resp = client.table(_T_SANDBOX_EXECUTION_LOG).insert(record, returning="representation").execute()
        data = resp.data
        if isinstance(data, list):
            return data[0] if data else record
        if isinstance(data, dict):
            return data
        return record
    except (SupabaseAPIError, SupabaseClientError) as exc:
        raise _wrap(operation, exc) from exc


# ---------------------------------------------------------------------------
# Agent Trust Profiles
# ---------------------------------------------------------------------------


def get_agent_trust_profile(agent_id: str) -> dict[str, Any] | None:
    operation = "get_agent_trust_profile"
    if not agent_id or not agent_id.strip():
        raise PersistenceError(operation, "agent_id is required")
    try:
        client = get_supabase_service_client()
        resp = client.table(_T_AGENT_TRUST_PROFILES).select("*").eq("agent_id", agent_id.strip()).maybe_single().execute()
        data = resp.data
        if isinstance(data, dict) and data:
            return data
        if isinstance(data, list):
            return data[0] if data else None
        return None
    except (SupabaseAPIError, SupabaseClientError) as exc:
        raise _wrap(operation, exc) from exc


def upsert_agent_trust_profile(record: dict[str, Any]) -> dict[str, Any]:
    operation = "upsert_agent_trust_profile"
    if not record.get("agent_id"):
        raise PersistenceError(operation, "record must include agent_id")
    try:
        client = get_supabase_service_client()
        if "updated_at" not in record:
            record = {**record, "updated_at": _now_utc()}
        resp = client.table(_T_AGENT_TRUST_PROFILES).upsert(record, on_conflict="agent_id", returning="representation").execute()
        data = resp.data
        if isinstance(data, list):
            return data[0] if data else record
        if isinstance(data, dict):
            return data
        return record
    except (SupabaseAPIError, SupabaseClientError) as exc:
        raise _wrap(operation, exc) from exc


# ---------------------------------------------------------------------------
# Trust Events
# ---------------------------------------------------------------------------


def insert_trust_event(record: dict[str, Any]) -> dict[str, Any]:
    operation = "insert_trust_event"
    if not record.get("agent_id"):
        raise PersistenceError(operation, "record must include agent_id")
    if not record.get("event_type"):
        raise PersistenceError(operation, "record must include event_type")
    try:
        client = get_supabase_service_client()
        if "recorded_at" not in record:
            record = {**record, "recorded_at": _now_utc()}
        if "event_id" in record:
            resp = client.table(_T_TRUST_EVENTS).upsert(record, on_conflict="event_id", returning="representation").execute()
        else:
            resp = client.table(_T_TRUST_EVENTS).insert(record, returning="representation").execute()
        data = resp.data
        if isinstance(data, list):
            return data[0] if data else record
        if isinstance(data, dict):
            return data
        return record
    except (SupabaseAPIError, SupabaseClientError) as exc:
        raise _wrap(operation, exc) from exc


def list_trust_events(
    agent_id: str,
    *,
    limit: int = 50,
    offset: int = 0,
) -> list[dict[str, Any]]:
    operation = "list_trust_events"
    if not agent_id or not agent_id.strip():
        raise PersistenceError(operation, "agent_id is required")
    try:
        client = get_supabase_service_client()
        resp = client.table(_T_TRUST_EVENTS).select("*").eq("agent_id", agent_id.strip()).order("recorded_at", desc=True).range(offset, offset + limit - 1).execute()
        data = resp.data
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return [data]
        return []
    except (SupabaseAPIError, SupabaseClientError) as exc:
        raise _wrap(operation, exc) from exc


# ---------------------------------------------------------------------------
# Webhook Subscriptions
# ---------------------------------------------------------------------------


def create_webhook_subscription(record: dict[str, Any]) -> dict[str, Any]:
    operation = "create_webhook_subscription"
    if not record.get("tenant_id"):
        raise PersistenceError(operation, "record must include tenant_id")
    if not record.get("target_url"):
        raise PersistenceError(operation, "record must include target_url")
    try:
        client = get_supabase_service_client()
        if "created_at" not in record:
            record = {**record, "created_at": _now_utc()}
        resp = client.table(_T_WEBHOOK_SUBSCRIPTIONS).insert(record, returning="representation").execute()
        data = resp.data
        if isinstance(data, list):
            return data[0] if data else record
        if isinstance(data, dict):
            return data
        return record
    except (SupabaseAPIError, SupabaseClientError) as exc:
        raise _wrap(operation, exc) from exc


def list_webhook_subscriptions(
    tenant_id: str,
    *,
    active_only: bool = False,
    limit: int = 100,
    offset: int = 0,
) -> list[dict[str, Any]]:
    operation = "list_webhook_subscriptions"
    if not tenant_id:
        raise PersistenceError(operation, "tenant_id is required")
    try:
        client = get_supabase_service_client()
        q = client.table(_T_WEBHOOK_SUBSCRIPTIONS).select("*").eq("tenant_id", tenant_id)
        if active_only:
            q = q.eq("active", True)
        q = q.order("created_at", desc=True).range(offset, offset + limit - 1)
        resp = q.execute()
        data = resp.data
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return [data]
        return []
    except (SupabaseAPIError, SupabaseClientError) as exc:
        raise _wrap(operation, exc) from exc


def get_webhook_subscription(subscription_id: str, tenant_id: str) -> dict[str, Any] | None:
    operation = "get_webhook_subscription"
    if not subscription_id:
        raise PersistenceError(operation, "subscription_id is required")
    if not tenant_id:
        raise PersistenceError(operation, "tenant_id is required")
    try:
        client = get_supabase_service_client()
        resp = client.table(_T_WEBHOOK_SUBSCRIPTIONS).select("*").eq("id", subscription_id).eq("tenant_id", tenant_id).maybe_single().execute()
        data = resp.data
        if isinstance(data, dict) and data:
            return data
        if isinstance(data, list):
            return data[0] if data else None
        return None
    except (SupabaseAPIError, SupabaseClientError) as exc:
        raise _wrap(operation, exc) from exc


def update_webhook_subscription(subscription_id: str, tenant_id: str, updates: dict[str, Any]) -> dict[str, Any] | None:
    operation = "update_webhook_subscription"
    if not subscription_id:
        raise PersistenceError(operation, "subscription_id is required")
    if not tenant_id:
        raise PersistenceError(operation, "tenant_id is required")
    try:
        client = get_supabase_service_client()
        updates = {**updates, "updated_at": _now_utc()}
        resp = client.table(_T_WEBHOOK_SUBSCRIPTIONS).update(updates, returning="representation").eq("id", subscription_id).eq("tenant_id", tenant_id).execute()
        data = resp.data
        if isinstance(data, list):
            return data[0] if data else None
        if isinstance(data, dict) and data:
            return data
        return None
    except (SupabaseAPIError, SupabaseClientError) as exc:
        raise _wrap(operation, exc) from exc


def delete_webhook_subscription(subscription_id: str, tenant_id: str) -> None:
    operation = "delete_webhook_subscription"
    if not subscription_id:
        raise PersistenceError(operation, "subscription_id is required")
    if not tenant_id:
        raise PersistenceError(operation, "tenant_id is required")
    try:
        client = get_supabase_service_client()
        client.table(_T_WEBHOOK_SUBSCRIPTIONS).delete().eq("id", subscription_id).eq("tenant_id", tenant_id).execute()
    except (SupabaseAPIError, SupabaseClientError) as exc:
        raise _wrap(operation, exc) from exc


# ---------------------------------------------------------------------------
# Webhook Delivery Log  (table: webhook_delivery_log)
# Used by webhook_service and webhooks router for delivery tracking.
# ---------------------------------------------------------------------------


def get_webhook_delivery_log(
    tenant_id: str,
    *,
    subscription_id: str | None = None,
    event_type: str | None = None,
    delivery_status: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[dict[str, Any]]:
    operation = "get_webhook_delivery_log"
    if not tenant_id:
        raise PersistenceError(operation, "tenant_id is required")
    try:
        client = get_supabase_service_client()
        q = client.table(_T_WEBHOOK_DELIVERY_LOG).select("*").eq("tenant_id", tenant_id)
        if subscription_id:
            q = q.eq("subscription_id", subscription_id)
        if event_type:
            q = q.eq("event_type", event_type)
        if delivery_status:
            q = q.eq("status", delivery_status)
        q = q.order("created_at", desc=True).range(offset, offset + limit - 1)
        resp = q.execute()
        data = resp.data
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return [data]
        return []
    except (SupabaseAPIError, SupabaseClientError) as exc:
        raise _wrap(operation, exc) from exc


def get_webhook_delivery_record(delivery_id: str) -> dict[str, Any] | None:
    operation = "get_webhook_delivery_record"
    if not delivery_id:
        raise PersistenceError(operation, "delivery_id is required")
    try:
        client = get_supabase_service_client()
        resp = client.table(_T_WEBHOOK_DELIVERY_LOG).select("*").eq("id", delivery_id).maybe_single().execute()
        data = resp.data
        if isinstance(data, dict) and data:
            return data
        if isinstance(data, list):
            return data[0] if data else None
        return None
    except (SupabaseAPIError, SupabaseClientError) as exc:
        raise _wrap(operation, exc) from exc


# ---------------------------------------------------------------------------
# Webhook Deliveries  (table: webhook_deliveries)
# Used for full delivery CRUD / upsert operations by webhook_service.
# ---------------------------------------------------------------------------


def list_webhook_deliveries(
    tenant_id: str,
    *,
    subscription_id: str | None = None,
    status: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[dict[str, Any]]:
    operation = "list_webhook_deliveries"
    if not tenant_id:
        raise PersistenceError(operation, "tenant_id is required")
    try:
        client = get_supabase_service_client()
        q = client.table(_T_WEBHOOK_DELIVERIES).select("*").eq("tenant_id", tenant_id)
        if subscription_id:
            q = q.eq("subscription_id", subscription_id)
        if status:
            q = q.eq("status", status)
        q = q.order("created_at", desc=True).range(offset, offset + limit - 1)
        resp = q.execute()
        data = resp.data
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return [data]
        return []
    except (SupabaseAPIError, SupabaseClientError) as exc:
        raise _wrap(operation, exc) from exc


def list_retryable_webhook_deliveries(
    tenant_id: str,
    *,
    limit: int = 100,
    offset: int = 0,
) -> list[dict[str, Any]]:
    operation = "list_retryable_webhook_deliveries"
    if not tenant_id:
        raise PersistenceError(operation, "tenant_id is required")
    try:
        client = get_supabase_service_client()
        resp = client.table(_T_WEBHOOK_DELIVERIES).select("*").eq("tenant_id", tenant_id).eq("status", "failed").order("created_at", desc=True).range(offset, offset + limit - 1).execute()
        data = resp.data
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return [data]
        return []
    except (SupabaseAPIError, SupabaseClientError) as exc:
        raise _wrap(operation, exc) from exc


def get_webhook_delivery(delivery_id: str, tenant_id: str) -> dict[str, Any] | None:
    operation = "get_webhook_delivery"
    if not delivery_id:
        raise PersistenceError(operation, "delivery_id is required")
    if not tenant_id:
        raise PersistenceError(operation, "tenant_id is required")
    try:
        client = get_supabase_service_client()
        resp = client.table(_T_WEBHOOK_DELIVERIES).select("*").eq("id", delivery_id).eq("tenant_id", tenant_id).maybe_single().execute()
        data = resp.data
        if isinstance(data, dict) and data:
            return data
        if isinstance(data, list):
            return data[0] if data else None
        return None
    except (SupabaseAPIError, SupabaseClientError) as exc:
        raise _wrap(operation, exc) from exc


def upsert_webhook_delivery(record: dict[str, Any]) -> dict[str, Any]:
    operation = "upsert_webhook_delivery"
    if not record.get("id"):
        raise PersistenceError(operation, "record must include id")
    if not record.get("tenant_id"):
        raise PersistenceError(operation, "record must include tenant_id")
    try:
        client = get_supabase_service_client()
        if "created_at" not in record:
            record = {**record, "created_at": _now_utc()}
        resp = client.table(_T_WEBHOOK_DELIVERIES).upsert(record, on_conflict="id", returning="representation").execute()
        data = resp.data
        if isinstance(data, list):
            return data[0] if data else record
        if isinstance(data, dict):
            return data
        return record
    except (SupabaseAPIError, SupabaseClientError) as exc:
        raise _wrap(operation, exc) from exc


def update_webhook_delivery(delivery_id: str, updates: dict[str, Any]) -> dict[str, Any] | None:
    operation = "update_webhook_delivery"
    if not delivery_id:
        raise PersistenceError(operation, "delivery_id is required")
    try:
        client = get_supabase_service_client()
        resp = client.table(_T_WEBHOOK_DELIVERIES).update(updates, returning="representation").eq("id", delivery_id).execute()
        data = resp.data
        if isinstance(data, list):
            return data[0] if data else None
        if isinstance(data, dict) and data:
            return data
        return None
    except (SupabaseAPIError, SupabaseClientError) as exc:
        raise _wrap(operation, exc) from exc


# ---------------------------------------------------------------------------
# Public surface
# ---------------------------------------------------------------------------


__all__ = [
    "PersistenceError",
    "upsert_scan",
    "get_scan_by_id",
    "list_scans",
    "upsert_audit_event",
    "upsert_telemetry",
    "upsert_quarantine_item",
    "get_review_queue",
    "upsert_ioc",
    "upsert_threat_detection",
    "get_policy_set",
    "get_scan_patterns",
    "get_rate_limit_state",
    "delete_rate_limit_state",
    "log_tool_call",
    "log_sandbox_execution",
    "get_agent_trust_profile",
    "upsert_agent_trust_profile",
    "insert_trust_event",
    "list_trust_events",
    # Webhook Subscriptions
    "create_webhook_subscription",
    "list_webhook_subscriptions",
    "get_webhook_subscription",
    "update_webhook_subscription",
    "delete_webhook_subscription",
    # Webhook Delivery Log
    "get_webhook_delivery_log",
    "get_webhook_delivery_record",
    # Webhook Deliveries
    "list_webhook_deliveries",
    "list_retryable_webhook_deliveries",
    "get_webhook_delivery",
    "upsert_webhook_delivery",
    "update_webhook_delivery",
]
