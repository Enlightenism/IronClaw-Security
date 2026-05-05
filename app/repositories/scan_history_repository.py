from __future__ import annotations

from typing import Any

from app.supabaseclient import (
    SupabaseAPIError,
    SupabaseClient,
    SupabaseConfigurationError,
    SupabaseConnectionError,
    createsupabaseclient,
)

TABLE_NAME = "scan_history"
MAX_LIST_LIMIT = 500
DEFAULT_LIST_LIMIT = 50


class ScanHistoryRepositoryError(Exception):
    pass


class ScanHistoryRepositoryConnectionError(ScanHistoryRepositoryError):
    pass


class ScanHistoryRepositoryAPIError(ScanHistoryRepositoryError):
    pass


def _translate_error(exc: Exception) -> None:
    if isinstance(exc, SupabaseConnectionError):
        raise ScanHistoryRepositoryConnectionError(str(exc)) from exc
    if isinstance(exc, SupabaseAPIError):
        raise ScanHistoryRepositoryAPIError(str(exc)) from exc
    if isinstance(exc, SupabaseConfigurationError):
        raise ScanHistoryRepositoryConnectionError(str(exc)) from exc
    raise exc


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return list(value)
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _clean_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _safe_int(value: Any, default: int | None = None) -> int | None:
    if value is None:
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _safe_limit(value: Any, *, default: int = DEFAULT_LIST_LIMIT) -> int:
    parsed = _safe_int(value, default)
    if parsed is None:
        parsed = default
    return max(1, min(parsed, MAX_LIST_LIMIT))


def _normalize_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return bool(value)
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off"}:
        return False
    return default


def _normalize_record(row: dict[str, Any]) -> dict[str, Any]:
    scan_id = _clean_text(row.get("scan_id") or row.get("scanid"))
    verdict = _clean_text(row.get("verdict"))
    review_status = _clean_text(row.get("review_status") or row.get("reviewstatus")) or "none"

    risk_score = _safe_int(row.get("risk_score", row.get("riskscore")), 0)
    if risk_score is not None:
        risk_score = max(0, min(100, risk_score))

    target_value = row.get("target_value", row.get("targetvalue"))
    if target_value is not None:
        target_value = str(target_value)[:5000]

    normalized = {
        "id": row.get("id"),
        "created_at": row.get("created_at") or row.get("createdat"),
        "scan_id": scan_id,
        "target_type": _clean_text(row.get("target_type") or row.get("targettype")),
        "target_value": target_value,
        "verdict": verdict,
        "risk_score": risk_score,
        "matched_patterns": _as_list(row.get("matched_patterns", row.get("matchedpatterns"))),
        "summary": _clean_text(row.get("summary")) or "",
        "risky_files": _as_list(row.get("risky_files", row.get("riskyfiles"))),
        "checks_loaded": _as_list(row.get("checks_loaded", row.get("checksloaded"))),
        "failed_checks": _as_list(row.get("failed_checks", row.get("failedchecks"))),
        "quarantine_reason": _clean_text(row.get("quarantine_reason") or row.get("quarantinereason")),
        "review_status": review_status,
        "reviewer": _clean_text(row.get("reviewer")),
        "reviewed_at": row.get("reviewed_at") or row.get("reviewedat"),
        "untrusted": _normalize_bool(row.get("untrusted"), default=verdict == "quarantine"),
        "sandbox_lane": _clean_text(row.get("sandbox_lane") or row.get("sandboxlane")) or "none",
        "timestamp": row.get("timestamp"),
        "max_severity": _clean_text(row.get("max_severity") or row.get("maxseverity")),
        "primary_category": _clean_text(row.get("primary_category") or row.get("primarycategory")),
        "explanation": _clean_text(row.get("explanation")),
        "source": _clean_text(row.get("source")),
        "session_id": _clean_text(row.get("session_id") or row.get("sessionid")),
        "user_id": _clean_text(row.get("user_id") or row.get("userid")),
        "context": row.get("context"),
    }

    return normalized


def _db_payload(record: dict[str, Any]) -> dict[str, Any]:
    normalized = _normalize_record(record)

    payload = {
        "scan_id": normalized["scan_id"],
        "target_type": normalized["target_type"],
        "target_value": normalized["target_value"],
        "verdict": normalized["verdict"],
        "risk_score": normalized["risk_score"],
        "matched_patterns": normalized["matched_patterns"],
        "summary": normalized["summary"],
        "risky_files": normalized["risky_files"],
        "checks_loaded": normalized["checks_loaded"],
        "failed_checks": normalized["failed_checks"],
        "quarantine_reason": normalized["quarantine_reason"],
        "review_status": normalized["review_status"],
        "reviewer": normalized["reviewer"],
        "reviewed_at": normalized["reviewed_at"],
        "untrusted": normalized["untrusted"],
        "sandbox_lane": normalized["sandbox_lane"],
        "timestamp": normalized["timestamp"],
        "max_severity": normalized["max_severity"],
        "primary_category": normalized["primary_category"],
        "explanation": normalized["explanation"],
        "source": normalized["source"],
        "session_id": normalized["session_id"],
        "user_id": normalized["user_id"],
        "context": normalized["context"],
    }

    if not payload["scan_id"]:
        raise ValueError("scan_id is required")
    if not payload["target_type"]:
        raise ValueError("target_type is required")
    if payload["target_value"] is None:
        raise ValueError("target_value is required")
    if not payload["verdict"]:
        raise ValueError("verdict is required")
    if payload["risk_score"] is None:
        payload["risk_score"] = 0

    return payload


class ScanHistoryRepository:
    def __init__(
        self,
        client: SupabaseClient | None = None,
        table_name: str = TABLE_NAME,
    ) -> None:
        self.client = client or createsupabaseclient()
        self.table_name = table_name

    def list_items(
        self,
        *,
        limit: int = DEFAULT_LIST_LIMIT,
        verdict: str | None = None,
        sandbox_lane: str | None = None,
        review_status: str | None = None,
        session_id: str | None = None,
        user_id: str | None = None,
    ) -> list[dict[str, Any]]:
        safe_limit = _safe_limit(limit)
        filters: dict[str, Any] = {}

        cleaned_verdict = _clean_text(verdict)
        cleaned_sandbox_lane = _clean_text(sandbox_lane)
        cleaned_review_status = _clean_text(review_status)
        cleaned_session_id = _clean_text(session_id)
        cleaned_user_id = _clean_text(user_id)

        if cleaned_verdict is not None:
            filters["verdict"] = cleaned_verdict
        if cleaned_sandbox_lane is not None:
            filters["sandbox_lane"] = cleaned_sandbox_lane
        if cleaned_review_status is not None:
            filters["review_status"] = cleaned_review_status
        if cleaned_session_id is not None:
            filters["session_id"] = cleaned_session_id
        if cleaned_user_id is not None:
            filters["user_id"] = cleaned_user_id

        try:
            result = self.client.select(
                self.table_name,
                filters=filters or None,
                limit=safe_limit,
                order=("timestamp", "desc"),
            )
        except Exception as exc:
            _translate_error(exc)

        if not isinstance(result, list):
            raise ScanHistoryRepositoryAPIError("Unexpected response format from scan_history list query.")

        return [_normalize_record(item) for item in result if isinstance(item, dict)]

    def get_by_scan_id(self, scan_id: str) -> dict[str, Any] | None:
        value = _clean_text(scan_id)
        if not value:
            return None

        try:
            result = self.client.select(
                self.table_name,
                filters={"scan_id": value},
                limit=1,
            )
        except Exception as exc:
            _translate_error(exc)

        if not isinstance(result, list):
            raise ScanHistoryRepositoryAPIError("Unexpected response format from scan_history lookup.")

        if not result:
            return None

        first = result[0]
        if not isinstance(first, dict):
            raise ScanHistoryRepositoryAPIError("Unexpected row format from scan_history lookup.")

        return _normalize_record(first)

    def upsert(self, record: dict[str, Any]) -> dict[str, Any]:
        payload = _db_payload(record)

        existing = self.get_by_scan_id(payload["scan_id"])
        if existing is None:
            try:
                result = self.client.insert(self.table_name, payload)
            except Exception as exc:
                _translate_error(exc)

            if isinstance(result, list) and result:
                first = result[0]
                if isinstance(first, dict):
                    return _normalize_record(first)

            if isinstance(result, dict):
                return _normalize_record(result)

            created = self.get_by_scan_id(payload["scan_id"])
            if created is not None:
                return created

            raise ScanHistoryRepositoryAPIError("Unexpected response format from scan_history insert.")

        try:
            result = self.client.update(
                self.table_name,
                payload=payload,
                filters={"scan_id": payload["scan_id"]},
            )
        except Exception as exc:
            _translate_error(exc)

        if isinstance(result, list) and result:
            first = result[0]
            if isinstance(first, dict):
                return _normalize_record(first)

        if isinstance(result, dict):
            return _normalize_record(result)

        refreshed = self.get_by_scan_id(payload["scan_id"])
        if refreshed is not None:
            return refreshed

        raise ScanHistoryRepositoryAPIError("Unexpected response format from scan_history upsert.")

    def update(self, scan_id: str, updates: dict[str, Any]) -> dict[str, Any] | None:
        value = _clean_text(scan_id)
        if not value:
            return None

        current = self.get_by_scan_id(value)
        if current is None:
            return None

        merged = {**current, **dict(updates)}
        payload = _db_payload(merged)
        payload["scan_id"] = value

        try:
            result = self.client.update(
                self.table_name,
                payload=payload,
                filters={"scan_id": value},
            )
        except Exception as exc:
            _translate_error(exc)

        if isinstance(result, list) and result:
            first = result[0]
            if isinstance(first, dict):
                return _normalize_record(first)

        if isinstance(result, dict):
            return _normalize_record(result)

        refreshed = self.get_by_scan_id(value)
        if refreshed is not None:
            return refreshed

        raise ScanHistoryRepositoryAPIError("Unexpected response format from scan_history update.")

    def reset(self) -> None:
        try:
            self.client.delete(
                self.table_name,
                filters={"id": "not.is.null"},
            )
        except Exception as exc:
            _translate_error(exc)


def build_scan_history_repository() -> ScanHistoryRepository:
    return ScanHistoryRepository()


def create_scan_history_repository() -> ScanHistoryRepository:
    return build_scan_history_repository()


def get_scan_history_repository() -> ScanHistoryRepository:
    return build_scan_history_repository()