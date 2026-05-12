from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from threading import RLock
from typing import Any, Protocol, cast


class ScanHistoryRepository(Protocol):
    def list_items(self) -> list[dict[str, Any]]: ...
    def get_by_scan_id(self, scan_id: str) -> dict[str, Any] | None: ...
    def upsert(self, record: dict[str, Any]) -> dict[str, Any]: ...
    def update(self, scan_id: str, updates: dict[str, Any]) -> dict[str, Any] | None: ...
    def reset(self) -> None: ...


class _InMemoryScanHistoryRepository:
    def __init__(self) -> None:
        self._lock = RLock()
        self._items: list[dict[str, Any]] = []

    def list_items(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(item) for item in self._items]

    def get_by_scan_id(self, scan_id: str) -> dict[str, Any] | None:
        if not scan_id:
            return None
        with self._lock:
            for item in self._items:
                if item.get("scan_id") == scan_id:
                    return dict(item)
        return None

    def upsert(self, record: dict[str, Any]) -> dict[str, Any]:
        stored = dict(record)
        scan_id = stored.get("scan_id")

        with self._lock:
            if scan_id:
                for idx, item in enumerate(self._items):
                    if item.get("scan_id") == scan_id:
                        self._items[idx] = stored
                        return dict(stored)
            self._items.append(stored)
            return dict(stored)

    def update(self, scan_id: str, updates: dict[str, Any]) -> dict[str, Any] | None:
        if not scan_id:
            return None

        with self._lock:
            for idx, item in enumerate(self._items):
                if item.get("scan_id") == scan_id:
                    merged = {**item, **dict(updates)}
                    self._items[idx] = merged
                    return dict(merged)
        return None

    def reset(self) -> None:
        with self._lock:
            self._items.clear()


_REPOSITORY: ScanHistoryRepository = _InMemoryScanHistoryRepository()


def set_scan_history_repository(repository: ScanHistoryRepository) -> None:
    global _REPOSITORY
    _REPOSITORY = repository


def reset_scan_history_repository() -> None:
    global _REPOSITORY
    _REPOSITORY = _InMemoryScanHistoryRepository()


def _get_repository() -> ScanHistoryRepository:
    return _REPOSITORY


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _parse_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)

    text = str(value).strip() if value is not None else ""
    if not text:
        return datetime.min.replace(tzinfo=UTC)

    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        parsed = datetime.fromisoformat(text)
        return parsed.astimezone(UTC) if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    except ValueError:
        return datetime.min.replace(tzinfo=UTC)


def _normalize_list_field(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return list(value)
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _coerce_record(result: Any) -> dict[str, Any]:
    if isinstance(result, dict):
        return dict(result)

    if isinstance(result, Mapping):
        return dict(result)

    model_dump = getattr(result, "model_dump", None)
    if callable(model_dump):
        dumped = model_dump()
        if isinstance(dumped, Mapping):
            return dict(dumped)

    legacy_dict = getattr(result, "dict", None)
    if callable(legacy_dict):
        dumped = legacy_dict()
        if isinstance(dumped, Mapping):
            return dict(dumped)

    if hasattr(result, "__dict__"):
        return {
            str(key): value
            for key, value in vars(result).items()
            if not str(key).startswith("_") and not callable(value)
        }

    raise TypeError("result is not serializable to dict")


def _normalize_record(record: Mapping[str, Any]) -> dict[str, Any]:
    normalized = dict(record)

    if normalized.get("timestamp") is None:
        normalized["timestamp"] = _utc_now_iso()

    if normalized.get("scan_id") is None and normalized.get("scanid") is not None:
        normalized["scan_id"] = normalized.get("scanid")

    if normalized.get("risk_score") is None and normalized.get("riskscore") is not None:
        normalized["risk_score"] = normalized.get("riskscore")

    normalized["matched_patterns"] = _normalize_list_field(normalized.get("matched_patterns"))
    normalized["risky_files"] = _normalize_list_field(normalized.get("risky_files"))
    normalized["checks_loaded"] = _normalize_list_field(normalized.get("checks_loaded"))
    normalized["failed_checks"] = _normalize_list_field(normalized.get("failed_checks"))
    normalized.setdefault("quarantine_reason", None)

    verdict = str(normalized.get("verdict") or "").strip().lower()
    if normalized.get("review_status") is None:
        normalized["review_status"] = "pending" if verdict == "quarantine" else "none"

    if normalized.get("untrusted") is None:
        normalized["untrusted"] = verdict == "quarantine"
    else:
        normalized["untrusted"] = bool(normalized.get("untrusted"))

    risk_score = normalized.get("risk_score")
    if risk_score is not None:
        try:
            normalized["risk_score"] = max(0, min(100, int(risk_score)))
        except (TypeError, ValueError):
            normalized["risk_score"] = 0

    return normalized


def append_scan_result(result: Any) -> dict[str, Any]:
    record = _normalize_record(_coerce_record(result))
    stored = _get_repository().upsert(record)
    return _normalize_record(stored)


def read_scan_history(limit: int = 20) -> dict[str, Any]:
    safe_limit = max(0, int(limit))
    items = [_normalize_record(item) for item in _get_repository().list_items()]
    items.sort(key=lambda item: _parse_timestamp(item.get("timestamp")), reverse=True)
    recent = items[:safe_limit] if safe_limit else []
    return {
        "count": len(recent),
        "items": recent,
    }


def get_scan_by_id(scan_id: str) -> dict[str, Any] | None:
    if not scan_id:
        return None

    item = _get_repository().get_by_scan_id(scan_id)
    if item is None:
        return None
    return _normalize_record(item)


def update_scan_by_id(scan_id: str, updates: dict[str, Any]) -> dict[str, Any] | None:
    if not scan_id:
        return None

    current = _get_repository().get_by_scan_id(scan_id)
    if current is None:
        return None

    merged = _normalize_record({**current, **dict(updates)})
    updated = _get_repository().upsert(merged)
    return _normalize_record(updated)


def reset_scan_history() -> None:
    _get_repository().reset()


# Backward-compatible aliases for older imports/tests if any still reference them.
appendscanresult = append_scan_result
readscanhistory = read_scan_history
getscanbyid = get_scan_by_id
updatescanbyid = update_scan_by_id
resetscanhistory = reset_scan_history


def get_history_items(limit: int = 20) -> list[dict[str, Any]]:
    return cast(list[dict[str, Any]], read_scan_history(limit=limit).get("items", []))


def get_history_item(scan_id: str) -> dict[str, Any] | None:
    return get_scan_by_id(scan_id)


def review_scan(scan_id: str, action: str) -> dict[str, Any] | None:
    item = get_scan_by_id(scan_id)
    if item is None:
        raise KeyError(scan_id)

    verdict = str(item.get("verdict") or "").strip().lower()
    if verdict != "quarantine":
        return None

    approved = str(action).strip().lower() == "approve"
    summary = str(item.get("summary") or "").strip()
    review_suffix = f"Review action: {'approve' if approved else 'reject'}."
    if summary:
        if not summary.endswith(review_suffix):
            summary = f"{summary} {review_suffix}"
    else:
        summary = review_suffix

    updates = {
        "review_status": "approved" if approved else "rejected",
        "untrusted": not approved,
        "verdict": "allow" if approved else "block",
        "summary": summary,
    }
    return update_scan_by_id(scan_id, updates)


def apply_review_action(item: Mapping[str, Any], action: str) -> dict[str, Any]:
    approved = str(action).strip().lower() == "approve"
    updated = dict(item)
    updated["review_status"] = "approved" if approved else "rejected"
    updated["untrusted"] = not approved
    updated["verdict"] = "allow" if approved else "block"
    summary = str(updated.get("summary") or "").strip()
    review_suffix = f"Review action: {'approve' if approved else 'reject'}."
    if summary:
        if not summary.endswith(review_suffix):
            updated["summary"] = f"{summary} {review_suffix}"
    else:
        updated["summary"] = review_suffix
    return _normalize_record(updated)


gethistoryitems = get_history_items
gethistoryitem = get_history_item
reviewscan = review_scan
applyreviewaction = apply_review_action