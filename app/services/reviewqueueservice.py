from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any


REVIEW_QUEUE_PATH = Path("review_queue.json")
_REVIEW_QUEUE_LOCK = threading.RLock()

_ALLOWED_STATUSES = {
    "pending",
    "in_review",
    "approved",
    "rejected",
    "resolved",
}

_ALLOWED_PRIORITIES = {
    "low",
    "medium",
    "high",
    "critical",
}


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc) if value.tzinfo else value.replace(tzinfo=timezone.utc)

    text = str(value).strip() if value is not None else ""
    if not text:
        return datetime.min.replace(tzinfo=timezone.utc)

    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        parsed = datetime.fromisoformat(text)
        return parsed.astimezone(timezone.utc) if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return datetime.min.replace(tzinfo=timezone.utc)


def _normalize_list_field(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return list(value)
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _coerce_record(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return dict(value)

    if hasattr(value, "model_dump") and callable(value.model_dump):
        dumped = value.model_dump()
        if isinstance(dumped, dict):
            return dict(dumped)

    if hasattr(value, "dict") and callable(value.dict):
        dumped = value.dict()
        if isinstance(dumped, dict):
            return dict(dumped)

    if hasattr(value, "__dict__"):
        return {
            str(key): item
            for key, item in vars(value).items()
            if not str(key).startswith("_") and not callable(item)
        }

    return dict(value)


def _load_queue() -> list[dict[str, Any]]:
    if not REVIEW_QUEUE_PATH.exists():
        return []

    try:
        data = json.loads(REVIEW_QUEUE_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []

    if not isinstance(data, list):
        return []

    items: list[dict[str, Any]] = []
    for item in data:
        if isinstance(item, dict):
            items.append(dict(item))
    return items


def _save_queue(items: list[dict[str, Any]]) -> None:
    REVIEW_QUEUE_PATH.parent.mkdir(parents=True, exist_ok=True)
    temp_path: Path | None = None

    try:
        with NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=str(REVIEW_QUEUE_PATH.parent),
            delete=False,
        ) as temp_file:
            json.dump(items, temp_file, ensure_ascii=False, indent=2)
            temp_file.flush()
            temp_path = Path(temp_file.name)

        temp_path.replace(REVIEW_QUEUE_PATH)
    finally:
        if temp_path is not None and temp_path.exists():
            try:
                temp_path.unlink()
            except OSError:
                pass


def _normalize_status(value: Any) -> str:
    status = str(value).strip().lower() if value is not None else ""
    return status if status in _ALLOWED_STATUSES else "pending"


def _normalize_priority(value: Any) -> str:
    priority = str(value).strip().lower() if value is not None else ""
    return priority if priority in _ALLOWED_PRIORITIES else "medium"


def _normalize_record(record: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(record)

    review_id = normalized.get("review_id") or normalized.get("id")
    if review_id is not None:
        review_id = str(review_id).strip()
    normalized["review_id"] = review_id or None

    scan_id = normalized.get("scan_id")
    if scan_id is not None:
        scan_id = str(scan_id).strip()
    normalized["scan_id"] = scan_id or None

    verdict = normalized.get("verdict")
    if verdict is not None:
        verdict = str(verdict).strip().lower()
    normalized["verdict"] = verdict or None

    created_at = normalized.get("created_at") or normalized.get("timestamp")
    updated_at = normalized.get("updated_at")

    if not created_at:
        created_at = _utc_now_iso()
    if not updated_at:
        updated_at = created_at

    normalized["created_at"] = str(created_at)
    normalized["updated_at"] = str(updated_at)
    normalized["timestamp"] = normalized["created_at"]

    normalized["status"] = _normalize_status(normalized.get("status"))
    normalized["priority"] = _normalize_priority(normalized.get("priority"))

    normalized["queue"] = str(normalized.get("queue") or "default").strip() or "default"
    normalized["source"] = str(normalized.get("source") or "scan").strip() or "scan"
    normalized["summary"] = str(normalized.get("summary") or "").strip()
    normalized["title"] = str(normalized.get("title") or normalized["summary"] or "Review item").strip()
    normalized["owner"] = normalized.get("owner")
    normalized["assigned_to"] = normalized.get("assigned_to")
    normalized["decision"] = normalized.get("decision")
    normalized["decision_reason"] = normalized.get("decision_reason")
    normalized["quarantine_reason"] = normalized.get("quarantine_reason")

    normalized["matched_patterns"] = _normalize_list_field(normalized.get("matched_patterns"))
    normalized["risky_files"] = _normalize_list_field(normalized.get("risky_files"))
    normalized["checks_loaded"] = _normalize_list_field(normalized.get("checks_loaded"))
    normalized["failed_checks"] = _normalize_list_field(normalized.get("failed_checks"))
    normalized["tags"] = [str(tag) for tag in _normalize_list_field(normalized.get("tags"))]
    normalized["notes"] = [str(note) for note in _normalize_list_field(normalized.get("notes"))]
    normalized["artifacts"] = _normalize_list_field(normalized.get("artifacts"))

    metadata = normalized.get("metadata")
    normalized["metadata"] = dict(metadata) if isinstance(metadata, dict) else {}

    if normalized.get("status") in {"approved", "rejected", "resolved"}:
        normalized.setdefault("resolved_at", normalized["updated_at"])
    else:
        normalized["resolved_at"] = normalized.get("resolved_at")

    return normalized


def _priority_rank(priority: str) -> int:
    return {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
    }.get(priority, 2)


def _sort_queue_items(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        items,
        key=lambda item: (
            item.get("status") not in {"pending", "in_review"},
            _priority_rank(str(item.get("priority", "medium"))),
            -_parse_timestamp(item.get("updated_at")).timestamp(),
        ),
    )


def enqueue_review_item(item: Any) -> dict[str, Any]:
    record = _normalize_record(_coerce_record(item))

    with _REVIEW_QUEUE_LOCK:
        items = _load_queue()

        review_id = record.get("review_id")
        scan_id = record.get("scan_id")
        replaced = False

        if review_id:
            for idx, existing in enumerate(items):
                if existing.get("review_id") == review_id:
                    record["created_at"] = existing.get("created_at") or record["created_at"]
                    record["updated_at"] = _utc_now_iso()
                    record["timestamp"] = record["created_at"]
                    items[idx] = _normalize_record(record)
                    replaced = True
                    break

        if not replaced and scan_id:
            for idx, existing in enumerate(items):
                if existing.get("scan_id") == scan_id:
                    record["review_id"] = existing.get("review_id") or review_id
                    record["created_at"] = existing.get("created_at") or record["created_at"]
                    record["updated_at"] = _utc_now_iso()
                    record["timestamp"] = record["created_at"]
                    items[idx] = _normalize_record(record)
                    replaced = True
                    break

        if not replaced:
            record["updated_at"] = record.get("updated_at") or _utc_now_iso()
            items.append(_normalize_record(record))

        _save_queue(items)

    return _normalize_record(record)


def list_review_queue(
    *,
    limit: int = 50,
    status: str | None = None,
    priority: str | None = None,
    assigned_to: str | None = None,
    queue: str | None = None,
) -> dict[str, Any]:
    safe_limit = max(0, int(limit))

    with _REVIEW_QUEUE_LOCK:
        items = [_normalize_record(item) for item in _load_queue()]

    if status:
        wanted_status = _normalize_status(status)
        items = [item for item in items if item.get("status") == wanted_status]

    if priority:
        wanted_priority = _normalize_priority(priority)
        items = [item for item in items if item.get("priority") == wanted_priority]

    if assigned_to:
        wanted_assignee = str(assigned_to).strip()
        items = [item for item in items if str(item.get("assigned_to") or "").strip() == wanted_assignee]

    if queue:
        wanted_queue = str(queue).strip()
        items = [item for item in items if str(item.get("queue") or "").strip() == wanted_queue]

    ordered = _sort_queue_items(items)
    visible = ordered[:safe_limit] if safe_limit else []

    return {
        "count": len(visible),
        "items": visible,
    }


def get_review_item_by_id(review_id: str) -> dict[str, Any] | None:
    if not review_id:
        return None

    wanted = str(review_id).strip()
    if not wanted:
        return None

    with _REVIEW_QUEUE_LOCK:
        items = _load_queue()

    for item in items:
        if str(item.get("review_id") or "").strip() == wanted:
            return _normalize_record(item)

    return None


def get_review_item_by_scan_id(scan_id: str) -> dict[str, Any] | None:
    if not scan_id:
        return None

    wanted = str(scan_id).strip()
    if not wanted:
        return None

    with _REVIEW_QUEUE_LOCK:
        items = _load_queue()

    for item in items:
        if str(item.get("scan_id") or "").strip() == wanted:
            return _normalize_record(item)

    return None


def update_review_item(review_id: str, updates: dict[str, Any]) -> dict[str, Any] | None:
    if not review_id:
        return None

    wanted = str(review_id).strip()
    if not wanted:
        return None

    with _REVIEW_QUEUE_LOCK:
        items = _load_queue()
        updated_item: dict[str, Any] | None = None

        for idx, item in enumerate(items):
            if str(item.get("review_id") or "").strip() == wanted:
                merged = {**item, **dict(updates)}
                merged["review_id"] = item.get("review_id")
                merged["created_at"] = item.get("created_at") or merged.get("created_at")
                merged["updated_at"] = _utc_now_iso()
                normalized = _normalize_record(merged)
                items[idx] = normalized
                updated_item = normalized
                break

        if updated_item is not None:
            _save_queue(items)

    return updated_item


def assign_review_item(review_id: str, assigned_to: str | None) -> dict[str, Any] | None:
    payload: dict[str, Any] = {
        "assigned_to": str(assigned_to).strip() if assigned_to else None,
    }
    if assigned_to:
        payload["status"] = "in_review"
    return update_review_item(review_id, payload)


def add_review_note(review_id: str, note: str) -> dict[str, Any] | None:
    if not review_id:
        return None

    clean_note = str(note).strip()
    if not clean_note:
        return get_review_item_by_id(review_id)

    with _REVIEW_QUEUE_LOCK:
        items = _load_queue()
        updated_item: dict[str, Any] | None = None

        for idx, item in enumerate(items):
            if str(item.get("review_id") or "").strip() == str(review_id).strip():
                normalized = _normalize_record(item)
                notes = list(normalized.get("notes", []))
                notes.append(clean_note)
                normalized["notes"] = notes
                normalized["updated_at"] = _utc_now_iso()
                normalized = _normalize_record(normalized)
                items[idx] = normalized
                updated_item = normalized
                break

        if updated_item is not None:
            _save_queue(items)

    return updated_item


def resolve_review_item(
    review_id: str,
    *,
    decision: str,
    decision_reason: str | None = None,
    resolved_by: str | None = None,
) -> dict[str, Any] | None:
    normalized_decision = str(decision).strip().lower()
    status = "approved" if normalized_decision in {"approve", "approved", "allow"} else "rejected"
    return update_review_item(
        review_id,
        {
            "decision": normalized_decision,
            "decision_reason": str(decision_reason).strip() if decision_reason else None,
            "owner": str(resolved_by).strip() if resolved_by else None,
            "status": status,
            "resolved_at": _utc_now_iso(),
        },
    )


def remove_review_item(review_id: str) -> bool:
    if not review_id:
        return False

    wanted = str(review_id).strip()
    if not wanted:
        return False

    with _REVIEW_QUEUE_LOCK:
        items = _load_queue()
        remaining = [
            item for item in items
            if str(item.get("review_id") or "").strip() != wanted
        ]

        if len(remaining) == len(items):
            return False

        _save_queue(remaining)

    return True


def get_review_queue_summary() -> dict[str, Any]:
    with _REVIEW_QUEUE_LOCK:
        items = [_normalize_record(item) for item in _load_queue()]

    pending = 0
    in_review = 0
    resolved = 0
    critical = 0
    high = 0

    for item in items:
        status = item.get("status")
        priority = item.get("priority")

        if status == "pending":
            pending += 1
        elif status == "in_review":
            in_review += 1
        elif status in {"approved", "rejected", "resolved"}:
            resolved += 1

        if priority == "critical":
            critical += 1
        elif priority == "high":
            high += 1

    ordered = _sort_queue_items(items)

    return {
        "count": len(items),
        "pending": pending,
        "in_review": in_review,
        "resolved": resolved,
        "critical": critical,
        "high": high,
        "items": ordered[:10],
    }


def reset_review_queue() -> None:
    with _REVIEW_QUEUE_LOCK:
        if REVIEW_QUEUE_PATH.exists():
            REVIEW_QUEUE_PATH.unlink()