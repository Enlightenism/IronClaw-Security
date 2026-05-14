from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def _safe_int(value: Any, default: int = 0) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def _safe_str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    if isinstance(value, str):
        return value
    return str(value)


def _safe_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    return {}


def _mask_secret(secret: str) -> str:
    cleaned = secret.strip()
    if not cleaned:
        return ""
    if len(cleaned) <= 8:
        return f"{cleaned[:2]}...{cleaned[-2:]}" if len(cleaned) > 4 else "****"
    return f"{cleaned[:4]}...{cleaned[-4:]}"


def _normalize_key(record: Mapping[str, Any]) -> dict[str, Any]:
    metadata = _safe_dict(record.get("metadata"))
    return {
        "key_id": _safe_str(
            record.get("key_id") or record.get("keyid") or record.get("id") or metadata.get("key_id"),
        ),
        "display_name": _safe_str(
            record.get("display_name") or record.get("displayname") or record.get("name") or metadata.get("display_name") or metadata.get("name") or "Unnamed key",
        ),
        "masked_key": _safe_str(
            record.get("masked_key") or record.get("maskedkey") or record.get("key_preview") or record.get("preview") or record.get("last4"),
        ),
        "created_at": _safe_str(
            record.get("created_at") or record.get("createdat") or record.get("created") or record.get("timestamp"),
        ),
        "last_used_at": (
            _safe_str(
                record.get("last_used_at") or record.get("lastusedat") or record.get("last_used") or record.get("last_seen_at"),
            )
            or None
        ),
        "active": bool(record.get("active", True)),
        "metadata": metadata,
    }


def _build_empty_state(now_iso: str) -> dict[str, Any]:
    return {
        "status": "ok",
        "service": "ironclaw-ui",
        "timestamp": now_iso,
        "page": {
            "id": "customer-keys",
            "title": "Customer Keys",
            "description": "Manage customer API keys for protected IronClaw access.",
            "path": "/ui/customer-keys",
            "section": "access",
        },
        "summary": {
            "total_keys": 0,
            "active_keys": 0,
            "revoked_keys": 0,
            "keys_used_7d": 0,
        },
        "filters": {
            "available_statuses": ["active", "revoked"],
            "default_status": "all",
            "selected_status": "all",
        },
        "actions": {
            "create": {
                "label": "Create key",
                "method": "POST",
                "path": "/customer-keys",
            },
        },
        "keys": [],
        "empty_state": {
            "title": "No customer keys created",
            "description": "Create a customer API key to start protected access flows.",
            "action": {
                "label": "Create first key",
                "method": "POST",
                "path": "/customer-keys",
            },
        },
    }


def build_customer_keys_view(
    customer_keys_response: Mapping[str, Any] | None,
    *,
    selected_status: str = "all",
) -> dict[str, Any]:
    source = _safe_dict(customer_keys_response)
    now_iso = _safe_str(source.get("timestamp"))
    base = _build_empty_state(now_iso)

    raw_keys = source.get("keys")
    if not isinstance(raw_keys, list):
        return base

    normalized_keys = [_normalize_key(item) for item in raw_keys if isinstance(item, Mapping)]

    status_filter = _safe_str(selected_status, "all").strip().lower() or "all"
    if status_filter == "active":
        filtered_keys = [item for item in normalized_keys if item["active"]]
    elif status_filter == "revoked":
        filtered_keys = [item for item in normalized_keys if not item["active"]]
    else:
        filtered_keys = normalized_keys

    active_count = sum(1 for item in normalized_keys if item["active"])
    revoked_count = max(len(normalized_keys) - active_count, 0)
    used_7d_count = sum(1 for item in normalized_keys if item["last_used_at"])

    keys = []
    for item in filtered_keys:
        metadata = item["metadata"]
        scopes = metadata.get("scopes")
        environments = metadata.get("environments")
        if not isinstance(scopes, list):
            scopes = []
        if not isinstance(environments, list):
            environments = []

        keys.append(
            {
                "key_id": item["key_id"],
                "display_name": item["display_name"],
                "masked_key": item["masked_key"] or _mask_secret(item["key_id"]),
                "created_at": item["created_at"],
                "last_used_at": item["last_used_at"],
                "active": item["active"],
                "status": "active" if item["active"] else "revoked",
                "detail_path": (f"/ui/customer-keys/{item['key_id']}" if item["key_id"] else None),
                "scopes": [str(scope) for scope in scopes],
                "environments": [str(environment) for environment in environments],
                "metadata": metadata,
                "actions": {
                    "view": {
                        "label": "View details",
                        "method": "GET",
                        "path": (f"/ui/customer-keys/{item['key_id']}" if item["key_id"] else None),
                    },
                    "revoke": {
                        "label": "Revoke key",
                        "method": "POST",
                        "path": (f"/customer-keys/{item['key_id']}/revoke" if item["key_id"] and item["active"] else None),
                        "enabled": bool(item["key_id"] and item["active"]),
                    },
                },
            },
        )

    base["timestamp"] = now_iso or base["timestamp"]
    base["service"] = _safe_str(source.get("service"), "ironclaw-ui")
    base["summary"] = {
        "total_keys": _safe_int(source.get("total_keys"), len(normalized_keys)),
        "active_keys": active_count,
        "revoked_keys": revoked_count,
        "keys_used_7d": used_7d_count,
    }
    base["filters"]["selected_status"] = status_filter
    base["keys"] = keys
    base["empty_state"] = (
        {
            "title": "No matching keys",
            "description": "No customer keys match the selected filter.",
            "action": {
                "label": "Clear filter",
                "method": "GET",
                "path": "/ui/customer-keys",
            },
        }
        if not keys and normalized_keys
        else base["empty_state"]
    )
    return base
