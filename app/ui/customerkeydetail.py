from __future__ import annotations

from collections.abc import Mapping
from typing import Any


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


def _safe_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return []


def _mask_secret(secret: str) -> str:
    cleaned = secret.strip()
    if not cleaned:
        return ""
    if len(cleaned) <= 8:
        return f"{cleaned[:2]}...{cleaned[-2:]}" if len(cleaned) > 4 else "****"
    return f"{cleaned[:4]}...{cleaned[-4:]}"


def _normalize_string_list(value: Any) -> list[str]:
    return [str(item) for item in _safe_list(value) if str(item).strip()]


def _extract_key(record: Mapping[str, Any] | None) -> dict[str, Any]:
    payload = _safe_dict(record)
    metadata = _safe_dict(payload.get("metadata"))

    key_id = _safe_str(
        payload.get("key_id") or payload.get("keyid") or payload.get("id") or metadata.get("key_id"),
    )
    display_name = _safe_str(
        payload.get("display_name") or payload.get("displayname") or payload.get("name") or metadata.get("display_name") or metadata.get("name") or "Unnamed key",
    )
    masked_key = _safe_str(
        payload.get("masked_key") or payload.get("maskedkey") or payload.get("key_preview") or payload.get("preview") or payload.get("last4"),
    )
    created_at = _safe_str(
        payload.get("created_at") or payload.get("createdat") or payload.get("created") or payload.get("timestamp"),
    )
    last_used_at = _safe_str(
        payload.get("last_used_at") or payload.get("lastusedat") or payload.get("last_used") or payload.get("last_seen_at"),
    )
    active = bool(payload.get("active", True))

    scopes = _normalize_string_list(
        payload.get("scopes") or metadata.get("scopes") or metadata.get("permissions"),
    )
    environments = _normalize_string_list(
        payload.get("environments") or metadata.get("environments"),
    )
    tags = _normalize_string_list(payload.get("tags") or metadata.get("tags"))

    return {
        "key_id": key_id,
        "display_name": display_name,
        "masked_key": masked_key or _mask_secret(key_id),
        "created_at": created_at,
        "last_used_at": last_used_at or None,
        "active": active,
        "status": "active" if active else "revoked",
        "scopes": scopes,
        "environments": environments,
        "tags": tags,
        "metadata": metadata,
    }


def _build_audit_items(payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    raw_items = payload.get("audit") or payload.get("audit_events") or payload.get("events") or payload.get("activity")
    items: list[dict[str, Any]] = []
    for raw_item in _safe_list(raw_items):
        if not isinstance(raw_item, Mapping):
            continue
        item = dict(raw_item)
        items.append(
            {
                "timestamp": _safe_str(
                    item.get("timestamp") or item.get("created_at") or item.get("occurred_at"),
                ),
                "event_type": _safe_str(
                    item.get("event_type") or item.get("type") or "event",
                ),
                "actor": _safe_str(item.get("actor") or item.get("requested_by")),
                "result": _safe_str(item.get("result") or item.get("status")),
                "detail": _safe_str(
                    item.get("detail") or item.get("reason") or item.get("message"),
                ),
                "metadata": _safe_dict(item.get("metadata")),
            },
        )
    return items


def build_customer_key_detail_view(
    key_id: str,
    customer_key_response: Mapping[str, Any] | None,
) -> dict[str, Any]:
    source = _safe_dict(customer_key_response)
    key = _extract_key(source.get("key") if "key" in source else source)
    effective_key_id = key["key_id"] or _safe_str(key_id)
    timestamp = _safe_str(source.get("timestamp") or key["created_at"])
    service = _safe_str(source.get("service"), "ironclaw-ui")
    audit_items = _build_audit_items(source)

    metadata = key["metadata"]
    owner = _safe_str(
        source.get("owner") or metadata.get("owner") or metadata.get("owner_key") or metadata.get("customer_id"),
    )
    organization_id = _safe_str(
        source.get("organization_id") or metadata.get("organization_id") or metadata.get("org_id"),
    )
    last_used_label = key["last_used_at"] or "Never used"

    return {
        "status": "ok",
        "service": service,
        "timestamp": timestamp,
        "page": {
            "id": "customer-key-detail",
            "title": "Customer Key Detail",
            "description": "Inspect key status, scope, lifecycle, and revocation controls.",
            "path": f"/ui/customer-keys/{effective_key_id}",
            "section": "access",
        },
        "breadcrumbs": [
            {"label": "Customer Keys", "path": "/ui/customer-keys"},
            {"label": key["display_name"], "path": f"/ui/customer-keys/{effective_key_id}"},
        ],
        "key": {
            "key_id": effective_key_id,
            "display_name": key["display_name"],
            "masked_key": key["masked_key"],
            "status": key["status"],
            "active": key["active"],
            "created_at": key["created_at"],
            "last_used_at": key["last_used_at"],
            "last_used_label": last_used_label,
            "owner": owner or None,
            "organization_id": organization_id or None,
            "scopes": key["scopes"],
            "environments": key["environments"],
            "tags": key["tags"],
            "metadata": metadata,
        },
        "summary": {
            "primary_status": key["status"],
            "created_at": key["created_at"],
            "last_used_at": key["last_used_at"],
            "scope_count": len(key["scopes"]),
            "environment_count": len(key["environments"]),
            "audit_event_count": len(audit_items),
        },
        "actions": {
            "back": {
                "label": "Back to keys",
                "method": "GET",
                "path": "/ui/customer-keys",
            },
            "revoke": {
                "label": "Revoke key",
                "method": "POST",
                "path": f"/customer-keys/{effective_key_id}/revoke" if key["active"] else None,
                "enabled": bool(effective_key_id and key["active"]),
            },
        },
        "sections": {
            "identity": {
                "title": "Identity",
                "items": [
                    {"label": "Key ID", "value": effective_key_id},
                    {"label": "Display name", "value": key["display_name"]},
                    {"label": "Masked key", "value": key["masked_key"]},
                    {"label": "Owner", "value": owner or "Unassigned"},
                    {"label": "Organization", "value": organization_id or "Not set"},
                ],
            },
            "lifecycle": {
                "title": "Lifecycle",
                "items": [
                    {"label": "Status", "value": key["status"]},
                    {"label": "Created at", "value": key["created_at"] or "Unknown"},
                    {"label": "Last used", "value": last_used_label},
                ],
            },
            "access": {
                "title": "Access",
                "scopes": key["scopes"],
                "environments": key["environments"],
                "tags": key["tags"],
            },
            "audit": {
                "title": "Recent audit",
                "items": audit_items,
                "empty_state": {
                    "title": "No audit activity",
                    "description": "No audit events are available for this customer key yet.",
                },
            },
        },
    }
