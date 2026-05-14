from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.services.integration_registry import (
    IntegrationRegistry,
    list_integrations,
)


def _clean_text(value: Any, *, default: str = "") -> str:
    if value is None:
        return default
    text = str(value).strip()
    return text or default


def _normalize_status(value: str | None) -> str:
    return _clean_text(value, default="unknown").lower()


def _access_level_for_record(status: str, metadata: dict[str, Any]) -> str:
    configured = _clean_text(metadata.get("access_level")).lower()
    if configured:
        return configured

    normalized = _normalize_status(status)
    if normalized in {"active", "enabled", "ready"}:
        return "operator"
    if normalized in {"planned", "draft", "review"}:
        return "review"
    if normalized in {"disabled", "inactive", "retired", "blocked"}:
        return "restricted"
    return "unknown"


def _auth_mode_for_record(record: Any, metadata: dict[str, Any]) -> str:
    for key in ("auth_mode", "authentication_mode", "auth_type"):
        value = _clean_text(metadata.get(key)).lower()
        if value:
            return value
    if getattr(record, "endpoint", None) or getattr(record, "base_url", None):
        return "service"
    return "local"


def _control_count(
    *,
    command_ready: bool,
    install_ready: bool,
    endpoint_ready: bool,
    secret_ready: bool,
) -> int:
    return sum((command_ready, install_ready, endpoint_ready, secret_ready))


def _access_state_for_control_count(control_count: int) -> str:
    if control_count >= 3:
        return "ready"
    if control_count >= 1:
        return "partial"
    return "minimal"


def _platform_label(record: Any) -> str:
    return _clean_text(getattr(record, "platform", None), default="unknown")


def _record_metadata(record: Any) -> dict[str, Any]:
    raw = getattr(record, "metadata", {}) or {}
    if isinstance(raw, dict):
        return dict(raw)
    return {}


@dataclass(slots=True)
class IntegrationAccessItem:
    integration_id: str
    slug: str
    name: str
    platform: str
    status: str
    access_level: str
    auth_mode: str
    command_ready: bool
    install_ready: bool
    endpoint_ready: bool
    secret_ready: bool
    control_count: int
    access_state: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "integration_id": self.integration_id,
            "slug": self.slug,
            "name": self.name,
            "platform": self.platform,
            "status": self.status,
            "access_level": self.access_level,
            "auth_mode": self.auth_mode,
            "command_ready": self.command_ready,
            "install_ready": self.install_ready,
            "endpoint_ready": self.endpoint_ready,
            "secret_ready": self.secret_ready,
            "control_count": self.control_count,
            "access_state": self.access_state,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class IntegrationAccessView:
    title: str
    total: int
    operator_count: int
    restricted_count: int
    ready_count: int
    partial_count: int
    minimal_count: int
    items: list[IntegrationAccessItem] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "total": self.total,
            "operator_count": self.operator_count,
            "restricted_count": self.restricted_count,
            "ready_count": self.ready_count,
            "partial_count": self.partial_count,
            "minimal_count": self.minimal_count,
            "items": [item.to_dict() for item in self.items],
            "metadata": dict(self.metadata),
        }


def build_integration_access_view(
    *,
    registry: IntegrationRegistry,
    requested_by: str = "ui-access",
) -> IntegrationAccessView:
    records = list_integrations(registry)

    items: list[IntegrationAccessItem] = []
    operator_count = 0
    restricted_count = 0
    ready_count = 0
    partial_count = 0
    minimal_count = 0

    for record in records:
        record_metadata = _record_metadata(record)
        status = _normalize_status(getattr(record, "status", "unknown"))
        access_level = _access_level_for_record(status, record_metadata)
        auth_mode = _auth_mode_for_record(record, record_metadata)

        command_ready = bool(getattr(record, "command_name", None))
        install_ready = bool(getattr(record, "install_target", None))
        endpoint_ready = bool(
            getattr(record, "endpoint", None) or getattr(record, "base_url", None),
        )
        secret_ready = bool(
            record_metadata.get("secret_ref") or record_metadata.get("credential_ref") or record_metadata.get("api_key_ref"),
        )

        control_count = _control_count(
            command_ready=command_ready,
            install_ready=install_ready,
            endpoint_ready=endpoint_ready,
            secret_ready=secret_ready,
        )

        if access_level == "operator":
            operator_count += 1
        if access_level == "restricted":
            restricted_count += 1

        access_state = _access_state_for_control_count(control_count)
        if access_state == "ready":
            ready_count += 1
        elif access_state == "partial":
            partial_count += 1
        else:
            minimal_count += 1

        items.append(
            IntegrationAccessItem(
                integration_id=_clean_text(getattr(record, "integration_id", None), default="unknown"),
                slug=_clean_text(getattr(record, "slug", None), default="unknown"),
                name=_clean_text(getattr(record, "name", None), default="Unnamed Integration"),
                platform=_platform_label(record),
                status=status,
                access_level=access_level,
                auth_mode=auth_mode,
                command_ready=command_ready,
                install_ready=install_ready,
                endpoint_ready=endpoint_ready,
                secret_ready=secret_ready,
                control_count=control_count,
                access_state=access_state,
                metadata={
                    "requested_by": requested_by,
                },
            ),
        )

    items.sort(
        key=lambda item: (
            0 if item.access_state == "ready" else 1 if item.access_state == "partial" else 2,
            item.platform,
            item.slug,
            item.integration_id,
        ),
    )

    return IntegrationAccessView(
        title="Integration Access",
        total=len(items),
        operator_count=operator_count,
        restricted_count=restricted_count,
        ready_count=ready_count,
        partial_count=partial_count,
        minimal_count=minimal_count,
        items=items,
        metadata={
            "requested_by": requested_by,
        },
    )
