from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.services.integration_registry import (
    IntegrationRegistry,
    list_integrations,
)


def _normalize(value: str | None, default: str = "unknown") -> str:
    if not value:
        return default
    normalized = value.strip().lower()
    return normalized or default


def _normalize_tags(raw: Any) -> list[str]:
    if not raw:
        return []
    if isinstance(raw, dict):
        for key in ("tags", "labels"):
            value = raw.get(key)
            if isinstance(value, (list, tuple, set)):
                return sorted({str(tag).strip() for tag in value if str(tag).strip()})
        return sorted({str(value).strip() for value in raw.values() if str(value).strip()})
    if isinstance(raw, (list, tuple, set)):
        return sorted({str(tag).strip() for tag in raw if str(tag).strip()})
    return [str(raw).strip()] if str(raw).strip() else []


@dataclass(slots=True)
class FilterOption:
    value: str
    label: str
    count: int
    active_count: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "label": self.label,
            "count": self.count,
            "active_count": self.active_count,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class FilterGroup:
    key: str
    title: str
    multi_select: bool
    options: list[FilterOption] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "title": self.title,
            "multi_select": self.multi_select,
            "options": [option.to_dict() for option in self.options],
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class IntegrationFilterPreset:
    key: str
    title: str
    filters: dict[str, list[str]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "title": self.title,
            "filters": {key: list(values) for key, values in self.filters.items()},
        }


@dataclass(slots=True)
class IntegrationFiltersView:
    title: str
    total_integrations: int
    filter_group_count: int
    preset_count: int
    groups: list[FilterGroup] = field(default_factory=list)
    presets: list[IntegrationFilterPreset] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "total_integrations": self.total_integrations,
            "filter_group_count": self.filter_group_count,
            "preset_count": self.preset_count,
            "groups": [group.to_dict() for group in self.groups],
            "presets": [preset.to_dict() for preset in self.presets],
            "metadata": dict(self.metadata),
        }


def _build_option_map() -> dict[str, dict[str, dict[str, int]]]:
    return {
        "platform": {},
        "status": {},
        "integration_type": {},
        "tags": {},
        "command_ready": {},
    }


def _touch_option(
    bucket: dict[str, dict[str, int]],
    *,
    value: str,
    is_active: bool,
) -> None:
    current = bucket.setdefault(value, {"count": 0, "active_count": 0})
    current["count"] += 1
    if is_active:
        current["active_count"] += 1


def _build_group(
    *,
    key: str,
    title: str,
    multi_select: bool,
    bucket: dict[str, dict[str, int]],
) -> FilterGroup:
    options = [
        FilterOption(
            value=value,
            label=value.replace("_", " ").title(),
            count=counts["count"],
            active_count=counts["active_count"],
        )
        for value, counts in bucket.items()
        if counts["count"] > 0
    ]
    options.sort(key=lambda option: (-option.count, option.label.lower()))

    return FilterGroup(
        key=key,
        title=title,
        multi_select=multi_select,
        options=options,
        metadata={
            "option_count": len(options),
        },
    )


def build_integration_filters_view(
    *,
    registry: IntegrationRegistry,
    requested_by: str = "ui-filters",
) -> IntegrationFiltersView:
    records = list_integrations(registry)
    option_map = _build_option_map()

    for record in records:
        status = _normalize(getattr(record, "status", None))
        platform = _normalize(getattr(record, "platform", None))
        integration_type = _normalize(getattr(record, "integration_type", None))
        is_active = status in {"active", "enabled"}
        command_ready = "yes" if bool(getattr(record, "command_name", None)) else "no"

        _touch_option(option_map["platform"], value=platform, is_active=is_active)
        _touch_option(option_map["status"], value=status, is_active=is_active)
        _touch_option(
            option_map["integration_type"],
            value=integration_type,
            is_active=is_active,
        )
        _touch_option(
            option_map["command_ready"],
            value=command_ready,
            is_active=is_active,
        )

        record_metadata = dict(getattr(record, "metadata", {}) or {})
        tags = _normalize_tags(record_metadata.get("tags") or record_metadata.get("labels"))
        for tag in tags:
            _touch_option(option_map["tags"], value=tag, is_active=is_active)

    groups = [
        _build_group(
            key="platform",
            title="Platform",
            multi_select=True,
            bucket=option_map["platform"],
        ),
        _build_group(
            key="status",
            title="Status",
            multi_select=True,
            bucket=option_map["status"],
        ),
        _build_group(
            key="integration_type",
            title="Integration Type",
            multi_select=True,
            bucket=option_map["integration_type"],
        ),
        _build_group(
            key="tags",
            title="Tags",
            multi_select=True,
            bucket=option_map["tags"],
        ),
        _build_group(
            key="command_ready",
            title="Command Ready",
            multi_select=False,
            bucket=option_map["command_ready"],
        ),
    ]

    presets = [
        IntegrationFilterPreset(
            key="active_only",
            title="Active Only",
            filters={"status": ["active"]},
        ),
        IntegrationFilterPreset(
            key="ready_to_run",
            title="Ready To Run",
            filters={
                "status": ["active"],
                "command_ready": ["yes"],
            },
        ),
        IntegrationFilterPreset(
            key="planned_work",
            title="Planned Work",
            filters={"status": ["planned", "draft"]},
        ),
    ]

    return IntegrationFiltersView(
        title="Integration Filters",
        total_integrations=len(records),
        filter_group_count=len(groups),
        preset_count=len(presets),
        groups=groups,
        presets=presets,
        metadata={
            "requested_by": requested_by,
        },
    )
