from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.services.integration_registry import (
    IntegrationRegistry,
    list_integrations,
)


@dataclass(slots=True)
class IntegrationTagItem:
    integration_id: str
    slug: str
    name: str
    platform: str
    tags: list[str] = field(default_factory=list)
    tag_count: int = 0
    status: str = "unknown"
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "integration_id": self.integration_id,
            "slug": self.slug,
            "name": self.name,
            "platform": self.platform,
            "tags": list(self.tags),
            "tag_count": self.tag_count,
            "status": self.status,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class TagSummaryItem:
    name: str
    usage_count: int
    active_usage_count: int
    platforms: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "usage_count": self.usage_count,
            "active_usage_count": self.active_usage_count,
            "platforms": sorted(set(self.platforms)),
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class IntegrationTagsView:
    title: str
    total_integrations: int
    tagged_integrations: int
    unique_tag_count: int
    items: list[IntegrationTagItem] = field(default_factory=list)
    tags: list[TagSummaryItem] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "total_integrations": self.total_integrations,
            "tagged_integrations": self.tagged_integrations,
            "unique_tag_count": self.unique_tag_count,
            "items": [item.to_dict() for item in self.items],
            "tags": [tag.to_dict() for tag in self.tags],
            "metadata": dict(self.metadata),
        }


def _normalize_tags(raw: Any) -> list[str]:
    if not raw:
        return []
    if isinstance(raw, dict):
        # Support shapes like {"tags": [...]} or {"labels": [...]}
        for key in ("tags", "labels"):
            if key in raw and isinstance(raw[key], list):
                return [str(t).strip() for t in raw[key] if str(t).strip()]
        # Fallback: take all values as tags
        return [str(v).strip() for v in raw.values() if str(v).strip()]
    if isinstance(raw, (list, tuple, set)):
        return [str(t).strip() for t in raw if str(t).strip()]
    # Single string or scalar
    return [str(raw).strip()]


def build_integration_tags_view(
    *,
    registry: IntegrationRegistry,
    requested_by: str = "ui-tags",
) -> IntegrationTagsView:
    records = list_integrations(registry)

    items: list[IntegrationTagItem] = []
    tag_usage: dict[str, TagSummaryItem] = {}

    total_integrations = len(records)
    tagged_integrations = 0

    for record in records:
        record_metadata = getattr(record, "metadata", {}) or {}
        raw_tags = record_metadata.get("tags") or record_metadata.get("labels") or []
        tags = _normalize_tags(raw_tags)

        status = getattr(record, "status", "unknown")
        status_normalized = str(status or "unknown").strip().lower()

        if tags:
            tagged_integrations += 1

        item = IntegrationTagItem(
            integration_id=record.integration_id,
            slug=record.slug,
            name=record.name,
            platform=record.platform,
            tags=tags,
            tag_count=len(tags),
            status=status,
            metadata={
                "requested_by": requested_by,
            },
        )
        items.append(item)

        for tag in tags:
            existing = tag_usage.get(tag)
            if existing is None:
                existing = TagSummaryItem(
                    name=tag,
                    usage_count=0,
                    active_usage_count=0,
                    platforms=[],
                    metadata={},
                )
                tag_usage[tag] = existing

            existing.usage_count += 1
            if status_normalized in {"active", "enabled"}:
                existing.active_usage_count += 1
            existing.platforms.append(record.platform)

    # Sort integration items by platform then name then slug.
    items.sort(
        key=lambda item: (
            item.platform,
            item.name,
            item.slug,
            item.integration_id,
        ),
    )

    # Build sorted tag summaries: highest usage, then name.
    tag_items: list[TagSummaryItem] = list(tag_usage.values())
    tag_items.sort(
        key=lambda t: (
            -t.usage_count,
            -t.active_usage_count,
            t.name.lower(),
        ),
    )

    unique_tag_count = len(tag_items)

    return IntegrationTagsView(
        title="Integration Tags",
        total_integrations=total_integrations,
        tagged_integrations=tagged_integrations,
        unique_tag_count=unique_tag_count,
        items=items,
        tags=tag_items,
        metadata={
            "requested_by": requested_by,
        },
    )
