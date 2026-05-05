from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from app.services.integration_registry import (
    IntegrationRegistry,
    list_integrations,
)


@dataclass(slots=True)
class IntegrationSearchItem:
    integration_id: str
    slug: str
    name: str
    platform: str
    status: str
    integration_type: str
    tags: list[str] = field(default_factory=list)
    score: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "integration_id": self.integration_id,
            "slug": self.slug,
            "name": self.name,
            "platform": self.platform,
            "status": self.status,
            "integration_type": self.integration_type,
            "tags": list(self.tags),
            "score": float(self.score),
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class IntegrationSearchView:
    title: str
    total: int
    query: str
    items: list[IntegrationSearchItem] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "total": self.total,
            "query": self.query,
            "items": [item.to_dict() for item in self.items],
            "metadata": dict(self.metadata),
        }


def _normalize(text: str | None) -> str:
    if not text:
        return ""
    return text.strip().lower()


def _tokenize(text: str | None) -> list[str]:
    normalized = _normalize(text)
    if not normalized:
        return []
    return [token for token in normalized.replace(",", " ").split() if token]


def _collect_tags(metadata: dict[str, Any]) -> list[str]:
    raw_tags = metadata.get("tags") or metadata.get("labels") or []
    if isinstance(raw_tags, dict):
        values: Iterable[Any] = raw_tags.values()
    elif isinstance(raw_tags, (list, tuple, set)):
        values = raw_tags
    else:
        values = [raw_tags]

    tags: list[str] = []
    for value in values:
        if isinstance(value, (list, tuple, set)):
            for nested in value:
                token = _normalize(str(nested))
                if token:
                    tags.append(token)
        else:
            token = _normalize(str(value))
            if token:
                tags.append(token)

    # Remove duplicates while preserving order.
    seen: set[str] = set()
    unique: list[str] = []
    for tag in tags:
        if tag not in seen:
            seen.add(tag)
            unique.append(tag)
    return unique


def _match_score(
    *,
    query_tokens: list[str],
    name_tokens: list[str],
    slug_tokens: list[str],
    platform: str,
    integration_type: str,
    tags: list[str],
    status: str,
) -> float:
    if not query_tokens:
        # No query: show everything with a neutral base score.
        return 0.0

    score = 0.0
    status_norm = _normalize(status)
    platform_norm = _normalize(platform)
    type_norm = _normalize(integration_type)

    for q in query_tokens:
        # Exact matches in name get highest weight.
        if q in name_tokens:
            score += 5.0
        # Prefix match on name.
        elif any(token.startswith(q) for token in name_tokens):
            score += 3.0

        # Slug and platform matches.
        if q in slug_tokens:
            score += 2.0
        if q and platform_norm.startswith(q):
            score += 1.5
        if q and type_norm.startswith(q):
            score += 1.5

        # Tag matches.
        if q in tags:
            score += 2.0

        # Status keyword matches.
        if q in {"active", "enabled"} and status_norm in {"active", "enabled"}:
            score += 1.0
        if q in {"planned", "draft"} and status_norm in {"planned", "draft"}:
            score += 0.5

    return score


def build_integration_search_view(
    *,
    registry: IntegrationRegistry,
    query: str = "",
    requested_by: str = "ui-search",
) -> IntegrationSearchView:
    records = list_integrations(registry)
    query_tokens = _tokenize(query)

    items: list[IntegrationSearchItem] = []

    for record in records:
        name_tokens = _tokenize(record.name)
        slug_tokens = _tokenize(record.slug)
        metadata = dict(getattr(record, "metadata", {}) or {})
        tags = _collect_tags(metadata)

        integration_type = getattr(record, "integration_type", "unknown")
        status = getattr(record, "status", "unknown")

        score = _match_score(
            query_tokens=query_tokens,
            name_tokens=name_tokens,
            slug_tokens=slug_tokens,
            platform=record.platform,
            integration_type=integration_type,
            tags=tags,
            status=status,
        )

        # If there is a non-empty query and the score is zero, omit the item.
        if query_tokens and score <= 0:
            continue

        items.append(
            IntegrationSearchItem(
                integration_id=record.integration_id,
                slug=record.slug,
                name=record.name,
                platform=record.platform,
                status=status,
                integration_type=integration_type,
                tags=tags,
                score=score,
                metadata={
                    "requested_by": requested_by,
                },
            )
        )

    # Sort by score (desc), then name.
    items.sort(
        key=lambda item: (
            -item.score,
            item.name.lower(),
            item.slug,
            item.integration_id,
        )
    )

    return IntegrationSearchView(
        title="Integration Search",
        total=len(items),
        query=query,
        items=items,
        metadata={
            "requested_by": requested_by,
        },
    )