from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from threading import Lock
from typing import Any, Literal
from uuid import uuid4

QuarantineStatus = Literal["isolated", "under_review", "released", "destroyed"]
QuarantineSource = Literal["scan", "guard", "sandbox", "review", "system"]
RiskLevel = Literal["low", "medium", "high", "critical"]


def _utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass(slots=True)
class QuarantineRecord:
    quarantine_id: str
    status: QuarantineStatus
    source: QuarantineSource
    title: str
    summary: str
    risk_level: RiskLevel
    created_at: datetime
    updated_at: datetime
    request_id: str | None = None
    trace_id: str | None = None
    incident_id: str | None = None
    asset_ref: str | None = None
    owner: str | None = None
    release_reason: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["created_at"] = self.created_at.isoformat().replace("+00:00", "Z")
        payload["updated_at"] = self.updated_at.isoformat().replace("+00:00", "Z")
        return payload


class QuarantineStore:
    def __init__(self) -> None:
        self._lock = Lock()
        self._items: list[QuarantineRecord] = []

    def seed_defaults(self) -> None:
        with self._lock:
            if self._items:
                return

            now = _utcnow()
            self._items.extend(
                [
                    QuarantineRecord(
                        quarantine_id=f"qtn-{uuid4().hex[:12]}",
                        status="isolated",
                        source="scan",
                        title="Injected prompt bundle isolated",
                        summary="A prompt payload was isolated after matching prompt-injection heuristics during ingress scanning.",
                        risk_level="high",
                        created_at=now,
                        updated_at=now,
                        request_id="req-qtn-001",
                        trace_id="trace-qtn-001",
                        incident_id="inc-seed-001",
                        asset_ref="prompt:user-input",
                        metadata={"verdict": "quarantine", "seeded": True},
                        tags=["prompt-injection", "ingress", "scanner"],
                    ),
                    QuarantineRecord(
                        quarantine_id=f"qtn-{uuid4().hex[:12]}",
                        status="under_review",
                        source="sandbox",
                        title="Suspicious tool output contained",
                        summary="Tool-returned content was moved into quarantine while sandbox review evaluates potential hostile instructions.",
                        risk_level="critical",
                        created_at=now,
                        updated_at=now,
                        request_id="req-qtn-002",
                        trace_id="trace-qtn-002",
                        incident_id="inc-seed-002",
                        asset_ref="tool-output:external-content",
                        owner="sandbox-review",
                        metadata={"verdict": "quarantine", "seeded": True},
                        tags=["sandbox", "tool-output", "containment"],
                    ),
                ],
            )

    def list_items(
        self,
        *,
        status: QuarantineStatus | None = None,
        source: QuarantineSource | None = None,
        risk_level: RiskLevel | None = None,
    ) -> list[QuarantineRecord]:
        with self._lock:
            items = list(self._items)

        if status is not None:
            items = [item for item in items if item.status == status]
        if source is not None:
            items = [item for item in items if item.source == source]
        if risk_level is not None:
            items = [item for item in items if item.risk_level == risk_level]

        return items

    def get_item(self, quarantine_id: str) -> QuarantineRecord | None:
        with self._lock:
            for item in self._items:
                if item.quarantine_id == quarantine_id:
                    return item
        return None

    def create_item(
        self,
        *,
        source: QuarantineSource,
        title: str,
        summary: str,
        risk_level: RiskLevel,
        status: QuarantineStatus = "isolated",
        request_id: str | None = None,
        trace_id: str | None = None,
        incident_id: str | None = None,
        asset_ref: str | None = None,
        owner: str | None = None,
        release_reason: str | None = None,
        metadata: dict[str, Any] | None = None,
        tags: list[str] | None = None,
    ) -> QuarantineRecord:
        now = _utcnow()
        record = QuarantineRecord(
            quarantine_id=f"qtn-{uuid4().hex[:12]}",
            status=status,
            source=source,
            title=title.strip(),
            summary=summary.strip(),
            risk_level=risk_level,
            created_at=now,
            updated_at=now,
            request_id=request_id,
            trace_id=trace_id,
            incident_id=incident_id,
            asset_ref=asset_ref,
            owner=owner,
            release_reason=release_reason,
            metadata=dict(metadata or {}),
            tags=list(tags or []),
        )

        with self._lock:
            self._items.append(record)

        return record

    def update_item(
        self,
        quarantine_id: str,
        *,
        status: QuarantineStatus,
        owner: str | None = None,
        release_reason: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> QuarantineRecord | None:
        with self._lock:
            for index, item in enumerate(self._items):
                if item.quarantine_id != quarantine_id:
                    continue

                updated = QuarantineRecord(
                    quarantine_id=item.quarantine_id,
                    status=status,
                    source=item.source,
                    title=item.title,
                    summary=item.summary,
                    risk_level=item.risk_level,
                    created_at=item.created_at,
                    updated_at=_utcnow(),
                    request_id=item.request_id,
                    trace_id=item.trace_id,
                    incident_id=item.incident_id,
                    asset_ref=item.asset_ref,
                    owner=owner if owner is not None else item.owner,
                    release_reason=release_reason if release_reason is not None else item.release_reason,
                    metadata={
                        **item.metadata,
                        **dict(metadata or {}),
                    },
                    tags=list(item.tags),
                )
                self._items[index] = updated
                return updated

        return None

    def reset(self) -> None:
        with self._lock:
            self._items.clear()


_QUARANTINE_STORE = QuarantineStore()
_QUARANTINE_STORE.seed_defaults()


def get_quarantine_store() -> QuarantineStore:
    return _QUARANTINE_STORE


def reset_quarantine_store() -> None:
    _QUARANTINE_STORE.reset()
    _QUARANTINE_STORE.seed_defaults()
