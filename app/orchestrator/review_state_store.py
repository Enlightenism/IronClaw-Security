from __future__ import annotations

from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
import json
from pathlib import Path
from typing import Any, Literal

ReviewStatus = Literal["pending", "approved", "rejected"]
ReceiptStatus = Literal["not_executed", "executed", "blocked", "expired"]


@dataclass(frozen=True)
class ReviewStateRecord:
    review_item_id: str
    scan_id: str
    actor_id: str
    target_type: str
    target_value: str
    risk_score: int
    reason: str
    status: ReviewStatus
    created_at: str
    updated_at: str
    file_path: str | None = None
    session_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ReviewDecisionRecord:
    review_item_id: str
    decision: ReviewStatus
    decided_by: str
    decided_at: str
    notes: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ExecutionReceipt:
    receipt_id: str
    review_item_id: str
    status: ReceiptStatus
    action_type: str
    target: str
    executed_by: str
    executed_at: str
    output_ref: str | None = None
    blocked_reason: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ReviewStateSnapshot:
    item: ReviewStateRecord
    decisions: list[ReviewDecisionRecord] = field(default_factory=list)
    receipts: list[ExecutionReceipt] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "item": self.item.to_dict(),
            "decisions": [record.to_dict() for record in self.decisions],
            "receipts": [record.to_dict() for record in self.receipts],
        }


class ReviewStateStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._items: dict[str, ReviewStateRecord] = {}
        self._decisions: dict[str, list[ReviewDecisionRecord]] = {}
        self._receipts: dict[str, list[ExecutionReceipt]] = {}
        self._load()

    def create_item(
        self,
        *,
        review_item_id: str,
        scan_id: str,
        actor_id: str,
        target_type: str,
        target_value: str,
        risk_score: int,
        reason: str,
        file_path: str | None = None,
        session_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ReviewStateRecord:
        if review_item_id in self._items:
            raise ValueError(f"Review item already exists: {review_item_id}")

        now = _utc_now()
        record = ReviewStateRecord(
            review_item_id=review_item_id,
            scan_id=scan_id,
            actor_id=actor_id,
            target_type=target_type,
            target_value=target_value,
            risk_score=risk_score,
            reason=reason,
            status="pending",
            created_at=now,
            updated_at=now,
            file_path=file_path,
            session_id=session_id,
            metadata=metadata or {},
        )
        self._items[review_item_id] = record
        self._append_event("review_item_created", record.to_dict())
        return record

    def set_decision(
        self,
        *,
        review_item_id: str,
        decision: Literal["approved", "rejected"],
        decided_by: str,
        notes: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ReviewStateRecord:
        item = self.require_item(review_item_id)

        decision_record = ReviewDecisionRecord(
            review_item_id=review_item_id,
            decision=decision,
            decided_by=decided_by,
            decided_at=_utc_now(),
            notes=notes,
            metadata=metadata or {},
        )
        self._decisions.setdefault(review_item_id, []).append(decision_record)

        updated_item = ReviewStateRecord(
            **{
                **item.to_dict(),
                "status": decision,
                "updated_at": decision_record.decided_at,
            },
        )
        self._items[review_item_id] = updated_item

        self._append_event("review_decision_recorded", decision_record.to_dict())
        self._append_event("review_item_updated", updated_item.to_dict())
        return updated_item

    def add_execution_receipt(
        self,
        *,
        review_item_id: str,
        action_type: str,
        target: str,
        executed_by: str,
        status: ReceiptStatus,
        output_ref: str | None = None,
        blocked_reason: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ExecutionReceipt:
        item = self.require_item(review_item_id)

        receipt = ExecutionReceipt(
            receipt_id=_build_receipt_id(),
            review_item_id=review_item_id,
            status=status,
            action_type=action_type,
            target=target,
            executed_by=executed_by,
            executed_at=_utc_now(),
            output_ref=output_ref,
            blocked_reason=blocked_reason,
            metadata={
                "review_status_at_execution": item.status,
                **(metadata or {}),
            },
        )
        self._receipts.setdefault(review_item_id, []).append(receipt)
        self._append_event("execution_receipt_recorded", receipt.to_dict())
        return receipt

    def get_snapshot(self, review_item_id: str) -> ReviewStateSnapshot:
        item = self.require_item(review_item_id)
        return ReviewStateSnapshot(
            item=item,
            decisions=list(self._decisions.get(review_item_id, [])),
            receipts=list(self._receipts.get(review_item_id, [])),
        )

    def list_items(
        self,
        *,
        status: ReviewStatus | None = None,
    ) -> list[ReviewStateRecord]:
        items = list(self._items.values())
        if status is not None:
            items = [item for item in items if item.status == status]
        return sorted(items, key=lambda item: item.updated_at, reverse=True)

    def list_pending(self) -> list[ReviewStateRecord]:
        return self.list_items(status="pending")

    def list_approved(self) -> list[ReviewStateRecord]:
        return self.list_items(status="approved")

    def list_rejected(self) -> list[ReviewStateRecord]:
        return self.list_items(status="rejected")

    def require_item(self, review_item_id: str) -> ReviewStateRecord:
        item = self._items.get(review_item_id)
        if item is None:
            raise KeyError(f"Unknown review item: {review_item_id}")
        return item

    def _append_event(self, event_type: str, payload: dict[str, Any]) -> None:
        event = {
            "event_type": event_type,
            "timestamp": _utc_now(),
            "payload": payload,
        }
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, ensure_ascii=False) + "\n")

    def _load(self) -> None:
        if not self.path.exists():
            return

        for raw_event in self._read_lines():
            event_type = raw_event.get("event_type")
            payload = raw_event.get("payload", {})

            if event_type in {"review_item_created", "review_item_updated"}:
                item = ReviewStateRecord(**payload)
                self._items[item.review_item_id] = item
            elif event_type == "review_decision_recorded":
                decision = ReviewDecisionRecord(**payload)
                self._decisions.setdefault(decision.review_item_id, []).append(decision)
            elif event_type == "execution_receipt_recorded":
                receipt = ExecutionReceipt(**payload)
                self._receipts.setdefault(receipt.review_item_id, []).append(receipt)

    def _read_lines(self) -> Iterable[dict[str, Any]]:
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                yield json.loads(line)


def initialize_review_state_store(
    path: str = "output/review-state-store.jsonl",
) -> ReviewStateStore:
    return ReviewStateStore(path)


def summarize_review_snapshot(snapshot: ReviewStateSnapshot) -> dict[str, Any]:
    last_decision = snapshot.decisions[-1].decision if snapshot.decisions else None
    latest_receipt = snapshot.receipts[-1].status if snapshot.receipts else "not_executed"
    return {
        "review_item_id": snapshot.item.review_item_id,
        "scan_id": snapshot.item.scan_id,
        "status": snapshot.item.status,
        "last_decision": last_decision,
        "decision_count": len(snapshot.decisions),
        "receipt_count": len(snapshot.receipts),
        "latest_receipt_status": latest_receipt,
        "risk_score": snapshot.item.risk_score,
        "target_type": snapshot.item.target_type,
        "target_value": snapshot.item.target_value,
    }


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _build_receipt_id() -> str:
    return f"receipt-{datetime.now(UTC).strftime('%Y%m%d%H%M%S%f')}"


if __name__ == "__main__":
    import json as _json

    store = initialize_review_state_store()

    created = store.create_item(
        review_item_id="review-0001",
        scan_id="scan-abc123",
        actor_id="agent-security-01",
        target_type="githubrepo",
        target_value="https://github.com/example/repo",
        risk_score=70,
        reason="githubrepo requires sandbox review",
        file_path="app/orchestrator/review_state_store.py",
        session_id="sess-003",
        metadata={"source": "manual_demo"},
    )

    store.set_decision(
        review_item_id=created.review_item_id,
        decision="approved",
        decided_by="reviewer-ops-01",
        notes="Sandbox-only execution approved",
    )

    store.add_execution_receipt(
        review_item_id=created.review_item_id,
        action_type="sandbox_fetch",
        target=created.target_value,
        executed_by="runtime-executor-01",
        status="executed",
        output_ref="sandbox://runs/review-0001",
    )

    snapshot = store.get_snapshot(created.review_item_id)
    print(_json.dumps(summarize_review_snapshot(snapshot), ensure_ascii=False, indent=2))
