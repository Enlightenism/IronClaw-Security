from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from orchestrator.orchestrator import (
    OrchestrationRequest,
    Orchestrator,
)


@dataclass(slots=True)
class SecurityOrchestrationRecord:
    record_id: str
    request_id: str
    status: str
    outcome: str
    allowed: bool
    orchestration: dict[str, Any]
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    updated_at: str | None = None

    def finalize(self) -> SecurityOrchestrationRecord:
        self.updated_at = datetime.now(UTC).isoformat()
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_id": self.record_id,
            "request_id": self.request_id,
            "status": self.status,
            "outcome": self.outcome,
            "allowed": self.allowed,
            "orchestration": dict(self.orchestration),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


class SecurityOrchestratorService:
    def __init__(self, *, orchestrator: Orchestrator | None = None) -> None:
        self.orchestrator = orchestrator or Orchestrator()
        self._records: dict[str, SecurityOrchestrationRecord] = {}

    def execute(
        self,
        request: OrchestrationRequest | Mapping[str, Any] | None,
    ) -> SecurityOrchestrationRecord:
        result = self.orchestrator.orchestrate(request)
        record = SecurityOrchestrationRecord(
            record_id=f"secorch-{uuid4().hex}",
            request_id=result.request_id,
            status=result.status,
            outcome=result.outcome,
            allowed=result.allowed,
            orchestration=result.to_dict(),
        ).finalize()
        self._records[record.record_id] = record
        return record

    def execute_dict(
        self,
        request: OrchestrationRequest | Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        return self.execute(request).to_dict()

    def get_record(self, record_id: str) -> SecurityOrchestrationRecord | None:
        return self._records.get(record_id)

    def get_record_dict(self, record_id: str) -> dict[str, Any] | None:
        record = self.get_record(record_id)
        return record.to_dict() if record else None

    def list_records(self) -> list[SecurityOrchestrationRecord]:
        return sorted(self._records.values(), key=lambda item: item.created_at)

    def list_records_dict(self) -> list[dict[str, Any]]:
        return [record.to_dict() for record in self.list_records()]

    def clear_records(self) -> None:
        self._records.clear()


def build_security_orchestration_request(
    *,
    request_id: str | None = None,
    action: str = "execute",
    target: str = "runtime",
    payload: Mapping[str, Any] | None = None,
    risk_score: int = 0,
    source: str | None = None,
    actor_id: str | None = None,
    session_id: str | None = None,
    organization_id: str | None = None,
    requires_network: bool = False,
    requires_filesystem: bool = False,
    requires_secrets: bool = False,
    requires_human_review: bool = False,
    metadata: Mapping[str, Any] | None = None,
) -> OrchestrationRequest:
    return OrchestrationRequest(
        request_id=request_id or f"req-{uuid4().hex}",
        action=action,
        target=target,
        payload=dict(payload or {}),
        risk_score=risk_score,
        source=source,
        actor_id=actor_id,
        session_id=session_id,
        organization_id=organization_id,
        requires_network=requires_network,
        requires_filesystem=requires_filesystem,
        requires_secrets=requires_secrets,
        requires_human_review=requires_human_review,
        metadata=dict(metadata or {}),
    )


def run_security_orchestration(
    request: OrchestrationRequest | Mapping[str, Any] | None,
    *,
    service: SecurityOrchestratorService | None = None,
) -> SecurityOrchestrationRecord:
    active_service = service or SecurityOrchestratorService()
    return active_service.execute(request)


def run_security_orchestration_dict(
    request: OrchestrationRequest | Mapping[str, Any] | None,
    *,
    service: SecurityOrchestratorService | None = None,
) -> dict[str, Any]:
    return run_security_orchestration(request, service=service).to_dict()


__all__ = [
    "SecurityOrchestrationRecord",
    "SecurityOrchestratorService",
    "build_security_orchestration_request",
    "run_security_orchestration",
    "run_security_orchestration_dict",
]