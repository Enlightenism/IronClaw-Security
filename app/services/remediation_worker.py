from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
import logging
from threading import Lock
from typing import Any
from uuid import uuid4

from app.services.audit_log_service import get_audit_log
from app.services.incident_store import (
    IncidentRecordInMemory,
    IncidentStoreInMemory,
    get_incident_store,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class RemediationAction(str, Enum):
    QUARANTINE = "quarantine"
    ISOLATE = "isolate"
    REVOKE_SESSION = "revoke_session"
    PATCH_POLICY = "patch_policy"
    NOTIFY = "notify"
    ESCALATE = "escalate"
    RESOLVE = "resolve"
    NO_OP = "no_op"


class RemediationStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    SKIPPED = "skipped"


# ---------------------------------------------------------------------------
# Severity → action mapping
# ---------------------------------------------------------------------------

_SEVERITY_ACTION_MAP: dict[str, list[RemediationAction]] = {
    "critical": [
        RemediationAction.QUARANTINE,
        RemediationAction.ISOLATE,
        RemediationAction.REVOKE_SESSION,
        RemediationAction.ESCALATE,
        RemediationAction.NOTIFY,
    ],
    "high": [
        RemediationAction.QUARANTINE,
        RemediationAction.ISOLATE,
        RemediationAction.NOTIFY,
    ],
    "medium": [
        RemediationAction.PATCH_POLICY,
        RemediationAction.NOTIFY,
    ],
    "low": [
        RemediationAction.NOTIFY,
    ],
}

_VERDICT_ACTION_OVERRIDE: dict[str, list[RemediationAction]] = {
    "block": [RemediationAction.QUARANTINE, RemediationAction.ISOLATE, RemediationAction.NOTIFY],
    "quarantine": [RemediationAction.QUARANTINE, RemediationAction.ISOLATE],
    "warn": [RemediationAction.NOTIFY],
    "allow": [RemediationAction.NO_OP],
}


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class RemediationStep:
    step_id: str
    action: RemediationAction
    status: RemediationStatus
    started_at: datetime | None
    completed_at: datetime | None
    error: str | None
    metadata: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "action": self.action.value,
            "status": self.status.value,
            "started_at": self.started_at.isoformat().replace("+00:00", "Z") if self.started_at else None,
            "completed_at": self.completed_at.isoformat().replace("+00:00", "Z") if self.completed_at else None,
            "error": self.error,
            "metadata": self.metadata,
        }


@dataclass(slots=True)
class RemediationRecord:
    remediation_id: str
    incident_id: str
    severity: str
    verdict: str | None
    steps: list[RemediationStep]
    overall_status: RemediationStatus
    triggered_at: datetime
    completed_at: datetime | None
    trigger_reason: str
    metadata: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "remediation_id": self.remediation_id,
            "incident_id": self.incident_id,
            "severity": self.severity,
            "verdict": self.verdict,
            "steps": [s.to_dict() for s in self.steps],
            "overall_status": self.overall_status.value,
            "triggered_at": self.triggered_at.isoformat().replace("+00:00", "Z"),
            "completed_at": self.completed_at.isoformat().replace("+00:00", "Z") if self.completed_at else None,
            "trigger_reason": self.trigger_reason,
            "metadata": self.metadata,
        }

    def dict(self) -> dict[str, Any]:
        return self.to_dict()

    def model_dump(self) -> dict[str, Any]:
        return self.to_dict()


# ---------------------------------------------------------------------------
# Action handlers
# ---------------------------------------------------------------------------


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _execute_quarantine(incident: IncidentRecordInMemory, store: IncidentStoreInMemory) -> dict[str, Any]:
    store.update_incident_status(
        incident.incident_id,
        status="contained",
        metadata={"remediation_action": "quarantine", "remediation_at": _utcnow().isoformat()},
    )
    return {"action": "quarantine", "incident_id": incident.incident_id, "new_status": "contained"}


def _execute_isolate(incident: IncidentRecordInMemory, store: IncidentStoreInMemory) -> dict[str, Any]:
    store.update_incident(
        incident.incident_id,
        {
            "metadata": {
                **incident.metadata,
                "isolated": True,
                "isolated_at": _utcnow().isoformat(),
            }
        },
    )
    return {"action": "isolate", "incident_id": incident.incident_id, "isolated": True}


def _execute_revoke_session(incident: IncidentRecordInMemory, store: IncidentStoreInMemory) -> dict[str, Any]:
    session_id = incident.metadata.get("session_id") or "unknown"
    store.update_incident(
        incident.incident_id,
        {
            "metadata": {
                **incident.metadata,
                "session_revoked": True,
                "revoked_session_id": session_id,
                "revoked_at": _utcnow().isoformat(),
            }
        },
    )
    return {"action": "revoke_session", "incident_id": incident.incident_id, "session_id": session_id}


def _execute_patch_policy(incident: IncidentRecordInMemory, store: IncidentStoreInMemory) -> dict[str, Any]:
    store.update_incident(
        incident.incident_id,
        {
            "metadata": {
                **incident.metadata,
                "policy_patched": True,
                "policy_patched_at": _utcnow().isoformat(),
                "policy_patch_reason": incident.summary,
            }
        },
    )
    return {"action": "patch_policy", "incident_id": incident.incident_id, "patched": True}


def _execute_notify(incident: IncidentRecordInMemory, store: IncidentStoreInMemory) -> dict[str, Any]:
    store.update_incident(
        incident.incident_id,
        {
            "metadata": {
                **incident.metadata,
                "notification_sent": True,
                "notified_at": _utcnow().isoformat(),
            }
        },
    )
    return {"action": "notify", "incident_id": incident.incident_id, "notification_sent": True}


def _execute_escalate(incident: IncidentRecordInMemory, store: IncidentStoreInMemory) -> dict[str, Any]:
    store.update_incident_status(
        incident.incident_id,
        status="investigating",
        metadata={"escalated": True, "escalated_at": _utcnow().isoformat()},
    )
    return {"action": "escalate", "incident_id": incident.incident_id, "escalated": True}


def _execute_resolve(incident: IncidentRecordInMemory, store: IncidentStoreInMemory) -> dict[str, Any]:
    store.resolve_incident(
        incident.incident_id,
        resolution="auto-remediated",
        verdict=incident.verdict,
        metadata={"auto_resolved": True, "resolved_by": "remediation_worker"},
    )
    return {"action": "resolve", "incident_id": incident.incident_id, "resolved": True}


def _execute_no_op(incident: IncidentRecordInMemory, store: IncidentStoreInMemory) -> dict[str, Any]:
    return {"action": "no_op", "incident_id": incident.incident_id}


_ACTION_DISPATCH: dict[RemediationAction, Any] = {
    RemediationAction.QUARANTINE: _execute_quarantine,
    RemediationAction.ISOLATE: _execute_isolate,
    RemediationAction.REVOKE_SESSION: _execute_revoke_session,
    RemediationAction.PATCH_POLICY: _execute_patch_policy,
    RemediationAction.NOTIFY: _execute_notify,
    RemediationAction.ESCALATE: _execute_escalate,
    RemediationAction.RESOLVE: _execute_resolve,
    RemediationAction.NO_OP: _execute_no_op,
}


# ---------------------------------------------------------------------------
# Remediation plan builder
# ---------------------------------------------------------------------------


def _build_action_plan(severity: str, verdict: str | None) -> list[RemediationAction]:
    if verdict and verdict in _VERDICT_ACTION_OVERRIDE:
        return list(_VERDICT_ACTION_OVERRIDE[verdict])
    return list(_SEVERITY_ACTION_MAP.get(severity, [RemediationAction.NOTIFY]))


def _make_step(action: RemediationAction) -> RemediationStep:
    return RemediationStep(
        step_id=f"step-{uuid4().hex[:10]}",
        action=action,
        status=RemediationStatus.PENDING,
        started_at=None,
        completed_at=None,
        error=None,
        metadata={},
    )


# ---------------------------------------------------------------------------
# In-memory remediation history store
# ---------------------------------------------------------------------------


class RemediationHistoryStore:
    def __init__(self) -> None:
        self._lock = Lock()
        self._records: list[RemediationRecord] = []

    def append(self, record: RemediationRecord) -> None:
        with self._lock:
            self._records.append(record)

    def list_all(self, limit: int = 200) -> list[RemediationRecord]:
        with self._lock:
            records = list(self._records)
        records.sort(key=lambda r: r.triggered_at, reverse=True)
        return records[:limit]

    def get_by_id(self, remediation_id: str) -> RemediationRecord | None:
        with self._lock:
            for record in self._records:
                if record.remediation_id == remediation_id:
                    return record
        return None

    def get_by_incident(self, incident_id: str) -> list[RemediationRecord]:
        with self._lock:
            return [r for r in self._records if r.incident_id == incident_id]

    def reset(self) -> None:
        with self._lock:
            self._records.clear()

    def summary(self) -> dict[str, Any]:
        with self._lock:
            records = list(self._records)
        total = len(records)
        by_status: dict[str, int] = {}
        by_action: dict[str, int] = {}
        for record in records:
            s = record.overall_status.value
            by_status[s] = by_status.get(s, 0) + 1
            for step in record.steps:
                a = step.action.value
                by_action[a] = by_action.get(a, 0) + 1
        return {
            "total": total,
            "by_status": by_status,
            "by_action": by_action,
        }


_REMEDIATION_HISTORY: RemediationHistoryStore = RemediationHistoryStore()


def get_remediation_history() -> RemediationHistoryStore:
    return _REMEDIATION_HISTORY


def reset_remediation_history() -> None:
    _REMEDIATION_HISTORY.reset()


# ---------------------------------------------------------------------------
# Core remediation worker
# ---------------------------------------------------------------------------


class RemediationWorker:
    """
    Automated remediation pipeline for IronClaw security incidents.

    Consumes an incident record, builds a severity/verdict-driven action plan,
    executes each step in sequence, persists results to the remediation history
    store, and emits a structured audit log entry per execution.
    """

    def __init__(
        self,
        incident_store: IncidentStoreInMemory | None = None,
        history_store: RemediationHistoryStore | None = None,
    ) -> None:
        self._incident_store = incident_store or get_incident_store()
        self._history_store = history_store or _REMEDIATION_HISTORY

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def remediate(
        self,
        incident_id: str,
        *,
        trigger_reason: str = "automated",
        extra_metadata: dict[str, Any] | None = None,
    ) -> RemediationRecord:
        incident = self._incident_store.get_incident(incident_id)
        if incident is None:
            raise ValueError(f"Incident not found: {incident_id}")

        actions = _build_action_plan(incident.severity, incident.verdict)
        steps = [_make_step(a) for a in actions]

        record = RemediationRecord(
            remediation_id=f"rem-{uuid4().hex[:12]}",
            incident_id=incident_id,
            severity=incident.severity,
            verdict=incident.verdict,
            steps=steps,
            overall_status=RemediationStatus.RUNNING,
            triggered_at=_utcnow(),
            completed_at=None,
            trigger_reason=trigger_reason,
            metadata=dict(extra_metadata or {}),
        )

        any_failed = False
        for step in record.steps:
            step.status = RemediationStatus.RUNNING
            step.started_at = _utcnow()
            handler = _ACTION_DISPATCH.get(step.action)
            try:
                if handler is None:
                    step.status = RemediationStatus.SKIPPED
                else:
                    result = handler(incident, self._incident_store)
                    step.metadata.update(result)
                    step.status = RemediationStatus.SUCCEEDED
            except Exception as exc:
                step.status = RemediationStatus.FAILED
                step.error = str(exc)
                any_failed = True
                logger.error(
                    "Remediation step failed",
                    extra={
                        "step_id": step.step_id,
                        "action": step.action.value,
                        "incident_id": incident_id,
                        "error": str(exc),
                    },
                )
            finally:
                step.completed_at = _utcnow()

        record.overall_status = RemediationStatus.FAILED if any_failed else RemediationStatus.SUCCEEDED
        record.completed_at = _utcnow()

        self._history_store.append(record)
        self._emit_audit(incident, record)
        logger.info(
            "Remediation completed",
            extra={
                "remediation_id": record.remediation_id,
                "incident_id": incident_id,
                "overall_status": record.overall_status.value,
                "steps": len(record.steps),
            },
        )
        return record

    async def remediate_async(
        self,
        incident_id: str,
        *,
        trigger_reason: str = "automated",
        extra_metadata: dict[str, Any] | None = None,
    ) -> RemediationRecord:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            lambda: self.remediate(
                incident_id,
                trigger_reason=trigger_reason,
                extra_metadata=extra_metadata,
            ),
        )

    def remediate_batch(
        self,
        incident_ids: list[str],
        *,
        trigger_reason: str = "automated_batch",
    ) -> list[RemediationRecord]:
        results: list[RemediationRecord] = []
        for iid in incident_ids:
            try:
                results.append(self.remediate(iid, trigger_reason=trigger_reason))
            except Exception as exc:
                logger.error(
                    "Batch remediation failed for incident",
                    extra={"incident_id": iid, "error": str(exc)},
                )
        return results

    def remediate_open_incidents(
        self,
        *,
        severity_filter: str | None = None,
        limit: int = 50,
    ) -> list[RemediationRecord]:
        incidents = self._incident_store.list_incidents(
            status="open",
            severity=severity_filter,
            limit=limit,
        )
        return self.remediate_batch(
            [i.incident_id for i in incidents],
            trigger_reason="automated_sweep",
        )

    def get_record(self, remediation_id: str) -> RemediationRecord | None:
        return self._history_store.get_by_id(remediation_id)

    def list_records(self, limit: int = 200) -> list[RemediationRecord]:
        return self._history_store.list_all(limit=limit)

    def history_for_incident(self, incident_id: str) -> list[RemediationRecord]:
        return self._history_store.get_by_incident(incident_id)

    def summary(self) -> dict[str, Any]:
        return self._history_store.summary()

    # ------------------------------------------------------------------
    # Audit integration
    # ------------------------------------------------------------------

    def _emit_audit(
        self,
        incident: IncidentRecordInMemory,
        record: RemediationRecord,
    ) -> None:
        try:
            audit_log = get_audit_log()
            audit_log.log(
                event_type="remediation_completed",
                actor_id="remediation_worker",
                resource_id=incident.incident_id,
                resource_type="incident",
                details={
                    "remediation_id": record.remediation_id,
                    "overall_status": record.overall_status.value,
                    "severity": incident.severity,
                    "verdict": incident.verdict,
                    "steps": [s.to_dict() for s in record.steps],
                    "trigger_reason": record.trigger_reason,
                },
            )
        except Exception as exc:
            logger.warning(
                "Remediation audit log emission failed",
                extra={"remediation_id": record.remediation_id, "error": str(exc)},
            )


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_REMEDIATION_WORKER: RemediationWorker | None = None
_WORKER_LOCK = Lock()


def get_remediation_worker() -> RemediationWorker:
    global _REMEDIATION_WORKER
    if _REMEDIATION_WORKER is None:
        with _WORKER_LOCK:
            if _REMEDIATION_WORKER is None:
                _REMEDIATION_WORKER = RemediationWorker()
    return _REMEDIATION_WORKER


def reset_remediation_worker() -> None:
    global _REMEDIATION_WORKER
    with _WORKER_LOCK:
        _REMEDIATION_WORKER = None
    reset_remediation_history()


# ---------------------------------------------------------------------------
# Free-function convenience API
# ---------------------------------------------------------------------------


def run_remediation(
    incident_id: str,
    *,
    trigger_reason: str = "automated",
    extra_metadata: dict[str, Any] | None = None,
) -> RemediationRecord:
    return get_remediation_worker().remediate(
        incident_id,
        trigger_reason=trigger_reason,
        extra_metadata=extra_metadata,
    )


def run_remediation_batch(
    incident_ids: list[str],
    *,
    trigger_reason: str = "automated_batch",
) -> list[RemediationRecord]:
    return get_remediation_worker().remediate_batch(
        incident_ids,
        trigger_reason=trigger_reason,
    )


def sweep_open_incidents(
    *,
    severity_filter: str | None = None,
    limit: int = 50,
) -> list[RemediationRecord]:
    return get_remediation_worker().remediate_open_incidents(
        severity_filter=severity_filter,
        limit=limit,
    )


def get_remediation_summary() -> dict[str, Any]:
    return get_remediation_worker().summary()
