from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from app.orchestrator.checkpoint_store import build_checkpoint_store
from app.orchestrator.decision_trace import build_decision_trace_store
from app.orchestrator.execution_plan import ExecutionPlan
from app.orchestrator.executorboundary import (
    ExecutionRequestBoundary,
    ExecutionResultBoundary,
)
from app.orchestrator.reviewstatestore import build_review_state_store
from app.persistencebootstrap import build_store

DEFAULT_SESSION_TABLE = "runtime_sessions"


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _utc_now_iso() -> str:
    return _utc_now().isoformat().replace("+00:00", "Z")


def _text(value: Any, default: str = "") -> str:
    if value is None:
        return default
    result = str(value).strip()
    return result or default


def _as_dict(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, dict):
        return dict(value)
    if isinstance(value, Mapping):
        return dict(value)
    if hasattr(value, "model_dump") and callable(value.model_dump):
        dumped = value.model_dump()
        if isinstance(dumped, Mapping):
            return dict(dumped)
    if hasattr(value, "dict") and callable(value.dict):
        dumped = value.dict()
        if isinstance(dumped, Mapping):
            return dict(dumped)
    if hasattr(value, "__dict__"):
        return {key: item for key, item in vars(value).items() if not key.startswith("_") and not callable(item)}
    raise TypeError("runtime session payload must be a mapping-like object")


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return list(value)
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, set):
        return list(value)
    return [value]


def _merge_metadata(*parts: Any) -> dict[str, Any]:
    merged: dict[str, Any] = {}
    for part in parts:
        if part is None:
            continue
        merged.update(_as_dict(part))
    return merged


@dataclass(slots=True)
class RuntimeSession:
    session_id: str
    request_id: str | None = None
    organization_id: str | None = None
    owner_id: str | None = None
    plan: ExecutionPlan | None = None
    request: ExecutionRequestBoundary | None = None
    result: ExecutionResultBoundary | None = None
    started_at: str | None = None
    completed_at: str | None = None
    last_updated_at: str | None = None
    status: str = "pending"
    steps_completed: int = 0
    total_steps: int | None = None
    checkpoints: list[dict[str, Any]] = field(default_factory=list)
    trace_id: str | None = None
    review_id: str | None = None
    resume_from_checkpoint_id: str | None = None
    resume_from_step_index: int | None = None
    resume_count: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "request_id": self.request_id,
            "organization_id": self.organization_id,
            "owner_id": self.owner_id,
            "plan": self.plan.as_dict() if hasattr(self.plan, "as_dict") else None,
            "request": self.request.as_dict() if hasattr(self.request, "as_dict") else None,
            "result": self.result.as_dict() if hasattr(self.result, "as_dict") else None,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "last_updated_at": self.last_updated_at,
            "status": self.status,
            "steps_completed": self.steps_completed,
            "total_steps": self.total_steps,
            "checkpoints": list(self.checkpoints),
            "trace_id": self.trace_id,
            "review_id": self.review_id,
            "resume_from_checkpoint_id": self.resume_from_checkpoint_id,
            "resume_from_step_index": self.resume_from_step_index,
            "resume_count": self.resume_count,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class RuntimeSessionStore:
    backend: Any = field(default_factory=build_store)
    table_name: str = DEFAULT_SESSION_TABLE
    checkpoint_store: Any = field(default_factory=build_checkpoint_store)
    decision_trace_store: Any = field(default_factory=build_decision_trace_store)
    review_state_store: Any = field(default_factory=build_review_state_store)

    @property
    def backend_name(self) -> str:
        return str(getattr(self.backend, "backend_name", "memory"))

    def is_ready(self) -> bool:
        return True

    def healthcheck(self) -> bool:
        probe = getattr(self.backend, "healthcheck", None)
        if callable(probe):
            return bool(probe())
        return True

    def as_dict(self) -> dict[str, Any]:
        return {
            "backend_name": self.backend_name,
            "table_name": self.table_name,
            "ready": self.is_ready(),
        }

    # Session lifecycle

    def _build_session_payload(
        self,
        payload: Mapping[str, Any] | None = None,
        *,
        session_id: str | None = None,
        request_id: str | None = None,
        organization_id: str | None = None,
        owner_id: str | None = None,
        status: str | None = None,
        plan: ExecutionPlan | None = None,
        request: ExecutionRequestBoundary | None = None,
        result: ExecutionResultBoundary | None = None,
        steps_completed: int | None = None,
        total_steps: int | None = None,
        trace_id: str | None = None,
        review_id: str | None = None,
        resume_from_checkpoint_id: str | None = None,
        resume_from_step_index: int | None = None,
        resume_count: int | None = None,
        metadata: Mapping[str, Any] | None = None,
        started_at: str | None = None,
        completed_at: str | None = None,
        last_updated_at: str | None = None,
        **extra: Any,
    ) -> dict[str, Any]:
        base = _as_dict(payload)
        base.update({key: value for key, value in extra.items() if value is not None})

        resolved_session_id = _text(session_id) or _text(base.get("session_id")) or _text(base.get("id")) or str(uuid4())
        resolved_request_id = _text(request_id) or _text(base.get("request_id")) or _text(getattr(request, "request_id", None))
        resolved_org_id = _text(organization_id) or _text(base.get("organization_id")) or _text(base.get("org_id"))
        resolved_owner_id = _text(owner_id) or _text(base.get("owner_id"))

        now_iso = _utc_now_iso()
        started_iso = started_at or _text(base.get("started_at")) or now_iso
        last_updated_iso = last_updated_at or _text(base.get("last_updated_at")) or now_iso
        completed_iso = completed_at or _text(base.get("completed_at"))

        resolved_status = _text(status) or _text(base.get("status")) or "pending"

        resolved_total_steps = total_steps if total_steps is not None else base.get("total_steps") if isinstance(base.get("total_steps"), int) else None

        resolved_steps_completed = steps_completed if steps_completed is not None else base.get("steps_completed") if isinstance(base.get("steps_completed"), int) else 0

        resolved_trace_id = _text(trace_id) or _text(base.get("trace_id"))

        resolved_review_id = _text(review_id) or _text(base.get("review_id"))

        resolved_resume_from_checkpoint_id = _text(resume_from_checkpoint_id) or _text(base.get("resume_from_checkpoint_id"))

        resolved_resume_from_step_index = resume_from_step_index if resume_from_step_index is not None else base.get("resume_from_step_index") if isinstance(base.get("resume_from_step_index"), int) else None

        resolved_resume_count = resume_count if resume_count is not None else base.get("resume_count") if isinstance(base.get("resume_count"), int) else 0

        resolved_metadata = _merge_metadata(base.get("metadata"), metadata)
        resolved_checkpoints = _as_list(base.get("checkpoints"))

        resolved_plan = plan or base.get("plan")
        resolved_request = request or base.get("request")
        resolved_result = result or base.get("result")

        return {
            "session_id": resolved_session_id,
            "id": resolved_session_id,
            "request_id": resolved_request_id or None,
            "organization_id": resolved_org_id or None,
            "owner_id": resolved_owner_id or None,
            "status": resolved_status,
            "started_at": started_iso,
            "completed_at": completed_iso,
            "last_updated_at": last_updated_iso,
            "steps_completed": resolved_steps_completed,
            "total_steps": resolved_total_steps,
            "trace_id": resolved_trace_id or None,
            "review_id": resolved_review_id or None,
            "resume_from_checkpoint_id": resolved_resume_from_checkpoint_id or None,
            "resume_from_step_index": resolved_resume_from_step_index,
            "resume_count": resolved_resume_count,
            "metadata": resolved_metadata,
            "checkpoints": resolved_checkpoints,
            "plan": (resolved_plan.as_dict() if hasattr(resolved_plan, "as_dict") else _as_dict(resolved_plan) if resolved_plan is not None else None),
            "request": (resolved_request.as_dict() if hasattr(resolved_request, "as_dict") else _as_dict(resolved_request) if resolved_request is not None else None),
            "result": (resolved_result.as_dict() if hasattr(resolved_result, "as_dict") else _as_dict(resolved_result) if resolved_result is not None else None),
        }

    def create_session(
        self,
        payload: Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        record = self._build_session_payload(payload, **kwargs)
        inserted = self.backend.insert(self.table_name, record)
        if isinstance(inserted, list) and inserted:
            return dict(inserted[0])
        if isinstance(inserted, dict):
            return dict(inserted)
        return record

    def create(
        self,
        payload: Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        return self.create_session(payload, **kwargs)

    def get_session(self, session_id: str) -> dict[str, Any] | None:
        if not _text(session_id):
            raise ValueError("session_id is required")

        for key in ("session_id", "id"):
            rows = self.backend.select(self.table_name, filters={key: session_id}, limit=1)
            if rows:
                return dict(rows[0])
        return None

    def get(self, session_id: str) -> dict[str, Any] | None:
        return self.get_session(session_id)

    def get_by_request_id(self, request_id: str) -> dict[str, Any] | None:
        normalized = _text(request_id)
        if not normalized:
            raise ValueError("request_id is required")

        rows = self.backend.select(self.table_name, filters={"request_id": normalized}, limit=1)
        if rows:
            return dict(rows[0])
        return None

    def list_sessions(
        self,
        *,
        limit: int = 100,
        filters: Mapping[str, Any] | None = None,
        organization_id: str | None = None,
        owner_id: str | None = None,
        status: str | None = None,
        active_only: bool | None = None,
    ) -> list[dict[str, Any]]:
        query_filters: dict[str, Any] = dict(filters or {})
        if organization_id:
            query_filters.setdefault("organization_id", organization_id)
        if owner_id:
            query_filters.setdefault("owner_id", owner_id)
        if status:
            query_filters.setdefault("status", status)
        if active_only:
            query_filters.setdefault("completed_at", None)

        rows = self.backend.select(self.table_name, filters=query_filters or None, limit=limit)
        items = [dict(row) for row in rows]
        items.sort(key=lambda row: _text(row.get("last_updated_at") or row.get("started_at")), reverse=True)
        return items

    def list(self, **kwargs: Any) -> list[dict[str, Any]]:
        return self.list_sessions(**kwargs)

    def update_session(self, session_id: str, updates: Mapping[str, Any]) -> dict[str, Any] | None:
        existing = self.get_session(session_id)
        if existing is None:
            return None

        merged = dict(existing)
        merged.update(_as_dict(updates))
        merged["session_id"] = existing.get("session_id") or existing.get("id") or session_id
        merged["id"] = merged["session_id"]
        merged["last_updated_at"] = _utc_now_iso()

        normalized = self._build_session_payload(merged)

        updated = self.backend.update(
            self.table_name,
            normalized,
            filters={"session_id": session_id},
        )
        if isinstance(updated, list) and updated:
            return dict(updated[0])

        updated = self.backend.update(
            self.table_name,
            normalized,
            filters={"id": session_id},
        )
        if isinstance(updated, list) and updated:
            return dict(updated[0])

        return normalized

    def update(self, session_id: str, updates: Mapping[str, Any]) -> dict[str, Any] | None:
        return self.update_session(session_id, updates)

    # Checkpoints & resume

    def add_checkpoint(
        self,
        session_id: str,
        checkpoint: Mapping[str, Any],
        *,
        step_index: int | None = None,
        label: str | None = None,
    ) -> dict[str, Any] | None:
        session = self.get_session(session_id)
        if session is None:
            return None

        checkpoint_payload: dict[str, Any] = {
            "session_id": session_id,
            "checkpoint_id": str(uuid4()),
            "created_at": _utc_now_iso(),
        }
        checkpoint_payload.update(_as_dict(checkpoint))
        if step_index is not None:
            checkpoint_payload.setdefault("step_index", step_index)
        if label:
            checkpoint_payload.setdefault("label", _text(label))

        try:
            stored = self.checkpoint_store.create_checkpoint(checkpoint_payload)  # type: ignore[attr-defined]
        except Exception:
            stored = checkpoint_payload

        checkpoints = _as_list(session.get("checkpoints"))
        checkpoints.append(stored)

        updates = {
            "checkpoints": checkpoints,
            "steps_completed": session.get("steps_completed", 0) + 1,
        }
        return self.update_session(session_id, updates)

    def resume_from_latest_checkpoint(
        self,
        session_id: str,
        *,
        mark_status: str = "resuming",
    ) -> dict[str, Any] | None:
        session = self.get_session(session_id)
        if session is None:
            return None

        checkpoints = _as_list(session.get("checkpoints"))
        if not checkpoints:
            return None

        latest = checkpoints[-1]
        checkpoint_id = _text(latest.get("checkpoint_id") or latest.get("id") or "")
        step_index = latest.get("step_index")
        resume_count = int(session.get("resume_count") or 0) + 1

        updates: dict[str, Any] = {
            "status": mark_status,
            "resume_from_checkpoint_id": checkpoint_id or None,
            "resume_from_step_index": step_index if isinstance(step_index, int) else None,
            "resume_count": resume_count,
        }
        return self.update_session(session_id, updates)

    # Status transitions

    def mark_started(
        self,
        session_id: str,
        *,
        status: str = "running",
    ) -> dict[str, Any] | None:
        updates = {
            "status": status,
            "started_at": _utc_now_iso(),
        }
        return self.update_session(session_id, updates)

    def mark_completed(
        self,
        session_id: str,
        result: ExecutionResultBoundary | Mapping[str, Any] | None = None,
        *,
        status: str = "completed",
    ) -> dict[str, Any] | None:
        updates: dict[str, Any] = {
            "status": status,
            "completed_at": _utc_now_iso(),
        }
        if result is not None:
            updates["result"] = result
        return self.update_session(session_id, updates)

    def mark_failed(
        self,
        session_id: str,
        error: Mapping[str, Any] | None = None,
        *,
        status: str = "failed",
    ) -> dict[str, Any] | None:
        updates: dict[str, Any] = {
            "status": status,
            "completed_at": _utc_now_iso(),
        }
        if error is not None:
            current = self.get_session(session_id) or {}
            meta = _merge_metadata(current.get("metadata"), {"error": _as_dict(error)})
            updates["metadata"] = meta
        return self.update_session(session_id, updates)

    # Decision trace and review links

    def attach_trace(
        self,
        session_id: str,
        trace_payload: Mapping[str, Any],
    ) -> dict[str, Any] | None:
        trace_record = self.decision_trace_store.create_trace(trace_payload)  # type: ignore[attr-defined]
        trace_id = _text(trace_record.get("trace_id") or trace_record.get("id"))
        if not trace_id:
            trace_id = str(uuid4())
        return self.update_session(session_id, {"trace_id": trace_id})

    def attach_review_state(
        self,
        session_id: str,
        review_payload: Mapping[str, Any],
    ) -> dict[str, Any] | None:
        session = self.get_session(session_id)
        if session is None:
            return None

        review_record = self.review_state_store.upsert_state(  # type: ignore[attr-defined]
            review_payload,
            request_id=session.get("request_id"),
            organization_id=session.get("organization_id"),
            owner_id=session.get("owner_id"),
        )
        review_id = _text(review_record.get("review_id") or review_record.get("id"))
        return self.update_session(session_id, {"review_id": review_id})

    # Deletion

    def delete_session(self, session_id: str) -> dict[str, Any] | None:
        if not _text(session_id):
            raise ValueError("session_id is required")

        deleted = self.backend.delete(self.table_name, filters={"session_id": session_id})
        if isinstance(deleted, list) and deleted:
            return dict(deleted[0])

        deleted = self.backend.delete(self.table_name, filters={"id": session_id})
        if isinstance(deleted, list) and deleted:
            return dict(deleted[0])

        return None

    def delete(self, session_id: str) -> dict[str, Any] | None:
        return self.delete_session(session_id)

    # Summary

    def summarize(
        self,
        *,
        organization_id: str | None = None,
        owner_id: str | None = None,
        limit: int = 1_000,
    ) -> dict[str, Any]:
        sessions = self.list_sessions(
            limit=limit,
            organization_id=organization_id,
            owner_id=owner_id,
        )

        by_status: dict[str, int] = {}
        active = 0
        completed = 0
        failed = 0

        for session in sessions:
            status = _text(session.get("status"), "unknown").lower()
            by_status[status] = by_status.get(status, 0) + 1
            if status in {"completed"}:
                completed += 1
            elif status in {"failed", "error"}:
                failed += 1
            elif session.get("completed_at") is None:
                active += 1

        return {
            "total_sessions": len(sessions),
            "active_sessions": active,
            "completed_sessions": completed,
            "failed_sessions": failed,
            "by_status": by_status,
            "backend_name": self.backend_name,
            "table_name": self.table_name,
        }


def build_runtime_session_store(
    *,
    backend: Any | None = None,
    table_name: str = DEFAULT_SESSION_TABLE,
    checkpoint_backend: Any | None = None,
    decision_trace_backend: Any | None = None,
    review_state_backend: Any | None = None,
    **store_kwargs: Any,
) -> RuntimeSessionStore:
    resolved_backend = backend if backend is not None else build_store(**store_kwargs)
    checkpoint_store = build_checkpoint_store(backend=checkpoint_backend or resolved_backend)
    decision_trace_store = build_decision_trace_store(backend=decision_trace_backend or resolved_backend)
    review_state_store = build_review_state_store(backend=review_state_backend or resolved_backend)
    return RuntimeSessionStore(
        backend=resolved_backend,
        table_name=table_name,
        checkpoint_store=checkpoint_store,
        decision_trace_store=decision_trace_store,
        review_state_store=review_state_store,
    )


def create_runtime_session_store(
    *,
    backend: Any | None = None,
    table_name: str = DEFAULT_SESSION_TABLE,
    **store_kwargs: Any,
) -> RuntimeSessionStore:
    return build_runtime_session_store(backend=backend, table_name=table_name, **store_kwargs)


def get_runtime_session_store(
    *,
    backend: Any | None = None,
    table_name: str = DEFAULT_SESSION_TABLE,
    **store_kwargs: Any,
) -> RuntimeSessionStore:
    return build_runtime_session_store(backend=backend, table_name=table_name, **store_kwargs)
