from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from app.orchestrator.reviewqueue import ReviewQueue, build_review_queue
from app.orchestrator.reviewstatestore import ReviewStateStore, build_review_state_store
from app.orchestrator.runtimesession import RuntimeSessionStore, build_runtime_session_store
from app.orchestrator.secureruntimepipeline import (
    SecureRuntimeDecision,
    SecureRuntimePipeline,
    initialize_secureruntimepipeline,
)
from app.persistencebootstrap import build_store


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _utc_now_iso() -> str:
    return _utc_now().isoformat().replace("+00:00", "Z")


def _text(value: Any, default: str = "") -> str:
    if value is None:
        return default
    result = str(value).strip()
    return result or default


def _bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, int | float):
        return bool(value)
    lowered = str(value).strip().lower()
    if lowered in {"1", "true", "yes", "y", "on", "enabled", "active"}:
        return True
    if lowered in {"0", "false", "no", "n", "off", "disabled", "inactive"}:
        return False
    return default


def _as_dict(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, dict):
        return dict(value)
    if isinstance(value, Mapping):
        return dict(value)
    if hasattr(value, "as_dict") and callable(value.as_dict):
        dumped = value.as_dict()
        if isinstance(dumped, Mapping):
            return dict(dumped)
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
    return {}


@dataclass(slots=True)
class CoordinatedResponse:
    decision: SecureRuntimeDecision
    session_state: dict[str, Any]
    review_state: dict[str, Any] | None
    queued_for_review: bool
    review_leased: bool
    persistencedegraded: bool
    reasons: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "decision": _as_dict(self.decision),
            "session_state": dict(self.session_state),
            "review_state": dict(self.review_state) if self.review_state is not None else None,
            "queued_for_review": self.queued_for_review,
            "review_leased": self.review_leased,
            "persistencedegraded": self.persistencedegraded,
            "reasons": [dict(r) for r in self.reasons],
        }


@dataclass(slots=True)
class ResponseCoordinator:
    runtime_sessions: RuntimeSessionStore
    review_states: ReviewStateStore
    review_queue: ReviewQueue
    runtime_pipeline: SecureRuntimePipeline
    name: str = "responsecoordinator"

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "runtime_sessions": self.runtime_sessions.as_dict(),
            "review_states": self.review_states.as_dict(),
            "review_queue": self.review_queue.as_dict(),
        }

    def healthcheck(self) -> dict[str, Any]:
        sessions_ok = self.runtime_sessions.healthcheck()
        reviews_ok = self.review_states.healthcheck()
        backend_ok = bool(sessions_ok and reviews_ok and self.review_queue.healthcheck())
        return {
            "runtime_sessions_ok": bool(sessions_ok),
            "review_states_ok": bool(reviews_ok),
            "review_queue_ok": bool(self.review_queue.healthcheck()),
            "backend_ok": backend_ok,
        }

    def _persistencedegraded(self) -> bool:
        hc = self.healthcheck()
        return not bool(hc.get("backend_ok", False))

    def coordinate_decision(
        self,
        *,
        session_id: str,
        actorid: str,
        actiontype: str,
        target: str,
        content: str,
        riskscore: int,
        filepath: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> CoordinatedResponse:
        session = self.runtime_sessions.get_session(session_id)
        if session is None:
            raise ValueError(f"runtime session '{session_id}' not found")

        persistencedegraded = self._persistencedegraded()

        decision = self.runtime_pipeline.evaluate(
            actorid=actorid,
            actiontype=actiontype,
            target=target,
            content=content,
            riskscore=riskscore,
            sessionid=session_id,
            filepath=filepath or _text(session.get("filepath")),
            metadata=_as_dict(metadata),
            persistencedegraded=persistencedegraded,
        )

        review_state: dict[str, Any] | None = None
        queued_for_review = False
        review_leased = False
        reasons: list[dict[str, Any]] = []

        if decision.reviewrequired or decision.quarantine:
            base_review_payload: dict[str, Any] = {
                "review_id": session.get("review_id") or None,
                "request_id": session.get("request_id"),
                "organization_id": session.get("organization_id"),
                "owner_id": session.get("owner_id"),
                "severity": "high" if decision.quarantine else "medium",
                "status": "queued" if decision.reviewrequired else "pending",
                "decision": None,
                "resolution": None,
                "source": "responsecoordinator",
                "notes": (f"Executionstate={decision.executionstate}, policyverdict={decision.policyverdict}, responseaction={decision.responseaction}."),
                "tags": ["runtime_decision"],
                "metadata": {
                    "session_id": session_id,
                    "actorid": actorid,
                    "actiontype": actiontype,
                    "target": target,
                    "filepath": filepath or _text(session.get("filepath")),
                    "degradedmode": decision.degradedmode,
                    "persistencedegraded": persistencedegraded,
                },
            }

            review_state = self.review_states.upsert_state(base_review_payload)
            queued_for_review = True

            queue_item = self.review_queue.enqueue(
                review_state,
                queue_id=_text(review_state.get("queue_id")) or self.review_queue.queue_id,
            )
            review_state = queue_item
            reasons.append(
                {
                    "source": "responsecoordinator",
                    "label": "Review enqueue",
                    "details": f"Queued review '{queue_item.get('review_id')}' for session '{session_id}'.",
                    "score": decision.adjustedriskscore,
                },
            )

        if queued_for_review and not decision.degradedmode:
            leased = self.review_queue.lease_next(reviewer_id=None)
            if leased is not None:
                review_leased = True
                review_state = leased
                reasons.append(
                    {
                        "source": "responsecoordinator",
                        "label": "Review lease",
                        "details": f"Leased review '{leased.get('review_id')}' for active handling.",
                        "score": decision.adjustedriskscore,
                    },
                )

        session_updates: dict[str, Any] = {
            "status": decision.executionstate,
            "last_updated_at": _utc_now_iso(),
        }
        if review_state is not None:
            session_updates["review_id"] = review_state.get("review_id") or review_state.get("id")
        session_state = self.runtime_sessions.update_session(session_id, session_updates) or session

        summary_reason = {
            "source": "responsecoordinator",
            "label": "Decision coordination",
            "details": (f"Coordinated decision '{decision.policyverdict}' for session '{session_id}' with executionstate '{decision.executionstate}'."),
            "score": decision.adjustedriskscore,
        }
        reasons.append(summary_reason)

        return CoordinatedResponse(
            decision=decision,
            session_state=session_state,
            review_state=review_state,
            queued_for_review=queued_for_review,
            review_leased=review_leased,
            persistencedegraded=persistencedegraded,
            reasons=reasons,
        )


def build_response_coordinator(
    *,
    backend: Any | None = None,
    session_backend: Any | None = None,
    review_backend: Any | None = None,
    queue_backend: Any | None = None,
    queue_id: str = "default",
    **backend_kwargs: Any,
) -> ResponseCoordinator:
    resolved_backend = backend if backend is not None else build_store(**backend_kwargs)

    runtime_sessions = build_runtime_session_store(
        backend=session_backend or resolved_backend,
    )
    review_states = build_review_state_store(
        backend=review_backend or resolved_backend,
    )
    review_queue = build_review_queue(
        backend=queue_backend or resolved_backend,
        queue_id=queue_id,
    )

    runtime_pipeline = initialize_secureruntimepipeline()

    return ResponseCoordinator(
        runtime_sessions=runtime_sessions,
        review_states=review_states,
        review_queue=review_queue,
        runtime_pipeline=runtime_pipeline,
    )


def create_response_coordinator(
    *,
    backend: Any | None = None,
    **backend_kwargs: Any,
) -> ResponseCoordinator:
    return build_response_coordinator(backend=backend, **backend_kwargs)


def get_response_coordinator(
    *,
    backend: Any | None = None,
    **backend_kwargs: Any,
) -> ResponseCoordinator:
    return build_response_coordinator(backend=backend, **backend_kwargs)
