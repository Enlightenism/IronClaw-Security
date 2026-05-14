from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from v.detection.sessionrisk import SessionRiskLevel, SessionRiskSnapshot
from v.services.attackcorrelation import CorrelationCluster


class ResponseDisposition(str, Enum):
    ALLOW = "allow"
    WARN = "warn"
    STEP_UP = "step_up"
    QUEUE_REVIEW = "queue_review"
    QUARANTINE = "quarantine"
    BLOCK = "block"
    REMEDIATE = "remediate"


class ResponseAction(BaseModel):
    action: ResponseDisposition = Field(..., description="Primary disposition selected")
    target: str = Field(
        ...,
        description="Target of the action, e.g. session, request, incident, artifact, integration",
    )
    target_id: str = Field(..., description="Identifier of the target object")
    reason: str = Field(..., description="Human-readable action rationale")
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional structured context for downstream workflow handlers",
    )


class CoordinatedResponse(BaseModel):
    session_id: str | None = Field(
        None,
        description="Runtime session being evaluated, if applicable",
    )
    incident_id: str | None = Field(
        None,
        description="Incident identifier if one already exists or is assigned upstream",
    )
    disposition: ResponseDisposition = Field(..., description="Overall final disposition")
    review_required: bool = Field(
        ...,
        description="Whether the cluster/session should be routed to human review",
    )
    escalation_required: bool = Field(
        ...,
        description="Whether automated escalation should occur immediately",
    )
    playbook: str | None = Field(
        None,
        description="Suggested playbook slug for downstream incident/remediation flow",
    )
    reasons: list[str] = Field(
        default_factory=list,
        description="Explainable reasons used for audit logs, UI, and downstream routing",
    )
    actions: list[ResponseAction] = Field(
        default_factory=list,
        description="Ordered actions that downstream handlers can execute",
    )


class ResponseCoordinator:
    """Coordinates outputs from threat correlation and session risk into a single,
    explainable response plan.

    This class is intentionally orchestration-only:
    - It does not persist incidents.
    - It does not call the review queue directly.
    - It does not execute quarantines or remediation.
    - It produces a structured plan for remediationgate / incidentservice / reviewqueueservice.

    Typical usage:
        coordinator = ResponseCoordinator()
        response = coordinator.coordinate(
            cluster=cluster,
            session_snapshot=session_snapshot,
            incident_id="inc_123",
        )
    """

    def coordinate(
        self,
        *,
        cluster: CorrelationCluster,
        session_snapshot: SessionRiskSnapshot | None = None,
        incident_id: str | None = None,
    ) -> CoordinatedResponse:
        reasons: list[str] = []
        actions: list[ResponseAction] = []

        session_id = self._resolve_session_id(cluster, session_snapshot)
        playbook = cluster.playbook_suggestion
        review_required = False
        escalation_required = False

        cluster_priority = (cluster.priority or "low").lower()
        cluster_action = (cluster.recommended_action or "monitor").lower()

        disposition = self._disposition_from_cluster_action(cluster_action)

        reasons.append(
            f"Correlation cluster {cluster.cluster_id} scored {cluster.risk_score:.2f} with priority '{cluster.priority}'.",
        )

        if cluster.playbook_suggestion:
            reasons.append(f"Suggested playbook: {cluster.playbook_suggestion}.")

        if session_snapshot is not None:
            reasons.append(
                f"Session {session_snapshot.session_id} scored {session_snapshot.risk_score:.2f} with level '{session_snapshot.level.value}'.",
            )
            disposition = self._tighten_disposition(disposition, session_snapshot)
            if session_snapshot.dominant_kinds:
                dominant = ", ".join(kind.value for kind in session_snapshot.dominant_kinds[:3])
                reasons.append(f"Dominant session risk signals: {dominant}.")

        if cluster_priority in {"high", "critical"}:
            review_required = True

        if cluster_priority == "critical":
            escalation_required = True

        if session_snapshot is not None:
            if session_snapshot.level in {SessionRiskLevel.HIGH, SessionRiskLevel.CRITICAL}:
                review_required = True
            if session_snapshot.level is SessionRiskLevel.CRITICAL:
                escalation_required = True

        if disposition in {
            ResponseDisposition.QUEUE_REVIEW,
            ResponseDisposition.QUARANTINE,
            ResponseDisposition.BLOCK,
            ResponseDisposition.REMEDIATE,
        }:
            review_required = True

        if disposition in {
            ResponseDisposition.QUARANTINE,
            ResponseDisposition.BLOCK,
            ResponseDisposition.REMEDIATE,
        }:
            escalation_required = True

        actions.extend(
            self._build_primary_actions(
                disposition=disposition,
                session_id=session_id,
                incident_id=incident_id,
                cluster=cluster,
                playbook=playbook,
            ),
        )

        if review_required:
            actions.append(
                ResponseAction(
                    action=ResponseDisposition.QUEUE_REVIEW,
                    target="cluster",
                    target_id=cluster.cluster_id,
                    reason="Threat correlation or session risk exceeded review threshold.",
                    metadata={
                        "cluster_priority": cluster.priority,
                        "cluster_risk_score": cluster.risk_score,
                        "incident_id": incident_id,
                        "playbook": playbook,
                    },
                ),
            )

        return CoordinatedResponse(
            session_id=session_id,
            incident_id=incident_id,
            disposition=disposition,
            review_required=review_required,
            escalation_required=escalation_required,
            playbook=playbook,
            reasons=reasons,
            actions=actions,
        )

    def _resolve_session_id(
        self,
        cluster: CorrelationCluster,
        session_snapshot: SessionRiskSnapshot | None,
    ) -> str | None:
        if session_snapshot is not None:
            return session_snapshot.session_id

        session_ids = {signal.session_id for signal in cluster.signals if signal.session_id}
        if len(session_ids) == 1:
            return next(iter(session_ids))
        return None

    def _disposition_from_cluster_action(
        self,
        cluster_action: str,
    ) -> ResponseDisposition:
        mapping = {
            "monitor": ResponseDisposition.ALLOW,
            "allow": ResponseDisposition.ALLOW,
            "warn": ResponseDisposition.WARN,
            "review": ResponseDisposition.QUEUE_REVIEW,
            "queue_for_review": ResponseDisposition.QUEUE_REVIEW,
            "review_and_rate_limit": ResponseDisposition.STEP_UP,
            "review_and_quarantine": ResponseDisposition.QUARANTINE,
            "quarantine": ResponseDisposition.QUARANTINE,
            "quarantine_and_review": ResponseDisposition.QUARANTINE,
            "quarantine_and_restrict": ResponseDisposition.BLOCK,
            "quarantine_and_block": ResponseDisposition.BLOCK,
            "remediate": ResponseDisposition.REMEDIATE,
            "auto_remediate": ResponseDisposition.REMEDIATE,
        }
        return mapping.get(cluster_action, ResponseDisposition.QUEUE_REVIEW)

    def _tighten_disposition(
        self,
        disposition: ResponseDisposition,
        session_snapshot: SessionRiskSnapshot,
    ) -> ResponseDisposition:
        """Raise the response severity when session risk is higher than the cluster's
        default recommendation.
        """
        session_action = (session_snapshot.recommended_action or "").lower()

        if session_snapshot.level is SessionRiskLevel.CRITICAL:
            if "block" in session_action:
                return ResponseDisposition.BLOCK
            return self._max_disposition(disposition, ResponseDisposition.QUARANTINE)

        if session_snapshot.level is SessionRiskLevel.HIGH:
            if "queue_review" in session_action or "review" in session_action:
                return self._max_disposition(disposition, ResponseDisposition.QUEUE_REVIEW)
            if "step_up" in session_action:
                return self._max_disposition(disposition, ResponseDisposition.STEP_UP)
            return self._max_disposition(disposition, ResponseDisposition.STEP_UP)

        if session_snapshot.level is SessionRiskLevel.MEDIUM:
            if disposition is ResponseDisposition.ALLOW:
                return ResponseDisposition.WARN

        return disposition

    def _max_disposition(
        self,
        left: ResponseDisposition,
        right: ResponseDisposition,
    ) -> ResponseDisposition:
        rank = {
            ResponseDisposition.ALLOW: 0,
            ResponseDisposition.WARN: 1,
            ResponseDisposition.STEP_UP: 2,
            ResponseDisposition.QUEUE_REVIEW: 3,
            ResponseDisposition.QUARANTINE: 4,
            ResponseDisposition.BLOCK: 5,
            ResponseDisposition.REMEDIATE: 6,
        }
        return left if rank[left] >= rank[right] else right

    def _build_primary_actions(
        self,
        *,
        disposition: ResponseDisposition,
        session_id: str | None,
        incident_id: str | None,
        cluster: CorrelationCluster,
        playbook: str | None,
    ) -> list[ResponseAction]:
        actions: list[ResponseAction] = []

        if disposition is ResponseDisposition.ALLOW:
            actions.append(
                ResponseAction(
                    action=ResponseDisposition.ALLOW,
                    target="cluster",
                    target_id=cluster.cluster_id,
                    reason="Risk posture remained below enforcement thresholds.",
                    metadata={"cluster_priority": cluster.priority},
                ),
            )
            return actions

        if disposition is ResponseDisposition.WARN:
            actions.append(
                ResponseAction(
                    action=ResponseDisposition.WARN,
                    target="session" if session_id else "cluster",
                    target_id=session_id or cluster.cluster_id,
                    reason="Elevated indicators detected; continue with warning and monitoring.",
                    metadata={"playbook": playbook, "incident_id": incident_id},
                ),
            )
            return actions

        if disposition is ResponseDisposition.STEP_UP:
            actions.append(
                ResponseAction(
                    action=ResponseDisposition.STEP_UP,
                    target="session" if session_id else "cluster",
                    target_id=session_id or cluster.cluster_id,
                    reason="Elevated threat posture requires stronger controls before proceeding.",
                    metadata={
                        "playbook": playbook,
                        "incident_id": incident_id,
                        "cluster_priority": cluster.priority,
                    },
                ),
            )
            return actions

        if disposition is ResponseDisposition.QUEUE_REVIEW:
            actions.append(
                ResponseAction(
                    action=ResponseDisposition.QUEUE_REVIEW,
                    target="incident" if incident_id else "cluster",
                    target_id=incident_id or cluster.cluster_id,
                    reason="Threat activity requires analyst review.",
                    metadata={"playbook": playbook, "cluster_risk_score": cluster.risk_score},
                ),
            )
            return actions

        if disposition is ResponseDisposition.QUARANTINE:
            actions.append(
                ResponseAction(
                    action=ResponseDisposition.QUARANTINE,
                    target="session" if session_id else "cluster",
                    target_id=session_id or cluster.cluster_id,
                    reason="Risk posture crossed quarantine threshold.",
                    metadata={"playbook": playbook, "incident_id": incident_id},
                ),
            )
            return actions

        if disposition is ResponseDisposition.BLOCK:
            actions.append(
                ResponseAction(
                    action=ResponseDisposition.BLOCK,
                    target="session" if session_id else "cluster",
                    target_id=session_id or cluster.cluster_id,
                    reason="Threat posture requires immediate blocking / restriction.",
                    metadata={"playbook": playbook, "incident_id": incident_id},
                ),
            )
            return actions

        if disposition is ResponseDisposition.REMEDIATE:
            actions.append(
                ResponseAction(
                    action=ResponseDisposition.REMEDIATE,
                    target="incident" if incident_id else "cluster",
                    target_id=incident_id or cluster.cluster_id,
                    reason="Automated remediation was selected for this threat cluster.",
                    metadata={"playbook": playbook, "cluster_priority": cluster.priority},
                ),
            )
            return actions

        actions.append(
            ResponseAction(
                action=ResponseDisposition.QUEUE_REVIEW,
                target="cluster",
                target_id=cluster.cluster_id,
                reason="Fallback review action selected.",
                metadata={"playbook": playbook},
            ),
        )
        return actions
