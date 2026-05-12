from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from v.orchestrator.responsecoordinator import CoordinatedResponse, ResponseDisposition
from v.services.attackcorrelation import CorrelationCluster


class IncidentStatus(str, Enum):
    OPEN = "open"
    TRIAGED = "triaged"
    QUARANTINED = "quarantined"
    REMEDIATING = "remediating"
    RESOLVED = "resolved"


class IncidentSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentEvidence(BaseModel):
    kind: str = Field(..., description="Evidence type such as signal, edge, session, artifact")
    value: str = Field(..., description="Stable identifier or compact value")
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional evidence context for analysts and UI",
    )


class IncidentRecord(BaseModel):
    incident_id: str = Field(..., description="Stable incident identifier")
    title: str = Field(..., description="Human-readable incident title")
    status: IncidentStatus = Field(..., description="Current lifecycle state")
    severity: IncidentSeverity = Field(..., description="Incident severity")
    cluster_id: str = Field(..., description="Source correlation cluster identifier")
    session_id: str | None = Field(
        None,
        description="Primary linked session when a single session is identifiable",
    )
    playbook: str | None = Field(
        None,
        description="Suggested or assigned response playbook",
    )
    disposition: ResponseDisposition | None = Field(
        None,
        description="Current coordinated response disposition",
    )
    reasons: list[str] = Field(
        default_factory=list,
        description="Analyst/audit reasons and explanation strings",
    )
    evidence: list[IncidentEvidence] = Field(
        default_factory=list,
        description="Incident evidence linked from cluster/session response",
    )
    created_at: str = Field(..., description="UTC ISO-8601 creation timestamp")
    updated_at: str = Field(..., description="UTC ISO-8601 update timestamp")


class IncidentService:
    """
    Minimal in-memory incident linker for correlated threat clusters.

    Design goals:
    - Deterministic, test-friendly, no external persistence required.
    - Convert correlation clusters + coordinated response plans into incident records.
    - Preserve evidence for analyst review and UI summaries.
    - Allow later replacement with a database-backed implementation without changing callers.
    """

    def __init__(self) -> None:
        self._incidents: dict[str, IncidentRecord] = {}
        self._counter = 1

    def list_incidents(self) -> list[IncidentRecord]:
        return list(self._incidents.values())

    def get(self, incident_id: str) -> IncidentRecord | None:
        return self._incidents.get(incident_id)

    def create_from_cluster(
        self,
        *,
        cluster: CorrelationCluster,
        coordinated_response: CoordinatedResponse,
        title: str | None = None,
    ) -> IncidentRecord:
        incident_id = self._next_incident_id()
        now = self._utcnow()

        record = IncidentRecord(
            incident_id=incident_id,
            title=title or self._default_title(cluster, coordinated_response),
            status=self._status_from_disposition(coordinated_response.disposition),
            severity=self._severity_from_cluster(cluster),
            cluster_id=cluster.cluster_id,
            session_id=coordinated_response.session_id,
            playbook=coordinated_response.playbook,
            disposition=coordinated_response.disposition,
            reasons=list(coordinated_response.reasons),
            evidence=self._build_evidence(cluster, coordinated_response),
            created_at=now,
            updated_at=now,
        )
        self._incidents[incident_id] = record
        return record

    def upsert_from_cluster(
        self,
        *,
        cluster: CorrelationCluster,
        coordinated_response: CoordinatedResponse,
        incident_id: str | None = None,
        title: str | None = None,
    ) -> IncidentRecord:
        if incident_id and incident_id in self._incidents:
            return self.update_from_cluster(
                incident_id=incident_id,
                cluster=cluster,
                coordinated_response=coordinated_response,
                title=title,
            )
        return self.create_from_cluster(
            cluster=cluster,
            coordinated_response=coordinated_response,
            title=title,
        )

    def update_from_cluster(
        self,
        *,
        incident_id: str,
        cluster: CorrelationCluster,
        coordinated_response: CoordinatedResponse,
        title: str | None = None,
    ) -> IncidentRecord:
        existing = self._incidents.get(incident_id)
        if existing is None:
            raise KeyError(f"incident not found: {incident_id}")

        updated = IncidentRecord(
            incident_id=existing.incident_id,
            title=title or existing.title or self._default_title(cluster, coordinated_response),
            status=self._status_from_disposition(coordinated_response.disposition),
            severity=self._max_severity(existing.severity, self._severity_from_cluster(cluster)),
            cluster_id=cluster.cluster_id,
            session_id=coordinated_response.session_id or existing.session_id,
            playbook=coordinated_response.playbook or existing.playbook,
            disposition=coordinated_response.disposition,
            reasons=self._merge_unique_strings(existing.reasons, coordinated_response.reasons),
            evidence=self._merge_evidence(
                existing.evidence,
                self._build_evidence(cluster, coordinated_response),
            ),
            created_at=existing.created_at,
            updated_at=self._utcnow(),
        )
        self._incidents[incident_id] = updated
        return updated

    def link_clusters(
        self,
        *,
        clusters: Sequence[CorrelationCluster],
        coordinated_responses: Sequence[CoordinatedResponse],
    ) -> list[IncidentRecord]:
        """
        Convenience method for batch orchestration flows.

        The caller is expected to pass aligned cluster/response sequences.
        """
        if len(clusters) != len(coordinated_responses):
            raise ValueError("clusters and coordinated_responses must have the same length")

        incidents: list[IncidentRecord] = []
        for cluster, response in zip(clusters, coordinated_responses, strict=False):
            incident_id = response.incident_id
            incidents.append(
                self.upsert_from_cluster(
                    cluster=cluster,
                    coordinated_response=response,
                    incident_id=incident_id,
                )
            )
        return incidents

    def _build_evidence(
        self,
        cluster: CorrelationCluster,
        coordinated_response: CoordinatedResponse,
    ) -> list[IncidentEvidence]:
        evidence: list[IncidentEvidence] = []

        evidence.append(
            IncidentEvidence(
                kind="cluster",
                value=cluster.cluster_id,
                metadata={
                    "risk_score": cluster.risk_score,
                    "priority": cluster.priority,
                    "recommended_action": cluster.recommended_action,
                },
            )
        )

        for signal in cluster.signals:
            evidence.append(
                IncidentEvidence(
                    kind="signal",
                    value=signal.signal_id,
                    metadata={
                        "kind": signal.kind.value,
                        "severity": signal.severity,
                        "confidence": signal.confidence,
                        "source": signal.source,
                        "session_id": signal.session_id,
                        "actor_id": signal.actor_id,
                    },
                )
            )

            if signal.session_id:
                evidence.append(
                    IncidentEvidence(
                        kind="session",
                        value=signal.session_id,
                        metadata={},
                    )
                )

            for artifact_id in sorted(signal.detonated_artifact_ids):
                evidence.append(
                    IncidentEvidence(
                        kind="artifact",
                        value=artifact_id,
                        metadata={"signal_id": signal.signal_id},
                    )
                )

            for hostile_context_id in sorted(signal.hostile_context_ids):
                evidence.append(
                    IncidentEvidence(
                        kind="hostile_context",
                        value=hostile_context_id,
                        metadata={"signal_id": signal.signal_id},
                    )
                )

        for edge in cluster.edges:
            evidence.append(
                IncidentEvidence(
                    kind="correlation_edge",
                    value=f"{edge.from_signal_id}:{edge.to_signal_id}",
                    metadata={
                        "edge_type": edge.edge_type.value,
                        "weight": edge.weight,
                        "reason": edge.reason,
                    },
                )
            )

        for action in coordinated_response.actions:
            evidence.append(
                IncidentEvidence(
                    kind="response_action",
                    value=action.action.value,
                    metadata={
                        "target": action.target,
                        "target_id": action.target_id,
                        "reason": action.reason,
                    },
                )
            )

        return self._dedupe_evidence(evidence)

    def _default_title(
        self,
        cluster: CorrelationCluster,
        coordinated_response: CoordinatedResponse,
    ) -> str:
        session_part = (
            f"session {coordinated_response.session_id}"
            if coordinated_response.session_id
            else cluster.cluster_id
        )
        return f"{cluster.priority.title()} threat incident for {session_part}"

    def _status_from_disposition(self, disposition: ResponseDisposition) -> IncidentStatus:
        if disposition in {ResponseDisposition.BLOCK, ResponseDisposition.QUARANTINE}:
            return IncidentStatus.QUARANTINED
        if disposition is ResponseDisposition.REMEDIATE:
            return IncidentStatus.REMEDIATING
        if disposition in {ResponseDisposition.QUEUE_REVIEW, ResponseDisposition.STEP_UP}:
            return IncidentStatus.TRIAGED
        return IncidentStatus.OPEN

    def _severity_from_cluster(self, cluster: CorrelationCluster) -> IncidentSeverity:
        priority = (cluster.priority or "low").lower()
        if priority == "critical":
            return IncidentSeverity.CRITICAL
        if priority == "high":
            return IncidentSeverity.HIGH
        if priority == "medium":
            return IncidentSeverity.MEDIUM
        return IncidentSeverity.LOW

    def _max_severity(
        self,
        left: IncidentSeverity,
        right: IncidentSeverity,
    ) -> IncidentSeverity:
        rank = {
            IncidentSeverity.LOW: 0,
            IncidentSeverity.MEDIUM: 1,
            IncidentSeverity.HIGH: 2,
            IncidentSeverity.CRITICAL: 3,
        }
        return left if rank[left] >= rank[right] else right

    def _merge_unique_strings(self, left: list[str], right: list[str]) -> list[str]:
        merged: list[str] = []
        seen = set()
        for item in [*left, *right]:
            if item not in seen:
                seen.add(item)
                merged.append(item)
        return merged

    def _merge_evidence(
        self,
        left: list[IncidentEvidence],
        right: list[IncidentEvidence],
    ) -> list[IncidentEvidence]:
        return self._dedupe_evidence([*left, *right])

    def _dedupe_evidence(self, evidence: list[IncidentEvidence]) -> list[IncidentEvidence]:
        deduped: list[IncidentEvidence] = []
        seen = set()
        for item in evidence:
            key = (item.kind, item.value, tuple(sorted(item.metadata.items())))
            if key in seen:
                continue
            seen.add(key)
            deduped.append(item)
        return deduped

    def _next_incident_id(self) -> str:
        incident_id = f"inc_{self._counter:05d}"
        self._counter += 1
        return incident_id

    def _utcnow(self) -> str:
        return datetime.now(UTC).isoformat()