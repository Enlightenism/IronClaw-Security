from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from pydantic import BaseModel, Field


class CorrelatedSignalKind(str, Enum):
    PROMPT_INJECTION = "prompt_injection"
    MALWARE_DETONATION = "malware_detonation"
    DATA_EXFIL = "data_exfiltration"
    POLICY_VIOLATION = "policy_violation"
    TOOL_ABUSE = "tool_abuse"
    NETWORK_EVASION = "network_evasion"
    HOSTILE_CONTEXT = "hostile_context"
    SESSION_RISK = "session_risk"
    OTHER = "other"


class CorrelationEdgeType(str, Enum):
    SAME_SESSION = "same_session"
    SAME_ACTOR = "same_actor"
    SHARED_IO = "shared_io"
    SHARED_RESOURCE = "shared_resource"
    TEMPORAL_CHAIN = "temporal_chain"
    MALWARE_CAMPAIGN = "malware_campaign"
    PLAYBOOK_PHASE = "playbook_phase"
    INCIDENT_LINK = "incident_link"


class CorrelatedSignal(BaseModel):
    signal_id: str = Field(..., description="Stable identifier of the originating signal")
    kind: CorrelatedSignalKind = Field(..., description="Normalized signal kind used for correlation")
    severity: float = Field(..., ge=0.0, le=10.0, description="Signal severity on a 0–10 scale")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Detector confidence in [0,1]")
    session_id: Optional[str] = Field(
        None, description="Runtime session identifier when available"
    )
    incident_id: Optional[str] = Field(
        None, description="Existing incident identifier if the signal is already attached"
    )
    actor_id: Optional[str] = Field(
        None,
        description="Logical actor identifier (API key, integration ID, user, unit wallet, etc.)",
    )
    tool_name: Optional[str] = Field(
        None, description="Tool or integration associated with the signal, if any"
    )
    source: str = Field(
        ..., description="Source subsystem (promptguard, malware, secrets, runtime, etc.)"
    )
    tags: Set[str] = Field(
        default_factory=set,
        description="Arbitrary tags (model id, integration name, environment, etc.)",
    )
    hostile_context_ids: Set[str] = Field(
        default_factory=set,
        description="IDs of hostile context patterns matched by this signal",
    )
    detonated_artifact_ids: Set[str] = Field(
        default_factory=set,
        description="Artifact/detonation IDs related to malware or sandbox execution",
    )
    related_request_ids: Set[str] = Field(
        default_factory=set,
        description="Request or action IDs this signal is attached to",
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Unstructured detector-specific metadata (kept for later enrichment)",
    )


class CorrelationEdge(BaseModel):
    from_signal_id: str
    to_signal_id: str
    edge_type: CorrelationEdgeType
    weight: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Edge contribution to overall campaign / incident strength",
    )
    reason: str = Field(..., description="Human-readable explanation for why these are linked")


class CorrelationCluster(BaseModel):
    cluster_id: str = Field(..., description="Deterministic cluster identifier")
    signals: List[CorrelatedSignal]
    edges: List[CorrelationEdge]
    risk_score: float = Field(..., ge=0.0, le=10.0)
    priority: str = Field(
        ...,
        description="Triage priority bucket (low, medium, high, critical)",
    )
    recommended_action: str = Field(
        ...,
        description="High-level recommendation (review, quarantine, auto-remediate, ignore)",
    )
    playbook_suggestion: Optional[str] = Field(
        None,
        description="Suggested response playbook slug for downstream automation",
    )


@dataclass(frozen=True)
class _CorrelationConfig:
    session_time_window_seconds: int = 600
    min_campaign_signals: int = 2
    min_high_risk_score: float = 6.0
    min_critical_risk_score: float = 8.5
    session_risk_boost: float = 1.0
    hostile_context_boost: float = 1.0
    malware_detonation_boost: float = 1.5
    shared_io_weight: float = 0.7
    same_session_weight: float = 0.6
    same_actor_weight: float = 0.5
    incident_link_weight: float = 0.8


class AttackCorrelationService:
    """
    Lightweight, local-first attack correlation engine for IronClaw-Security.

    This service:
    - Normalizes incoming threat signals from PromptGuard, malware detonation, session risk, etc.
    - Builds a simple correlation graph connecting signals by session, actor, IO, hostile context, and malware artifacts.
    - Computes cluster-level risk scores and triage priorities.
    - Produces recommended actions and optional playbook hints for use by policy engine / remediation gate.

    It is deliberately stateless: it operates on a batch of signals, and the caller
    is responsible for persistence and incident lifecycle management.
    """

    def __init__(self, config: Optional[_CorrelationConfig] = None) -> None:
        self._config = config or _CorrelationConfig()

    def correlate(
        self, signals: Sequence[CorrelatedSignal]
    ) -> List[CorrelationCluster]:
        """
        Correlate a batch of signals into higher-level campaigns/incident candidates.

        The algorithm is intentionally conservative and explainable:
        - Build edges for same session, same actor, shared IO, malware artifacts, hostile context.
        - Compute connected components as clusters.
        - Score each cluster based on aggregated severity, confidence, and enrichment.
        - Classify into priority buckets and advise next actions.

        The caller can feed the resulting clusters into:
        - reviewqueueservice for human review
        - remediationgate / responsecoordinator for automated actions
        - incidentservice for persistent incident objects
        """
        if not signals:
            return []

        signal_by_id: Dict[str, CorrelatedSignal] = {s.signal_id: s for s in signals}
        edges: List[CorrelationEdge] = []

        edges.extend(self._link_same_session(signals))
        edges.extend(self._link_same_actor(signals))
        edges.extend(self._link_shared_io(signals))
        edges.extend(self._link_hostile_context(signals))
        edges.extend(self._link_malware_artifacts(signals))
        edges.extend(self._link_incidents(signals))

        clusters = self._build_clusters(signal_by_id, edges)
        return [self._score_cluster(cluster) for cluster in clusters]

    def _link_same_session(
        self, signals: Sequence[CorrelatedSignal]
    ) -> List[CorrelationEdge]:
        by_session: Dict[str, List[CorrelatedSignal]] = {}
        for s in signals:
            if s.session_id:
                by_session.setdefault(s.session_id, []).append(s)

        edges: List[CorrelationEdge] = []
        for bucket in by_session.values():
            if len(bucket) < 2:
                continue
            ids = [s.signal_id for s in bucket]
            for i, src in enumerate(ids):
                for dst in ids[i + 1 :]:
                    edges.append(
                        CorrelationEdge(
                            from_signal_id=src,
                            to_signal_id=dst,
                            edge_type=CorrelationEdgeType.SAME_SESSION,
                            weight=self._config.same_session_weight,
                            reason="Signals share the same runtime session",
                        )
                    )
        return edges

    def _link_same_actor(
        self, signals: Sequence[CorrelatedSignal]
    ) -> List[CorrelationEdge]:
        by_actor: Dict[str, List[CorrelatedSignal]] = {}
        for s in signals:
            if s.actor_id:
                by_actor.setdefault(s.actor_id, []).append(s)

        edges: List[CorrelationEdge] = []
        for bucket in by_actor.values():
            if len(bucket) < 2:
                continue
            ids = [s.signal_id for s in bucket]
            for i, src in enumerate(ids):
                for dst in ids[i + 1 :]:
                    edges.append(
                        CorrelationEdge(
                            from_signal_id=src,
                            to_signal_id=dst,
                            edge_type=CorrelationEdgeType.SAME_ACTOR,
                            weight=self._config.same_actor_weight,
                            reason="Signals originate from the same actor or API key",
                        )
                    )
        return edges

    def _link_shared_io(
        self, signals: Sequence[CorrelatedSignal]
    ) -> List[CorrelationEdge]:
        """
        Link signals that share IO artifacts (requests, tool calls, files).

        We currently approximate shared IO via overlapping related_request_ids.
        """
        by_request: Dict[str, List[CorrelatedSignal]] = {}
        for s in signals:
            for req_id in s.related_request_ids:
                by_request.setdefault(req_id, []).append(s)

        edges: List[CorrelationEdge] = []
        for bucket in by_request.values():
            if len(bucket) < 2:
                continue
            ids = [s.signal_id for s in bucket]
            for i, src in enumerate(ids):
                for dst in ids[i + 1 :]:
                    edges.append(
                        CorrelationEdge(
                            from_signal_id=src,
                            to_signal_id=dst,
                            edge_type=CorrelationEdgeType.SHARED_IO,
                            weight=self._config.shared_io_weight,
                            reason="Signals share one or more related requests or tool executions",
                        )
                    )
        return edges

    def _link_hostile_context(
        self, signals: Sequence[CorrelatedSignal]
    ) -> List[CorrelationEdge]:
        """
        Link signals that share hostile context patterns.

        This ties prompt injection, evasive chains, and other hostile context matches together.
        """
        by_hostile: Dict[str, List[CorrelatedSignal]] = {}
        for s in signals:
            for ctx_id in s.hostile_context_ids:
                by_hostile.setdefault(ctx_id, []).append(s)

        edges: List[CorrelationEdge] = []
        for bucket in by_hostile.values():
            if len(bucket) < 2:
                continue
            ids = [s.signal_id for s in bucket]
            for i, src in enumerate(ids):
                for dst in ids[i + 1 :]:
                    edges.append(
                        CorrelationEdge(
                            from_signal_id=src,
                            to_signal_id=dst,
                            edge_type=CorrelationEdgeType.HOSTILE_CONTEXT,
                            weight=self._config.hostile_context_boost,
                            reason="Signals share hostile context pattern matches",
                        )
                    )
        return edges

    def _link_malware_artifacts(
        self, signals: Sequence[CorrelatedSignal]
    ) -> List[CorrelationEdge]:
        """
        Link signals that share malware artifacts or detonation runs.

        This ties malware sandbox output back into higher-level incident reasoning.
        """
        by_artifact: Dict[str, List[CorrelatedSignal]] = {}
        for s in signals:
            for artifact_id in s.detonated_artifact_ids:
                by_artifact.setdefault(artifact_id, []).append(s)

        edges: List[CorrelationEdge] = []
        for bucket in by_artifact.values():
            if len(bucket) < 2:
                continue
            ids = [s.signal_id for s in bucket]
            for i, src in enumerate(ids):
                for dst in ids[i + 1 :]:
                    edges.append(
                        CorrelationEdge(
                            from_signal_id=src,
                            to_signal_id=dst,
                            edge_type=CorrelationEdgeType.MALWARE_CAMPAIGN,
                            weight=self._config.malware_detonation_boost,
                            reason="Signals share malware or detonation artifacts",
                        )
                    )
        return edges

    def _link_incidents(
        self, signals: Sequence[CorrelatedSignal]
    ) -> List[CorrelationEdge]:
        """
        Link signals that are already associated with the same incident.

        This helps keep enrichment from multiple detectors grouped coherently.
        """
        by_incident: Dict[str, List[CorrelatedSignal]] = {}
        for s in signals:
            if s.incident_id:
                by_incident.setdefault(s.incident_id, []).append(s)

        edges: List[CorrelationEdge] = []
        for bucket in by_incident.values():
            if len(bucket) < 2:
                continue
            ids = [s.signal_id for s in bucket]
            for i, src in enumerate(ids):
                for dst in ids[i + 1 :]:
                    edges.append(
                        CorrelationEdge(
                            from_signal_id=src,
                            to_signal_id=dst,
                            edge_type=CorrelationEdgeType.INCIDENT_LINK,
                            weight=self._config.incident_link_weight,
                            reason="Signals are attached to the same existing incident",
                        )
                    )
        return edges

    def _build_clusters(
        self,
        signals: Mapping[str, CorrelatedSignal],
        edges: Sequence[CorrelationEdge],
    ) -> List[CorrelationCluster]:
        """
        Compute connected components over the correlation graph.

        Each connected component becomes a correlation cluster.
        """
        adjacency: Dict[str, Set[str]] = {sid: set() for sid in signals.keys()}
        for edge in edges:
            if edge.from_signal_id not in adjacency or edge.to_signal_id not in adjacency:
                continue
            adjacency[edge.from_signal_id].add(edge.to_signal_id)
            adjacency[edge.to_signal_id].add(edge.from_signal_id)

        visited: Set[str] = set()
        clusters: List[CorrelationCluster] = []
        cluster_index = 0

        for sid in signals.keys():
            if sid in visited:
                continue
            component_ids = self._dfs_component(sid, adjacency, visited)
            component_signals = [signals[cid] for cid in component_ids]
            component_edges = [
                e
                for e in edges
                if e.from_signal_id in component_ids and e.to_signal_id in component_ids
            ]
            cluster_id = f"cluster-{cluster_index}"
            cluster_index += 1
            clusters.append(
                CorrelationCluster(
                    cluster_id=cluster_id,
                    signals=component_signals,
                    edges=component_edges,
                    risk_score=0.0,
                    priority="low",
                    recommended_action="review",
                    playbook_suggestion=None,
                )
            )
        return clusters

    def _dfs_component(
        self,
        start: str,
        adjacency: Mapping[str, Set[str]],
        visited: Set[str],
    ) -> Set[str]:
        stack = [start]
        component: Set[str] = set()
        while stack:
            sid = stack.pop()
            if sid in visited:
                continue
            visited.add(sid)
            component.add(sid)
            neighbors = adjacency.get(sid, set())
            for n in neighbors:
                if n not in visited:
                    stack.append(n)
        return component

    def _score_cluster(self, cluster: CorrelationCluster) -> CorrelationCluster:
        """
        Compute a cluster-level risk score and triage metadata.

        We combine:
        - max per-signal severity
        - mean severity weighted by confidence
        - enrichment boosts from hostile context and malware detonation
        - graph density as a weak indicator of campaign coordination
        """
        if not cluster.signals:
            return cluster

        severities = [s.severity for s in cluster.signals]
        confidences = [s.confidence for s in cluster.signals]
        max_severity = max(severities)
        weighted_severity = (
            sum(s * c for s, c in zip(severities, confidences)) / max(1e-6, sum(confidences))
        )

        hostile_boost = self._config.hostile_context_boost if any(
            s.hostile_context_ids for s in cluster.signals
        ) else 0.0
        malware_boost = self._config.malware_detonation_boost if any(
            s.detonated_artifact_ids for s in cluster.signals
        ) else 0.0
        session_boost = self._config.session_risk_boost if any(
            s.kind == CorrelatedSignalKind.SESSION_RISK for s in cluster.signals
        ) else 0.0

        # Simple graph density approximation
        n = len(cluster.signals)
        max_edges = max(1, n * (n - 1) / 2)
        density = min(1.0, len(cluster.edges) / max_edges)

        base_score = (max_severity * 0.6) + (weighted_severity * 0.4)
        score = base_score + hostile_boost + malware_boost + session_boost + (density * 1.0)
        score = max(0.0, min(10.0, score))

        priority = self._priority_for_score(score)
        action, playbook = self._action_for_cluster(cluster, score, priority)

        return CorrelationCluster(
            cluster_id=cluster.cluster_id,
            signals=cluster.signals,
            edges=cluster.edges,
            risk_score=score,
            priority=priority,
            recommended_action=action,
            playbook_suggestion=playbook,
        )

    def _priority_for_score(self, score: float) -> str:
        if score >= self._config.min_critical_risk_score:
            return "critical"
        if score >= self._config.min_high_risk_score:
            return "high"
        if score >= 3.0:
            return "medium"
        return "low"

    def _action_for_cluster(
        self,
        cluster: CorrelationCluster,
        score: float,
        priority: str,
    ) -> Tuple[str, Optional[str]]:
        """
        Decide recommended action and playbook suggestion.

        This does NOT perform actions; it only provides guidance for:
        - remediationgate / responsecoordinator
        - reviewqueueservice / incidentservice
        """
        contains_malware = any(
            s.kind == CorrelatedSignalKind.MALWARE_DETONATION for s in cluster.signals
        )
        contains_prompt_injection = any(
            s.kind == CorrelatedSignalKind.PROMPT_INJECTION for s in cluster.signals
        )
        contains_data_exfil = any(
            s.kind == CorrelatedSignalKind.DATA_EXFIL for s in cluster.signals
        )

        if priority == "critical":
            if contains_malware or contains_data_exfil:
                return "quarantine_and_restrict", "malware-data-exfiltration-response"
            if contains_prompt_injection:
                return "quarantine_and_review", "prompt-injection-incident-response"
            return "quarantine_and_review", "generic-critical-incident"

        if priority == "high":
            if contains_malware:
                return "review_and_quarantine", "malware-sandbox-review"
            if contains_prompt_injection:
                return "review_and_rate_limit", "prompt-guard-hot-incident"
            return "review_and_rate_limit", "security-hot-incident"

        if priority == "medium":
            return "queue_for_review", "security-signal-triage"

        return "monitor", None