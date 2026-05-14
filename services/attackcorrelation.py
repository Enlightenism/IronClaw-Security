from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any


def _utcnow_iso() -> str:
    return datetime.now(UTC).isoformat()


def _as_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    return {}


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _uniq(values: Sequence[Any]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        ordered.append(text)
    return ordered


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _severity_rank(value: str) -> int:
    return {
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }.get(str(value or "").lower(), 0)


def _max_severity(values: Sequence[str]) -> str:
    best = "low"
    best_rank = 0
    for value in values:
        rank = _severity_rank(value)
        if rank > best_rank:
            best = str(value).lower()
            best_rank = rank
    return best


def _risk_band(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


def _hash_parts(*parts: Any) -> str:
    joined = "|".join(str(part) for part in parts if part is not None)
    return sha256(joined.encode("utf-8")).hexdigest()[:24]


@dataclass(slots=True)
class CorrelatedSignal:
    signal_id: str
    signal_type: str
    source: str
    severity: str
    summary: str
    score: int
    evidence: dict[str, Any] = field(default_factory=dict)
    indicator_keys: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=_utcnow_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "signal_id": self.signal_id,
            "signal_type": self.signal_type,
            "source": self.source,
            "severity": self.severity,
            "summary": self.summary,
            "score": self.score,
            "evidence": dict(self.evidence),
            "indicator_keys": list(self.indicator_keys),
            "created_at": self.created_at,
        }


class AttackCorrelationService:
    def __init__(
        self,
        incident_store: Any | None = None,
        review_queue_service: Any | None = None,
        quarantine_store: Any | None = None,
        playbook_registry: Any | None = None,
        remediation_gate: Any | None = None,
        malware_service: Any | None = None,
        detonation_service: Any | None = None,
        hostile_context_service: Any | None = None,
    ) -> None:
        self.incident_store = incident_store
        self.review_queue_service = review_queue_service
        self.quarantine_store = quarantine_store
        self.playbook_registry = playbook_registry
        self.remediation_gate = remediation_gate
        self.malware_service = malware_service
        self.detonation_service = detonation_service
        self.hostile_context_service = hostile_context_service

    def correlate(
        self,
        signals: Sequence[Mapping[str, Any]] | None,
        *,
        session_id: str | None = None,
        actor_id: str | None = None,
        organization_id: str | None = None,
        request_id: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        normalized_signals = [self._normalize_signal(signal) for signal in (signals or [])]

        malware_summary = self._lookup_malware_summary(
            normalized_signals,
            session_id=session_id,
            actor_id=actor_id,
            organization_id=organization_id,
        )
        detonation_summary = self._lookup_detonation_summary(
            normalized_signals,
            session_id=session_id,
            actor_id=actor_id,
            organization_id=organization_id,
        )
        hostile_context = self._lookup_hostile_context(
            normalized_signals,
            session_id=session_id,
            actor_id=actor_id,
            organization_id=organization_id,
        )

        derived_signals = self._build_derived_signals(
            malware_summary=malware_summary,
            detonation_summary=detonation_summary,
            hostile_context=hostile_context,
        )
        all_signals = normalized_signals + derived_signals

        indicators = self._collect_indicators(
            all_signals,
            malware_summary=malware_summary,
            detonation_summary=detonation_summary,
            hostile_context=hostile_context,
        )
        attack_fingerprint = self._build_attack_fingerprint(
            session_id=session_id,
            actor_id=actor_id,
            organization_id=organization_id,
            indicators=indicators,
            signals=all_signals,
        )
        risk_score = self._compute_risk_score(
            all_signals,
            malware_summary=malware_summary,
            detonation_summary=detonation_summary,
            hostile_context=hostile_context,
        )
        severity = _max_severity(
            [
                *(signal.severity for signal in all_signals),
                str(malware_summary.get("severity", "")),
                str(detonation_summary.get("severity", "")),
                str(hostile_context.get("severity", "")),
                _risk_band(risk_score),
            ],
        )
        confidence = self._compute_confidence(
            all_signals,
            malware_summary=malware_summary,
            detonation_summary=detonation_summary,
            hostile_context=hostile_context,
        )

        incident_id = self._resolve_incident_id(
            attack_fingerprint=attack_fingerprint,
            session_id=session_id,
            organization_id=organization_id,
        )
        playbooks = self._resolve_playbooks(
            severity=severity,
            risk_score=risk_score,
            signals=all_signals,
            malware_summary=malware_summary,
            detonation_summary=detonation_summary,
            hostile_context=hostile_context,
        )
        linked_reviews = self._enqueue_review(
            incident_id=incident_id,
            severity=severity,
            risk_score=risk_score,
            attack_fingerprint=attack_fingerprint,
            session_id=session_id,
            actor_id=actor_id,
            organization_id=organization_id,
            signals=all_signals,
            playbooks=playbooks,
        )
        linked_quarantine_records = self._quarantine_if_needed(
            incident_id=incident_id,
            severity=severity,
            risk_score=risk_score,
            attack_fingerprint=attack_fingerprint,
            session_id=session_id,
            actor_id=actor_id,
            organization_id=organization_id,
            signals=all_signals,
            malware_summary=malware_summary,
            detonation_summary=detonation_summary,
        )
        escalation_actions = self._open_remediation_actions(
            incident_id=incident_id,
            severity=severity,
            risk_score=risk_score,
            attack_fingerprint=attack_fingerprint,
            session_id=session_id,
            actor_id=actor_id,
            organization_id=organization_id,
            indicators=indicators,
            playbooks=playbooks,
        )

        incident = {
            "incident_id": incident_id,
            "title": self._build_title(all_signals, severity),
            "status": self._derive_status(linked_reviews, linked_quarantine_records, escalation_actions),
            "severity": severity,
            "risk_score": risk_score,
            "risk_band": _risk_band(risk_score),
            "confidence": confidence,
            "signal_count": len(all_signals),
            "attack_fingerprint": attack_fingerprint,
            "session_id": session_id,
            "actor_id": actor_id,
            "organization_id": organization_id,
            "indicators": indicators,
            "linked_reviews": linked_reviews,
            "linked_quarantine_records": linked_quarantine_records,
            "recommended_playbooks": playbooks,
            "escalation_actions": escalation_actions,
            "malware_summary": malware_summary,
            "detonation_summary": detonation_summary,
            "hostile_context": hostile_context,
            "signals": [signal.to_dict() for signal in all_signals],
            "metadata": {
                **_as_dict(metadata),
                "request_id": request_id,
                "created_at": _utcnow_iso(),
            },
        }

        self._persist_incident(incident)

        return {
            "incident": incident,
            "risk_score": risk_score,
            "risk_band": _risk_band(risk_score),
            "confidence": confidence,
            "attack_fingerprint": attack_fingerprint,
            "recommended_playbooks": playbooks,
            "linked_reviews": linked_reviews,
            "linked_quarantine_records": linked_quarantine_records,
            "escalation_actions": escalation_actions,
            "signals": [signal.to_dict() for signal in all_signals],
        }

    def _normalize_signal(self, raw: Mapping[str, Any]) -> CorrelatedSignal:
        evidence = _as_dict(raw.get("evidence"))
        severity = str(raw.get("severity") or "medium").lower()
        signal_type = str(raw.get("signal_type") or raw.get("type") or "generic")
        signal_id = str(raw.get("signal_id") or _hash_parts(signal_type, raw.get("source"), raw.get("summary")))
        indicator_keys = _uniq(
            [
                *_as_list(raw.get("indicator_keys")),
                *_as_list(evidence.get("hashes")),
                *_as_list(evidence.get("domains")),
                *_as_list(evidence.get("ips")),
                *_as_list(evidence.get("files")),
                *_as_list(evidence.get("tools")),
                raw.get("session_id"),
                raw.get("tool_name"),
                raw.get("prompt_fingerprint"),
            ],
        )
        return CorrelatedSignal(
            signal_id=signal_id,
            signal_type=signal_type,
            source=str(raw.get("source") or "unknown"),
            severity=severity,
            summary=str(raw.get("summary") or raw.get("message") or signal_type),
            score=_safe_int(raw.get("score"), self._default_score_for_severity(severity)),
            evidence=evidence,
            indicator_keys=indicator_keys,
            created_at=str(raw.get("created_at") or _utcnow_iso()),
        )

    def _default_score_for_severity(self, severity: str) -> int:
        return {
            "low": 20,
            "medium": 45,
            "high": 72,
            "critical": 92,
        }.get(str(severity).lower(), 45)

    def _lookup_malware_summary(
        self,
        signals: Sequence[CorrelatedSignal],
        *,
        session_id: str | None,
        actor_id: str | None,
        organization_id: str | None,
    ) -> dict[str, Any]:
        payload = {
            "session_id": session_id,
            "actor_id": actor_id,
            "organization_id": organization_id,
            "signals": [signal.to_dict() for signal in signals],
            "artifacts": self._extract_artifacts(signals),
        }
        return self._call_optional(
            self.malware_service,
            ["summarize", "analyze", "scan", "enrich"],
            payload,
        )

    def _lookup_detonation_summary(
        self,
        signals: Sequence[CorrelatedSignal],
        *,
        session_id: str | None,
        actor_id: str | None,
        organization_id: str | None,
    ) -> dict[str, Any]:
        payload = {
            "session_id": session_id,
            "actor_id": actor_id,
            "organization_id": organization_id,
            "signals": [signal.to_dict() for signal in signals],
            "artifacts": self._extract_artifacts(signals),
        }
        return self._call_optional(
            self.detonation_service,
            ["summarize", "analyze", "detonate"],
            payload,
        )

    def _lookup_hostile_context(
        self,
        signals: Sequence[CorrelatedSignal],
        *,
        session_id: str | None,
        actor_id: str | None,
        organization_id: str | None,
    ) -> dict[str, Any]:
        payload = {
            "session_id": session_id,
            "actor_id": actor_id,
            "organization_id": organization_id,
            "signals": [signal.to_dict() for signal in signals],
        }
        return self._call_optional(
            self.hostile_context_service,
            ["summarize", "analyze", "correlate", "lookup"],
            payload,
        )

    def _extract_artifacts(self, signals: Sequence[CorrelatedSignal]) -> list[dict[str, Any]]:
        artifacts: list[dict[str, Any]] = []
        for signal in signals:
            evidence = signal.evidence
            for artifact in _as_list(evidence.get("artifacts")):
                if isinstance(artifact, Mapping):
                    artifacts.append(dict(artifact))
            for file_name in _as_list(evidence.get("files")):
                artifacts.append({"name": str(file_name)})
            for file_hash in _as_list(evidence.get("hashes")):
                artifacts.append({"hash": str(file_hash)})
        return artifacts

    def _build_derived_signals(
        self,
        *,
        malware_summary: Mapping[str, Any],
        detonation_summary: Mapping[str, Any],
        hostile_context: Mapping[str, Any],
    ) -> list[CorrelatedSignal]:
        derived: list[CorrelatedSignal] = []

        if malware_summary:
            verdict = str(malware_summary.get("verdict") or malware_summary.get("status") or "").lower()
            severity = str(malware_summary.get("severity") or ("high" if verdict in {"malicious", "suspicious"} else "medium"))
            score = _safe_int(
                malware_summary.get("risk_score"),
                _safe_int(malware_summary.get("score"), self._default_score_for_severity(severity)),
            )
            derived.append(
                CorrelatedSignal(
                    signal_id=f"sig_{_hash_parts('malware', verdict, malware_summary.get('family'), malware_summary.get('summary'))}",
                    signal_type="malware_enrichment",
                    source="malware_service",
                    severity=severity,
                    summary=str(malware_summary.get("summary") or verdict or "Malware analysis matched suspicious artifacts"),
                    score=score,
                    evidence=dict(malware_summary),
                    indicator_keys=_uniq(
                        [
                            *_as_list(malware_summary.get("hashes")),
                            *_as_list(malware_summary.get("families")),
                            *_as_list(malware_summary.get("files")),
                        ],
                    ),
                ),
            )

        if detonation_summary:
            severity = str(
                detonation_summary.get("severity")
                or _risk_band(
                    _safe_int(
                        detonation_summary.get("risk_score"),
                        _safe_int(detonation_summary.get("score")) or 50,
                    )
                )
            )
            score = _safe_int(
                detonation_summary.get("risk_score"),
                _safe_int(detonation_summary.get("score"), self._default_score_for_severity(severity)),
            )
            derived.append(
                CorrelatedSignal(
                    signal_id=f"sig_{_hash_parts('detonation', detonation_summary.get('verdict'), detonation_summary.get('summary'))}",
                    signal_type="detonation_signal",
                    source="detonation_service",
                    severity=severity,
                    summary=str(detonation_summary.get("summary") or "Detonation behavior indicates hostile runtime activity"),
                    score=score,
                    evidence=dict(detonation_summary),
                    indicator_keys=_uniq(
                        [
                            *_as_list(detonation_summary.get("hashes")),
                            *_as_list(detonation_summary.get("domains")),
                            *_as_list(detonation_summary.get("ips")),
                        ],
                    ),
                ),
            )

        if hostile_context:
            severity = str(
                hostile_context.get("severity")
                or _risk_band(
                    _safe_int(
                        hostile_context.get("risk_score"),
                        _safe_int(hostile_context.get("score")) or 60,
                    )
                )
            )
            score = _safe_int(
                hostile_context.get("risk_score"),
                _safe_int(hostile_context.get("score"), self._default_score_for_severity(severity)),
            )
            derived.append(
                CorrelatedSignal(
                    signal_id=f"sig_{_hash_parts('hostile', hostile_context.get('campaign'), hostile_context.get('cluster'))}",
                    signal_type="hostile_context",
                    source="hostile_context_service",
                    severity=severity,
                    summary=str(hostile_context.get("summary") or "Threat context matched hostile campaign activity"),
                    score=score,
                    evidence=dict(hostile_context),
                    indicator_keys=_uniq(
                        [
                            hostile_context.get("campaign"),
                            hostile_context.get("cluster"),
                            *_as_list(hostile_context.get("ttp_ids")),
                        ],
                    ),
                ),
            )

        return derived

    def _collect_indicators(
        self,
        signals: Sequence[CorrelatedSignal],
        *,
        malware_summary: Mapping[str, Any],
        detonation_summary: Mapping[str, Any],
        hostile_context: Mapping[str, Any],
    ) -> dict[str, list[str]]:
        indicators: dict[str, list[str]] = {
            "hashes": [],
            "domains": [],
            "ips": [],
            "files": [],
            "tools": [],
            "families": [],
            "campaigns": [],
            "clusters": [],
            "ttp_ids": [],
            "prompt_fingerprints": [],
        }

        for signal in signals:
            evidence = signal.evidence
            indicators["hashes"].extend(_as_list(evidence.get("hashes")))
            indicators["domains"].extend(_as_list(evidence.get("domains")))
            indicators["ips"].extend(_as_list(evidence.get("ips")))
            indicators["files"].extend(_as_list(evidence.get("files")))
            indicators["tools"].extend(_as_list(evidence.get("tools")))
            indicators["families"].extend(_as_list(evidence.get("families")))
            indicators["campaigns"].extend(_as_list(evidence.get("campaigns")))
            indicators["clusters"].extend(_as_list(evidence.get("clusters")))
            indicators["ttp_ids"].extend(_as_list(evidence.get("ttp_ids")))
            indicators["prompt_fingerprints"].extend(_as_list(evidence.get("prompt_fingerprints")))

        indicators["hashes"].extend(_as_list(malware_summary.get("hashes")))
        indicators["families"].extend(_as_list(malware_summary.get("families")))
        indicators["files"].extend(_as_list(malware_summary.get("files")))
        indicators["domains"].extend(_as_list(detonation_summary.get("domains")))
        indicators["ips"].extend(_as_list(detonation_summary.get("ips")))
        indicators["hashes"].extend(_as_list(detonation_summary.get("hashes")))
        indicators["campaigns"].extend(_as_list(hostile_context.get("campaigns")))
        indicators["clusters"].extend(_as_list(hostile_context.get("clusters")))
        indicators["ttp_ids"].extend(_as_list(hostile_context.get("ttp_ids")))

        if hostile_context.get("campaign"):
            indicators["campaigns"].append(str(hostile_context.get("campaign")))
        if hostile_context.get("cluster"):
            indicators["clusters"].append(str(hostile_context.get("cluster")))

        return {key: _uniq(values) for key, values in indicators.items()}

    def _build_attack_fingerprint(
        self,
        *,
        session_id: str | None,
        actor_id: str | None,
        organization_id: str | None,
        indicators: Mapping[str, list[str]],
        signals: Sequence[CorrelatedSignal],
    ) -> str:
        signal_types = ",".join(sorted(signal.signal_type for signal in signals))
        stable_indicators = []
        for key in sorted(indicators.keys()):
            stable_indicators.append(f"{key}={','.join(sorted(indicators[key]))}")
        return _hash_parts(organization_id, actor_id, session_id, signal_types, "|".join(stable_indicators))

    def _compute_risk_score(
        self,
        signals: Sequence[CorrelatedSignal],
        *,
        malware_summary: Mapping[str, Any],
        detonation_summary: Mapping[str, Any],
        hostile_context: Mapping[str, Any],
    ) -> int:
        highest_signal = max((signal.score for signal in signals), default=0)
        malware_score = _safe_int(malware_summary.get("risk_score"), _safe_int(malware_summary.get("score")))
        detonation_score = _safe_int(detonation_summary.get("risk_score"), _safe_int(detonation_summary.get("score")))
        hostile_score = _safe_int(hostile_context.get("risk_score"), _safe_int(hostile_context.get("score")))

        risk_score = max(highest_signal, malware_score, detonation_score, hostile_score)

        if len(signals) >= 4:
            risk_score += 5
        if str(malware_summary.get("verdict") or "").lower() == "malicious":
            risk_score += 10
        if str(detonation_summary.get("verdict") or "").lower() in {"malicious", "blocked"}:
            risk_score += 10
        if hostile_context.get("campaign") or hostile_context.get("cluster"):
            risk_score += 8

        return min(risk_score, 100)

    def _compute_confidence(
        self,
        signals: Sequence[CorrelatedSignal],
        *,
        malware_summary: Mapping[str, Any],
        detonation_summary: Mapping[str, Any],
        hostile_context: Mapping[str, Any],
    ) -> float:
        confidence = 0.45
        confidence += min(len(signals) * 0.06, 0.24)
        if malware_summary:
            confidence += 0.10
        if detonation_summary:
            confidence += 0.10
        if hostile_context:
            confidence += 0.10
        if hostile_context.get("campaign") or hostile_context.get("cluster"):
            confidence += 0.05
        return round(min(confidence, 0.99), 2)

    def _resolve_incident_id(
        self,
        *,
        attack_fingerprint: str,
        session_id: str | None,
        organization_id: str | None,
    ) -> str:
        existing = self._call_optional(
            self.incident_store,
            ["find_by_attack_fingerprint", "find_by_fingerprint", "get_by_fingerprint"],
            {
                "attack_fingerprint": attack_fingerprint,
                "session_id": session_id,
                "organization_id": organization_id,
            },
            allow_none=True,
        )
        if isinstance(existing, Mapping):
            incident_id = existing.get("incident_id") or existing.get("id")
            if incident_id:
                return str(incident_id)
        return f"inc_{attack_fingerprint}"

    def _resolve_playbooks(
        self,
        *,
        severity: str,
        risk_score: int,
        signals: Sequence[CorrelatedSignal],
        malware_summary: Mapping[str, Any],
        detonation_summary: Mapping[str, Any],
        hostile_context: Mapping[str, Any],
    ) -> list[str]:
        signal_types = [signal.signal_type for signal in signals]
        tags = _uniq(
            [
                "malware" if malware_summary else None,
                "detonation" if detonation_summary else None,
                "threatintel" if hostile_context else None,
                "critical" if risk_score >= 85 else None,
                *signal_types,
            ],
        )

        result = self._call_optional(
            self.playbook_registry,
            ["resolve", "recommend", "match_playbooks"],
            {
                "severity": severity,
                "risk_score": risk_score,
                "signal_types": signal_types,
                "tags": tags,
            },
            allow_none=True,
        )
        if isinstance(result, Mapping):
            return _uniq(_as_list(result.get("playbooks")))
        if isinstance(result, list):
            return _uniq(result)

        playbooks: list[str] = []
        if risk_score >= 85:
            playbooks.append("critical-incident-response")
        if malware_summary:
            playbooks.append("malware-containment")
        if detonation_summary:
            playbooks.append("sandbox-detonation-review")
        if hostile_context:
            playbooks.append("threat-intel-correlation")
        if "prompt_injection" in signal_types:
            playbooks.append("prompt-injection-remediation")
        if "data_exfiltration" in signal_types:
            playbooks.append("exfiltration-containment")
        return _uniq(playbooks)

    def _enqueue_review(
        self,
        *,
        incident_id: str,
        severity: str,
        risk_score: int,
        attack_fingerprint: str,
        session_id: str | None,
        actor_id: str | None,
        organization_id: str | None,
        signals: Sequence[CorrelatedSignal],
        playbooks: Sequence[str],
    ) -> list[str]:
        if self.review_queue_service is None:
            return []
        if risk_score < 65 and _severity_rank(severity) < _severity_rank("high"):
            return []

        payload = {
            "incident_id": incident_id,
            "attack_fingerprint": attack_fingerprint,
            "severity": severity,
            "risk_score": risk_score,
            "session_id": session_id,
            "actor_id": actor_id,
            "organization_id": organization_id,
            "signal_count": len(signals),
            "playbooks": list(playbooks),
        }
        result = self._call_optional(
            self.review_queue_service,
            ["enqueue", "create_review", "open_review"],
            payload,
            allow_none=True,
        )
        if isinstance(result, Mapping):
            return _uniq([result.get("review_id"), result.get("id")])
        if isinstance(result, list):
            return _uniq(result)
        if result:
            return _uniq([result])
        return []

    def _quarantine_if_needed(
        self,
        *,
        incident_id: str,
        severity: str,
        risk_score: int,
        attack_fingerprint: str,
        session_id: str | None,
        actor_id: str | None,
        organization_id: str | None,
        signals: Sequence[CorrelatedSignal],
        malware_summary: Mapping[str, Any],
        detonation_summary: Mapping[str, Any],
    ) -> list[str]:
        if self.quarantine_store is None:
            return []

        requires_quarantine = risk_score >= 85 or str(malware_summary.get("verdict") or "").lower() == "malicious" or str(detonation_summary.get("verdict") or "").lower() in {"malicious", "blocked"}
        if not requires_quarantine:
            return []

        payload = {
            "incident_id": incident_id,
            "attack_fingerprint": attack_fingerprint,
            "severity": severity,
            "risk_score": risk_score,
            "session_id": session_id,
            "actor_id": actor_id,
            "organization_id": organization_id,
            "signals": [signal.to_dict() for signal in signals],
        }
        result = self._call_optional(
            self.quarantine_store,
            ["create_record", "quarantine", "create_quarantine_record"],
            payload,
            allow_none=True,
        )
        if isinstance(result, Mapping):
            return _uniq([result.get("quarantine_id"), result.get("record_id"), result.get("id")])
        if isinstance(result, list):
            return _uniq(result)
        if result:
            return _uniq([result])
        return []

    def _open_remediation_actions(
        self,
        *,
        incident_id: str,
        severity: str,
        risk_score: int,
        attack_fingerprint: str,
        session_id: str | None,
        actor_id: str | None,
        organization_id: str | None,
        indicators: Mapping[str, list[str]],
        playbooks: Sequence[str],
    ) -> list[dict[str, Any]]:
        if self.remediation_gate is None:
            return []
        if risk_score < 65:
            return []

        payload = {
            "incident_id": incident_id,
            "severity": severity,
            "risk_score": risk_score,
            "attack_fingerprint": attack_fingerprint,
            "session_id": session_id,
            "actor_id": actor_id,
            "organization_id": organization_id,
            "indicators": dict(indicators),
            "playbooks": list(playbooks),
        }
        result = self._call_optional(
            self.remediation_gate,
            ["open_actions", "create_actions", "evaluate"],
            payload,
            allow_none=True,
        )
        if isinstance(result, Mapping):
            actions = result.get("actions")
            if isinstance(actions, list):
                return [dict(action) for action in actions if isinstance(action, Mapping)]
            return [dict(result)]
        if isinstance(result, list):
            return [dict(action) for action in result if isinstance(action, Mapping)]
        return []

    def _derive_status(
        self,
        linked_reviews: Sequence[str],
        linked_quarantine_records: Sequence[str],
        escalation_actions: Sequence[Mapping[str, Any]],
    ) -> str:
        if linked_quarantine_records:
            return "quarantined"
        if escalation_actions:
            return "action_required"
        if linked_reviews:
            return "under_review"
        return "observed"

    def _build_title(self, signals: Sequence[CorrelatedSignal], severity: str) -> str:
        signal_types = _uniq(signal.signal_type for signal in signals)
        if signal_types:
            return f"{severity.upper()} incident: {', '.join(signal_types[:3])}"
        return f"{severity.upper()} incident"

    def _persist_incident(self, incident: Mapping[str, Any]) -> None:
        self._call_optional(
            self.incident_store,
            ["upsert_incident", "save_incident", "save", "upsert"],
            dict(incident),
            allow_none=True,
        )

    def _call_optional(
        self,
        target: Any,
        method_names: Sequence[str],
        payload: Any,
        default: Any = None,
        *,
        allow_none: bool = False,
    ) -> Any:
        if target is None:
            return {} if default is None and not allow_none else default

        for method_name in method_names:
            method = getattr(target, method_name, None)
            if callable(method):
                try:
                    if isinstance(payload, Mapping):
                        result = method(**dict(payload))
                    else:
                        result = method(payload)
                except TypeError:
                    result = method(payload)
                if result is None and not allow_none:
                    return {} if default is None else default
                return result
        return {} if default is None and not allow_none else default
