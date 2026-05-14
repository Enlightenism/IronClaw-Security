from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import uuid4


class GateStatus(str, Enum):
    OPEN = "open"
    CONDITIONAL = "conditional"
    CLOSED = "closed"
    QUARANTINED = "quarantined"
    NEEDS_REVIEW = "needs_review"


class RemediationAction(str, Enum):
    NONE = "none"
    REQUIRE_REVIEW = "require_review"
    APPLY_REDACTION = "apply_redaction"
    SANDBOX_ONLY = "sandbox_only"
    QUARANTINE = "quarantine"
    BLOCK = "block"


@dataclass(slots=True)
class RemediationRule:
    rule_id: str
    name: str
    condition: str
    action: RemediationAction
    severity: str = "medium"
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "condition": self.condition,
            "action": self.action.value,
            "severity": self.severity,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class GateEvidence:
    kind: str
    value: Any
    label: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "value": self.value,
            "label": self.label,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class GateDecision:
    gate_id: str
    request_id: str
    status: GateStatus
    allowed: bool
    action: RemediationAction
    reasons: list[str] = field(default_factory=list)
    matched_rules: list[RemediationRule] = field(default_factory=list)
    evidence: list[GateEvidence] = field(default_factory=list)
    review_required: bool = False
    quarantine_required: bool = False
    redaction_required: bool = False
    sandbox_required: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "gate_id": self.gate_id,
            "request_id": self.request_id,
            "status": self.status.value,
            "allowed": self.allowed,
            "action": self.action.value,
            "reasons": list(self.reasons),
            "matched_rules": [rule.to_dict() for rule in self.matched_rules],
            "evidence": [item.to_dict() for item in self.evidence],
            "review_required": self.review_required,
            "quarantine_required": self.quarantine_required,
            "redaction_required": self.redaction_required,
            "sandbox_required": self.sandbox_required,
            "metadata": dict(self.metadata),
            "created_at": self.created_at,
        }


class RemediationGate:
    def __init__(
        self,
        rules: Iterable[RemediationRule] | None = None,
        *,
        sink: Callable[[dict[str, Any]], Any] | None = None,
    ) -> None:
        self.rules = list(rules) if rules is not None else self._default_rules()
        self.sink = sink

    def evaluate(self, payload: Mapping[str, Any] | None) -> GateDecision:
        request = dict(payload or {})
        request_id = str(request.get("request_id") or f"req-{uuid4().hex}")

        matched_rules: list[RemediationRule] = []
        reasons: list[str] = []
        evidence: list[GateEvidence] = self._build_evidence(request)

        risk_score = int(request.get("risk_score", 0) or 0)
        verdict = str(request.get("verdict", "allow")).lower()
        review_required = bool(request.get("review_required", False))
        quarantine_required = bool(request.get("quarantine_required", False))
        secret_detected = bool(request.get("secret_detected", False))
        prompt_injection_detected = bool(request.get("prompt_injection_detected", False))
        requires_network = bool(request.get("requires_network", False))
        untrusted_output = bool(request.get("untrusted_output", False))
        malware_detected = bool(request.get("malware_detected", False))

        for rule in self.rules:
            if self._matches(rule, request):
                matched_rules.append(rule)
                reasons.append(rule.name)

        action = RemediationAction.NONE
        status = GateStatus.OPEN
        allowed = True
        redaction_required = False
        sandbox_required = False

        if malware_detected or verdict == "block":
            action = RemediationAction.BLOCK
            status = GateStatus.CLOSED
            allowed = False
        elif quarantine_required or verdict == "quarantine":
            action = RemediationAction.QUARANTINE
            status = GateStatus.QUARANTINED
            allowed = False
        elif secret_detected:
            action = RemediationAction.APPLY_REDACTION
            status = GateStatus.CONDITIONAL
            redaction_required = True
            sandbox_required = requires_network
        elif review_required or verdict == "warn":
            action = RemediationAction.REQUIRE_REVIEW
            status = GateStatus.NEEDS_REVIEW
            allowed = False
            review_required = True
        elif prompt_injection_detected or untrusted_output or risk_score >= 70 or (requires_network and risk_score >= 40):
            action = RemediationAction.SANDBOX_ONLY
            status = GateStatus.CONDITIONAL
            sandbox_required = True

        if action == RemediationAction.BLOCK:
            reasons.append("Blocking condition met.")
        elif action == RemediationAction.QUARANTINE:
            reasons.append("Quarantine condition met.")
        elif action == RemediationAction.APPLY_REDACTION:
            reasons.append("Sensitive data requires redaction before release.")
        elif action == RemediationAction.REQUIRE_REVIEW:
            reasons.append("Human review required before continuation.")
        elif action == RemediationAction.SANDBOX_ONLY:
            reasons.append("Execution must remain inside sandbox boundaries.")
        else:
            reasons.append("No additional remediation required.")

        decision = GateDecision(
            gate_id=f"gate-{uuid4().hex}",
            request_id=request_id,
            status=status,
            allowed=allowed,
            action=action,
            reasons=self._dedupe(reasons),
            matched_rules=matched_rules,
            evidence=evidence,
            review_required=review_required,
            quarantine_required=action == RemediationAction.QUARANTINE or quarantine_required,
            redaction_required=redaction_required,
            sandbox_required=sandbox_required,
            metadata={
                "risk_score": risk_score,
                "verdict": verdict,
                "requires_network": requires_network,
                "secret_detected": secret_detected,
                "prompt_injection_detected": prompt_injection_detected,
                "untrusted_output": untrusted_output,
                "malware_detected": malware_detected,
            },
        )
        self._emit(decision)
        return decision

    def evaluate_dict(self, payload: Mapping[str, Any] | None) -> dict[str, Any]:
        return self.evaluate(payload).to_dict()

    def _matches(self, rule: RemediationRule, request: Mapping[str, Any]) -> bool:
        condition = rule.condition

        if condition == "malware_detected":
            return bool(request.get("malware_detected"))
        if condition == "quarantine_required":
            return bool(request.get("quarantine_required")) or str(request.get("verdict", "")).lower() == "quarantine"
        if condition == "review_required":
            return bool(request.get("review_required")) or str(request.get("verdict", "")).lower() == "warn"
        if condition == "secret_detected":
            return bool(request.get("secret_detected"))
        if condition == "prompt_injection_or_untrusted_output":
            return bool(request.get("prompt_injection_detected")) or bool(request.get("untrusted_output"))
        if condition == "high_risk_network":
            return bool(request.get("requires_network")) and int(request.get("risk_score", 0) or 0) >= 40
        if condition == "high_risk_score":
            return int(request.get("risk_score", 0) or 0) >= 70

        return False

    def _build_evidence(self, request: Mapping[str, Any]) -> list[GateEvidence]:
        evidence: list[GateEvidence] = []

        for key in (
            "risk_score",
            "verdict",
            "review_required",
            "quarantine_required",
            "secret_detected",
            "prompt_injection_detected",
            "requires_network",
            "untrusted_output",
            "malware_detected",
            "session_id",
            "execution_id",
            "tool_name",
        ):
            if key in request:
                evidence.append(GateEvidence(kind="signal", label=key, value=request.get(key)))

        if "reasons" in request:
            evidence.append(
                GateEvidence(
                    kind="reasons",
                    label="upstream_reasons",
                    value=list(request.get("reasons") or []),
                ),
            )

        return evidence

    def _default_rules(self) -> list[RemediationRule]:
        return [
            RemediationRule(
                rule_id="rr-block-malware",
                name="Malware detected",
                condition="malware_detected",
                action=RemediationAction.BLOCK,
                severity="critical",
            ),
            RemediationRule(
                rule_id="rr-quarantine",
                name="Quarantine required",
                condition="quarantine_required",
                action=RemediationAction.QUARANTINE,
                severity="critical",
            ),
            RemediationRule(
                rule_id="rr-review",
                name="Human review required",
                condition="review_required",
                action=RemediationAction.REQUIRE_REVIEW,
                severity="high",
            ),
            RemediationRule(
                rule_id="rr-secret",
                name="Secret detected",
                condition="secret_detected",
                action=RemediationAction.APPLY_REDACTION,
                severity="high",
            ),
            RemediationRule(
                rule_id="rr-untrusted",
                name="Prompt injection or untrusted output detected",
                condition="prompt_injection_or_untrusted_output",
                action=RemediationAction.SANDBOX_ONLY,
                severity="high",
            ),
            RemediationRule(
                rule_id="rr-network",
                name="High-risk network execution",
                condition="high_risk_network",
                action=RemediationAction.SANDBOX_ONLY,
                severity="medium",
            ),
            RemediationRule(
                rule_id="rr-risk",
                name="High risk score",
                condition="high_risk_score",
                action=RemediationAction.SANDBOX_ONLY,
                severity="medium",
            ),
        ]

    def _dedupe(self, values: Iterable[str]) -> list[str]:
        seen: set[str] = set()
        ordered: list[str] = []
        for value in values:
            normalized = str(value).strip()
            if normalized and normalized not in seen:
                seen.add(normalized)
                ordered.append(normalized)
        return ordered

    def _emit(self, decision: GateDecision) -> None:
        if self.sink is not None:
            self.sink(
                {
                    "event": "remediation.gate.evaluated",
                    "decision": decision.to_dict(),
                    "timestamp": datetime.now(UTC).isoformat(),
                },
            )


def evaluate_remediation_gate(payload: Mapping[str, Any] | None) -> GateDecision:
    return RemediationGate().evaluate(payload)


def evaluate_remediation_gate_dict(payload: Mapping[str, Any] | None) -> dict[str, Any]:
    return evaluate_remediation_gate(payload).to_dict()


__all__ = [
    "GateDecision",
    "GateEvidence",
    "GateStatus",
    "RemediationAction",
    "RemediationGate",
    "RemediationRule",
    "evaluate_remediation_gate",
    "evaluate_remediation_gate_dict",
]
