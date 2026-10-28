from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from app.config import RISK_THRESHOLD_ALLOW_MAX, RISK_THRESHOLD_BLOCK_MIN


class GateStatus(StrEnum):
    OPEN = "open"
    CONDITIONAL = "conditional"
    CLOSED = "closed"
    QUARANTINED = "quarantined"
    NEEDS_REVIEW = "needs_review"


class RemediationAction(StrEnum):
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

        incoming_verdict = str(request.get("verdict", "allow") or "").strip().lower()
        risk_score, risk_score_valid = self._normalize_risk_score(request.get("risk_score", 0))
        review_required = bool(request.get("review_required", False)) or incoming_verdict in {"warn", "review", "needs_review"} or bool(request.get("should_review", False)) or bool(request.get("shouldreview", False))
        quarantine_required = bool(request.get("quarantine_required", False)) or incoming_verdict == "quarantine"
        secret_detected = bool(request.get("secret_detected", False))
        prompt_injection_detected = bool(request.get("prompt_injection_detected", False))
        requires_network = bool(request.get("requires_network", False))
        untrusted_output = bool(request.get("untrusted_output", False))
        malware_detected = bool(request.get("malware_detected", False))

        match_request = dict(request)
        match_request.update(
            risk_score=risk_score,
            incoming_verdict=incoming_verdict,
        )
        for rule in self.rules:
            if self._matches(rule, match_request):
                matched_rules.append(rule)
                reasons.append(rule.name)

        matched_signals = any(bool(request.get(key)) for key in ("matched_patterns", "matched_rules", "patterns", "should_warn", "should_block", "should_quarantine"))
        errors_detected = bool(request.get("error")) or bool(request.get("errors"))
        blocked = (
            incoming_verdict != "allow" or not risk_score_valid or risk_score > RISK_THRESHOLD_ALLOW_MAX or bool(matched_rules) or matched_signals or errors_detected or review_required or quarantine_required or secret_detected or prompt_injection_detected or untrusted_output or malware_detected
        )
        action = RemediationAction.BLOCK if blocked else RemediationAction.NONE
        status = GateStatus.NEEDS_REVIEW if blocked and review_required else GateStatus.CLOSED if blocked else GateStatus.OPEN
        allowed = not blocked
        redaction_required = secret_detected or bool(request.get("redaction_required", False))
        sandbox_required = bool(request.get("sandbox_required", False)) or (requires_network and risk_score > RISK_THRESHOLD_ALLOW_MAX)

        if blocked:
            reasons.append("Suspicious signal detected; request blocked.")
        else:
            reasons.append("No suspicious signal detected.")

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
            quarantine_required=quarantine_required or any(rule.action == RemediationAction.QUARANTINE for rule in matched_rules),
            redaction_required=redaction_required,
            sandbox_required=sandbox_required,
            metadata={
                "risk_score": max(risk_score, RISK_THRESHOLD_BLOCK_MIN) if blocked else risk_score,
                "verdict": "block" if blocked else "allow",
                "incoming_verdict": incoming_verdict,
                "requires_network": requires_network,
                "secret_detected": secret_detected,
                "prompt_injection_detected": prompt_injection_detected,
                "untrusted_output": untrusted_output,
                "malware_detected": malware_detected,
                "errors_detected": errors_detected,
            },
        )
        self._emit(decision)
        return decision

    def evaluate_dict(self, payload: Mapping[str, Any] | None) -> dict[str, Any]:
        return self.evaluate(payload).to_dict()

    def _matches(self, rule: RemediationRule, request: Mapping[str, Any]) -> bool:
        condition = rule.condition
        incoming_verdict = str(request.get("incoming_verdict", request.get("verdict", ""))).lower()

        if condition == "malware_detected":
            return bool(request.get("malware_detected"))
        if condition == "quarantine_required":
            return bool(request.get("quarantine_required")) or incoming_verdict == "quarantine"
        if condition == "review_required":
            return bool(request.get("review_required")) or bool(request.get("should_review")) or bool(request.get("shouldreview")) or incoming_verdict in {"warn", "review", "needs_review"}
        if condition == "secret_detected":
            return bool(request.get("secret_detected"))
        if condition == "prompt_injection_or_untrusted_output":
            return bool(request.get("prompt_injection_detected")) or bool(request.get("untrusted_output"))
        if condition == "high_risk_network":
            return bool(request.get("requires_network")) and int(request.get("risk_score", 0) or 0) > RISK_THRESHOLD_ALLOW_MAX
        if condition == "high_risk_score":
            return int(request.get("risk_score", 0) or 0) > RISK_THRESHOLD_ALLOW_MAX

        return False

    def _normalize_risk_score(self, value: Any) -> tuple[int, bool]:
        if value is None:
            return 0, True
        if isinstance(value, bool):
            return RISK_THRESHOLD_BLOCK_MIN, False
        try:
            risk_score = int(value)
        except (TypeError, ValueError, OverflowError):
            return RISK_THRESHOLD_BLOCK_MIN, False
        if isinstance(value, float) and not value.is_integer():
            return RISK_THRESHOLD_BLOCK_MIN, False
        if risk_score < 0:
            return RISK_THRESHOLD_BLOCK_MIN, False
        return min(risk_score, 100), risk_score <= 100

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
                action=RemediationAction.BLOCK,
                severity="critical",
            ),
            RemediationRule(
                rule_id="rr-review",
                name="Human review required",
                condition="review_required",
                action=RemediationAction.BLOCK,
                severity="high",
            ),
            RemediationRule(
                rule_id="rr-secret",
                name="Secret detected",
                condition="secret_detected",
                action=RemediationAction.BLOCK,
                severity="high",
            ),
            RemediationRule(
                rule_id="rr-untrusted",
                name="Prompt injection or untrusted output detected",
                condition="prompt_injection_or_untrusted_output",
                action=RemediationAction.BLOCK,
                severity="high",
            ),
            RemediationRule(
                rule_id="rr-network",
                name="High-risk network execution",
                condition="high_risk_network",
                action=RemediationAction.BLOCK,
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
