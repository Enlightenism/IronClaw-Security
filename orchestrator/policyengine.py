from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Iterable, Mapping, Sequence
from uuid import uuid4


class PolicyVerdict(str, Enum):
    ALLOW = "allow"
    WARN = "warn"
    QUARANTINE = "quarantine"
    BLOCK = "block"


class PolicyTarget(str, Enum):
    PROMPT = "prompt"
    ACTION = "action"
    TOOL = "tool"
    RUNTIME = "runtime"
    FILE = "file"
    NETWORK = "network"
    UNKNOWN = "unknown"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(slots=True)
class PolicyEvidence:
    code: str
    message: str
    severity: RiskLevel = RiskLevel.MEDIUM
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "severity": self.severity.value,
            "details": dict(self.details),
        }


@dataclass(slots=True)
class PolicyRule:
    rule_id: str
    name: str
    description: str
    target: PolicyTarget = PolicyTarget.UNKNOWN
    verdict: PolicyVerdict = PolicyVerdict.WARN
    enabled: bool = True
    priority: int = 100
    tags: tuple[str, ...] = ()
    match_any_keys: tuple[str, ...] = ()
    match_all_keys: tuple[str, ...] = ()
    equals: dict[str, Any] = field(default_factory=dict)
    contains: dict[str, tuple[str, ...]] = field(default_factory=dict)
    min_risk_score: int | None = None
    require_human_review: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "PolicyRule":
        target = data.get("target", PolicyTarget.UNKNOWN)
        verdict = data.get("verdict", PolicyVerdict.WARN)

        if not isinstance(target, PolicyTarget):
            target = PolicyTarget(str(target).lower()) if str(target).lower() in {t.value for t in PolicyTarget} else PolicyTarget.UNKNOWN
        if not isinstance(verdict, PolicyVerdict):
            verdict = PolicyVerdict(str(verdict).lower()) if str(verdict).lower() in {v.value for v in PolicyVerdict} else PolicyVerdict.WARN

        contains_raw = data.get("contains", {}) or {}
        normalized_contains: dict[str, tuple[str, ...]] = {}
        for key, value in contains_raw.items():
            if isinstance(value, str):
                normalized_contains[str(key)] = (value.lower(),)
            elif isinstance(value, Sequence):
                normalized_contains[str(key)] = tuple(str(item).lower() for item in value)
            else:
                normalized_contains[str(key)] = (str(value).lower(),)

        return cls(
            rule_id=str(data.get("rule_id") or data.get("id") or f"rule-{uuid4().hex[:12]}"),
            name=str(data.get("name") or data.get("rule_id") or "unnamed_rule"),
            description=str(data.get("description") or ""),
            target=target,
            verdict=verdict,
            enabled=bool(data.get("enabled", True)),
            priority=int(data.get("priority", 100)),
            tags=tuple(str(tag) for tag in (data.get("tags") or ())),
            match_any_keys=tuple(str(k) for k in (data.get("match_any_keys") or ())),
            match_all_keys=tuple(str(k) for k in (data.get("match_all_keys") or ())),
            equals={str(k): v for k, v in (data.get("equals") or {}).items()},
            contains=normalized_contains,
            min_risk_score=int(data["min_risk_score"]) if data.get("min_risk_score") is not None else None,
            require_human_review=bool(data.get("require_human_review", False)),
            metadata={str(k): v for k, v in (data.get("metadata") or {}).items()},
        )

    def matches(self, request: "PolicyRequest") -> bool:
        if not self.enabled:
            return False

        if self.target not in (PolicyTarget.UNKNOWN, request.target):
            return False

        if self.match_any_keys and not any(key in request.attributes for key in self.match_any_keys):
            return False

        if self.match_all_keys and not all(key in request.attributes for key in self.match_all_keys):
            return False

        for key, expected in self.equals.items():
            if request.attributes.get(key) != expected:
                return False

        for key, needles in self.contains.items():
            haystack = str(request.attributes.get(key, "")).lower()
            if not all(needle in haystack for needle in needles):
                return False

        if self.min_risk_score is not None and request.risk_score < self.min_risk_score:
            return False

        return True

    def build_evidence(self, request: "PolicyRequest") -> PolicyEvidence:
        return PolicyEvidence(
            code=self.rule_id,
            message=self.description or f"Policy rule '{self.name}' matched.",
            severity=_severity_for_verdict(self.verdict),
            details={
                "rule_id": self.rule_id,
                "rule_name": self.name,
                "target": self.target.value,
                "request_target": request.target.value,
                "tags": list(self.tags),
                "metadata": dict(self.metadata),
            },
        )


@dataclass(slots=True)
class PolicyRequest:
    target: PolicyTarget = PolicyTarget.UNKNOWN
    action: str = "unknown"
    risk_score: int = 0
    attributes: dict[str, Any] = field(default_factory=dict)
    source: str | None = None
    actor_id: str | None = None
    session_id: str | None = None
    organization_id: str | None = None
    requires_network: bool = False
    requires_filesystem: bool = False
    requires_secrets: bool = False
    requires_human_review: bool = False
    fail_closed: bool = True

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any] | None) -> "PolicyRequest":
        data = data or {}

        target_raw = data.get("target", PolicyTarget.UNKNOWN)
        if isinstance(target_raw, PolicyTarget):
            target = target_raw
        else:
            target_str = str(target_raw).lower()
            target = PolicyTarget(target_str) if target_str in {t.value for t in PolicyTarget} else PolicyTarget.UNKNOWN

        attributes = dict(data.get("attributes") or {})

        promoted_keys = (
            "prompt",
            "tool_name",
            "command",
            "path",
            "hostname",
            "url",
            "runtime",
            "content",
            "sensitivity",
            "review_reason",
        )
        for key in promoted_keys:
            if key in data and key not in attributes:
                attributes[key] = data[key]

        return cls(
            target=target,
            action=str(data.get("action") or "unknown"),
            risk_score=_safe_int(data.get("risk_score"), default=0),
            attributes=attributes,
            source=_none_if_blank(data.get("source")),
            actor_id=_none_if_blank(data.get("actor_id")),
            session_id=_none_if_blank(data.get("session_id")),
            organization_id=_none_if_blank(data.get("organization_id")),
            requires_network=bool(data.get("requires_network", False)),
            requires_filesystem=bool(data.get("requires_filesystem", False)),
            requires_secrets=bool(data.get("requires_secrets", False)),
            requires_human_review=bool(data.get("requires_human_review", False)),
            fail_closed=bool(data.get("fail_closed", True)),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target.value,
            "action": self.action,
            "risk_score": self.risk_score,
            "attributes": dict(self.attributes),
            "source": self.source,
            "actor_id": self.actor_id,
            "session_id": self.session_id,
            "organization_id": self.organization_id,
            "requires_network": self.requires_network,
            "requires_filesystem": self.requires_filesystem,
            "requires_secrets": self.requires_secrets,
            "requires_human_review": self.requires_human_review,
            "fail_closed": self.fail_closed,
        }


@dataclass(slots=True)
class PolicyDecision:
    decision_id: str
    verdict: PolicyVerdict
    allowed: bool
    action: str
    target: PolicyTarget
    risk_score: int
    reasons: list[str] = field(default_factory=list)
    evidence: list[PolicyEvidence] = field(default_factory=list)
    matched_rules: list[str] = field(default_factory=list)
    requires_human_review: bool = False
    confidence: float = 1.0
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "verdict": self.verdict.value,
            "allowed": self.allowed,
            "action": self.action,
            "target": self.target.value,
            "risk_score": self.risk_score,
            "reasons": list(self.reasons),
            "evidence": [item.to_dict() for item in self.evidence],
            "matched_rules": list(self.matched_rules),
            "requires_human_review": self.requires_human_review,
            "confidence": self.confidence,
            "metadata": dict(self.metadata),
            "created_at": self.created_at,
        }


DEFAULT_POLICY_RULES: tuple[PolicyRule, ...] = (
    PolicyRule(
        rule_id="deny-critical-risk",
        name="deny_critical_risk",
        description="Critical-risk requests are blocked by default.",
        verdict=PolicyVerdict.BLOCK,
        min_risk_score=90,
        priority=1000,
    ),
    PolicyRule(
        rule_id="quarantine-high-risk-runtime",
        name="quarantine_high_risk_runtime",
        description="High-risk runtime requests are quarantined for containment.",
        target=PolicyTarget.RUNTIME,
        verdict=PolicyVerdict.QUARANTINE,
        min_risk_score=75,
        priority=900,
        require_human_review=True,
    ),
    PolicyRule(
        rule_id="block-secrets-exfiltration",
        name="block_secrets_exfiltration",
        description="Requests attempting to expose or transmit secrets are blocked.",
        verdict=PolicyVerdict.BLOCK,
        priority=950,
        contains={"content": ("api_key", "secret"), "prompt": ("exfiltrate",)},
    ),
    PolicyRule(
        rule_id="warn-networked-tool-use",
        name="warn_networked_tool_use",
        description="Network-enabled tool use requires elevated scrutiny.",
        target=PolicyTarget.TOOL,
        verdict=PolicyVerdict.WARN,
        priority=300,
        match_any_keys=("tool_name",),
    ),
    PolicyRule(
        rule_id="review-sensitive-filesystem-access",
        name="review_sensitive_filesystem_access",
        description="Sensitive filesystem access must be reviewed before execution.",
        target=PolicyTarget.ACTION,
        verdict=PolicyVerdict.WARN,
        priority=400,
        contains={"path": ("users", "appdata")},
        require_human_review=True,
    ),
)


class PolicyEngine:
    def __init__(
        self,
        rules: Iterable[PolicyRule | Mapping[str, Any]] | None = None,
        *,
        default_verdict: PolicyVerdict = PolicyVerdict.ALLOW,
        fail_closed_verdict: PolicyVerdict = PolicyVerdict.BLOCK,
        enable_default_rules: bool = True,
    ) -> None:
        materialized_rules: list[PolicyRule] = []
        if enable_default_rules:
            materialized_rules.extend(DEFAULT_POLICY_RULES)
        if rules:
            for rule in rules:
                materialized_rules.append(rule if isinstance(rule, PolicyRule) else PolicyRule.from_mapping(rule))

        self._rules: list[PolicyRule] = sorted(materialized_rules, key=lambda item: item.priority, reverse=True)
        self.default_verdict = default_verdict
        self.fail_closed_verdict = fail_closed_verdict

    @property
    def rules(self) -> tuple[PolicyRule, ...]:
        return tuple(self._rules)

    def evaluate(self, request: PolicyRequest | Mapping[str, Any] | None) -> PolicyDecision:
        normalized = request if isinstance(request, PolicyRequest) else PolicyRequest.from_mapping(request)

        matched_rules: list[PolicyRule] = [rule for rule in self._rules if rule.matches(normalized)]
        evidence: list[PolicyEvidence] = [rule.build_evidence(normalized) for rule in matched_rules]

        verdict = self._resolve_verdict(normalized, matched_rules)
        requires_human_review = normalized.requires_human_review or any(rule.require_human_review for rule in matched_rules)

        reasons = [item.message for item in evidence]
        if not reasons:
            reasons.append(self._default_reason_for_verdict(verdict, normalized))

        metadata = {
            "source": normalized.source,
            "actor_id": normalized.actor_id,
            "session_id": normalized.session_id,
            "organization_id": normalized.organization_id,
            "requires_network": normalized.requires_network,
            "requires_filesystem": normalized.requires_filesystem,
            "requires_secrets": normalized.requires_secrets,
            "fail_closed": normalized.fail_closed,
            "rule_count": len(matched_rules),
        }

        decision = PolicyDecision(
            decision_id=f"pol-{uuid4().hex}",
            verdict=verdict,
            allowed=verdict in {PolicyVerdict.ALLOW, PolicyVerdict.WARN},
            action=normalized.action,
            target=normalized.target,
            risk_score=normalized.risk_score,
            reasons=reasons,
            evidence=evidence,
            matched_rules=[rule.rule_id for rule in matched_rules],
            requires_human_review=requires_human_review,
            confidence=self._calculate_confidence(normalized, matched_rules, verdict),
            metadata=metadata,
        )

        if verdict in {PolicyVerdict.BLOCK, PolicyVerdict.QUARANTINE}:
            decision.allowed = False

        if requires_human_review and verdict == PolicyVerdict.ALLOW:
            decision.verdict = PolicyVerdict.WARN
            decision.allowed = True
            if "Human review required before unrestricted execution." not in decision.reasons:
                decision.reasons.append("Human review required before unrestricted execution.")

        return decision

    def decide(self, request: PolicyRequest | Mapping[str, Any] | None) -> dict[str, Any]:
        return self.evaluate(request).to_dict()

    def register_rule(self, rule: PolicyRule | Mapping[str, Any]) -> PolicyRule:
        materialized = rule if isinstance(rule, PolicyRule) else PolicyRule.from_mapping(rule)
        self._rules.append(materialized)
        self._rules.sort(key=lambda item: item.priority, reverse=True)
        return materialized

    def extend_rules(self, rules: Iterable[PolicyRule | Mapping[str, Any]]) -> None:
        for rule in rules:
            self.register_rule(rule)

    def clear_rules(self) -> None:
        self._rules.clear()

    def replace_rules(self, rules: Iterable[PolicyRule | Mapping[str, Any]]) -> None:
        self._rules = []
        self.extend_rules(rules)

    def _resolve_verdict(self, request: PolicyRequest, matched_rules: Sequence[PolicyRule]) -> PolicyVerdict:
        if matched_rules:
            return max((rule.verdict for rule in matched_rules), key=_verdict_rank)

        if request.fail_closed and self._request_is_unsafe_or_unknown(request):
            return self.fail_closed_verdict

        return self.default_verdict

    def _request_is_unsafe_or_unknown(self, request: PolicyRequest) -> bool:
        if request.target == PolicyTarget.UNKNOWN:
            return True
        if request.risk_score >= 70:
            return True
        if request.requires_secrets and request.requires_network:
            return True
        return False

    def _default_reason_for_verdict(self, verdict: PolicyVerdict, request: PolicyRequest) -> str:
        if verdict == PolicyVerdict.ALLOW:
            return "No blocking policy conditions were matched."
        if verdict == PolicyVerdict.WARN:
            return "Request is allowed with elevated caution."
        if verdict == PolicyVerdict.QUARANTINE:
            return "Request is quarantined pending containment or review."
        return f"Request was blocked by {request.target.value} policy safeguards."

    def _calculate_confidence(
        self,
        request: PolicyRequest,
        matched_rules: Sequence[PolicyRule],
        verdict: PolicyVerdict,
    ) -> float:
        base = 0.55
        if matched_rules:
            base += min(len(matched_rules) * 0.1, 0.3)
        base += min(max(request.risk_score, 0), 100) / 1000.0
        if verdict in {PolicyVerdict.BLOCK, PolicyVerdict.QUARANTINE}:
            base += 0.1
        return round(min(base, 0.99), 3)


def evaluate_policy(
    request: PolicyRequest | Mapping[str, Any] | None,
    *,
    rules: Iterable[PolicyRule | Mapping[str, Any]] | None = None,
    default_verdict: PolicyVerdict = PolicyVerdict.ALLOW,
    fail_closed_verdict: PolicyVerdict = PolicyVerdict.BLOCK,
    enable_default_rules: bool = True,
) -> PolicyDecision:
    engine = PolicyEngine(
        rules=rules,
        default_verdict=default_verdict,
        fail_closed_verdict=fail_closed_verdict,
        enable_default_rules=enable_default_rules,
    )
    return engine.evaluate(request)


def decide_policy(
    request: PolicyRequest | Mapping[str, Any] | None,
    *,
    rules: Iterable[PolicyRule | Mapping[str, Any]] | None = None,
    default_verdict: PolicyVerdict = PolicyVerdict.ALLOW,
    fail_closed_verdict: PolicyVerdict = PolicyVerdict.BLOCK,
    enable_default_rules: bool = True,
) -> dict[str, Any]:
    return evaluate_policy(
        request,
        rules=rules,
        default_verdict=default_verdict,
        fail_closed_verdict=fail_closed_verdict,
        enable_default_rules=enable_default_rules,
    ).to_dict()


def _verdict_rank(verdict: PolicyVerdict) -> int:
    order = {
        PolicyVerdict.ALLOW: 0,
        PolicyVerdict.WARN: 1,
        PolicyVerdict.QUARANTINE: 2,
        PolicyVerdict.BLOCK: 3,
    }
    return order[verdict]


def _severity_for_verdict(verdict: PolicyVerdict) -> RiskLevel:
    mapping = {
        PolicyVerdict.ALLOW: RiskLevel.LOW,
        PolicyVerdict.WARN: RiskLevel.MEDIUM,
        PolicyVerdict.QUARANTINE: RiskLevel.HIGH,
        PolicyVerdict.BLOCK: RiskLevel.CRITICAL,
    }
    return mapping[verdict]


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _none_if_blank(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


__all__ = [
    "DEFAULT_POLICY_RULES",
    "PolicyDecision",
    "PolicyEngine",
    "PolicyEvidence",
    "PolicyRequest",
    "PolicyRule",
    "PolicyTarget",
    "PolicyVerdict",
    "RiskLevel",
    "decide_policy",
    "evaluate_policy",
]