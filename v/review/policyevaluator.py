from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class PolicyDecision(str, Enum):
    ALLOW = "allow"
    REVIEW = "review"
    BLOCK = "block"
    ESCALATE = "escalate"


class PolicyMatchType(str, Enum):
    EXACT = "exact"
    CONTAINS = "contains"
    PREFIX = "prefix"
    SUFFIX = "suffix"
    GREATER_EQUAL = "greater_equal"
    LESS_EQUAL = "less_equal"
    PRESENT = "present"


@dataclass(frozen=True)
class PolicyRule:
    rule_id: str
    field: str
    match_type: PolicyMatchType
    value: Any = None
    decision: PolicyDecision = PolicyDecision.REVIEW
    severity: str = "medium"
    reason: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class PolicyOverride:
    override_id: str
    target_field: str | None = None
    target_value: Any | None = None
    force_decision: PolicyDecision | None = None
    add_reasons: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    enabled: bool = True


@dataclass
class PolicyEvaluationResult:
    decision: PolicyDecision
    severity: str
    matched_rules: list[str] = field(default_factory=list)
    matched_overrides: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    signals: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


class PolicyEvaluator:
    """Deterministic policy evaluator for review and incident workflows.

    Goals:
    - Pure in-memory evaluation for tests and orchestration flows.
    - Stable decision ordering so stronger outcomes always win.
    - Simple rule/override model that can later be backed by database config.
    """

    def __init__(
        self,
        *,
        rules: Sequence[PolicyRule] | None = None,
        overrides: Sequence[PolicyOverride] | None = None,
    ) -> None:
        self._rules: list[PolicyRule] = list(rules or [])
        self._overrides: list[PolicyOverride] = list(overrides or [])

    def set_rules(self, rules: Sequence[PolicyRule]) -> None:
        self._rules = list(rules)

    def set_overrides(self, overrides: Sequence[PolicyOverride]) -> None:
        self._overrides = list(overrides)

    def add_rule(self, rule: PolicyRule) -> None:
        self._rules.append(rule)

    def add_override(self, override: PolicyOverride) -> None:
        self._overrides.append(override)

    def evaluate(
        self,
        payload: dict[str, Any],
        *,
        rules: Sequence[PolicyRule] | None = None,
        overrides: Sequence[PolicyOverride] | None = None,
        default_decision: PolicyDecision = PolicyDecision.ALLOW,
        default_severity: str = "low",
    ) -> PolicyEvaluationResult:
        active_rules = list(rules or self._rules)
        active_overrides = list(overrides or self._overrides)

        matched_rules: list[PolicyRule] = []
        matched_overrides: list[PolicyOverride] = []
        reasons: list[str] = []
        signals: list[dict[str, Any]] = []

        final_decision = default_decision
        final_severity = default_severity

        for rule in active_rules:
            if not self._matches_rule(rule, payload):
                continue

            matched_rules.append(rule)
            final_decision = self._max_decision(final_decision, rule.decision)
            final_severity = self._max_severity(final_severity, rule.severity)

            if rule.reason:
                reasons.append(rule.reason)

            signals.append(
                {
                    "type": "rule_match",
                    "rule_id": rule.rule_id,
                    "field": rule.field,
                    "decision": rule.decision.value,
                    "severity": rule.severity,
                    "metadata": dict(rule.metadata),
                },
            )

        for override in active_overrides:
            if not override.enabled:
                continue
            if not self._matches_override(override, payload):
                continue

            matched_overrides.append(override)

            if override.force_decision is not None:
                final_decision = override.force_decision

            reasons.extend(override.add_reasons)
            signals.append(
                {
                    "type": "override_match",
                    "override_id": override.override_id,
                    "force_decision": (override.force_decision.value if override.force_decision is not None else None),
                    "metadata": dict(override.metadata),
                },
            )

        deduped_reasons = self._dedupe(reasons)

        return PolicyEvaluationResult(
            decision=final_decision,
            severity=final_severity,
            matched_rules=[rule.rule_id for rule in matched_rules],
            matched_overrides=[override.override_id for override in matched_overrides],
            reasons=deduped_reasons,
            signals=signals,
            metadata={
                "rule_count": len(active_rules),
                "override_count": len(active_overrides),
                "matched_rule_count": len(matched_rules),
                "matched_override_count": len(matched_overrides),
            },
        )

    def evaluate_many(
        self,
        payloads: Sequence[dict[str, Any]],
        *,
        rules: Sequence[PolicyRule] | None = None,
        overrides: Sequence[PolicyOverride] | None = None,
        default_decision: PolicyDecision = PolicyDecision.ALLOW,
        default_severity: str = "low",
    ) -> list[PolicyEvaluationResult]:
        return [
            self.evaluate(
                payload,
                rules=rules,
                overrides=overrides,
                default_decision=default_decision,
                default_severity=default_severity,
            )
            for payload in payloads
        ]

    def _matches_rule(self, rule: PolicyRule, payload: dict[str, Any]) -> bool:
        actual = self._extract_field(payload, rule.field)

        if rule.match_type is PolicyMatchType.PRESENT:
            return actual is not None

        if actual is None:
            return False

        if rule.match_type is PolicyMatchType.EXACT:
            return actual == rule.value

        if rule.match_type is PolicyMatchType.CONTAINS:
            if isinstance(actual, (list, tuple, set)):
                return rule.value in actual
            return str(rule.value).lower() in str(actual).lower()

        if rule.match_type is PolicyMatchType.PREFIX:
            return str(actual).lower().startswith(str(rule.value).lower())

        if rule.match_type is PolicyMatchType.SUFFIX:
            return str(actual).lower().endswith(str(rule.value).lower())

        if rule.match_type is PolicyMatchType.GREATER_EQUAL:
            return self._coerce_number(actual) >= self._coerce_number(rule.value)

        if rule.match_type is PolicyMatchType.LESS_EQUAL:
            return self._coerce_number(actual) <= self._coerce_number(rule.value)

        return False

    def _matches_override(self, override: PolicyOverride, payload: dict[str, Any]) -> bool:
        if override.target_field is None:
            return True

        actual = self._extract_field(payload, override.target_field)
        if override.target_value is None:
            return actual is not None
        return actual == override.target_value

    def _extract_field(self, payload: dict[str, Any], field_path: str) -> Any:
        current: Any = payload
        for part in field_path.split("."):
            if isinstance(current, dict):
                current = current.get(part)
            else:
                return None
        return current

    def _max_decision(
        self,
        left: PolicyDecision,
        right: PolicyDecision,
    ) -> PolicyDecision:
        rank = {
            PolicyDecision.ALLOW: 0,
            PolicyDecision.REVIEW: 1,
            PolicyDecision.ESCALATE: 2,
            PolicyDecision.BLOCK: 3,
        }
        return left if rank[left] >= rank[right] else right

    def _max_severity(self, left: str, right: str) -> str:
        rank = {
            "low": 0,
            "medium": 1,
            "high": 2,
            "critical": 3,
        }
        left_value = rank.get((left or "low").lower(), 0)
        right_value = rank.get((right or "low").lower(), 0)
        return left if left_value >= right_value else right

    def _coerce_number(self, value: Any) -> float:
        if isinstance(value, bool):
            return float(int(value))
        if isinstance(value, (int, float)):
            return float(value)
        return float(str(value).strip())

    def _dedupe(self, values: Sequence[str]) -> list[str]:
        seen = set()
        result: list[str] = []
        for value in values:
            if not value or value in seen:
                continue
            seen.add(value)
            result.append(value)
        return result
