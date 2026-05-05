from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass, field
from typing import Any


DEFAULT_POLICY_ACTION = "allow"
DEFAULT_OVERRIDE_REASON = "manual review override"
OVERRIDE_SOURCE = "policy_override_service"


@dataclass(slots=True)
class PolicyOverrideResult:
    action: str
    reason: str
    policy_id: str | None = None
    matched_rule_ids: list[str] = field(default_factory=list)
    overridden_fields: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _normalize_string(value: Any, default: str = "") -> str:
    if value is None:
        return default
    return str(value).strip()


def _normalize_string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    text = str(value).strip()
    return [text] if text else []


def _extract_override_fields(override_payload: dict[str, Any]) -> list[str]:
    tracked_fields = ("action", "reason", "policy_id", "matched_rule_ids")
    return [field_name for field_name in tracked_fields if override_payload.get(field_name) not in (None, "", [])]


def build_policy_override_result(override_payload: dict[str, Any] | None) -> PolicyOverrideResult:
    payload = override_payload or {}

    action = _normalize_string(payload.get("action"), DEFAULT_POLICY_ACTION) or DEFAULT_POLICY_ACTION
    reason = _normalize_string(payload.get("reason"), DEFAULT_OVERRIDE_REASON) or DEFAULT_OVERRIDE_REASON
    policy_id_raw = _normalize_string(payload.get("policy_id"))
    policy_id = policy_id_raw or None
    matched_rule_ids = _normalize_string_list(payload.get("matched_rule_ids"))
    overridden_fields = _extract_override_fields(payload)

    metadata = deepcopy(payload.get("metadata") or {})
    metadata["source"] = OVERRIDE_SOURCE

    return PolicyOverrideResult(
        action=action,
        reason=reason,
        policy_id=policy_id,
        matched_rule_ids=matched_rule_ids,
        overridden_fields=overridden_fields,
        metadata=metadata,
    )


def apply_policy_override(
    review_result: dict[str, Any],
    override_payload: dict[str, Any] | None,
) -> dict[str, Any]:
    result = deepcopy(review_result)
    override = build_policy_override_result(override_payload)

    result["action"] = override.action
    result["reason"] = override.reason

    if override.policy_id is not None:
        result["policy_id"] = override.policy_id
    if override.matched_rule_ids:
        result["matched_rule_ids"] = override.matched_rule_ids

    result["policy_override"] = override.to_dict()
    return result


__all__ = [
    "DEFAULT_POLICY_ACTION",
    "DEFAULT_OVERRIDE_REASON",
    "OVERRIDE_SOURCE",
    "PolicyOverrideResult",
    "build_policy_override_result",
    "apply_policy_override",
]