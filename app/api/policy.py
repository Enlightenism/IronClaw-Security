from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException, status

from app.orchestrator.policy_engine import (
    PolicyContext,
    PolicyEvaluation,
    build_default_policy_rules,
    evaluate_policy,
)
from app.orchestrator.policy_engine import (
    PolicyRule as EngineRule,
)
from app.schemas.policy import (
    PolicyCreateRequest,
    PolicyEnforcementMode,
    PolicyEvaluationResult,
    PolicyRule,
    PolicyRuleSet,
    PolicyScope,
    PolicySeverity,
    PolicyStatus,
    PolicyUpdateRequest,
)

_log = logging.getLogger(__name__)

router = APIRouter(tags=["policy"])

# ---------------------------------------------------------------------------
# In-process policy store (replaced by DB layer when available)
# ---------------------------------------------------------------------------

_active_ruleset: dict[str, Any] | None = None
_engine_rules: list[EngineRule] = build_default_policy_rules()
_policy_config: dict[str, Any] = {
    "heuristic_threshold": 50,
    "unicode_normalization_enabled": True,
    "enforcement_mode": PolicyEnforcementMode.block,
    "scope": PolicyScope.global_,
    "name": "default",
    "version": "1.0.0",
    "metadata": {},
}


def _schema_rule_to_engine_rule(rule: PolicyRule) -> EngineRule:
    """Convert a schema PolicyRule into the engine dataclass PolicyRule."""
    return EngineRule(
        rule_id=rule.rule_id,
        name=rule.name,
        description=rule.description or "",
        effect=rule.enforcement_mode.value,
        enabled=rule.enabled,
        priority=100,
    )


def _engine_eval_to_schema_result(
    evaluation: PolicyEvaluation,
    policy_version: str | None = None,
) -> PolicyEvaluationResult:
    """Convert a PolicyEvaluation dataclass to the schema response model."""
    try:
        verdict = PolicyEnforcementMode(evaluation.final_effect)
    except ValueError:
        verdict = PolicyEnforcementMode.allow

    matched_ids = [m.rule_id for m in evaluation.matched_rules]
    risk = evaluation.context.risk_score if evaluation.context else 0

    try:
        severity = PolicySeverity.high if risk >= 70 else (PolicySeverity.medium if risk >= 40 else PolicySeverity.low)
    except Exception:
        severity = PolicySeverity.info

    return PolicyEvaluationResult(
        verdict=verdict,
        matched_rules=matched_ids,
        severity=severity,
        risk_score=risk,
        reasoning=f"decision={evaluation.decision} mode={evaluation.mode}",
        categories=[],
        policy_version=policy_version,
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get(
    "/status",
    response_model=PolicyStatus,
    summary="Get active policy status",
    tags=["policy"],
)
def get_policy_status() -> PolicyStatus:
    global _engine_rules, _policy_config, _active_ruleset

    enabled = [r for r in _engine_rules if r.enabled]
    disabled = [r for r in _engine_rules if not r.enabled]

    severity_counts: dict[str, int] = {}
    category_counts: dict[str, int] = {}
    tags_union: list[str] = []

    try:
        enforcement = PolicyEnforcementMode(_policy_config["enforcement_mode"])
    except (ValueError, KeyError):
        enforcement = PolicyEnforcementMode.block

    try:
        scope = PolicyScope(_policy_config["scope"])
    except (ValueError, KeyError):
        scope = PolicyScope.global_

    return PolicyStatus(
        heuristic_threshold=int(_policy_config.get("heuristic_threshold", 50)),
        unicode_normalization_enabled=bool(_policy_config.get("unicode_normalization_enabled", True)),
        rule_count=len(_engine_rules),
        policy_loaded_from_db=_active_ruleset is not None,
        enforcement_mode=enforcement,
        active_ruleset_id=_active_ruleset.get("ruleset_id") if _active_ruleset else None,
        active_ruleset_version=_policy_config.get("version"),
        scope=scope,
        enabled_rules=len(enabled),
        disabled_rules=len(disabled),
        severity_counts=severity_counts,
        category_counts=category_counts,
        tags_index=tags_union,
    )


@router.post(
    "/create",
    response_model=PolicyRuleSet,
    status_code=status.HTTP_201_CREATED,
    summary="Create or replace the active policy ruleset",
    tags=["policy"],
)
def create_policy(body: PolicyCreateRequest) -> PolicyRuleSet:
    global _active_ruleset, _engine_rules, _policy_config

    from datetime import datetime
    from uuid import uuid4

    ruleset_id = f"rs-{uuid4().hex[:12]}"
    now = datetime.utcnow()

    _engine_rules = [_schema_rule_to_engine_rule(r) for r in body.rules] if body.rules else build_default_policy_rules()

    _policy_config.update(
        {
            "name": body.name,
            "version": body.version,
            "heuristic_threshold": body.heuristic_threshold,
            "unicode_normalization_enabled": body.unicode_normalization_enabled,
            "enforcement_mode": body.enforcement_mode,
            "scope": body.scope,
            "metadata": body.metadata,
        }
    )

    _active_ruleset = {
        "ruleset_id": ruleset_id,
        "name": body.name,
        "version": body.version,
        "created_at": now.isoformat(),
        "updated_at": now.isoformat(),
        "is_active": True,
        "rules": [r.model_dump() for r in body.rules],
    }

    _log.info("policy.create_policy: ruleset_id=%s rules=%d", ruleset_id, len(_engine_rules))

    return PolicyRuleSet(
        ruleset_id=ruleset_id,
        name=body.name,
        version=body.version,
        rules=body.rules,
        created_at=now,
        updated_at=now,
        is_active=True,
    )


@router.patch(
    "/update",
    response_model=PolicyStatus,
    summary="Partially update the active policy configuration",
    tags=["policy"],
)
def update_policy(body: PolicyUpdateRequest) -> PolicyStatus:
    global _engine_rules, _policy_config, _active_ruleset

    from datetime import datetime

    if body.name is not None:
        _policy_config["name"] = body.name
    if body.version is not None:
        _policy_config["version"] = body.version
    if body.heuristic_threshold is not None:
        _policy_config["heuristic_threshold"] = body.heuristic_threshold
    if body.unicode_normalization_enabled is not None:
        _policy_config["unicode_normalization_enabled"] = body.unicode_normalization_enabled
    if body.enforcement_mode is not None:
        _policy_config["enforcement_mode"] = body.enforcement_mode
    if body.scope is not None:
        _policy_config["scope"] = body.scope
    if body.metadata is not None:
        _policy_config["metadata"] = {**_policy_config.get("metadata", {}), **body.metadata}
    if body.rules is not None:
        _engine_rules = [_schema_rule_to_engine_rule(r) for r in body.rules]
        if _active_ruleset is not None:
            _active_ruleset["rules"] = [r.model_dump() for r in body.rules]
            _active_ruleset["updated_at"] = datetime.utcnow().isoformat()

    _log.info("policy.update_policy: updated fields applied")

    return get_policy_status()


@router.post(
    "/evaluate",
    response_model=PolicyEvaluationResult,
    summary="Evaluate a payload against the active policy",
    tags=["policy"],
)
def evaluate_against_policy(body: dict[str, Any]) -> PolicyEvaluationResult:
    global _engine_rules, _policy_config

    agent_id = str(body.get("agent_id") or "unknown")
    file_path = str(body.get("file_path") or "unknown")
    action_type = str(body.get("action_type") or "inspect")
    target = str(body.get("target") or file_path)
    risk_score = int(body.get("risk_score") or 0)
    lane = str(body.get("lane") or "default")
    verdict_raw = str(body.get("verdict") or "allow")
    matched_patterns: list[str] = list(body.get("matched_patterns") or [])

    context = PolicyContext(
        agent_id=agent_id,
        file_path=file_path,
        action_type=action_type,
        target=target,
        risk_score=risk_score,
        lane=lane,
        verdict=verdict_raw,
        matched_patterns=matched_patterns,
        metadata={},
    )

    try:
        evaluation = evaluate_policy(
            context,
            _engine_rules,
            mode=str(_policy_config.get("enforcement_mode", "enforce")),
        )
    except Exception as exc:
        _log.error("policy.evaluate: engine error: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Policy evaluation failed: {exc}",
        ) from exc

    return _engine_eval_to_schema_result(evaluation, policy_version=_policy_config.get("version"))


@router.get(
    "/rules",
    summary="List active policy rules",
    tags=["policy"],
)
def list_policy_rules() -> dict[str, Any]:
    return {
        "rules": [r.to_dict() for r in _engine_rules],
        "total": len(_engine_rules),
        "policy_version": _policy_config.get("version"),
        "ruleset_id": _active_ruleset.get("ruleset_id") if _active_ruleset else None,
    }


@router.delete(
    "/reset",
    response_model=PolicyStatus,
    summary="Reset policy to system defaults",
    tags=["policy"],
)
def reset_policy() -> PolicyStatus:
    global _active_ruleset, _engine_rules, _policy_config

    _active_ruleset = None
    _engine_rules = build_default_policy_rules()
    _policy_config = {
        "heuristic_threshold": 50,
        "unicode_normalization_enabled": True,
        "enforcement_mode": PolicyEnforcementMode.block,
        "scope": PolicyScope.global_,
        "name": "default",
        "version": "1.0.0",
        "metadata": {},
    }

    _log.info("policy.reset_policy: policy reset to system defaults")
    return get_policy_status()
