from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
import logging
import re
import time
from typing import Any, Literal
import uuid

from app.core.logging import get_logger
from app.core.verdicts import ALLOW, BLOCK

_logger: logging.Logger = get_logger("ironclaw.policy_engine")

# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

InputType = Literal["prompt", "tool_call", "execution_plan"]

VerdictAction = Literal["allow", "block"]

# Trust score threshold below which policy blocks the request.
_TRUST_WARN_THRESHOLD: float = 0.25


@dataclass(frozen=True, slots=True)
class MatchedRule:
    rule_id: str
    rule_name: str
    rule_type: str
    action: VerdictAction
    risk_contribution: float
    matched_field: str
    matched_value: str


@dataclass(slots=True)
class PolicyVerdict:
    verdict_id: str
    action: VerdictAction
    matched_rules: list[MatchedRule]
    risk_score: float
    explanation: str
    input_type: InputType
    policy_set_key: str
    evaluated_at: str
    duration_ms: float
    # Trust gate fields — set when agent_id is present on the input
    trust_score_at_eval: float | None = None
    agent_suspended: bool = False


# ---------------------------------------------------------------------------
# Input envelope — callers build this and pass it to evaluate()
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class PolicyInput:
    input_type: InputType
    content: str
    metadata: dict[str, Any] = field(default_factory=dict)
    agent_id: str | None = None
    tenant_key: str | None = None


# ---------------------------------------------------------------------------
# Rule evaluator dispatch
# ---------------------------------------------------------------------------

_RULE_EVALUATORS: dict[str, Any] = {}


def _rule_evaluator(rule_type: str):
    def decorator(fn):
        _RULE_EVALUATORS[rule_type] = fn
        return fn

    return decorator


@_rule_evaluator("keyword_block")
def _eval_keyword_block(rule: dict[str, Any], pinput: PolicyInput) -> MatchedRule | None:
    pattern: str = (rule.get("value") or "").strip().lower()
    if not pattern:
        return None
    content_lower = pinput.content.lower()
    if pattern in content_lower:
        return MatchedRule(
            rule_id=str(rule.get("id", "")),
            rule_name=str(rule.get("rule_name") or rule.get("name") or rule_type_label(rule)),
            rule_type="keyword_block",
            action=BLOCK,
            risk_contribution=1.0,
            matched_field="content",
            matched_value=_truncate(pattern, 120),
        )
    return None


@_rule_evaluator("keyword_warn")
def _eval_keyword_warn(rule: dict[str, Any], pinput: PolicyInput) -> MatchedRule | None:
    pattern: str = (rule.get("value") or "").strip().lower()
    if not pattern:
        return None
    if pattern in pinput.content.lower():
        return MatchedRule(
            rule_id=str(rule.get("id", "")),
            rule_name=str(rule.get("rule_name") or rule.get("name") or rule_type_label(rule)),
            rule_type="keyword_warn",
            action=BLOCK,
            risk_contribution=0.4,
            matched_field="content",
            matched_value=_truncate(pattern, 120),
        )
    return None


@_rule_evaluator("regex_block")
def _eval_regex_block(rule: dict[str, Any], pinput: PolicyInput) -> MatchedRule | None:
    pattern: str = (rule.get("value") or "").strip()
    if not pattern:
        return None
    try:
        compiled = re.compile(pattern, re.IGNORECASE | re.DOTALL)
    except re.error as exc:
        _logger.warning("policy_engine: invalid regex in rule %s: %s", rule.get("id"), exc)
        return None
    m = compiled.search(pinput.content)
    if m:
        return MatchedRule(
            rule_id=str(rule.get("id", "")),
            rule_name=str(rule.get("rule_name") or rule.get("name") or rule_type_label(rule)),
            rule_type="regex_block",
            action=BLOCK,
            risk_contribution=1.0,
            matched_field="content",
            matched_value=_truncate(m.group(0), 120),
        )
    return None


@_rule_evaluator("regex_warn")
def _eval_regex_warn(rule: dict[str, Any], pinput: PolicyInput) -> MatchedRule | None:
    pattern: str = (rule.get("value") or "").strip()
    if not pattern:
        return None
    try:
        compiled = re.compile(pattern, re.IGNORECASE | re.DOTALL)
    except re.error as exc:
        _logger.warning("policy_engine: invalid regex in rule %s: %s", rule.get("id"), exc)
        return None
    m = compiled.search(pinput.content)
    if m:
        return MatchedRule(
            rule_id=str(rule.get("id", "")),
            rule_name=str(rule.get("rule_name") or rule.get("name") or rule_type_label(rule)),
            rule_type="regex_warn",
            action=BLOCK,
            risk_contribution=0.5,
            matched_field="content",
            matched_value=_truncate(m.group(0), 120),
        )
    return None


@_rule_evaluator("regex_quarantine")
def _eval_regex_quarantine(rule: dict[str, Any], pinput: PolicyInput) -> MatchedRule | None:
    pattern: str = (rule.get("value") or "").strip()
    if not pattern:
        return None
    try:
        compiled = re.compile(pattern, re.IGNORECASE | re.DOTALL)
    except re.error as exc:
        _logger.warning("policy_engine: invalid regex in rule %s: %s", rule.get("id"), exc)
        return None
    m = compiled.search(pinput.content)
    if m:
        return MatchedRule(
            rule_id=str(rule.get("id", "")),
            rule_name=str(rule.get("rule_name") or rule.get("name") or rule_type_label(rule)),
            rule_type="regex_quarantine",
            action=BLOCK,
            risk_contribution=0.8,
            matched_field="content",
            matched_value=_truncate(m.group(0), 120),
        )
    return None


@_rule_evaluator("input_type_block")
def _eval_input_type_block(rule: dict[str, Any], pinput: PolicyInput) -> MatchedRule | None:
    allowed_types_raw: str = (rule.get("value") or "").strip().lower()
    if not allowed_types_raw:
        return None
    blocked_types = {t.strip() for t in allowed_types_raw.split(",") if t.strip()}
    if pinput.input_type in blocked_types:
        return MatchedRule(
            rule_id=str(rule.get("id", "")),
            rule_name=str(rule.get("rule_name") or rule.get("name") or rule_type_label(rule)),
            rule_type="input_type_block",
            action=BLOCK,
            risk_contribution=1.0,
            matched_field="input_type",
            matched_value=pinput.input_type,
        )
    return None


@_rule_evaluator("content_length_block")
def _eval_content_length_block(rule: dict[str, Any], pinput: PolicyInput) -> MatchedRule | None:
    try:
        max_len = int(rule.get("value") or 0)
    except (ValueError, TypeError):
        return None
    if max_len > 0 and len(pinput.content) > max_len:
        return MatchedRule(
            rule_id=str(rule.get("id", "")),
            rule_name=str(rule.get("rule_name") or rule.get("name") or rule_type_label(rule)),
            rule_type="content_length_block",
            action=BLOCK,
            risk_contribution=0.9,
            matched_field="content_length",
            matched_value=str(len(pinput.content)),
        )
    return None


@_rule_evaluator("agent_id_block")
def _eval_agent_id_block(rule: dict[str, Any], pinput: PolicyInput) -> MatchedRule | None:
    blocked_agent: str = (rule.get("value") or "").strip()
    if not blocked_agent:
        return None
    if pinput.agent_id and pinput.agent_id.strip() == blocked_agent:
        return MatchedRule(
            rule_id=str(rule.get("id", "")),
            rule_name=str(rule.get("rule_name") or rule.get("name") or rule_type_label(rule)),
            rule_type="agent_id_block",
            action=BLOCK,
            risk_contribution=1.0,
            matched_field="agent_id",
            matched_value=_truncate(blocked_agent, 120),
        )
    return None


@_rule_evaluator("prompt_injection_pattern")
def _eval_prompt_injection(rule: dict[str, Any], pinput: PolicyInput) -> MatchedRule | None:
    if pinput.input_type not in ("prompt", "execution_plan"):
        return None
    pattern: str = (rule.get("value") or "").strip()
    if not pattern:
        return None
    try:
        compiled = re.compile(pattern, re.IGNORECASE | re.DOTALL)
    except re.error as exc:
        _logger.warning("policy_engine: invalid injection pattern in rule %s: %s", rule.get("id"), exc)
        return None
    m = compiled.search(pinput.content)
    if m:
        return MatchedRule(
            rule_id=str(rule.get("id", "")),
            rule_name=str(rule.get("rule_name") or rule.get("name") or rule_type_label(rule)),
            rule_type="prompt_injection_pattern",
            action=BLOCK,
            risk_contribution=1.0,
            matched_field="content",
            matched_value=_truncate(m.group(0), 120),
        )
    return None


@_rule_evaluator("tool_call_block")
def _eval_tool_call_block(rule: dict[str, Any], pinput: PolicyInput) -> MatchedRule | None:
    if pinput.input_type != "tool_call":
        return None
    blocked_tool: str = (rule.get("value") or "").strip().lower()
    if not blocked_tool:
        return None
    if blocked_tool in pinput.content.lower():
        return MatchedRule(
            rule_id=str(rule.get("id", "")),
            rule_name=str(rule.get("rule_name") or rule.get("name") or rule_type_label(rule)),
            rule_type="tool_call_block",
            action=BLOCK,
            risk_contribution=1.0,
            matched_field="content",
            matched_value=_truncate(blocked_tool, 120),
        )
    return None


@_rule_evaluator("data_exfiltration_pattern")
def _eval_data_exfil(rule: dict[str, Any], pinput: PolicyInput) -> MatchedRule | None:
    pattern: str = (rule.get("value") or "").strip()
    if not pattern:
        return None
    try:
        compiled = re.compile(pattern, re.IGNORECASE | re.DOTALL)
    except re.error as exc:
        _logger.warning("policy_engine: invalid exfil pattern in rule %s: %s", rule.get("id"), exc)
        return None
    m = compiled.search(pinput.content)
    if m:
        return MatchedRule(
            rule_id=str(rule.get("id", "")),
            rule_name=str(rule.get("rule_name") or rule.get("name") or rule_type_label(rule)),
            rule_type="data_exfiltration_pattern",
            action=BLOCK,
            risk_contribution=0.9,
            matched_field="content",
            matched_value=_truncate(m.group(0), 120),
        )
    return None


# ---------------------------------------------------------------------------
# Built-in safety net — delegates to pattern_registry for zero duplication
# ---------------------------------------------------------------------------

# Severity → verdict mapping for safety-net hits from the registry
_SAFETY_NET_SEVERITY_ACTION: dict[str, VerdictAction] = {
    "critical": BLOCK,
    "high": BLOCK,
    "medium": BLOCK,
    "low": BLOCK,
}

# Risk contribution per severity level for safety-net hits
_SAFETY_NET_SEVERITY_RISK: dict[str, float] = {
    "critical": 1.0,
    "high": 1.0,
    "medium": 0.6,
    "low": 0.3,
}


def _apply_builtin_safety_net(pinput: PolicyInput) -> list[MatchedRule]:
    """Apply the built-in injection safety net via pattern_registry.

    Delegates entirely to pattern_registry.match_by_category() — no compiled
    pattern list is maintained here.  Covers prompt_injection and
    separator_injection categories for prompt and execution_plan inputs.
    """
    if pinput.input_type not in ("prompt", "execution_plan"):
        return []

    try:
        from app.core import pattern_registry  # noqa: PLC0415

        hits = pattern_registry.match_by_category(
            pinput.content,
            ["prompt_injection", "separator_injection"],
        )
    except Exception as exc:  # noqa: BLE001
        _logger.warning(
            "policy_engine: pattern_registry.match_by_category failed — safety net skipped: %s",
            exc,
        )
        return []

    results: list[MatchedRule] = []
    for hit in hits:
        action = _SAFETY_NET_SEVERITY_ACTION.get(hit.severity, BLOCK)
        risk = _SAFETY_NET_SEVERITY_RISK.get(hit.severity, 1.0)
        results.append(
            MatchedRule(
                rule_id=f"builtin:{hit.pattern_id}",
                rule_name=hit.pattern_name,
                rule_type="prompt_injection_pattern",
                action=action,
                risk_contribution=risk,
                matched_field="content",
                matched_value=_truncate(hit.matched_value, 120),
            )
        )
    return results


# ---------------------------------------------------------------------------
# Policy set cache — TTL-based in-process cache to avoid per-request DB hits
# ---------------------------------------------------------------------------

_CACHE_TTL_SECONDS: float = 60.0

_cache_store: dict[str, tuple[list[dict[str, Any]], float]] = {}


def _get_cached_rules(set_key: str) -> list[dict[str, Any]] | None:
    entry = _cache_store.get(set_key)
    if entry is None:
        return None
    rules, expires_at = entry
    if time.monotonic() > expires_at:
        del _cache_store[set_key]
        return None
    return rules


def _set_cached_rules(set_key: str, rules: list[dict[str, Any]]) -> None:
    _cache_store[set_key] = (rules, time.monotonic() + _CACHE_TTL_SECONDS)


def invalidate_policy_cache(set_key: str | None = None) -> None:
    """Invalidate the in-process policy rule cache.

    Call after mutating policy_rules or policy_set_memberships in the DB.
    When set_key is None, the entire cache is cleared.
    """
    if set_key is None:
        _cache_store.clear()
    else:
        _cache_store.pop(set_key, None)


# ---------------------------------------------------------------------------
# Rule loader
# ---------------------------------------------------------------------------

_DEFAULT_POLICY_SET_KEY = "ironclaw_default"


def _load_rules_for_set(set_key: str) -> list[dict[str, Any]]:
    cached = _get_cached_rules(set_key)
    if cached is not None:
        return cached

    try:
        from app.core.supabase_persistence import get_policy_set  # noqa: PLC0415

        result = get_policy_set(set_key)
        if result and isinstance(result, dict):
            rules: list[dict[str, Any]] = result.get("rules") or []
            if isinstance(rules, list):
                active_rules = [r for r in rules if isinstance(r, dict) and r.get("is_active", True)]
                _set_cached_rules(set_key, active_rules)
                return active_rules
    except Exception as exc:  # noqa: BLE001
        _logger.error(
            "policy_engine: failed to load rules for set %r: %s",
            set_key,
            exc,
        )

    _set_cached_rules(set_key, [])
    return []


def _resolve_rules(tenant_key: str | None) -> tuple[str, list[dict[str, Any]]]:
    if tenant_key:
        rules = _load_rules_for_set(tenant_key)
        if rules:
            return tenant_key, rules
        _logger.debug(
            "policy_engine: tenant set %r empty or not found — falling back to %r",
            tenant_key,
            _DEFAULT_POLICY_SET_KEY,
        )

    rules = _load_rules_for_set(_DEFAULT_POLICY_SET_KEY)
    return _DEFAULT_POLICY_SET_KEY, rules


# ---------------------------------------------------------------------------
# Trust gate — evaluated before any rule matching
# ---------------------------------------------------------------------------


def _apply_trust_gate(pinput: PolicyInput) -> tuple[list[MatchedRule], float | None, bool]:
    """Evaluate the trust profile for pinput.agent_id.

    Returns:
        matched_rules  — synthetic MatchedRule entries injected by the trust gate
        trust_score    — the agent's current trust_score (None if no agent_id)
        is_suspended   — whether the agent is currently suspended

    Resolution:
      - No agent_id → no trust gate applied (pass-through).
      - is_suspended=True → immediate block rule injected; callers must short-circuit.
      - trust_score < _TRUST_WARN_THRESHOLD → block rule injected.
      - Otherwise → no synthetic rules added.
    """
    if not pinput.agent_id or not pinput.agent_id.strip():
        return [], None, False

    try:
        from app.core.trust_engine import get_trust  # noqa: PLC0415

        profile = get_trust(pinput.agent_id)
    except Exception as exc:  # noqa: BLE001
        _logger.warning(
            "policy_engine: trust_engine.get_trust failed for agent %r — skipping trust gate: %s",
            pinput.agent_id,
            exc,
        )
        return [], None, False

    trust_score: float = profile.trust_score
    is_suspended: bool = profile.is_suspended

    if is_suspended:
        reason = profile.suspension_reason or "Agent suspended"
        rule = MatchedRule(
            rule_id="trust_gate",
            rule_name="Suspended agent blocked by trust gate",
            rule_type="trust_gated_block",
            action=BLOCK,
            risk_contribution=1.0,
            matched_field="agent_id",
            matched_value=_truncate(f"{pinput.agent_id} — {reason}", 120),
        )
        _logger.warning(
            "policy_engine.trust_gate.suspended",
            extra={"agent_id": pinput.agent_id, "suspension_reason": reason},
        )
        return [rule], trust_score, True

    if trust_score < _TRUST_WARN_THRESHOLD:
        rule = MatchedRule(
            rule_id="trust_gate",
            rule_name="Low trust score blocked by trust gate",
            rule_type="trust_score_warn",
            action=BLOCK,
            risk_contribution=round(1.0 - trust_score, 4),
            matched_field="trust_score",
            matched_value=str(round(trust_score, 4)),
        )
        _logger.info(
            "policy_engine.trust_gate.low_score",
            extra={"agent_id": pinput.agent_id, "trust_score": trust_score},
        )
        return [rule], trust_score, False

    return [], trust_score, False


# ---------------------------------------------------------------------------
# Core evaluation
# ---------------------------------------------------------------------------


def _evaluate_rule(rule: dict[str, Any], pinput: PolicyInput) -> MatchedRule | None:
    rule_type: str = (rule.get("rule_type") or "").strip()
    evaluator = _RULE_EVALUATORS.get(rule_type)
    if evaluator is None:
        _logger.debug("policy_engine: no evaluator for rule_type %r — skipped", rule_type)
        return None
    try:
        return evaluator(rule, pinput)
    except Exception as exc:  # noqa: BLE001
        _logger.warning(
            "policy_engine: evaluator %r raised for rule %s: %s",
            rule_type,
            rule.get("id"),
            exc,
        )
        return None


def _compute_risk_score(matched_rules: list[MatchedRule]) -> float:
    if not matched_rules:
        return 0.0
    total = sum(r.risk_contribution for r in matched_rules)
    return min(round(total / max(len(matched_rules), 1), 4), 1.0)


def _resolve_action(matched_rules: list[MatchedRule]) -> VerdictAction:
    return BLOCK if matched_rules else ALLOW


def _build_explanation(
    action: VerdictAction,
    matched_rules: list[MatchedRule],
    risk_score: float,
    policy_set_key: str,
    is_suspended: bool = False,
) -> str:
    if is_suspended:
        return f"Verdict '{action}' issued: agent is suspended. All further evaluation was skipped. Policy set: '{policy_set_key}'. Risk score: {risk_score:.4f}."
    if action == ALLOW:
        return f"Input passed all {len(matched_rules)} evaluated rules in policy set '{policy_set_key}'. Risk score: {risk_score:.4f}."
    rule_names = ", ".join({r.rule_name for r in matched_rules if r.action != ALLOW})
    return f"Verdict '{action}' issued by policy set '{policy_set_key}'. Matched {len(matched_rules)} rule(s): [{rule_names}]. Aggregate risk score: {risk_score:.4f}."


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def evaluate(pinput: PolicyInput) -> PolicyVerdict:
    """Evaluate a PolicyInput against the active policy set.

    This is the single source of truth for all PolicyVerdict computation.
    No other module may independently compute a PolicyVerdict.

    Resolution order:
      0. Trust gate — if agent_id is set, trust_engine.get_trust() is called.
         Suspended agents receive an immediate block verdict; no further
         rule evaluation is performed.  Low-trust agents receive a synthetic
         block rule that propagates into the final verdict.
      1. pinput.tenant_key — tenant-specific policy set if non-empty and found.
      2. ironclaw_default  — authoritative fallback policy set.
      3. Built-in safety net — always applied via pattern_registry regardless
         of DB state; covers prompt_injection and separator_injection categories.

    Returns a PolicyVerdict with action: allow | block,
    matched_rules, risk_score, trust_score_at_eval, agent_suspended, and a
    human-readable explanation.
    """
    start = time.perf_counter()

    # --- Trust gate (step 0) ------------------------------------------------
    trust_matched, trust_score, is_suspended = _apply_trust_gate(pinput)

    if is_suspended:
        # Short-circuit: suspended agents never reach rule evaluation
        risk_score = _compute_risk_score(trust_matched)
        explanation = _build_explanation(BLOCK, trust_matched, risk_score, _DEFAULT_POLICY_SET_KEY, is_suspended=True)
        duration_ms = round((time.perf_counter() - start) * 1000, 4)
        verdict = PolicyVerdict(
            verdict_id=str(uuid.uuid4()),
            action=BLOCK,
            matched_rules=trust_matched,
            risk_score=risk_score,
            explanation=explanation,
            input_type=pinput.input_type,
            policy_set_key=_DEFAULT_POLICY_SET_KEY,
            evaluated_at=datetime.now(UTC).isoformat(),
            duration_ms=duration_ms,
            trust_score_at_eval=trust_score,
            agent_suspended=True,
        )
        _logger.info(
            "policy_engine.verdict",
            extra={
                "verdict_id": verdict.verdict_id,
                "action": BLOCK,
                "risk_score": risk_score,
                "input_type": pinput.input_type,
                "policy_set_key": _DEFAULT_POLICY_SET_KEY,
                "matched_rule_count": len(trust_matched),
                "duration_ms": duration_ms,
                "agent_id": pinput.agent_id,
                "trust_score": trust_score,
                "agent_suspended": True,
            },
        )
        return verdict

    # --- Policy set resolution + rule evaluation (steps 1-3) ---------------
    policy_set_key, db_rules = _resolve_rules(pinput.tenant_key)

    matched: list[MatchedRule] = list(trust_matched)  # carry low-trust block if present

    builtin_hits = _apply_builtin_safety_net(pinput)
    matched.extend(builtin_hits)

    for rule in db_rules:
        hit = _evaluate_rule(rule, pinput)
        if hit is not None:
            matched.append(hit)

    action = _resolve_action(matched)
    risk_score = _compute_risk_score(matched)
    explanation = _build_explanation(action, matched, risk_score, policy_set_key)
    duration_ms = round((time.perf_counter() - start) * 1000, 4)

    verdict = PolicyVerdict(
        verdict_id=str(uuid.uuid4()),
        action=action,
        matched_rules=matched,
        risk_score=risk_score,
        explanation=explanation,
        input_type=pinput.input_type,
        policy_set_key=policy_set_key,
        evaluated_at=datetime.now(UTC).isoformat(),
        duration_ms=duration_ms,
        trust_score_at_eval=trust_score,
        agent_suspended=False,
    )

    _logger.info(
        "policy_engine.verdict",
        extra={
            "verdict_id": verdict.verdict_id,
            "action": action,
            "risk_score": risk_score,
            "input_type": pinput.input_type,
            "policy_set_key": policy_set_key,
            "matched_rule_count": len(matched),
            "duration_ms": duration_ms,
            "agent_id": pinput.agent_id,
            "trust_score": trust_score,
            "agent_suspended": False,
        },
    )

    return verdict


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def rule_type_label(rule: dict[str, Any]) -> str:
    return str(rule.get("rule_type") or "unknown_rule")


def _truncate(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return f"{value[:limit]}...[truncated]"


# ---------------------------------------------------------------------------
# Public surface
# ---------------------------------------------------------------------------

__all__ = [
    "InputType",
    "VerdictAction",
    "MatchedRule",
    "PolicyVerdict",
    "PolicyInput",
    "evaluate",
    "invalidate_policy_cache",
]
