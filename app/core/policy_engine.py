from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
import logging
import re
import time
from typing import Any, Literal
import uuid

from app.core.logging import get_logger
from app.core.verdicts import ALLOW, BLOCK, QUARANTINE, WARN

_logger: logging.Logger = get_logger("ironclaw.policy_engine")

# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

InputType = Literal["prompt", "tool_call", "execution_plan"]

VerdictAction = Literal["allow", "warn", "quarantine", "block"]

VERDICT_PRIORITY: dict[str, int] = {
    ALLOW: 0,
    WARN: 1,
    QUARANTINE: 2,
    BLOCK: 3,
}


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
            action=WARN,
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
            action=WARN,
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
            action=QUARANTINE,
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
            action=QUARANTINE,
            risk_contribution=0.9,
            matched_field="content",
            matched_value=_truncate(m.group(0), 120),
        )
    return None


# ---------------------------------------------------------------------------
# Built-in safety net patterns — active even when DB has no rules
# ---------------------------------------------------------------------------

_BUILTIN_INJECTION_PATTERNS: list[re.Pattern[str]] = []

_RAW_INJECTION_PATTERNS: list[str] = [
    r"ignore\s+(all\s+)?previous\s+instructions",
    r"disregard\s+(all\s+)?prior\s+(instructions|directives|constraints)",
    r"you\s+are\s+now\s+in\s+developer\s+mode",
    r"jailbreak",
    r"do\s+anything\s+now",
    r"DAN\s+mode",
    r"<\s*SYSTEM\s*>",
    r"\[\s*SYSTEM\s*\]",
    r"pretend\s+(you\s+are|to\s+be)\s+.{0,60}(without|no)\s+(restrictions|limits|filter)",
    r"act\s+as\s+(if\s+you\s+(are|have\s+no)|a)\s+.{0,40}(uncensored|unfiltered|unrestricted)",
]

for _raw in _RAW_INJECTION_PATTERNS:
    try:
        _BUILTIN_INJECTION_PATTERNS.append(re.compile(_raw, re.IGNORECASE | re.DOTALL))
    except re.error:
        pass


def _apply_builtin_safety_net(pinput: PolicyInput) -> list[MatchedRule]:
    if pinput.input_type not in ("prompt", "execution_plan"):
        return []
    results: list[MatchedRule] = []
    for compiled in _BUILTIN_INJECTION_PATTERNS:
        m = compiled.search(pinput.content)
        if m:
            results.append(
                MatchedRule(
                    rule_id="builtin",
                    rule_name="Built-in prompt injection pattern",
                    rule_type="prompt_injection_pattern",
                    action=BLOCK,
                    risk_contribution=1.0,
                    matched_field="content",
                    matched_value=_truncate(m.group(0), 120),
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
    if not matched_rules:
        return ALLOW
    best = max(matched_rules, key=lambda r: VERDICT_PRIORITY.get(r.action, 0))
    return best.action


def _build_explanation(
    action: VerdictAction,
    matched_rules: list[MatchedRule],
    risk_score: float,
    policy_set_key: str,
) -> str:
    if action == ALLOW:
        return f"Input passed all {len(matched_rules)} evaluated rules in policy set " f"'{policy_set_key}'. Risk score: {risk_score:.4f}."
    rule_names = ", ".join({r.rule_name for r in matched_rules if r.action != ALLOW})
    return f"Verdict '{action}' issued by policy set '{policy_set_key}'. " f"Matched {len(matched_rules)} rule(s): [{rule_names}]. " f"Aggregate risk score: {risk_score:.4f}."


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def evaluate(pinput: PolicyInput) -> PolicyVerdict:
    """Evaluate a PolicyInput against the active policy set.

    This is the single source of truth for all PolicyVerdict computation.
    No other module may independently compute a PolicyVerdict.

    Resolution order:
      1. pinput.tenant_key — tenant-specific policy set if non-empty and found.
      2. ironclaw_default  — authoritative fallback policy set.
      3. Built-in safety net patterns — always applied regardless of DB state.

    Returns a PolicyVerdict with action: allow | warn | quarantine | block,
    matched_rules, risk_score, and a human-readable explanation.
    """
    start = time.perf_counter()

    policy_set_key, db_rules = _resolve_rules(pinput.tenant_key)

    matched: list[MatchedRule] = []

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
