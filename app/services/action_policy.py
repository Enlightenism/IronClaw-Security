from __future__ import annotations

import logging
from typing import Any, Literal, TypedDict

from app.services.action_guard import ActionType, VerdictType

logger = logging.getLogger(__name__)

PolicyMode = Literal["allow", "review", "block"]

DEFAULT_POLICY_SET_KEY = "ironclaw_default"

# ---------------------------------------------------------------------------
# Cold-start fallback constants — used when DB is unavailable at startup.
# These are the authoritative defaults; the DB loader overwrites them.
# ---------------------------------------------------------------------------

_DEFAULT_BLOCKED_TARGETS: frozenset[str] = frozenset(
    {
        "c:\\windows\\system32",
        "c:\\windows\\syswow64",
        "c:\\programdata",
        "/etc/",
        "/root/",
        "/var/run/",
        ".ssh",
        "id_rsa",
        "id_dsa",
        ".env",
        ".pem",
        ".pfx",
        ".key",
        "secrets",
        "credential",
        "token",
        "passwd",
        "shadow",
        "known_hosts",
        "authorized_keys",
        "aws",
        ".azure",
        ".config/gcloud",
        "kubeconfig",
    },
)

_DEFAULT_HIGH_REVIEW_TARGETS: frozenset[str] = frozenset(
    {
        "powershell",
        "pwsh",
        "cmd.exe",
        "bash",
        "sh",
        "zsh",
        "curl",
        "wget",
        "invoke-webrequest",
        "iwr",
        "scp",
        "ssh",
        "sftp",
        "ftp",
        "git",
        "python",
        "py",
        "node",
        "npm",
        "npx",
        "pip",
        "docker",
        "kubectl",
        "az",
        "aws",
        "gcloud",
        "rclone",
        "certutil",
        "regsvr32",
        "mshta",
        "rundll32",
    },
)

_DEFAULT_ELEVATED_REVIEW_ACTIONS: frozenset[str] = frozenset(
    {
        "shell_command",
        "network_request",
        "git_operation",
        "file_write",
        "tool_call",
    },
)

# ---------------------------------------------------------------------------
# Runtime mutable sets — hydrated from DB at startup, fallback to defaults.
# Never import these directly from outside this module; use the accessors.
# ---------------------------------------------------------------------------

BLOCKED_TARGETS: frozenset[str] = _DEFAULT_BLOCKED_TARGETS
HIGH_REVIEW_TARGETS: frozenset[str] = _DEFAULT_HIGH_REVIEW_TARGETS
ELEVATED_REVIEW_ACTIONS: frozenset[str] = _DEFAULT_ELEVATED_REVIEW_ACTIONS

_policy_loaded_from_db: bool = False


# ---------------------------------------------------------------------------
# TypedDicts
# ---------------------------------------------------------------------------


class ActionPolicyReason(TypedDict):
    source: Literal["policy"]
    label: str
    details: str
    score: float | None


class ActionPolicyDecision(TypedDict):
    action_type: ActionType
    target: str
    policy_mode: PolicyMode
    verdict: VerdictType
    summary: str
    should_halt: bool
    should_warn: bool
    client_id: str | None
    session_id: str | None
    reasons: list[ActionPolicyReason]


# ---------------------------------------------------------------------------
# DB-backed rule loader
# ---------------------------------------------------------------------------

_RULE_TYPE_TO_SET: dict[str, str] = {
    "blocked_target": "blocked",
    "high_review_target": "high_review",
    "elevated_review_action": "elevated_action",
}

# Canonical column in policy_set_memberships that references a policy rule.
_COL_POLICY_RULE_ID = "policy_rule_id"


def _invalidate_policy_engine_cache() -> None:
    """
    Notify policy_engine that its rule cache is stale after a DB reload.
    Imported lazily to avoid circular imports at module load time.
    Failures are swallowed — action_policy must never crash due to a
    cache-sync side-effect.
    """
    try:
        from app.core.policy_engine import invalidate_policy_cache  # noqa: PLC0415

        invalidate_policy_cache()
        logger.debug("action_policy: policy_engine cache invalidated after rule reload")
    except Exception as exc:  # noqa: BLE001
        logger.warning("action_policy: could not invalidate policy_engine cache: %s", exc)


def load_builtin_policy_rules_from_db(
    tenant_key: str | None = None,
) -> bool:
    """
    Hydrate BLOCKED_TARGETS, HIGH_REVIEW_TARGETS, and ELEVATED_REVIEW_ACTIONS
    from policy_sets + policy_set_memberships + policy_rules in Supabase.

    Resolution order:
      1. Tenant-specific set identified by `tenant_key` (when provided).
      2. `ironclaw_default` set as the authoritative fallback.
      3. Python cold-start constants when the DB is unavailable or returns nothing.

    On successful hydration, invalidates policy_engine's rule cache so both
    caches stay synchronized with the same DB state.

    Returns True if rules were successfully loaded from the DB, False otherwise.
    """
    global BLOCKED_TARGETS, HIGH_REVIEW_TARGETS, ELEVATED_REVIEW_ACTIONS, _policy_loaded_from_db

    try:
        from app.supabaseclient import get_supabase_client, is_supabase_configured  # noqa: PLC0415
    except ImportError:
        logger.warning("action_policy: supabaseclient unavailable — using cold-start defaults")
        return False

    if not is_supabase_configured():
        logger.warning("action_policy: Supabase not configured — using cold-start defaults")
        return False

    try:
        client = get_supabase_client()

        set_key = tenant_key or DEFAULT_POLICY_SET_KEY

        # --- resolve policy_set id by set_key, fall back to ironclaw_default ---
        set_rows = client.table("policy_sets").select("id, set_key").eq("set_key", set_key).eq("is_active", True).limit(1).execute().data

        if not set_rows and tenant_key and set_key != DEFAULT_POLICY_SET_KEY:
            logger.info(
                "action_policy: tenant set %r not found — falling back to %r",
                set_key,
                DEFAULT_POLICY_SET_KEY,
            )
            set_rows = client.table("policy_sets").select("id, set_key").eq("set_key", DEFAULT_POLICY_SET_KEY).eq("is_active", True).limit(1).execute().data

        if not set_rows:
            logger.warning(
                "action_policy: policy_set %r not found in DB — using cold-start defaults",
                set_key,
            )
            return False

        policy_set_id: str = set_rows[0]["id"]
        resolved_key: str = set_rows[0]["set_key"]

        # --- fetch rule IDs via policy_rule_id (canonical column) ---
        membership_rows = client.table("policy_set_memberships").select(_COL_POLICY_RULE_ID).eq("set_id", policy_set_id).execute().data

        if not membership_rows:
            logger.warning(
                "action_policy: policy_set %r has no memberships — using cold-start defaults",
                resolved_key,
            )
            return False

        rule_ids: list[str] = [row[_COL_POLICY_RULE_ID] for row in membership_rows if isinstance(row, dict) and row.get(_COL_POLICY_RULE_ID)]

        if not rule_ids:
            logger.warning(
                "action_policy: no policy_rule_ids from memberships for set %r — using cold-start defaults",
                resolved_key,
            )
            return False

        # --- fetch the actual policy_rules rows ---
        rules_rows = client.table("policy_rules").select("rule_type, value").in_("id", rule_ids).eq("is_active", True).execute().data

        if not rules_rows:
            logger.warning(
                "action_policy: no active rules found for set %r — using cold-start defaults",
                resolved_key,
            )
            return False

        blocked: set[str] = set()
        high_review: set[str] = set()
        elevated_action: set[str] = set()

        for row in rules_rows:
            rule_type = (row.get("rule_type") or "").strip()
            value = (row.get("value") or "").strip().lower()
            if not value:
                continue
            if rule_type == "blocked_target":
                blocked.add(value)
            elif rule_type == "high_review_target":
                high_review.add(value)
            elif rule_type == "elevated_review_action":
                elevated_action.add(value)
            else:
                logger.debug("action_policy: unrecognised rule_type %r — skipped", rule_type)

        # Merge DB rules with cold-start defaults so the defaults are always
        # a minimum floor — the DB can only extend, never leave the set empty.
        BLOCKED_TARGETS = _DEFAULT_BLOCKED_TARGETS | frozenset(blocked)
        HIGH_REVIEW_TARGETS = _DEFAULT_HIGH_REVIEW_TARGETS | frozenset(high_review)
        ELEVATED_REVIEW_ACTIONS = _DEFAULT_ELEVATED_REVIEW_ACTIONS | frozenset(elevated_action)

        _policy_loaded_from_db = True

        logger.info(
            "action_policy: loaded rules from DB set %r — " "blocked=%d high_review=%d elevated_action=%d",
            resolved_key,
            len(BLOCKED_TARGETS),
            len(HIGH_REVIEW_TARGETS),
            len(ELEVATED_REVIEW_ACTIONS),
        )

        # Synchronize policy_engine's cache so both caches reflect the same DB state.
        _invalidate_policy_engine_cache()

        return True

    except Exception as exc:  # noqa: BLE001
        logger.error(
            "action_policy: DB rule load failed — using cold-start defaults. Error: %s",
            exc,
        )
        return False


def is_policy_loaded_from_db() -> bool:
    """Return True if rules were successfully hydrated from the DB at startup."""
    return _policy_loaded_from_db


def reload_policy_rules(tenant_key: str | None = None) -> bool:
    """Force a live reload of policy rules from the DB. Thread-safe via GIL for frozenset swap."""
    return load_builtin_policy_rules_from_db(tenant_key=tenant_key)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _target_contains_any(target: str, needles: frozenset[str]) -> bool:
    return any(needle in target for needle in needles)


def _normalize_target(target: str | None) -> str:
    return (target or "").strip().lower()


def _build_reason(
    *,
    label: str,
    details: str,
    score: float | None,
) -> ActionPolicyReason:
    return {
        "source": "policy",
        "label": label,
        "details": details,
        "score": score,
    }


def _build_policy_decision(
    *,
    action_type: ActionType,
    target: str,
    policy_mode: PolicyMode,
    verdict: VerdictType,
    summary: str,
    should_halt: bool,
    should_warn: bool,
    client_id: str | None,
    session_id: str | None,
    reasons: list[ActionPolicyReason],
) -> ActionPolicyDecision:
    return {
        "action_type": action_type,
        "target": target,
        "policy_mode": policy_mode,
        "verdict": verdict,
        "summary": summary,
        "should_halt": should_halt,
        "should_warn": should_warn,
        "client_id": client_id,
        "session_id": session_id,
        "reasons": reasons,
    }


def _build_block_decision(
    *,
    action_type: ActionType,
    target: str,
    summary: str,
    client_id: str | None,
    session_id: str | None,
) -> ActionPolicyDecision:
    return _build_policy_decision(
        action_type=action_type,
        target=target,
        policy_mode="block",
        verdict="block",
        summary=summary,
        should_halt=True,
        should_warn=False,
        client_id=client_id,
        session_id=session_id,
        reasons=[
            _build_reason(
                label="Blocked target",
                details=summary,
                score=1.0,
            ),
        ],
    )


def _build_review_decision(
    *,
    action_type: ActionType,
    target: str,
    summary: str,
    client_id: str | None,
    session_id: str | None,
    label: str,
) -> ActionPolicyDecision:
    return _build_policy_decision(
        action_type=action_type,
        target=target,
        policy_mode="review",
        verdict="warn",
        summary=summary,
        should_halt=False,
        should_warn=True,
        client_id=client_id,
        session_id=session_id,
        reasons=[
            _build_reason(
                label=label,
                details=summary,
                score=0.7,
            ),
        ],
    )


def _build_allow_decision(
    *,
    action_type: ActionType,
    target: str,
    client_id: str | None,
    session_id: str | None,
) -> ActionPolicyDecision:
    summary = "Action is within the current allowed policy scope."
    return _build_policy_decision(
        action_type=action_type,
        target=target,
        policy_mode="allow",
        verdict="allow",
        summary=summary,
        should_halt=False,
        should_warn=False,
        client_id=client_id,
        session_id=session_id,
        reasons=[
            _build_reason(
                label="Allowed by policy",
                details=summary,
                score=0.0,
            ),
        ],
    )


def _fire_verdict_event(
    *,
    tenant_id: str | None,
    verdict: VerdictType,
    action_type: ActionType,
    target: str,
    policy_mode: PolicyMode,
    client_id: str | None,
    session_id: str | None,
) -> None:
    if not tenant_id:
        return
    try:
        from app.services.webhook_service import dispatch_event  # noqa: PLC0415

        event_type = f"policy.{verdict}"
        payload: dict[str, Any] = {
            "verdict": verdict,
            "policy_mode": policy_mode,
            "action_type": action_type,
            "target": target,
            "client_id": client_id,
            "session_id": session_id,
        }
        dispatch_event(tenant_id, event_type, payload)
    except Exception:  # noqa: BLE001
        pass


# ---------------------------------------------------------------------------
# Public evaluation entry point
# ---------------------------------------------------------------------------


def evaluate_action_policy(
    action_type: ActionType,
    target: str,
    client_id: str | None = None,
    session_id: str | None = None,
    tenant_id: str | None = None,
) -> ActionPolicyDecision:
    normalized_target = _normalize_target(target)

    if _target_contains_any(normalized_target, BLOCKED_TARGETS):
        decision = _build_block_decision(
            action_type=action_type,
            target=target,
            summary="Target is outside the allowed safety boundary.",
            client_id=client_id,
            session_id=session_id,
        )
        _fire_verdict_event(
            tenant_id=tenant_id,
            verdict=decision["verdict"],
            action_type=action_type,
            target=target,
            policy_mode=decision["policy_mode"],
            client_id=client_id,
            session_id=session_id,
        )
        return decision

    if action_type in ELEVATED_REVIEW_ACTIONS:
        decision = _build_review_decision(
            action_type=action_type,
            target=target,
            summary="Action type requires elevated review before execution.",
            client_id=client_id,
            session_id=session_id,
            label="Elevated action type",
        )
        _fire_verdict_event(
            tenant_id=tenant_id,
            verdict=decision["verdict"],
            action_type=action_type,
            target=target,
            policy_mode=decision["policy_mode"],
            client_id=client_id,
            session_id=session_id,
        )
        return decision

    if _target_contains_any(normalized_target, HIGH_REVIEW_TARGETS):
        decision = _build_review_decision(
            action_type=action_type,
            target=target,
            summary="Target requires elevated review before execution.",
            client_id=client_id,
            session_id=session_id,
            label="Elevated target",
        )
        _fire_verdict_event(
            tenant_id=tenant_id,
            verdict=decision["verdict"],
            action_type=action_type,
            target=target,
            policy_mode=decision["policy_mode"],
            client_id=client_id,
            session_id=session_id,
        )
        return decision

    decision = _build_allow_decision(
        action_type=action_type,
        target=target,
        client_id=client_id,
        session_id=session_id,
    )
    _fire_verdict_event(
        tenant_id=tenant_id,
        verdict=decision["verdict"],
        action_type=action_type,
        target=target,
        policy_mode=decision["policy_mode"],
        client_id=client_id,
        session_id=session_id,
    )
    return decision
