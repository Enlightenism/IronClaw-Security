from __future__ import annotations

from typing import Literal, TypedDict

from app.services.action_guard import ActionType, VerdictType

PolicyMode = Literal["allow", "review", "block"]


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


BLOCKED_TARGETS = frozenset(
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

HIGH_REVIEW_TARGETS = frozenset(
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

ELEVATED_REVIEW_ACTIONS = frozenset(
    {
        "shell_command",
        "network_request",
        "git_operation",
        "file_write",
        "tool_call",
    },
)


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


def evaluate_action_policy(
    action_type: ActionType,
    target: str,
    client_id: str | None = None,
    session_id: str | None = None,
) -> ActionPolicyDecision:
    normalized_target = _normalize_target(target)

    if _target_contains_any(normalized_target, BLOCKED_TARGETS):
        return _build_block_decision(
            action_type=action_type,
            target=target,
            summary="Target is outside the allowed safety boundary.",
            client_id=client_id,
            session_id=session_id,
        )

    if action_type in ELEVATED_REVIEW_ACTIONS:
        return _build_review_decision(
            action_type=action_type,
            target=target,
            summary="Action type requires elevated review before execution.",
            client_id=client_id,
            session_id=session_id,
            label="Elevated action type",
        )

    if _target_contains_any(normalized_target, HIGH_REVIEW_TARGETS):
        return _build_review_decision(
            action_type=action_type,
            target=target,
            summary="Target requires elevated review before execution.",
            client_id=client_id,
            session_id=session_id,
            label="Elevated target",
        )

    return _build_allow_decision(
        action_type=action_type,
        target=target,
        client_id=client_id,
        session_id=session_id,
    )
