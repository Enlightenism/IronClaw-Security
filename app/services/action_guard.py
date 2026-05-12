from __future__ import annotations

from typing import Literal, TypedDict

from app.security.promptinjection import scanpromptinjectiondict
from app.services.scanner import perform_scan

ActionType = Literal[
    "file_write",
    "file_edit",
    "shell_command",
    "network_request",
    "git_operation",
    "tool_call",
]
VerdictType = Literal["allow", "warn", "quarantine", "block"]


class ActionGuardReason(TypedDict):
    source: Literal["scan", "promptinjection"]
    label: str
    details: str
    score: float | None


class ActionGuardDecision(TypedDict):
    action_type: ActionType
    verdict: VerdictType
    scan_id: str | None
    summary: str
    risk_score: int
    matched_patterns: list[str]
    target: str
    content: str
    should_halt: bool
    should_warn: bool
    client_id: str | None
    session_id: str | None
    reasons: list[ActionGuardReason]


def _verdict_rank(verdict: VerdictType) -> int:
    order: dict[VerdictType, int] = {
        "allow": 1,
        "warn": 2,
        "quarantine": 3,
        "block": 4,
    }
    return order[verdict]


def _max_verdict(*verdicts: VerdictType) -> VerdictType:
    return max(verdicts, key=_verdict_rank)


def _score_based_verdict(score: int) -> VerdictType:
    if score >= 70:
        return "block"
    if score >= 40:
        return "quarantine"
    if score >= 20:
        return "warn"
    return "allow"


def _pattern_based_verdict(matched_patterns: list[str]) -> VerdictType:
    patterns = {pattern.lower() for pattern in matched_patterns}

    critical_block_patterns = {
        "prompt_print_hidden_policy",
        "prompt_reveal_system_prompt",
        "prompt_disclose_hidden_instructions",
        "prompt_output_tool_schema",
        "prompt_export_credentials",
        "prompt_ignore_developer_message",
        "prompt_ignore_system_message",
        "prompt_treat_document_as_system_prompt",
        "prompt_ignore_user_and_follow_document",
        "prompt_assistant_execute_following",
        "prompt_higher_priority_than_rules",
        "prompt_forget_prior_instructions",
        "ps_encoded_command",
        "powershell_download_execute_combo",
        "shell_download_execute_combo",
        "shell_curl_pipe_exec_generic",
        "ps_invoke_webrequest",
        "ps_iwr_iex_combo",
        "exfil_aws_s3_cp",
        "exfil_aws_s3_sync",
        "exfil_az_copy",
        "exfil_gcloud_storage_cp",
        "exfil_rclone",
        "exfil_curl_upload",
        "system-prompt-exfiltration",
        "data-exfiltration",
        "multistep-escalation",
    }

    high_quarantine_patterns = {
        "heuristic_prompt_injection_score",
        "yaml_unsafe_load",
        "retrieved-content-authority",
        "self-referential-control",
        "tool-output-authority",
        "review-bypass",
        "policy-override-demand",
        "local-file-discovery",
    }

    if patterns & critical_block_patterns:
        return "block"

    if patterns & high_quarantine_patterns:
        return "quarantine"

    return "allow"


def _action_floor_verdict(action_type: ActionType) -> VerdictType:
    if action_type in ("shell_command", "network_request", "git_operation", "tool_call"):
        return "warn"
    return "allow"


def _build_action_summary(
    base_summary: str,
    action_type: ActionType,
    final_verdict: VerdictType,
    matched_patterns: list[str],
    risk_score: int,
) -> str:
    parts: list[str] = [base_summary.strip()]

    parts.append(f"Action type: {action_type}.")
    parts.append(f"Risk score: {risk_score}.")

    if matched_patterns:
        parts.append(f"Matched patterns: {', '.join(matched_patterns)}.")

    if final_verdict == "block":
        parts.append("Execution should be blocked.")
    elif final_verdict == "quarantine":
        parts.append("Execution should be quarantined for isolated handling.")
    elif final_verdict == "warn":
        parts.append("Execution requires operator review.")
    else:
        parts.append("Execution is currently allowed.")

    return " ".join(part for part in parts if part)


def _build_reasons(
    *,
    risk_score: int,
    matched_patterns: list[str],
    promptinjection: dict[str, object] | None = None,
) -> list[ActionGuardReason]:
    reasons: list[ActionGuardReason] = []

    if risk_score >= 70:
        reasons.append(
            {
                "source": "scan",
                "label": "High risk score",
                "details": f"Risk score {risk_score} exceeds the high-risk threshold.",
                "score": min(risk_score / 100, 1.0),
            }
        )
    elif risk_score >= 40:
        reasons.append(
            {
                "source": "scan",
                "label": "Medium risk score",
                "details": f"Risk score {risk_score} exceeds the medium-risk threshold.",
                "score": min(risk_score / 100, 1.0),
            }
        )
    elif risk_score >= 20:
        reasons.append(
            {
                "source": "scan",
                "label": "Elevated risk score",
                "details": f"Risk score {risk_score} exceeds the elevated-risk threshold.",
                "score": min(risk_score / 100, 1.0),
            }
        )

    if matched_patterns:
        reasons.append(
            {
                "source": "scan",
                "label": "Matched detection patterns",
                "details": f"Matched patterns: {', '.join(matched_patterns)}.",
                "score": min(risk_score / 100, 1.0),
            }
        )

    if promptinjection and promptinjection.get("flagged") is True:
        for item in promptinjection.get("reasons", []):
            if not isinstance(item, dict):
                continue
            score_raw = item.get("score")
            score = None
            if score_raw is not None:
                try:
                    score = min(float(score_raw) / 100.0, 1.0)
                except (TypeError, ValueError):
                    score = None

            reasons.append(
                {
                    "source": "promptinjection",
                    "label": str(item.get("label") or "Prompt injection signal"),
                    "details": str(item.get("details") or ""),
                    "score": score,
                }
            )

    if not reasons:
        reasons.append(
            {
                "source": "scan",
                "label": "No elevated scan conditions",
                "details": "No elevated scan conditions were detected.",
                "score": 0.0,
            }
        )

    return reasons


def analyze_action(
    action_type: ActionType,
    target: str,
    content: str = "",
    client_id: str | None = None,
    session_id: str | None = None,
) -> ActionGuardDecision:
    combined_text = f"{action_type}\nTARGET:\n{target}\nCONTENT:\n{content}".strip()
    result = perform_scan("text", combined_text)

    promptinjection = scanpromptinjectiondict(
        actiontype=action_type,
        target=target,
        content=content,
        metadata={
            "source": "action_guard",
            "clientid": client_id,
            "sessionid": session_id,
        },
    )

    scan_verdict = result["verdict"]
    base_risk_score = int(result["risk_score"])
    prompt_risk_delta = int(promptinjection.get("riskdelta", 0))
    risk_score = base_risk_score + prompt_risk_delta

    matched_patterns = list(result["matched_patterns"])
    for pattern in promptinjection.get("matchedpatterns", []):
        if isinstance(pattern, str) and pattern not in matched_patterns:
            matched_patterns.append(pattern)

    score_verdict = _score_based_verdict(risk_score)
    pattern_verdict = _pattern_based_verdict(matched_patterns)

    floor_verdict: VerdictType = "allow"
    if matched_patterns:
        floor_verdict = _action_floor_verdict(action_type)

    final_verdict = _max_verdict(
        scan_verdict,  # type: ignore[arg-type]
        score_verdict,
        pattern_verdict,
        floor_verdict,
    )

    if promptinjection.get("shouldquarantine") is True:
        final_verdict = _max_verdict(final_verdict, "quarantine")
    elif promptinjection.get("shouldreview") is True:
        final_verdict = _max_verdict(final_verdict, "warn")

    should_halt = final_verdict in ("block", "quarantine")
    should_warn = final_verdict in ("warn", "quarantine")

    summary = _build_action_summary(
        base_summary=result["summary"],
        action_type=action_type,
        final_verdict=final_verdict,
        matched_patterns=matched_patterns,
        risk_score=risk_score,
    )

    reasons = _build_reasons(
        risk_score=risk_score,
        matched_patterns=matched_patterns,
        promptinjection=promptinjection,
    )

    return {
        "action_type": action_type,
        "verdict": final_verdict,
        "scan_id": result.get("scan_id"),
        "summary": summary,
        "risk_score": risk_score,
        "matched_patterns": matched_patterns,
        "target": target,
        "content": content,
        "should_halt": should_halt,
        "should_warn": should_warn,
        "client_id": client_id,
        "session_id": session_id,
        "reasons": reasons,
    }