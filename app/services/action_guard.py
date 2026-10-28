from __future__ import annotations

import logging
from typing import Any, Literal, TypedDict

from app.config import RISK_THRESHOLD_ALLOW_MAX, RISK_THRESHOLD_BLOCK_MIN
from app.security.promptinjection import scanpromptinjectiondict
from app.services.scanner import perform_scan

logger = logging.getLogger(__name__)

ActionType = Literal[
    "file_write",
    "file_edit",
    "shell_command",
    "network_request",
    "git_operation",
    "tool_call",
]
VerdictType = Literal["allow", "block"]


def normalize_action_type(action_type: str) -> str:
    normalized = action_type.strip().lower().replace("-", "_")
    compact = normalized.replace("_", "")
    if compact in {"httpfetch", "browseropen", "networkrequest"}:
        return "network_request"
    return normalized


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
    categories: list[str]
    target: str
    content: str
    should_halt: bool
    should_warn: bool
    client_id: str | None
    session_id: str | None
    agent_id: str | None
    reasons: list[ActionGuardReason]
    drift_report: dict[str, Any] | None


def _score_based_verdict(score: int) -> VerdictType:
    return "block" if score > RISK_THRESHOLD_ALLOW_MAX else "allow"


def _pattern_based_verdict(matched_patterns: list[str]) -> VerdictType:
    return "block" if matched_patterns else "allow"


def _action_floor_verdict(action_type: ActionType) -> VerdictType:
    if action_type in (
        "shell_command",
        "network_request",
        "git_operation",
        "tool_call",
    ):
        return "block"
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
    else:
        parts.append("Execution is currently allowed.")
    return " ".join(part for part in parts if part)


def _build_reasons(
    *,
    risk_score: int,
    matched_patterns: list[str],
    action_type: ActionType,
    failed_checks: list[str],
    promptinjection_error: bool,
    promptinjection: dict[str, object] | None = None,
) -> list[ActionGuardReason]:
    reasons: list[ActionGuardReason] = []

    if risk_score >= RISK_THRESHOLD_BLOCK_MIN:
        reasons.append(
            {
                "source": "scan",
                "label": "Block-level risk score",
                "details": (f"Risk score {risk_score} meets the configured block threshold of {RISK_THRESHOLD_BLOCK_MIN}."),
                "score": min(risk_score / 100, 1.0),
            },
        )
    elif risk_score > RISK_THRESHOLD_ALLOW_MAX:
        reasons.append(
            {
                "source": "scan",
                "label": "Risk score exceeds allow threshold",
                "details": (f"Risk score {risk_score} exceeds the configured allow maximum of {RISK_THRESHOLD_ALLOW_MAX}."),
                "score": min(risk_score / 100, 1.0),
            },
        )

    if _action_floor_verdict(action_type) == "block":
        reasons.append(
            {
                "source": "scan",
                "label": "Sensitive action type",
                "details": (f"Action type {action_type} is blocked by the action security policy."),
                "score": min(risk_score / 100, 1.0),
            },
        )

    if failed_checks:
        reasons.append(
            {
                "source": "scan",
                "label": "Scan failed",
                "details": (f"Scan checks failed: {', '.join(failed_checks)}. The action was blocked."),
                "score": None,
            },
        )

    if promptinjection_error:
        reasons.append(
            {
                "source": "promptinjection",
                "label": "Prompt injection scan unavailable",
                "details": "Prompt injection scanning failed; the action was blocked.",
                "score": None,
            },
        )

    if matched_patterns:
        reasons.append(
            {
                "source": "scan",
                "label": "Matched detection patterns",
                "details": f"Matched patterns: {', '.join(matched_patterns)}.",
                "score": min(risk_score / 100, 1.0),
            },
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
                },
            )

    if not reasons:
        reasons.append(
            {
                "source": "scan",
                "label": "No elevated scan conditions",
                "details": "No elevated scan conditions were detected.",
                "score": 0.0,
            },
        )

    return reasons


def _record_and_drift(
    *,
    agent_id: str,
    action_type: str,
    target: str,
    risk_score: int,
    session_id: str | None,
    client_id: str | None,
    matched_patterns: list[str],
) -> dict[str, Any] | None:
    try:
        from app.services.behavioral_baseline import get_behavioral_baseline_store

        store = get_behavioral_baseline_store()
        store.record_observation(
            agent_id=agent_id,
            action_type=action_type,
            target=target,
            risk_score=risk_score,
            session_id=session_id,
            client_id=client_id,
            matched_patterns=matched_patterns,
        )
        report = store.compute_drift(
            agent_id,
            session_id=session_id,
            client_id=client_id,
        )
        return report.to_dict()
    except Exception:  # noqa: BLE001
        return None


def _fire_verdict_event(
    *,
    tenant_id: str | None,
    verdict: VerdictType,
    action_type: ActionType,
    target: str,
    risk_score: int,
    scan_id: str | None,
    client_id: str | None,
    session_id: str | None,
    agent_id: str | None,
    matched_patterns: list[str],
) -> None:
    if not tenant_id:
        return
    try:
        from app.services.webhook_service import dispatch_event  # noqa: PLC0415

        event_type = f"guard.{verdict}"
        payload: dict[str, Any] = {
            "verdict": verdict,
            "action_type": action_type,
            "target": target,
            "risk_score": risk_score,
            "scan_id": scan_id,
            "client_id": client_id,
            "session_id": session_id,
            "agent_id": agent_id,
            "matched_patterns": matched_patterns,
        }
        dispatch_event(tenant_id, event_type, payload)
    except Exception:  # noqa: BLE001
        pass


def analyze_action(
    action_type: ActionType,
    target: str,
    content: str = "",
    client_id: str | None = None,
    session_id: str | None = None,
    agent_id: str | None = None,
    tenant_id: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> ActionGuardDecision:
    combined_text = f"{action_type}\nTARGET:\n{target}\nCONTENT:\n{content}".strip()
    scan_error = False
    try:
        result = perform_scan("text", combined_text)
        if not isinstance(result, dict):
            raise TypeError("Scanner returned an invalid result.")
    except Exception:  # noqa: BLE001
        logger.exception("action_guard: scan unavailable; blocking action")
        result = {
            "verdict": "block",
            "risk_score": 0,
            "matched_patterns": [],
            "failed_checks": ["scan_unavailable"],
            "summary": "Scan failed; request blocked.",
            "scan_id": None,
        }
        scan_error = True

    merged_metadata: dict[str, Any] = {
        "source": "action_guard",
        "clientid": client_id,
        "sessionid": session_id,
    }
    if metadata:
        merged_metadata.update(metadata)

    promptinjection_error = False
    try:
        promptinjection = scanpromptinjectiondict(
            actiontype=action_type,
            target=target,
            content=content,
            metadata=merged_metadata,
        )
        if not isinstance(promptinjection, dict):
            raise TypeError("Prompt injection scanner returned an invalid result.")
        prompt_risk_delta = int(promptinjection.get("riskdelta", 0))
        prompt_patterns = promptinjection.get("matchedpatterns", [])
        if not isinstance(prompt_patterns, list) or any(not isinstance(pattern, str) for pattern in prompt_patterns):
            raise TypeError("Prompt injection scanner returned invalid patterns.")
        prompt_categories = promptinjection.get("categories", [])
        if not isinstance(prompt_categories, list) or any(not isinstance(category, str) for category in prompt_categories):
            raise TypeError("Prompt injection scanner returned invalid categories.")
        if not isinstance(promptinjection.get("reasons", []), list):
            raise TypeError("Prompt injection scanner returned invalid reasons.")
    except Exception:  # noqa: BLE001
        logger.exception("action_guard: prompt injection scan failed; blocking action")
        promptinjection = {}
        prompt_risk_delta = 0
        prompt_patterns = []
        prompt_categories = []
        promptinjection_error = True

    raw_verdict = result.get("verdict")
    invalid_scan_verdict = raw_verdict not in ("allow", "block")
    if invalid_scan_verdict:
        logger.error("action_guard: invalid scan verdict; blocking action")
        scan_verdict = "block"
        scan_error = True
    else:
        scan_verdict = raw_verdict

    raw_failed_checks = result.get("failed_checks", [])
    if not isinstance(raw_failed_checks, list) or any(not isinstance(check, str) for check in raw_failed_checks):
        logger.error("action_guard: invalid scan failure details; blocking action")
        failed_checks = ["invalid_failed_checks"]
        scan_error = True
    else:
        failed_checks = list(raw_failed_checks)
        scan_error = scan_error or bool(failed_checks)
    if invalid_scan_verdict and "invalid_scan_verdict" not in failed_checks:
        failed_checks.append("invalid_scan_verdict")

    raw_risk_score = result.get("risk_score")
    try:
        if isinstance(raw_risk_score, bool):
            raise TypeError("Scanner returned a boolean risk score.")
        base_risk_score = int(raw_risk_score)
    except (TypeError, ValueError, OverflowError):
        logger.exception("action_guard: invalid scan risk score; blocking action")
        base_risk_score = 0
        failed_checks.append("invalid_risk_score")
        scan_error = True

    raw_matched_patterns = result.get("matched_patterns", [])
    if not isinstance(raw_matched_patterns, list) or any(not isinstance(pattern, str) for pattern in raw_matched_patterns):
        logger.error("action_guard: invalid scan patterns; blocking action")
        matched_patterns = []
        failed_checks.append("invalid_matched_patterns")
        scan_error = True
    else:
        matched_patterns = list(raw_matched_patterns)

    for pattern in prompt_patterns:
        if pattern not in matched_patterns:
            matched_patterns.append(pattern)

    categories = list(prompt_categories)
    risk_score = min(max(base_risk_score + prompt_risk_delta, 0), 100)

    score_verdict = _score_based_verdict(risk_score)
    pattern_verdict = _pattern_based_verdict(matched_patterns)
    action_floor_verdict = _action_floor_verdict(action_type)
    final_verdict: VerdictType = (
        "block"
        if (
            scan_error
            or scan_verdict != "allow"
            or bool(matched_patterns)
            or bool(categories)
            or prompt_risk_delta > 0
            or bool(promptinjection.get("flagged"))
            or bool(promptinjection.get("shouldreview"))
            or bool(promptinjection.get("shouldquarantine"))
            or bool(promptinjection.get("reasons"))
            or promptinjection_error
            or score_verdict == "block"
            or pattern_verdict == "block"
            or action_floor_verdict == "block"
        )
        else "allow"
    )
    if final_verdict == "block":
        risk_score = max(risk_score, RISK_THRESHOLD_BLOCK_MIN)

    drift_report: dict[str, Any] | None = None
    if agent_id:
        drift_report = _record_and_drift(
            agent_id=agent_id,
            action_type=action_type,
            target=target,
            risk_score=risk_score,
            session_id=session_id,
            client_id=client_id,
            matched_patterns=matched_patterns,
        )
        if drift_report and drift_report.get("should_suspend"):
            final_verdict = "block"
            risk_score = max(risk_score, RISK_THRESHOLD_BLOCK_MIN)

    should_halt = final_verdict == "block"
    should_warn = False

    summary = _build_action_summary(
        base_summary=("Scan failed; request blocked." if failed_checks or scan_error else str(result.get("summary") or "Scan complete.")),
        action_type=action_type,
        final_verdict=final_verdict,
        matched_patterns=matched_patterns,
        risk_score=risk_score,
    )

    reasons = _build_reasons(
        risk_score=risk_score,
        matched_patterns=matched_patterns,
        action_type=action_type,
        failed_checks=failed_checks,
        promptinjection_error=promptinjection_error,
        promptinjection=promptinjection,
    )

    raw_scan_id = result.get("scan_id")
    scan_id = raw_scan_id if isinstance(raw_scan_id, str) else None

    _fire_verdict_event(
        tenant_id=tenant_id,
        verdict=final_verdict,
        action_type=action_type,
        target=target,
        risk_score=risk_score,
        scan_id=scan_id,
        client_id=client_id,
        session_id=session_id,
        agent_id=agent_id,
        matched_patterns=matched_patterns,
    )

    return {
        "action_type": action_type,
        "verdict": final_verdict,
        "scan_id": scan_id,
        "summary": summary,
        "risk_score": risk_score,
        "matched_patterns": matched_patterns,
        "categories": categories,
        "target": target,
        "content": content,
        "should_halt": should_halt,
        "should_warn": should_warn,
        "client_id": client_id,
        "session_id": session_id,
        "agent_id": agent_id,
        "reasons": reasons,
        "drift_report": drift_report,
    }
