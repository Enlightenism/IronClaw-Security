from __future__ import annotations

from typing import Any

from app.config import RISK_THRESHOLD_BLOCK_MIN
from app.models.guard_facade import GuardActionResponse
from app.services.guard_facade import execute_guard_action
from app.services.scan_to_guard_adapter import build_guard_request_from_scan
from app.services.scanner import perform_scan


def orchestrate_security_action(
    *,
    target_type: str,
    target_value: str,
    action_type: str,
    target: str,
    content: str,
    client_id: str | None = None,
    session_id: str | None = None,
    file_path: str | None = None,
    agent_id: str | None = None,
) -> dict[str, Any]:
    scan_result = perform_scan(target_type=target_type, target_value=target_value)
    if scan_result.get("verdict") != "allow" or scan_result.get("matched_patterns") or scan_result.get("failed_checks") or scan_result.get("errors") or scan_result.get("error"):
        scan_result["verdict"] = "block"
        scan_result["risk_score"] = max(
            int(scan_result.get("risk_score") or 0),
            RISK_THRESHOLD_BLOCK_MIN,
        )
        scan_result["untrusted"] = True

    if scan_result["verdict"] == "block":
        # Record observation before returning so the baseline captures blocked actions
        if agent_id:
            _record_baseline_observation(
                agent_id=agent_id,
                action_type=action_type,
                target=target,
                risk_score=int(scan_result.get("risk_score", 100)),
                session_id=session_id,
                client_id=client_id,
                matched_patterns=list(scan_result.get("matched_patterns", [])),
            )

        return {
            "scan": scan_result,
            "guard_request": None,
            "guard_response": None,
            "final_verdict": "block",
            "blocked_by": "scan",
            "sandbox_lane": scan_result.get("sandbox_lane", "none"),
            "review_status": scan_result.get("review_status", "none"),
            "quarantine_reason": scan_result.get("quarantine_reason"),
            "untrusted": scan_result.get("untrusted", False),
            "drift_report": None,
        }

    guard_request = build_guard_request_from_scan(
        scan_result=scan_result,
        action_type=action_type,
        target=target,
        content=content,
        client_id=client_id,
        session_id=session_id,
        file_path=file_path,
    )

    guard_response: GuardActionResponse = execute_guard_action(guard_request)

    final_verdict = "allow" if guard_response.verdict == "allow" else "block"

    # Record behavioral observation for baseline learning
    risk_score = int(scan_result.get("risk_score", 0))
    matched_patterns = list(scan_result.get("matched_patterns", []))

    if agent_id:
        _record_baseline_observation(
            agent_id=agent_id,
            action_type=action_type,
            target=target,
            risk_score=risk_score,
            session_id=session_id,
            client_id=client_id,
            matched_patterns=matched_patterns,
        )

    # Behavioral drift check — runs after observation is recorded
    drift_report: dict[str, Any] | None = None
    if agent_id:
        drift_report = _compute_drift_and_apply(
            agent_id=agent_id,
            session_id=session_id,
            client_id=client_id,
        )
        if drift_report and drift_report.get("should_suspend"):
            final_verdict = "block"

    blocked_by: str | None = None
    if final_verdict == "block":
        if drift_report and drift_report.get("should_suspend"):
            blocked_by = "behavioral_drift"
        else:
            blocked_by = "guard"

    return {
        "scan": scan_result,
        "guard_request": guard_request.model_dump(),
        "guard_response": guard_response.model_dump(),
        "final_verdict": final_verdict,
        "blocked_by": blocked_by,
        "sandbox_lane": scan_result.get("sandbox_lane", "none"),
        "review_status": scan_result.get("review_status", "none"),
        "quarantine_reason": scan_result.get("quarantine_reason"),
        "untrusted": bool(scan_result.get("untrusted", False)) or final_verdict == "block",
        "drift_report": drift_report,
    }


# ---------------------------------------------------------------------------
# Internal helpers — deferred imports to avoid circular dependencies
# ---------------------------------------------------------------------------


def _record_baseline_observation(
    *,
    agent_id: str,
    action_type: str,
    target: str,
    risk_score: int,
    session_id: str | None,
    client_id: str | None,
    matched_patterns: list[str],
) -> None:
    try:
        from app.services.behavioral_baseline import get_behavioral_baseline_store

        get_behavioral_baseline_store().record_observation(
            agent_id=agent_id,
            action_type=action_type,
            target=target,
            risk_score=risk_score,
            session_id=session_id,
            client_id=client_id,
            matched_patterns=matched_patterns,
        )
    except Exception:  # noqa: BLE001
        pass


def _compute_drift_and_apply(
    *,
    agent_id: str,
    session_id: str | None,
    client_id: str | None,
) -> dict[str, Any] | None:
    try:
        from app.services.behavioral_baseline import get_behavioral_baseline_store

        report = get_behavioral_baseline_store().compute_drift(
            agent_id,
            session_id=session_id,
            client_id=client_id,
        )
        return report.to_dict()
    except Exception:  # noqa: BLE001
        return None
