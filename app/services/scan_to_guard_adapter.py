from __future__ import annotations

from typing import Any, Dict

from app.models.guard_facade import GuardActionRequest


def build_guard_request_from_scan(
    *,
    scan_result: Dict[str, Any],
    action_type: str,
    target: str,
    content: str,
    client_id: str | None = None,
    session_id: str | None = None,
    file_path: str | None = None,
) -> GuardActionRequest:
    """
    Translate a scan result + proposed action into a GuardActionRequest.

    This keeps scanner-side verdicts and the execution guard loosely coupled:
    the scanner decides risk and sandbox_lane, the orchestrator decides whether
    to call the guard, and this adapter just maps fields between them.
    """
    risk_score = int(scan_result.get("risk_score", 0))
    extra_metadata: dict[str, Any] = {
        "scan_verdict": scan_result.get("verdict"),
        "scan_summary": scan_result.get("summary"),
        "scan_matched_patterns": scan_result.get("matched_patterns", []),
        "scan_sandbox_lane": scan_result.get("sandbox_lane"),
        "scan_untrusted": scan_result.get("untrusted"),
        "scan_quarantine_reason": scan_result.get("quarantine_reason"),
        "scan_review_status": scan_result.get("review_status"),
        "scan_target_type": scan_result.get("target_type"),
        "scan_target_value": scan_result.get("target_value"),
    }

    return GuardActionRequest(
        action_type=action_type,
        target=target,
        content=content,
        risk_score=risk_score,
        client_id=client_id,
        session_id=session_id,
        file_path=file_path,
        extra_metadata=extra_metadata,
    )