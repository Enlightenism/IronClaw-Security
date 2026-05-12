from __future__ import annotations

from typing import Any

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
) -> dict[str, Any]:
    scan_result = perform_scan(target_type=target_type, target_value=target_value)

    if scan_result["verdict"] == "block":
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

    final_verdict = guard_response.verdict
    if scan_result["verdict"] == "quarantine" and guard_response.verdict == "allow":
        final_verdict = "quarantine"

    return {
        "scan": scan_result,
        "guard_request": guard_request.model_dump(),
        "guard_response": guard_response.model_dump(),
        "final_verdict": final_verdict,
        "blocked_by": "guard" if final_verdict == "block" else None,
        "sandbox_lane": scan_result.get("sandbox_lane", "none"),
        "review_status": scan_result.get("review_status", "none"),
        "quarantine_reason": scan_result.get("quarantine_reason"),
        "untrusted": scan_result.get("untrusted", False),
    }