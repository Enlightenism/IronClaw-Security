from __future__ import annotations


from fastapi import APIRouter, Depends, Request

from app.core.auth import require_api_key


router = APIRouter(tags=["ui-admin"])


@router.get("/admin/operators")
def get_admin_operators(
    request: Request,
    _: str | None = Depends(require_api_key),
) -> dict[str, object]:
    request_id = getattr(request.state, "request_id", None)

    operators = [
        {
            "operator_id": "ops-primary",
            "display_name": "Primary Security Operator",
            "role": "admin_operator",
            "status": "ready",
            "capabilities": [
                "review_queue",
                "incident_triage",
                "detonation_release",
                "system_diagnostics",
            ],
            "current_assignment": "global",
        },
        {
            "operator_id": "ops-response",
            "display_name": "Response Coordinator",
            "role": "incident_operator",
            "status": "ready",
            "capabilities": [
                "incident_response",
                "containment_actions",
                "evidence_tracking",
            ],
            "current_assignment": "incident-response",
        },
    ]

    summary = {
        "total": len(operators),
        "ready": sum(1 for operator in operators if operator["status"] == "ready"),
        "degraded": sum(1 for operator in operators if operator["status"] == "degraded"),
        "offline": sum(1 for operator in operators if operator["status"] == "offline"),
    }

    return {
        "title": "Admin Operators",
        "status": "ok",
        "summary": summary,
        "operators": operators,
        "request_id": request_id,
    }