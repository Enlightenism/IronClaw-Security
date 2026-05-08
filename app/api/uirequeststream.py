from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from app.core.auth import require_api_key

router = APIRouter(tags=["ui-admin"])


@router.get("/admin/request-stream")
def get_admin_request_stream(
    request: Request,
    _: str | None = Depends(require_api_key),
) -> dict[str, object]:
    request_id = getattr(request.state, "request_id", None)

    items = [
        {
            "request_id": "req-001",
            "path": "/scan",
            "method": "POST",
            "decision": "allow",
            "severity": "low",
            "status_code": 200,
            "organization_id": "org-default",
        },
        {
            "request_id": "req-002",
            "path": "/guard/execute",
            "method": "POST",
            "decision": "quarantine",
            "severity": "high",
            "status_code": 403,
            "organization_id": "org-default",
        },
        {
            "request_id": "req-003",
            "path": "/review/queue",
            "method": "GET",
            "decision": "review",
            "severity": "medium",
            "status_code": 200,
            "organization_id": "org-internal",
        },
    ]

    summary = {
        "total": len(items),
        "allow": sum(1 for item in items if item["decision"] == "allow"),
        "review": sum(1 for item in items if item["decision"] == "review"),
        "quarantine": sum(1 for item in items if item["decision"] == "quarantine"),
        "block": sum(1 for item in items if item["decision"] == "block"),
    }

    return {
        "title": "Request Stream",
        "status": "ok",
        "summary": summary,
        "items": items,
        "request_id": request_id,
    }