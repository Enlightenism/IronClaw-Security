from __future__ import annotations


from fastapi import APIRouter, Depends, Request

from app.core.auth import require_api_key


router = APIRouter(tags=["ui-admin"])


@router.get("/admin/roles")
def get_admin_roles(
    request: Request,
    _: str | None = Depends(require_api_key),
) -> dict[str, object]:
    request_id = getattr(request.state, "request_id", None)

    roles = [
        {
            "role_id": "platform_admin",
            "display_name": "Platform Admin",
            "scope": "platform",
            "permissions": [
                "operators:read",
                "operators:write",
                "roles:read",
                "roles:write",
                "organizations:read",
                "organizations:write",
                "diagnostics:read",
                "execution_test:run",
            ],
        },
        {
            "role_id": "security_analyst",
            "display_name": "Security Analyst",
            "scope": "operations",
            "permissions": [
                "review_queue:read",
                "incidents:read",
                "incidents:write",
                "detonation:read",
                "request_stream:read",
            ],
        },
        {
            "role_id": "org_admin",
            "display_name": "Organization Admin",
            "scope": "tenant",
            "permissions": [
                "organization:read",
                "organization:write",
                "api_keys:read",
                "telemetry:read",
            ],
        },
    ]

    summary = {
        "total": len(roles),
        "platform_roles": sum(1 for role in roles if role["scope"] == "platform"),
        "operations_roles": sum(1 for role in roles if role["scope"] == "operations"),
        "tenant_roles": sum(1 for role in roles if role["scope"] == "tenant"),
    }

    return {
        "title": "Admin Roles",
        "status": "ok",
        "summary": summary,
        "roles": roles,
        "request_id": request_id,
    }