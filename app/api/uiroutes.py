from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from app.core.auth import require_api_key

router = APIRouter(tags=["ui-admin"])


@router.get("/admin/routes")
def get_ui_routes(
    request: Request,
    _: str | None = Depends(require_api_key),
) -> dict[str, object]:
    request_id = getattr(request.state, "request_id", None)

    routes = [
        {
            "path": "/admin/operators",
            "method": "GET",
            "name": "get_admin_operators",
            "category": "admin",
            "status": "active",
        },
        {
            "path": "/admin/roles",
            "method": "GET",
            "name": "get_admin_roles",
            "category": "admin",
            "status": "active",
        },
        {
            "path": "/admin/data-retention",
            "method": "GET",
            "name": "get_data_retention_settings",
            "category": "admin",
            "status": "active",
        },
        {
            "path": "/admin/request-stream",
            "method": "GET",
            "name": "get_admin_request_stream",
            "category": "operations",
            "status": "active",
        },
        {
            "path": "/admin/system-diagnostics",
            "method": "GET",
            "name": "get_system_diagnostics",
            "category": "diagnostics",
            "status": "active",
        },
        {
            "path": "/admin/execution-test-console",
            "method": "GET",
            "name": "get_admin_execution_test_console",
            "category": "diagnostics",
            "status": "active",
        },
    ]

    summary = {
        "total": len(routes),
        "active": sum(1 for route in routes if route["status"] == "active"),
        "inactive": sum(1 for route in routes if route["status"] == "inactive"),
    }

    return {
        "title": "UI Routes",
        "status": "ok",
        "summary": summary,
        "routes": routes,
        "request_id": request_id,
    }
