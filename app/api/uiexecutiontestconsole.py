from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from app.core.auth import require_api_key

router = APIRouter(tags=["ui-admin"])


@router.get("/admin/execution-test-console")
def get_admin_execution_test_console(
    request: Request,
    _: str | None = Depends(require_api_key),
) -> dict[str, object]:
    request_id = getattr(request.state, "request_id", None)

    supported_tests = [
        {
            "test_id": "guard-allow-smoke",
            "label": "Guard Allow Smoke",
            "method": "POST",
            "path": "/guard",
            "expected_outcome": "allow",
            "status": "ready",
        },
        {
            "test_id": "guard-quarantine-smoke",
            "label": "Guard Quarantine Smoke",
            "method": "POST",
            "path": "/guard",
            "expected_outcome": "quarantine",
            "status": "ready",
        },
        {
            "test_id": "scan-malicious-sample",
            "label": "Scan Malicious Sample",
            "method": "POST",
            "path": "/scan",
            "expected_outcome": "block",
            "status": "ready",
        },
    ]

    summary = {
        "total": len(supported_tests),
        "ready": sum(1 for item in supported_tests if item["status"] == "ready"),
        "disabled": sum(1 for item in supported_tests if item["status"] == "disabled"),
    }

    return {
        "title": "Execution Test Console",
        "status": "ok",
        "summary": summary,
        "tests": supported_tests,
        "request_id": request_id,
    }
