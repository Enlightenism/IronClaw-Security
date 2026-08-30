from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.routes.auditlog import router as auditlog_router


def test_auditlog_route_serves_ui_page_payload() -> None:
    app = FastAPI()
    app.include_router(auditlog_router)

    client = TestClient(app)
    response = client.get(
        "/ui/audit-log",
        params={
            "selected_event_id": "audit_001",
            "actor_id": "operator_123",
            "request_id": "req_900",
            "limit": 25,
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["page"] == "ui-audit-log"
    assert body["title"] == "Audit Log"
    assert body["table"]["rows"]
