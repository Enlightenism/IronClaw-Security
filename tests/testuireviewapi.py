from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app
from app.routes.reviewqueue import get_review_queue_service

client = TestClient(app)


def setup_function() -> None:
    service = get_review_queue_service()
    service._items.clear()
    service._index_by_source.clear()
    service._pending_order.clear()
    service._counter = 1


def _seed_review_item() -> str:
    service = get_review_queue_service()
    item = service.escalate_incident(
        incident_id="inc_301",
        priority="critical",
        title="Critical prompt injection review",
        summary="Escalated session requires human decision.",
        reasons=["critical severity", "hostile pattern"],
        evidence=[
            {"type": "signal", "name": "prompt_injection", "score": 0.995},
            {"type": "session", "session_id": "sess_301"},
        ],
    )
    return item.review_id


def test_ui_review_route_is_registered() -> None:
    review_id = _seed_review_item()
    response = client.get(f"/api/ui/reviews/{review_id}")
    assert response.status_code == 200


def test_ui_review_returns_json_object() -> None:
    review_id = _seed_review_item()
    response = client.get(f"/api/ui/reviews/{review_id}")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")

    payload = response.json()
    assert isinstance(payload, dict)


def test_ui_review_contains_review_contract_fields() -> None:
    review_id = _seed_review_item()
    response = client.get(f"/api/ui/reviews/{review_id}")
    assert response.status_code == 200

    payload = response.json()
    assert payload["review_id"] == review_id
    assert payload["title"] == "Critical prompt injection review"
    assert payload["summary"] == "Escalated session requires human decision."
    assert payload["status"] == "pending"
    assert payload["priority"] == "critical"
    assert payload["source"] == "incident"
    assert payload["source_id"] == "inc_301"
    assert "fields" in payload
    assert "reasons" in payload
    assert "evidence" in payload
    assert "actions" in payload


def test_ui_review_returns_evidence_and_actions() -> None:
    review_id = _seed_review_item()
    response = client.get(f"/api/ui/reviews/{review_id}")
    assert response.status_code == 200

    payload = response.json()
    assert len(payload["evidence"]) == 2
    assert any(item["data"].get("name") == "prompt_injection" for item in payload["evidence"])
    assert any(action["key"] == "assign" for action in payload["actions"])


def test_ui_review_returns_404_for_unknown_review() -> None:
    response = client.get("/api/ui/reviews/rev_missing")
    assert response.status_code == 404
    assert response.json()["detail"] == "review item not found: rev_missing"