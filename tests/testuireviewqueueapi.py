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


def _seed_review_queue() -> None:
    service = get_review_queue_service()
    service.escalate_incident(
        incident_id="inc_101",
        priority="high",
        title="Prompt injection escalation",
        summary="High-confidence hostile prompt pattern detected.",
        reasons=["policy escalation", "hostile pattern"],
        evidence=[{"type": "signal", "name": "prompt_injection", "score": 0.99}],
    )
    service.escalate_session(
        session_id="sess_202",
        priority="medium",
        title="Suspicious session review",
        summary="Analyst session requires manual review.",
        reasons=["session anomaly"],
        evidence=[{"type": "session", "session_id": "sess_202"}],
    )


def test_ui_review_queue_route_is_registered() -> None:
    response = client.get("/api/ui/review-queue")
    assert response.status_code == 200


def test_ui_review_queue_returns_json_object() -> None:
    response = client.get("/api/ui/review-queue")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")

    data = response.json()
    assert isinstance(data, dict)


def test_ui_review_queue_contains_core_fields() -> None:
    _seed_review_queue()

    response = client.get("/api/ui/review-queue")
    assert response.status_code == 200

    data = response.json()
    assert data["title"] == "Review Queue"
    assert "description" in data
    assert "summary_cards" in data
    assert "filters" in data
    assert "items" in data
    assert "total_items" in data


def test_ui_review_queue_returns_seeded_items() -> None:
    _seed_review_queue()

    response = client.get("/api/ui/review-queue")
    assert response.status_code == 200

    data = response.json()
    assert data["total_items"] == 2
    assert len(data["items"]) == 2

    first = data["items"][0]
    assert "review_id" in first
    assert "title" in first
    assert "summary" in first
    assert "source" in first
    assert "source_id" in first
    assert "priority" in first
    assert "status" in first
    assert "detail_href" in first
    assert "actions" in first


def test_ui_review_queue_supports_status_filter() -> None:
    _seed_review_queue()
    service = get_review_queue_service()
    claimed = service.claim_next("analyst-1")
    assert claimed is not None

    response = client.get("/api/ui/review-queue?status=in_progress")
    assert response.status_code == 200

    data = response.json()
    assert data["total_items"] == 1
    assert len(data["items"]) == 1
    assert data["items"][0]["status"] == "in_progress"
    assert data["items"][0]["assigned_to"] == "analyst-1"
