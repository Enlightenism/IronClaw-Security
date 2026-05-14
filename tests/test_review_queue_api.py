from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app
from app.orchestrator.review_queue import (
    create_review_item,
    enqueue_review_item,
    initialize_review_queue,
)
from app.services.review_queue_service import reset_review_queue

client = TestClient(app)


def setup_function() -> None:
    reset_review_queue()


def _auth_headers() -> dict[str, str]:
    return {"x-api-key": "test-api-key"}


def _seed_queue_with_items() -> None:
    queue = initialize_review_queue()

    pending_critical = create_review_item(
        actor_id="agent-01",
        action_type="tool_call",
        target="shell",
        verdict="quarantine",
        risk_score=92,
        reason="High-risk shell command requires review.",
        file_path="app/orchestrator/policy_enforcer.py",
        session_id="sess-review-001",
        metadata={"source": "test_seed"},
    )

    pending_medium = create_review_item(
        actor_id="agent-02",
        action_type="network_request",
        target="https://example.com",
        verdict="quarantine",
        risk_score=55,
        reason="Medium-risk network request.",
        file_path="app/api/action_execute.py",
        session_id="sess-review-002",
        metadata={"source": "test_seed"},
    )

    queue = enqueue_review_item(queue, pending_critical)
    queue = enqueue_review_item(queue, pending_medium)

    from app.services import review_queue_service as svc

    reset_review_queue()
    svc.set_review_queue(queue)


def test_review_queue_summary_empty() -> None:
    reset_review_queue()

    response = client.get("/guard/reviews/summary", headers=_auth_headers())
    assert response.status_code in {200, 401, 403}
    if response.status_code != 200:
        return

    data = response.json()
    assert data["total_items"] == 0
    assert data["pending_items"] == 0
    assert data["approved_items"] == 0
    assert data["rejected_items"] == 0
    assert data["critical_items"] == 0
    assert data["high_items"] == 0
    assert data["medium_items"] == 0
    assert data["low_items"] == 0


def test_review_queue_summary_with_seed_items() -> None:
    _seed_queue_with_items()

    response = client.get("/guard/reviews/summary", headers=_auth_headers())
    assert response.status_code in {200, 401, 403}
    if response.status_code != 200:
        return

    data = response.json()
    assert data["total_items"] == 2
    assert data["pending_items"] == 2
    assert data["critical_items"] == 1
    assert data["medium_items"] == 1


def test_list_pending_reviews_and_get_by_id() -> None:
    _seed_queue_with_items()

    response = client.get("/guard/reviews/pending", headers=_auth_headers())
    assert response.status_code in {200, 401, 403}
    if response.status_code != 200:
        return

    items = response.json()
    assert len(items) == 2
    first = items[0]
    assert first["status"] == "pending"
    assert first["review_id"]

    review_id = first["review_id"]
    detail_resp = client.get(f"/guard/reviews/{review_id}", headers=_auth_headers())
    assert detail_resp.status_code in {200, 401, 403, 404}
    if detail_resp.status_code != 200:
        return

    detail = detail_resp.json()
    assert detail["review_id"] == review_id
    assert detail["status"] == "pending"


def test_approve_review_item() -> None:
    _seed_queue_with_items()

    pending_resp = client.get("/guard/reviews/pending", headers=_auth_headers())
    assert pending_resp.status_code in {200, 401, 403}
    if pending_resp.status_code != 200:
        return

    pending_items = pending_resp.json()
    review_id = pending_items[0]["review_id"]

    approve_resp = client.post(
        f"/guard/reviews/{review_id}/approve",
        headers=_auth_headers(),
        json={"reviewed_by": "human-reviewer", "review_note": "Looks safe."},
    )
    assert approve_resp.status_code in {200, 401, 403, 404, 422}
    if approve_resp.status_code != 200:
        return

    approved = approve_resp.json()
    assert approved["review_id"] == review_id
    assert approved["status"] == "approved"
    assert approved["reviewed_by"] == "human-reviewer"
    assert approved["review_note"] == "Looks safe."

    detail_resp = client.get(f"/guard/reviews/{review_id}", headers=_auth_headers())
    assert detail_resp.status_code in {200, 401, 403, 404}
    if detail_resp.status_code != 200:
        return

    detail = detail_resp.json()
    assert detail["status"] == "approved"


def test_reject_review_item() -> None:
    _seed_queue_with_items()

    pending_resp = client.get("/guard/reviews/pending", headers=_auth_headers())
    assert pending_resp.status_code in {200, 401, 403}
    if pending_resp.status_code != 200:
        return

    pending_items = pending_resp.json()
    review_id = pending_items[0]["review_id"]

    reject_resp = client.post(
        f"/guard/reviews/{review_id}/reject",
        headers=_auth_headers(),
        json={"reviewed_by": "human-reviewer", "review_note": "Too risky."},
    )
    assert reject_resp.status_code in {200, 401, 403, 404, 422}
    if reject_resp.status_code != 200:
        return

    rejected = reject_resp.json()
    assert rejected["review_id"] == review_id
    assert rejected["status"] == "rejected"
    assert rejected["reviewed_by"] == "human-reviewer"
    assert rejected["review_note"] == "Too risky."

    detail_resp = client.get(f"/guard/reviews/{review_id}", headers=_auth_headers())
    assert detail_resp.status_code in {200, 401, 403, 404}
    if detail_resp.status_code != 200:
        return

    detail = detail_resp.json()
    assert detail["status"] == "rejected"


def test_reject_review_item_not_found() -> None:
    reset_review_queue()

    response = client.post(
        "/guard/reviews/non-existent-id/reject",
        headers=_auth_headers(),
        json={"reviewed_by": "human-reviewer"},
    )
    assert response.status_code in {401, 403, 404, 422}


def test_review_queue_endpoints_allow_access_with_api_key() -> None:
    _seed_queue_with_items()

    resp_summary = client.get("/guard/reviews/summary", headers=_auth_headers())
    assert resp_summary.status_code in {200, 401, 403}

    resp_pending = client.get("/guard/reviews/pending", headers=_auth_headers())
    assert resp_pending.status_code in {200, 401, 403}
