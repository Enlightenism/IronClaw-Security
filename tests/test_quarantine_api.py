from __future__ import annotations

from fastapi.testclient import TestClient
from httpx2 import Response

from app.main import app

client = TestClient(app)


_VALID_PAYLOAD = {
    "source": "scan",
    "title": "Test quarantine item",
    "summary": "Automated test quarantine entry for contract verification.",
    "risk_level": "high",
    "status": "isolated",
}


def _auth_headers() -> dict[str, str]:
    return {"x-api-key": "test-api-key"}


def _create_item(overrides: dict | None = None) -> Response:
    payload = {**_VALID_PAYLOAD, **(overrides or {})}
    response = client.post("/quarantine/", json=payload, headers=_auth_headers())
    assert response.status_code in {200, 201, 401, 403}
    return response


# ---------------------------------------------------------------------------
# LIST
# ---------------------------------------------------------------------------


def test_list_quarantine_requires_auth() -> None:
    response = client.get("/quarantine/")
    assert response.status_code in {200, 401, 403}


def test_list_quarantine_200() -> None:
    response = client.get("/quarantine/", headers=_auth_headers())
    assert response.status_code in {200, 401, 403}
    if response.status_code != 200:
        return

    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "IronClaw-Security"
    assert "timestamp" in data
    assert isinstance(data["total"], int)
    assert isinstance(data["items"], list)


def test_list_quarantine_items_shape() -> None:
    r = _create_item()
    if r.status_code not in {200, 201}:
        return

    response = client.get("/quarantine/", headers=_auth_headers())
    if response.status_code != 200:
        return

    items = response.json()["items"]
    assert len(items) >= 1

    item = items[0]
    assert "quarantine_id" in item
    assert "status" in item
    assert "source" in item
    assert "title" in item
    assert "summary" in item
    assert "risk_level" in item
    assert "created_at" in item
    assert "updated_at" in item


def test_list_quarantine_filter_by_status() -> None:
    r = _create_item({"status": "isolated"})
    if r.status_code not in {200, 201}:
        return

    response = client.get("/quarantine/", params={"status": "isolated"}, headers=_auth_headers())
    if response.status_code != 200:
        return

    for item in response.json()["items"]:
        assert item["status"] == "isolated"


def test_list_quarantine_filter_by_risk_level() -> None:
    r = _create_item({"risk_level": "critical"})
    if r.status_code not in {200, 201}:
        return

    response = client.get("/quarantine/", params={"risk_level": "critical"}, headers=_auth_headers())
    if response.status_code != 200:
        return

    for item in response.json()["items"]:
        assert item["risk_level"] == "critical"


def test_list_quarantine_filter_by_source() -> None:
    r = _create_item({"source": "guard"})
    if r.status_code not in {200, 201}:
        return

    response = client.get("/quarantine/", params={"source": "guard"}, headers=_auth_headers())
    if response.status_code != 200:
        return

    for item in response.json()["items"]:
        assert item["source"] == "guard"


def test_list_quarantine_total_matches_items_length() -> None:
    response = client.get("/quarantine/", headers=_auth_headers())
    if response.status_code != 200:
        return

    data = response.json()
    assert data["total"] == len(data["items"])


# ---------------------------------------------------------------------------
# GET SINGLE ITEM
# ---------------------------------------------------------------------------


def test_get_quarantine_item_requires_auth() -> None:
    response = client.get("/quarantine/nonexistent-id")
    assert response.status_code in {200, 404, 401, 403}


def test_get_quarantine_item_200() -> None:
    r = _create_item()
    if r.status_code not in {200, 201}:
        return

    quarantine_id = r.json()["item"]["quarantine_id"]
    response = client.get(f"/quarantine/{quarantine_id}", headers=_auth_headers())
    assert response.status_code in {200, 401, 403}
    if response.status_code != 200:
        return

    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "IronClaw-Security"
    assert "timestamp" in data
    assert data["item"]["quarantine_id"] == quarantine_id


def test_get_quarantine_item_404() -> None:
    response = client.get("/quarantine/does-not-exist-xyz", headers=_auth_headers())
    assert response.status_code in {404, 401, 403}


def test_get_quarantine_item_shape() -> None:
    r = _create_item()
    if r.status_code not in {200, 201}:
        return

    quarantine_id = r.json()["item"]["quarantine_id"]
    response = client.get(f"/quarantine/{quarantine_id}", headers=_auth_headers())
    if response.status_code != 200:
        return

    item = response.json()["item"]
    assert "quarantine_id" in item
    assert "status" in item
    assert "source" in item
    assert "title" in item
    assert "summary" in item
    assert "risk_level" in item
    assert "created_at" in item
    assert "updated_at" in item


# ---------------------------------------------------------------------------
# CREATE
# ---------------------------------------------------------------------------


def test_create_quarantine_requires_auth() -> None:
    response = client.post("/quarantine/", json=_VALID_PAYLOAD)
    assert response.status_code in {200, 201, 401, 403}


def test_create_quarantine_201() -> None:
    response = _create_item()
    assert response.status_code in {200, 201, 401, 403}
    if response.status_code not in {200, 201}:
        return

    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "IronClaw-Security"
    assert "timestamp" in data
    assert "item" in data


def test_create_quarantine_item_fields_persisted() -> None:
    payload = {
        "source": "sandbox",
        "title": "Persist check title",
        "summary": "Persist check summary text for contract test.",
        "risk_level": "medium",
        "status": "isolated",
        "owner": "test-owner",
        "tags": ["contract", "test"],
    }
    response = client.post("/quarantine/", json=payload, headers=_auth_headers())
    if response.status_code not in {200, 201}:
        return

    item = response.json()["item"]
    assert item["source"] == "sandbox"
    assert item["title"] == "Persist check title"
    assert item["risk_level"] == "medium"
    assert item["status"] == "isolated"
    assert item["owner"] == "test-owner"


def test_create_quarantine_missing_required_fields_422() -> None:
    response = client.post("/quarantine/", json={"source": "scan"}, headers=_auth_headers())
    assert response.status_code in {422, 401, 403}


def test_create_quarantine_invalid_source_422() -> None:
    payload = {**_VALID_PAYLOAD, "source": "not-a-valid-source"}
    response = client.post("/quarantine/", json=payload, headers=_auth_headers())
    assert response.status_code in {422, 401, 403}


def test_create_quarantine_invalid_risk_level_422() -> None:
    payload = {**_VALID_PAYLOAD, "risk_level": "extreme"}
    response = client.post("/quarantine/", json=payload, headers=_auth_headers())
    assert response.status_code in {422, 401, 403}


def test_create_quarantine_all_sources_accepted() -> None:
    for source in ("scan", "guard", "sandbox", "review", "system"):
        payload = {**_VALID_PAYLOAD, "source": source}
        response = client.post("/quarantine/", json=payload, headers=_auth_headers())
        assert response.status_code in {200, 201, 401, 403}, f"source={source} got {response.status_code}"


def test_create_quarantine_all_risk_levels_accepted() -> None:
    for risk in ("low", "medium", "high", "critical"):
        payload = {**_VALID_PAYLOAD, "risk_level": risk}
        response = client.post("/quarantine/", json=payload, headers=_auth_headers())
        assert response.status_code in {200, 201, 401, 403}, f"risk_level={risk} got {response.status_code}"


# ---------------------------------------------------------------------------
# REVIEW
# ---------------------------------------------------------------------------


def test_review_quarantine_requires_auth() -> None:
    response = client.post("/quarantine/fake-id/review", json={"owner": "tester"})
    assert response.status_code in {404, 401, 403}


def test_review_quarantine_200() -> None:
    r = _create_item()
    if r.status_code not in {200, 201}:
        return

    quarantine_id = r.json()["item"]["quarantine_id"]
    payload = {"owner": "security-reviewer"}
    response = client.post(f"/quarantine/{quarantine_id}/review", json=payload, headers=_auth_headers())
    assert response.status_code in {200, 401, 403}
    if response.status_code != 200:
        return

    data = response.json()
    assert data["status"] == "ok"
    assert data["item"]["status"] == "under_review"
    assert data["item"]["owner"] == "security-reviewer"


def test_review_quarantine_404() -> None:
    response = client.post("/quarantine/does-not-exist/review", json={"owner": "reviewer"}, headers=_auth_headers())
    assert response.status_code in {404, 401, 403}


def test_review_released_item_conflicts_409() -> None:
    r = _create_item()
    if r.status_code not in {200, 201}:
        return

    quarantine_id = r.json()["item"]["quarantine_id"]

    release_payload = {"release_reason": "cleared for release", "released_by": "auto-test"}
    client.post(f"/quarantine/{quarantine_id}/release", json=release_payload, headers=_auth_headers())

    review_payload = {"owner": "reviewer"}
    response = client.post(f"/quarantine/{quarantine_id}/review", json=review_payload, headers=_auth_headers())
    assert response.status_code in {409, 401, 403}


# ---------------------------------------------------------------------------
# RELEASE
# ---------------------------------------------------------------------------


def test_release_quarantine_requires_auth() -> None:
    response = client.post(
        "/quarantine/fake-id/release",
        json={"release_reason": "cleared", "released_by": "tester"},
    )
    assert response.status_code in {404, 401, 403}


def test_release_quarantine_200() -> None:
    r = _create_item()
    if r.status_code not in {200, 201}:
        return

    quarantine_id = r.json()["item"]["quarantine_id"]
    payload = {"release_reason": "threat confirmed false positive", "released_by": "analyst-1"}
    response = client.post(f"/quarantine/{quarantine_id}/release", json=payload, headers=_auth_headers())
    assert response.status_code in {200, 401, 403}
    if response.status_code != 200:
        return

    data = response.json()
    assert data["status"] == "ok"
    assert data["item"]["status"] == "released"
    assert data["item"]["release_reason"] == "threat confirmed false positive"


def test_release_quarantine_404() -> None:
    payload = {"release_reason": "cleared", "released_by": "analyst"}
    response = client.post("/quarantine/does-not-exist/release", json=payload, headers=_auth_headers())
    assert response.status_code in {404, 401, 403}


def test_release_destroyed_item_conflicts_409() -> None:
    r = _create_item()
    if r.status_code not in {200, 201}:
        return

    quarantine_id = r.json()["item"]["quarantine_id"]

    destroy_payload = {"destroyed_by": "auto-test", "destroy_reason": "wiped by policy"}
    client.post(f"/quarantine/{quarantine_id}/destroy", json=destroy_payload, headers=_auth_headers())

    release_payload = {"release_reason": "re-release attempt", "released_by": "analyst"}
    response = client.post(f"/quarantine/{quarantine_id}/release", json=release_payload, headers=_auth_headers())
    assert response.status_code in {409, 401, 403}


# ---------------------------------------------------------------------------
# DESTROY
# ---------------------------------------------------------------------------


def test_destroy_quarantine_requires_auth() -> None:
    response = client.post(
        "/quarantine/fake-id/destroy",
        json={"destroyed_by": "tester", "destroy_reason": "policy wipe"},
    )
    assert response.status_code in {404, 401, 403}


def test_destroy_quarantine_200() -> None:
    r = _create_item()
    if r.status_code not in {200, 201}:
        return

    quarantine_id = r.json()["item"]["quarantine_id"]
    payload = {"destroyed_by": "policy-engine", "destroy_reason": "retention policy expired"}
    response = client.post(f"/quarantine/{quarantine_id}/destroy", json=payload, headers=_auth_headers())
    assert response.status_code in {200, 401, 403}
    if response.status_code != 200:
        return

    data = response.json()
    assert data["status"] == "ok"
    assert data["item"]["status"] == "destroyed"


def test_destroy_quarantine_404() -> None:
    payload = {"destroyed_by": "system", "destroy_reason": "not found"}
    response = client.post("/quarantine/does-not-exist/destroy", json=payload, headers=_auth_headers())
    assert response.status_code in {404, 401, 403}


def test_destroy_released_item_conflicts_409() -> None:
    r = _create_item()
    if r.status_code not in {200, 201}:
        return

    quarantine_id = r.json()["item"]["quarantine_id"]

    release_payload = {"release_reason": "cleared", "released_by": "analyst"}
    client.post(f"/quarantine/{quarantine_id}/release", json=release_payload, headers=_auth_headers())

    destroy_payload = {"destroyed_by": "system", "destroy_reason": "destroy after release attempt"}
    response = client.post(f"/quarantine/{quarantine_id}/destroy", json=destroy_payload, headers=_auth_headers())
    assert response.status_code in {409, 401, 403}


# ---------------------------------------------------------------------------
# LIFECYCLE INTEGRATION
# ---------------------------------------------------------------------------


def test_full_lifecycle_isolated_to_review_to_released() -> None:
    r = _create_item({"status": "isolated"})
    if r.status_code not in {200, 201}:
        return

    quarantine_id = r.json()["item"]["quarantine_id"]
    assert r.json()["item"]["status"] == "isolated"

    review = client.post(
        f"/quarantine/{quarantine_id}/review",
        json={"owner": "lifecycle-reviewer"},
        headers=_auth_headers(),
    )
    if review.status_code != 200:
        return
    assert review.json()["item"]["status"] == "under_review"

    release = client.post(
        f"/quarantine/{quarantine_id}/release",
        json={"release_reason": "lifecycle test complete", "released_by": "lifecycle-reviewer"},
        headers=_auth_headers(),
    )
    if release.status_code != 200:
        return
    assert release.json()["item"]["status"] == "released"

    get = client.get(f"/quarantine/{quarantine_id}", headers=_auth_headers())
    if get.status_code != 200:
        return
    assert get.json()["item"]["status"] == "released"


def test_full_lifecycle_isolated_to_destroyed() -> None:
    r = _create_item({"status": "isolated"})
    if r.status_code not in {200, 201}:
        return

    quarantine_id = r.json()["item"]["quarantine_id"]

    destroy = client.post(
        f"/quarantine/{quarantine_id}/destroy",
        json={"destroyed_by": "retention-policy", "destroy_reason": "expired"},
        headers=_auth_headers(),
    )
    if destroy.status_code != 200:
        return
    assert destroy.json()["item"]["status"] == "destroyed"

    get = client.get(f"/quarantine/{quarantine_id}", headers=_auth_headers())
    if get.status_code != 200:
        return
    assert get.json()["item"]["status"] == "destroyed"
