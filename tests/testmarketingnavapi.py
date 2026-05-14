from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_marketing_nav_route_is_registered() -> None:
    response = client.get("/marketing/nav")
    assert response.status_code == 200


def test_marketing_nav_returns_list_of_items() -> None:
    response = client.get("/marketing/nav")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")

    data = response.json()
    assert isinstance(data, list)

    if data:
        first = data[0]
        assert isinstance(first, dict)

        # minimal flexible contract
        assert any(k in first for k in ("id", "slug", "key", "name"))
        assert any(k in first for k in ("href", "path", "url"))
        # optional grouping metadata
        assert any(
            k in first
            for k in (
                "section",
                "group",
                "category",
                "position",
                "items",  # nested children
            )
        )
