from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_dashboard_overview_response_contract() -> None:
    response = client.get("/dashboard/overview")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")

    data = response.json()
    assert isinstance(data, dict)
    assert set(data.keys()) >= {
        "status",
        "service",
        "timestamp",
        "environment",
        "kpis",
        "alerts",
        "activity",
        "metadata",
    }


def test_organizations_response_contract() -> None:
    response = client.get("/organizations")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")

    data = response.json()
    assert isinstance(data, dict)
    assert set(data.keys()) >= {
        "status",
        "service",
        "timestamp",
        "total",
        "items",
    }


def test_ui_routes_response_contract() -> None:
    response = client.get("/ui/routes")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")

    data = response.json()
    assert isinstance(data, dict)
    assert set(data.keys()) >= {
        "status",
        "service",
        "timestamp",
        "totalroutes",
        "routes",
        "metadata",
    }


def test_ui_pages_response_contract() -> None:
    response = client.get("/ui/pages")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")

    data = response.json()
    assert isinstance(data, dict)
    assert set(data.keys()) >= {
        "generatedat",
        "summary",
        "sections",
        "items",
        "metadata",
    }


def test_ui_manifest_response_contract() -> None:
    response = client.get("/ui/manifest")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")

    data = response.json()
    assert isinstance(data, dict)
    assert set(data.keys()) >= {
        "status",
        "service",
        "timestamp",
        "totalroutes",
        "routes",
        "metadata",
    }