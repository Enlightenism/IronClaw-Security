from __future__ import annotations

from collections.abc import Iterator

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from app.api.integrations import router as integrations_router


@pytest.fixture
def client() -> Iterator[TestClient]:
    app = FastAPI()
    app.include_router(integrations_router)
    with TestClient(app) as test_client:
        yield test_client


def test_integrations_router_registers_expected_paths(client: TestClient) -> None:
    route_paths = {route.path for route in client.app.routes}
    expected_paths = {
        "/integrations/installers",
        "/integrations/installers/{integration_id}",
        "/integrations/verifiers",
        "/integrations/verifiers/{integration_id}",
    }

    missing_paths = expected_paths - route_paths
    assert not missing_paths, f"missing integration routes: {sorted(missing_paths)}"


def test_integrations_router_exposes_expected_http_methods(client: TestClient) -> None:
    route_methods = {
        (
            route.path,
            tuple(
                sorted(method for method in route.methods if method not in {"HEAD", "OPTIONS"}),
            ),
        )
        for route in client.app.routes
        if route.path.startswith("/integrations")
    }

    expected_methods = {
        ("/integrations/installers", ("GET",)),
        ("/integrations/installers/{integration_id}", ("GET",)),
        ("/integrations/verifiers", ("GET",)),
        ("/integrations/verifiers/{integration_id}", ("GET",)),
    }

    missing_methods = expected_methods - route_methods
    assert not missing_methods, f"missing integration route methods: {sorted(missing_methods)}"


@pytest.mark.parametrize(
    ("path", "expected_status"),
    [
        ("/integrations/installers", 200),
        ("/integrations/verifiers", 200),
        ("/integrations/installers/openai", 200),
        ("/integrations/verifiers/openai", 200),
    ],
)
def test_integrations_endpoints_return_success_shapes(
    client: TestClient,
    path: str,
    expected_status: int,
) -> None:
    response = client.get(path)
    assert response.status_code == expected_status, response.text

    payload = response.json()
    assert isinstance(payload, dict)
    assert payload.get("status") == "ok"
    assert payload.get("service") == "IronClaw-Security"
    assert "timestamp" in payload


def test_installer_detail_endpoint_returns_requested_integration_id(
    client: TestClient,
) -> None:
    integration_id = "openai"

    response = client.get(f"/integrations/installers/{integration_id}")
    assert response.status_code == 200, response.text

    payload = response.json()
    assert payload.get("integration_id") == integration_id


def test_verifier_detail_endpoint_returns_requested_integration_id(
    client: TestClient,
) -> None:
    integration_id = "openai"

    response = client.get(f"/integrations/verifiers/{integration_id}")
    assert response.status_code == 200, response.text

    payload = response.json()
    assert payload.get("integration_id") == integration_id


def test_installer_detail_route_validates_blank_integration_id_as_not_found(
    client: TestClient,
) -> None:
    response = client.get("/integrations/installers/%20")
    assert response.status_code in {404, 422}


def test_verifier_detail_route_validates_blank_integration_id_as_not_found(
    client: TestClient,
) -> None:
    response = client.get("/integrations/verifiers/%20")
    assert response.status_code in {404, 422}
