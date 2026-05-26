from __future__ import annotations

from fastapi.testclient import TestClient
import pytest

from app.ui import UI_ROUTERS
from app.ui.docs.api_reference import router as docs_api_reference_router
from app.ui.docs.authentication import router as docs_authentication_router
from app.ui.docs.changelog import router as docs_changelog_router
from app.ui.docs.policy_guide import router as docs_policy_guide_router
from app.ui.docs.quickstart import router as docs_quickstart_router
from app.ui.docs.telemetry_guide import router as docs_telemetry_guide_router
from app.ui.docs.webhooks import router as docs_webhooks_router

_AUTH_HEADERS = {"X-API-Key": "test-api-key"}

_DOC_ROUTES = [
    "/ui/docs/quickstart",
    "/ui/docs/api-reference",
    "/ui/docs/authentication",
    "/ui/docs/policy-guide",
    "/ui/docs/telemetry",
    "/ui/docs/webhooks",
    "/ui/docs/changelog",
]

_EXPECTED_DOC_ROUTERS = [
    docs_quickstart_router,
    docs_api_reference_router,
    docs_authentication_router,
    docs_policy_guide_router,
    docs_telemetry_guide_router,
    docs_webhooks_router,
    docs_changelog_router,
]


def test_doc_route_count() -> None:
    assert len(_DOC_ROUTES) == 7


def test_doc_routes_are_unique() -> None:
    assert len(_DOC_ROUTES) == len(set(_DOC_ROUTES))


def test_all_doc_routers_in_ui_routers() -> None:
    for doc_router in _EXPECTED_DOC_ROUTERS:
        assert doc_router in UI_ROUTERS, f"Doc router with prefix {doc_router.prefix!r} " f"and tags {doc_router.tags!r} is not registered in UI_ROUTERS"


def test_ui_routers_contains_exactly_seven_docs_prefix_routers() -> None:
    docs_prefix_routers = [r for r in UI_ROUTERS if r.prefix == "/ui/docs"]
    assert len(docs_prefix_routers) == 7, f"Expected 7 routers with prefix '/ui/docs', found {len(docs_prefix_routers)}"


@pytest.mark.parametrize("path", _DOC_ROUTES)
def test_doc_route_returns_200(test_client: TestClient, path: str) -> None:
    response = test_client.get(path, headers=_AUTH_HEADERS)
    assert response.status_code == 200, f"Expected 200 for {path!r}, got {response.status_code}: {response.text[:200]}"


@pytest.mark.parametrize("path", _DOC_ROUTES)
def test_doc_route_returns_json(test_client: TestClient, path: str) -> None:
    response = test_client.get(path, headers=_AUTH_HEADERS)
    assert response.status_code == 200
    content_type = response.headers.get("content-type", "")
    assert "application/json" in content_type, f"Expected JSON content-type for {path!r}, got {content_type!r}"


@pytest.mark.parametrize("path", _DOC_ROUTES)
def test_doc_route_returns_non_empty_body(test_client: TestClient, path: str) -> None:
    response = test_client.get(path, headers=_AUTH_HEADERS)
    assert response.status_code == 200
    body = response.json()
    assert isinstance(body, dict), f"Expected dict body for {path!r}, got {type(body)}"
    assert len(body) > 0, f"Response body is empty for {path!r}"
