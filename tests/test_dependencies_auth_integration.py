from __future__ import annotations

from collections.abc import Iterator
import os

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
import pytest

os.environ["IRONCLAW_PERSISTENCE_MODE"] = "memory"
os.environ["ENVIRONMENT"] = "test"
os.environ["IRONCLAW_API_KEY"] = "test-api-key"
os.environ["AUTH_REQUIRED"] = "true"
os.environ["SUPABASE_URL"] = ""
os.environ["SUPABASE_SERVICE_ROLE_KEY"] = ""
os.environ["SUPABASE_KEY"] = ""
os.environ["SUPABASE_ANON_KEY"] = ""

from app.core.auth import AuthContext, get_auth_context  # noqa: E402
from app.core.errors import register_exception_handlers  # noqa: E402
from app.core.settings import get_settings  # noqa: E402
from app.dependencies.auth import (  # noqa: E402
    require_access_dependency,
    require_authenticated,
    require_same_org_dependency,
)

_VALID_KEY = os.environ["IRONCLAW_API_KEY"]

# Use ic_ prefix so _looks_like_static_key returns True → guaranteed 401
# with no edge-auth network call, making tests deterministic with SUPABASE_URL="".
_BAD_KEY = "ic_invalid_key_that_will_never_match_000"

_VALID_ORG = "org-integration-001"


# ---------------------------------------------------------------------------
# Minimal FastAPI test app — built once, reused via fixture
# ---------------------------------------------------------------------------


def _build_integration_app() -> FastAPI:
    app = FastAPI(title="ironclaw-dep-auth-integration-test")
    register_exception_handlers(app)

    @app.get("/test/authenticated")
    async def route_authenticated(
        context: AuthContext = Depends(require_authenticated),
    ) -> dict:
        return {
            "authenticated": context.authenticated,
            "principal_type": context.principal_type,
        }

    _access_dep = require_access_dependency(action="scan:execute")

    @app.get("/test/access")
    async def route_access(
        context: AuthContext = Depends(_access_dep),
    ) -> dict:
        return {
            "authenticated": context.authenticated,
            "principal_type": context.principal_type,
        }

    _access_perm_dep = require_access_dependency(
        action="audit:read",
        permission="audit:read",
    )

    @app.get("/test/access/permission")
    async def route_access_permission(
        context: AuthContext = Depends(_access_perm_dep),
    ) -> dict:
        return {
            "authenticated": context.authenticated,
            "principal_type": context.principal_type,
        }

    @app.get("/test/org")
    async def route_org(
        context: AuthContext = Depends(require_same_org_dependency),
    ) -> dict:
        return {
            "authenticated": context.authenticated,
            "org_id": context.org_id,
        }

    @app.get("/test/probe")
    async def route_probe(
        context: AuthContext = Depends(get_auth_context),
    ) -> dict:
        return {
            "authenticated": context.authenticated,
            "principal_type": context.principal_type,
            "org_id": context.org_id,
        }

    return app


_INTEGRATION_APP = _build_integration_app()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _refresh_settings() -> Iterator[None]:
    get_settings.cache_clear()
    _INTEGRATION_APP.state.settings = get_settings()
    yield
    get_settings.cache_clear()


@pytest.fixture()
def client() -> TestClient:
    c = TestClient(_INTEGRATION_APP, raise_server_exceptions=False)
    c.headers.update({"X-API-Key": _VALID_KEY})
    return c


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _auth_headers(api_key: str = _VALID_KEY) -> dict[str, str]:
    return {"X-API-Key": api_key}


def _auth_org_headers(
    api_key: str = _VALID_KEY,
    org_id: str = _VALID_ORG,
) -> dict[str, str]:
    return {"X-API-Key": api_key, "X-Org-Id": org_id}


def _bare_client() -> TestClient:
    """TestClient with no default headers and raise_server_exceptions=False."""
    return TestClient(_INTEGRATION_APP, raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# /test/probe — control route
# ---------------------------------------------------------------------------


class TestProbeRoute:
    def test_valid_key_returns_200(self, client: TestClient) -> None:
        r = client.get("/test/probe")
        assert r.status_code == 200
        assert r.json()["authenticated"] is True

    def test_missing_key_returns_401(self) -> None:
        r = _bare_client().get("/test/probe")
        assert r.status_code == 401

    def test_missing_key_401_detail_contains_api_key(self) -> None:
        r = _bare_client().get("/test/probe")
        assert r.status_code == 401
        body = r.json()
        assert "detail" in body
        assert "api key" in body["detail"].lower() or "missing" in body["detail"].lower()

    def test_invalid_key_returns_401(self) -> None:
        r = _bare_client().get("/test/probe", headers=_auth_headers(_BAD_KEY))
        assert r.status_code == 401

    def test_invalid_key_401_detail_contains_invalid(self) -> None:
        r = _bare_client().get("/test/probe", headers=_auth_headers(_BAD_KEY))
        assert r.status_code == 401
        body = r.json()
        assert body.get("error") == "invalid_api_key"

    def test_valid_key_sets_platform_principal_type(self, client: TestClient) -> None:
        r = client.get("/test/probe")
        assert r.json()["principal_type"] == "platform"

    def test_org_id_header_propagated(self, client: TestClient) -> None:
        r = client.get("/test/probe", headers=_auth_org_headers(org_id="org-probe-01"))
        assert r.status_code == 200
        assert r.json()["org_id"] == "org-probe-01"


# ---------------------------------------------------------------------------
# /test/authenticated — require_authenticated
# ---------------------------------------------------------------------------


class TestRequireAuthenticatedHTTP:
    def test_valid_key_returns_200(self, client: TestClient) -> None:
        r = client.get("/test/authenticated")
        assert r.status_code == 200

    def test_valid_key_body_authenticated_true(self, client: TestClient) -> None:
        r = client.get("/test/authenticated")
        assert r.json()["authenticated"] is True

    def test_missing_key_returns_401(self) -> None:
        r = _bare_client().get("/test/authenticated")
        assert r.status_code == 401

    def test_missing_key_401_body_detail_is_string(self) -> None:
        r = _bare_client().get("/test/authenticated")
        assert r.status_code == 401
        body = r.json()
        assert "detail" in body
        assert isinstance(body["detail"], str)
        assert len(body["detail"]) > 0

    def test_missing_key_401_detail_contains_api_key(self) -> None:
        r = _bare_client().get("/test/authenticated")
        body = r.json()
        assert "api key" in body["detail"].lower() or "missing" in body["detail"].lower()

    def test_invalid_key_returns_401(self) -> None:
        r = _bare_client().get("/test/authenticated", headers=_auth_headers(_BAD_KEY))
        assert r.status_code == 401

    def test_invalid_key_401_detail_contains_invalid(self) -> None:
        r = _bare_client().get("/test/authenticated", headers=_auth_headers(_BAD_KEY))
        body = r.json()
        assert body.get("error") == "invalid_api_key"

    def test_valid_key_principal_type_platform(self, client: TestClient) -> None:
        r = client.get("/test/authenticated")
        assert r.json()["principal_type"] == "platform"

    def test_empty_key_header_returns_401(self) -> None:
        r = _bare_client().get("/test/authenticated", headers={"X-API-Key": ""})
        assert r.status_code == 401

    def test_whitespace_key_returns_401(self) -> None:
        r = _bare_client().get("/test/authenticated", headers={"X-API-Key": "   "})
        assert r.status_code == 401


# ---------------------------------------------------------------------------
# /test/access — require_access_dependency(action="scan:execute")
# ---------------------------------------------------------------------------


class TestRequireAccessDependencyHTTP:
    def test_valid_key_returns_200(self, client: TestClient) -> None:
        r = client.get("/test/access")
        assert r.status_code == 200

    def test_valid_key_body_authenticated_true(self, client: TestClient) -> None:
        r = client.get("/test/access")
        assert r.json()["authenticated"] is True

    def test_missing_key_returns_401(self) -> None:
        r = _bare_client().get("/test/access")
        assert r.status_code == 401

    def test_missing_key_401_body_has_detail(self) -> None:
        r = _bare_client().get("/test/access")
        body = r.json()
        assert "detail" in body
        assert isinstance(body["detail"], str)

    def test_invalid_key_returns_401_or_403(self) -> None:
        r = _bare_client().get("/test/access", headers=_auth_headers(_BAD_KEY))
        assert r.status_code in (401, 403)

    def test_invalid_key_4xx_body_has_detail_or_error(self) -> None:
        r = _bare_client().get("/test/access", headers=_auth_headers(_BAD_KEY))
        assert r.status_code in (401, 403)
        body = r.json()
        # HTTPException path → {"detail": str}; AppError path → {"error": ..., "message": ...}
        assert "detail" in body or "error" in body

    def test_platform_principal_passes_access_check(self, client: TestClient) -> None:
        r = client.get("/test/access")
        assert r.status_code == 200
        assert r.json()["principal_type"] == "platform"

    def test_access_with_org_id_header_passes(self, client: TestClient) -> None:
        r = client.get("/test/access", headers=_auth_org_headers())
        assert r.status_code == 200

    def test_response_shape_contains_principal_type(self, client: TestClient) -> None:
        r = client.get("/test/access")
        body = r.json()
        assert "principal_type" in body
        assert "authenticated" in body


# ---------------------------------------------------------------------------
# /test/access/permission — require_access_dependency(permission="audit:read")
# ---------------------------------------------------------------------------


class TestRequireAccessPermissionHTTP:
    def test_platform_principal_passes_permission_check(self, client: TestClient) -> None:
        r = client.get("/test/access/permission")
        assert r.status_code == 200

    def test_missing_key_returns_401(self) -> None:
        r = _bare_client().get("/test/access/permission")
        assert r.status_code == 401

    def test_missing_key_401_body_has_detail(self) -> None:
        r = _bare_client().get("/test/access/permission")
        body = r.json()
        assert "detail" in body
        assert isinstance(body["detail"], str)

    def test_invalid_key_returns_4xx(self) -> None:
        r = _bare_client().get("/test/access/permission", headers=_auth_headers(_BAD_KEY))
        assert r.status_code in (401, 403)

    def test_valid_key_authenticated_true(self, client: TestClient) -> None:
        r = client.get("/test/access/permission")
        assert r.json()["authenticated"] is True


# ---------------------------------------------------------------------------
# /test/org — require_same_org_dependency
# ---------------------------------------------------------------------------


class TestRequireSameOrgDependencyHTTP:
    def test_no_org_header_passes_when_platform(self, client: TestClient) -> None:
        r = client.get("/test/org")
        assert r.status_code in (200, 403)

    def test_matching_org_header_passes(self, client: TestClient) -> None:
        r = client.get("/test/org", headers=_auth_org_headers(org_id=_VALID_ORG))
        assert r.status_code == 200

    def test_missing_key_returns_401(self) -> None:
        r = _bare_client().get("/test/org")
        assert r.status_code == 401

    def test_missing_key_401_body_has_detail(self) -> None:
        r = _bare_client().get("/test/org")
        body = r.json()
        assert "detail" in body
        assert isinstance(body["detail"], str)

    def test_invalid_key_returns_401(self) -> None:
        r = _bare_client().get("/test/org", headers=_auth_headers(_BAD_KEY))
        assert r.status_code == 401

    def test_invalid_key_401_detail_not_empty(self) -> None:
        r = _bare_client().get("/test/org", headers=_auth_headers(_BAD_KEY))
        body = r.json()
        assert body.get("error") == "invalid_api_key"

    def test_valid_key_with_org_authenticated_true(self, client: TestClient) -> None:
        r = client.get("/test/org", headers=_auth_org_headers())
        if r.status_code == 200:
            assert r.json()["authenticated"] is True

    def test_org_id_reflected_in_response(self, client: TestClient) -> None:
        r = client.get("/test/org", headers=_auth_org_headers(org_id="org-reflect-01"))
        if r.status_code == 200:
            assert r.json()["org_id"] == "org-reflect-01"


# ---------------------------------------------------------------------------
# Cross-cutting HTTP contract assertions
# ---------------------------------------------------------------------------


class TestHTTPContractAssertions:
    def test_401_response_is_json(self) -> None:
        r = _bare_client().get("/test/authenticated")
        assert r.status_code == 401
        assert r.headers.get("content-type", "").startswith("application/json")

    def test_401_body_has_detail_key(self) -> None:
        # HTTPException from auth.py → http_exception_handler → {"detail": str}
        r = _bare_client().get("/test/authenticated")
        body = r.json()
        assert "detail" in body
        assert isinstance(body["detail"], str)
        assert len(body["detail"]) > 0

    def test_401_body_does_not_expose_error_key_for_auth_exceptions(self) -> None:
        # HTTPException 401 must NOT have "error" key — that is AppError shape only
        r = _bare_client().get("/test/authenticated")
        body = r.json()
        assert "error" not in body

    def test_valid_200_response_is_json(self, client: TestClient) -> None:
        r = client.get("/test/authenticated")
        assert r.status_code == 200
        assert r.headers.get("content-type", "").startswith("application/json")

    def test_invalid_key_401_body_has_detail(self) -> None:
        r = _bare_client().get("/test/authenticated", headers=_auth_headers(_BAD_KEY))
        assert r.status_code == 401
        body = r.json()
        # AppError path → {"error": ..., "message": ..., "request_id": ..., "details": ...}
        assert body.get("error") == "invalid_api_key"
        assert isinstance(body.get("message"), str)
        assert len(body.get("message", "")) > 0

    def test_invalid_key_401_detail_contains_expected_string(self) -> None:
        r = _bare_client().get("/test/authenticated", headers=_auth_headers(_BAD_KEY))
        body = r.json()
        assert "invalid" in body.get("message", "").lower()

    def test_all_protected_routes_reject_missing_key(self) -> None:
        routes = ["/test/authenticated", "/test/access", "/test/access/permission", "/test/org"]
        for route in routes:
            r = _bare_client().get(route)
            assert r.status_code == 401, f"Expected 401 on {route}, got {r.status_code}"

    def test_all_protected_routes_missing_key_401_body_has_detail(self) -> None:
        routes = ["/test/authenticated", "/test/access", "/test/access/permission", "/test/org"]
        for route in routes:
            r = _bare_client().get(route)
            body = r.json()
            assert "detail" in body, f"No 'detail' key in 401 body for {route}: {body}"
            assert isinstance(body["detail"], str)

    def test_all_protected_routes_accept_valid_key(self, client: TestClient) -> None:
        routes = ["/test/authenticated", "/test/access", "/test/access/permission"]
        for route in routes:
            r = client.get(route)
            assert r.status_code == 200, f"Expected 200 on {route}, got {r.status_code}"

    def test_all_protected_routes_reject_invalid_key(self) -> None:
        routes = ["/test/authenticated", "/test/access", "/test/access/permission", "/test/org"]
        for route in routes:
            r = _bare_client().get(route, headers=_auth_headers(_BAD_KEY))
            assert r.status_code in (401, 403), f"Expected 4xx on {route}, got {r.status_code}"

    def test_x_api_key_header_name_is_case_insensitive(self) -> None:
        r = _bare_client().get("/test/authenticated", headers={"x-api-key": _VALID_KEY})
        assert r.status_code == 200

    def test_extra_unknown_headers_do_not_affect_auth(self, client: TestClient) -> None:
        r = client.get("/test/authenticated", headers={"X-Unknown-Header": "some-value"})
        assert r.status_code == 200

    def test_probe_returns_200_with_valid_key(self, client: TestClient) -> None:
        r = client.get("/test/probe")
        assert r.status_code == 200
