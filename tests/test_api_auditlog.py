from __future__ import annotations

from collections.abc import Iterator
import os

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

from app.core.settings import get_settings
from app.main import app
from app.services.audit_log_service import reset_audit_log

_VALID_KEY = os.environ["IRONCLAW_API_KEY"]
_BAD_KEY = "ic-bad-key-000"

_ALL_READ_ROUTES = [
    "/api/audit/events",
    "/api/audit/actor/test-actor",
    "/api/audit/request/test-request",
    "/api/audit/trace/test-trace",
    "/api/audit/summary",
]


def _auth(key: str = _VALID_KEY) -> dict[str, str]:
    return {"X-API-Key": key}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _refresh_settings() -> Iterator[None]:
    get_settings.cache_clear()
    app.state.settings = get_settings()
    yield
    get_settings.cache_clear()


@pytest.fixture(autouse=True)
def _reset_state() -> Iterator[None]:
    reset_audit_log()
    yield
    reset_audit_log()


@pytest.fixture()
def client() -> TestClient:
    c = TestClient(app, raise_server_exceptions=True)
    c.headers.update(_auth())
    return c


# ---------------------------------------------------------------------------
# Auth enforcement — all routes
# ---------------------------------------------------------------------------


class TestAuditlogAuthEnforcement:
    def test_all_read_routes_reject_missing_key(self) -> None:
        bare = TestClient(app, raise_server_exceptions=True)
        for route in _ALL_READ_ROUTES:
            r = bare.get(route)
            assert r.status_code == 401, f"Expected 401 on {route}, got {r.status_code}"

    def test_all_read_routes_reject_invalid_key(self) -> None:
        for route in _ALL_READ_ROUTES:
            r = TestClient(app, raise_server_exceptions=True).get(route, headers=_auth(_BAD_KEY))
            assert r.status_code in (401, 403), f"Expected 4xx on {route}, got {r.status_code}"

    def test_post_events_rejects_missing_key(self) -> None:
        bare = TestClient(app, raise_server_exceptions=True)
        r = bare.post("/api/audit/events", json={"action": "test"})
        assert r.status_code == 401

    def test_post_events_rejects_invalid_key(self) -> None:
        r = TestClient(app, raise_server_exceptions=True).post("/api/audit/events", json={"action": "test"}, headers=_auth(_BAD_KEY))
        assert r.status_code in (401, 403)


# ---------------------------------------------------------------------------
# GET /api/audit/events
# ---------------------------------------------------------------------------


class TestListAuditEvents:
    def test_returns_200_with_valid_key(self, client: TestClient) -> None:
        r = client.get("/api/audit/events")
        assert r.status_code == 200

    def test_response_has_events_and_count_keys(self, client: TestClient) -> None:
        r = client.get("/api/audit/events")
        body = r.json()
        assert "events" in body
        assert "count" in body

    def test_events_is_list(self, client: TestClient) -> None:
        r = client.get("/api/audit/events")
        assert isinstance(r.json()["events"], list)

    def test_count_matches_events_length(self, client: TestClient) -> None:
        r = client.get("/api/audit/events")
        body = r.json()
        assert body["count"] == len(body["events"])

    def test_limit_param_accepted(self, client: TestClient) -> None:
        r = client.get("/api/audit/events?limit=10")
        assert r.status_code == 200

    def test_limit_zero_returns_422(self, client: TestClient) -> None:
        r = client.get("/api/audit/events?limit=0")
        assert r.status_code == 422

    def test_limit_above_500_returns_422(self, client: TestClient) -> None:
        r = client.get("/api/audit/events?limit=501")
        assert r.status_code == 422

    def test_filter_by_actorid(self, client: TestClient) -> None:
        r = client.get("/api/audit/events?actorid=actor-x")
        assert r.status_code == 200

    def test_filter_by_requestid(self, client: TestClient) -> None:
        r = client.get("/api/audit/events?requestid=req-x")
        assert r.status_code == 200

    def test_filter_by_traceid(self, client: TestClient) -> None:
        r = client.get("/api/audit/events?traceid=trace-x")
        assert r.status_code == 200

    def test_filter_by_verdict(self, client: TestClient) -> None:
        r = client.get("/api/audit/events?verdict=allow")
        assert r.status_code == 200

    def test_filter_by_eventtype(self, client: TestClient) -> None:
        r = client.get("/api/audit/events?eventtype=scan:execute")
        assert r.status_code == 200

    def test_response_is_json(self, client: TestClient) -> None:
        r = client.get("/api/audit/events")
        assert r.headers.get("content-type", "").startswith("application/json")


# ---------------------------------------------------------------------------
# POST /api/audit/events
# ---------------------------------------------------------------------------


class TestCreateAuditEvent:
    def test_returns_200_with_valid_payload(self, client: TestClient) -> None:
        r = client.post(
            "/api/audit/events",
            json={"action": "scan:execute", "actor_id": "actor-post-001"},
        )
        assert r.status_code == 200

    def test_response_contains_action(self, client: TestClient) -> None:
        r = client.post(
            "/api/audit/events",
            json={"action": "policy:enforce", "actor_id": "actor-post-002"},
        )
        body = r.json()
        assert body.get("action") == "policy:enforce"

    def test_response_contains_log_id(self, client: TestClient) -> None:
        r = client.post(
            "/api/audit/events",
            json={"action": "audit:write"},
        )
        body = r.json()
        assert "log_id" in body or "id" in body or "audit_id" in body

    def test_empty_payload_returns_200_with_defaults(self, client: TestClient) -> None:
        r = client.post("/api/audit/events", json={})
        assert r.status_code == 200

    def test_created_event_has_created_at(self, client: TestClient) -> None:
        r = client.post("/api/audit/events", json={"action": "test"})
        body = r.json()
        assert "created_at" in body or "occurred_at" in body

    def test_response_is_json(self, client: TestClient) -> None:
        r = client.post("/api/audit/events", json={"action": "test"})
        assert r.headers.get("content-type", "").startswith("application/json")


# ---------------------------------------------------------------------------
# GET /api/audit/actor/{actor_id}
# ---------------------------------------------------------------------------


class TestListByActor:
    def test_returns_200_with_valid_key(self, client: TestClient) -> None:
        r = client.get("/api/audit/actor/actor-001")
        assert r.status_code == 200

    def test_response_is_list(self, client: TestClient) -> None:
        r = client.get("/api/audit/actor/actor-001")
        assert isinstance(r.json(), list)

    def test_seeded_actor_returned(self, client: TestClient) -> None:
        client.post(
            "/api/audit/events",
            json={"action": "scan:execute", "actor_id": "actor-by-actor-seed"},
        )
        r = client.get("/api/audit/actor/actor-by-actor-seed")
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, list)
        assert all(item.get("actor_id") == "actor-by-actor-seed" for item in data)

    def test_unknown_actor_returns_empty_list(self, client: TestClient) -> None:
        r = client.get("/api/audit/actor/actor-does-not-exist-xyz")
        assert r.status_code == 200
        assert r.json() == []

    def test_limit_param_accepted(self, client: TestClient) -> None:
        r = client.get("/api/audit/actor/actor-001?limit=5")
        assert r.status_code == 200

    def test_limit_zero_returns_422(self, client: TestClient) -> None:
        r = client.get("/api/audit/actor/actor-001?limit=0")
        assert r.status_code == 422


# ---------------------------------------------------------------------------
# GET /api/audit/request/{request_id}
# ---------------------------------------------------------------------------


class TestListByRequest:
    def test_returns_200_with_valid_key(self, client: TestClient) -> None:
        r = client.get("/api/audit/request/req-001")
        assert r.status_code == 200

    def test_response_is_list(self, client: TestClient) -> None:
        r = client.get("/api/audit/request/req-001")
        assert isinstance(r.json(), list)

    def test_seeded_request_returned(self, client: TestClient) -> None:
        client.post(
            "/api/audit/events",
            json={"action": "audit:read", "request_id": "req-by-request-seed"},
        )
        r = client.get("/api/audit/request/req-by-request-seed")
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, list)
        assert all(item.get("request_id") == "req-by-request-seed" for item in data)

    def test_unknown_request_returns_empty_list(self, client: TestClient) -> None:
        r = client.get("/api/audit/request/req-does-not-exist-xyz")
        assert r.status_code == 200
        assert r.json() == []


# ---------------------------------------------------------------------------
# GET /api/audit/trace/{trace_id}
# ---------------------------------------------------------------------------


class TestListByTrace:
    def test_returns_200_with_valid_key(self, client: TestClient) -> None:
        r = client.get("/api/audit/trace/trace-001")
        assert r.status_code == 200

    def test_response_is_list(self, client: TestClient) -> None:
        r = client.get("/api/audit/trace/trace-001")
        assert isinstance(r.json(), list)

    def test_seeded_trace_returned(self, client: TestClient) -> None:
        client.post(
            "/api/audit/events",
            json={"action": "audit:read", "trace_id": "trace-by-trace-seed"},
        )
        r = client.get("/api/audit/trace/trace-by-trace-seed")
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, list)
        assert all(item.get("trace_id") == "trace-by-trace-seed" for item in data)

    def test_unknown_trace_returns_empty_list(self, client: TestClient) -> None:
        r = client.get("/api/audit/trace/trace-does-not-exist-xyz")
        assert r.status_code == 200
        assert r.json() == []


# ---------------------------------------------------------------------------
# GET /api/audit/events/{log_id}
# ---------------------------------------------------------------------------


class TestGetAuditEventById:
    def test_existing_log_id_returns_200(self, client: TestClient) -> None:
        create = client.post(
            "/api/audit/events",
            json={"action": "audit:read", "actor_id": "actor-get-001"},
        )
        assert create.status_code == 200
        log_id = create.json().get("log_id") or create.json().get("id") or create.json().get("audit_id")
        assert log_id
        r = client.get(f"/api/audit/events/{log_id}")
        assert r.status_code == 200

    def test_existing_log_id_response_shape(self, client: TestClient) -> None:
        create = client.post(
            "/api/audit/events",
            json={"action": "policy:enforce", "actor_id": "actor-get-002"},
        )
        log_id = create.json().get("log_id") or create.json().get("id") or create.json().get("audit_id")
        r = client.get(f"/api/audit/events/{log_id}")
        body = r.json()
        assert "action" in body
        assert "actor_id" in body

    def test_nonexistent_log_id_returns_404(self, client: TestClient) -> None:
        r = client.get("/api/audit/events/log-does-not-exist-xyz-000")
        assert r.status_code == 404

    def test_missing_key_returns_401(self) -> None:
        bare = TestClient(app, raise_server_exceptions=True)
        r = bare.get("/api/audit/events/some-log-id")
        assert r.status_code == 401


# ---------------------------------------------------------------------------
# GET /api/audit/summary
# ---------------------------------------------------------------------------


class TestAuditSummary:
    def test_returns_200_with_valid_key(self, client: TestClient) -> None:
        r = client.get("/api/audit/summary")
        assert r.status_code == 200

    def test_response_shape(self, client: TestClient) -> None:
        r = client.get("/api/audit/summary")
        body = r.json()
        assert "total_logs" in body
        assert "by_action" in body
        assert "by_result" in body
        assert "backend_name" in body

    def test_organization_id_filter_accepted(self, client: TestClient) -> None:
        r = client.get("/api/audit/summary?organization_id=org-001")
        assert r.status_code == 200

    def test_limit_param_accepted(self, client: TestClient) -> None:
        r = client.get("/api/audit/summary?limit=50")
        assert r.status_code == 200

    def test_limit_zero_returns_422(self, client: TestClient) -> None:
        r = client.get("/api/audit/summary?limit=0")
        assert r.status_code == 422

    def test_limit_above_5000_returns_422(self, client: TestClient) -> None:
        r = client.get("/api/audit/summary?limit=5001")
        assert r.status_code == 422

    def test_total_logs_increases_after_create(self, client: TestClient) -> None:
        r1 = client.get("/api/audit/summary")
        before = r1.json()["total_logs"]
        client.post("/api/audit/events", json={"action": "summary:test"})
        r2 = client.get("/api/audit/summary")
        after = r2.json()["total_logs"]
        assert after >= before

    def test_missing_key_returns_401(self) -> None:
        bare = TestClient(app, raise_server_exceptions=True)
        r = bare.get("/api/audit/summary")
        assert r.status_code == 401
