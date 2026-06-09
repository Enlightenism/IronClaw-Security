from __future__ import annotations

from collections.abc import Iterator
import os

from fastapi.testclient import TestClient
import pytest

os.environ["IRONCLAW_PERSISTENCE_MODE"] = "memory"
os.environ["ENVIRONMENT"] = "test"
os.environ["IRONCLAW_API_KEY"] = "test-api-key"
os.environ["AUTH_REQUIRED"] = "true"
os.environ["IRONCLAW_RATE_LIMIT_ENABLED"] = "false"
os.environ["SUPABASE_URL"] = ""
os.environ["SUPABASE_SERVICE_ROLE_KEY"] = ""
os.environ["SUPABASE_KEY"] = ""
os.environ["SUPABASE_ANON_KEY"] = ""

from app.core.auth import AuthContext, require_auth_context
from app.core.settings import get_settings
from app.main import app
from app.services.audit_log_service import reset_audit_log

_VALID_KEY = os.environ["IRONCLAW_API_KEY"]
_BAD_KEY = "ic-bad-key-000"

# Actual route that exists in app/api/audit.py (prefix=/audit, route=/event)
_AUDIT_EVENT_ROUTE = "/api/audit/event"

_VALID_PAYLOAD = {
    "actiontype": "toolcall",
    "target": "https://example.com/api",
    "content": "Test prompt for audit event creation",
    "riskscore": 25,
    "clientid": "test-client-001",
    "sessionid": "test-session-001",
}

_TEST_AUTH_CONTEXT = AuthContext(
    api_key=_VALID_KEY,
    principal_type="api_key",
    principal_id="test-principal",
    session_id=None,
    org_id="test-org",
    permissions=(),
    roles=(),
    authenticated=True,
    auth_source="test",
    auth_method="api_key",
)


def _override_require_auth_context() -> AuthContext:
    return _TEST_AUTH_CONTEXT


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


@pytest.fixture(autouse=True)
def override_auth() -> Iterator[None]:
    app.dependency_overrides[require_auth_context] = _override_require_auth_context
    yield
    app.dependency_overrides.pop(require_auth_context, None)


@pytest.fixture()
def client() -> TestClient:
    c = TestClient(app, raise_server_exceptions=True)
    c.headers.update(_auth())
    return c


# ---------------------------------------------------------------------------
# POST /api/audit/event — creation and response shape
# ---------------------------------------------------------------------------


class TestCreateAuditEvent:
    def test_returns_200_with_valid_payload(self, client: TestClient) -> None:
        r = client.post(_AUDIT_EVENT_ROUTE, json=_VALID_PAYLOAD)
        assert r.status_code == 200

    def test_response_is_json(self, client: TestClient) -> None:
        r = client.post(_AUDIT_EVENT_ROUTE, json=_VALID_PAYLOAD)
        assert r.headers.get("content-type", "").startswith("application/json")

    def test_response_contains_auditeventid(self, client: TestClient) -> None:
        r = client.post(_AUDIT_EVENT_ROUTE, json=_VALID_PAYLOAD)
        body = r.json()
        assert "auditeventid" in body
        assert str(body["auditeventid"]).strip() != ""

    def test_auditeventid_has_audit_prefix(self, client: TestClient) -> None:
        r = client.post(_AUDIT_EVENT_ROUTE, json=_VALID_PAYLOAD)
        assert r.json()["auditeventid"].startswith("audit_")

    def test_response_contains_eventtype(self, client: TestClient) -> None:
        r = client.post(_AUDIT_EVENT_ROUTE, json=_VALID_PAYLOAD)
        assert "eventtype" in r.json()

    def test_response_contains_severity(self, client: TestClient) -> None:
        r = client.post(_AUDIT_EVENT_ROUTE, json=_VALID_PAYLOAD)
        assert "severity" in r.json()

    def test_response_contains_actiontype(self, client: TestClient) -> None:
        r = client.post(_AUDIT_EVENT_ROUTE, json=_VALID_PAYLOAD)
        assert r.json()["actiontype"] == "toolcall"

    def test_response_contains_target(self, client: TestClient) -> None:
        r = client.post(_AUDIT_EVENT_ROUTE, json=_VALID_PAYLOAD)
        assert r.json()["target"] == "https://example.com/api"

    def test_response_contains_createdat(self, client: TestClient) -> None:
        r = client.post(_AUDIT_EVENT_ROUTE, json=_VALID_PAYLOAD)
        assert "createdat" in r.json()

    def test_response_contains_traceid(self, client: TestClient) -> None:
        r = client.post(_AUDIT_EVENT_ROUTE, json=_VALID_PAYLOAD)
        assert "traceid" in r.json()

    def test_response_contains_requestid(self, client: TestClient) -> None:
        r = client.post(_AUDIT_EVENT_ROUTE, json=_VALID_PAYLOAD)
        assert "requestid" in r.json()

    def test_response_contains_decisionid(self, client: TestClient) -> None:
        r = client.post(_AUDIT_EVENT_ROUTE, json=_VALID_PAYLOAD)
        assert "decisionid" in r.json()

    def test_response_contains_baseriskscore(self, client: TestClient) -> None:
        r = client.post(_AUDIT_EVENT_ROUTE, json=_VALID_PAYLOAD)
        assert "baseriskscore" in r.json()

    def test_response_contains_adjustedriskscore(self, client: TestClient) -> None:
        r = client.post(_AUDIT_EVENT_ROUTE, json=_VALID_PAYLOAD)
        assert "adjustedriskscore" in r.json()

    def test_response_contains_reasons_list(self, client: TestClient) -> None:
        r = client.post(_AUDIT_EVENT_ROUTE, json=_VALID_PAYLOAD)
        assert isinstance(r.json().get("reasons"), list)

    def test_response_contains_promptinjection_dict(self, client: TestClient) -> None:
        r = client.post(_AUDIT_EVENT_ROUTE, json=_VALID_PAYLOAD)
        assert isinstance(r.json().get("promptinjection"), dict)

    def test_response_contains_hostilecontext_dict(self, client: TestClient) -> None:
        r = client.post(_AUDIT_EVENT_ROUTE, json=_VALID_PAYLOAD)
        assert isinstance(r.json().get("hostilecontext"), dict)

    def test_response_contains_summary(self, client: TestClient) -> None:
        r = client.post(_AUDIT_EVENT_ROUTE, json=_VALID_PAYLOAD)
        assert "summary" in r.json()
        assert isinstance(r.json()["summary"], str)

    def test_eventtype_valid_literal(self, client: TestClient) -> None:
        r = client.post(_AUDIT_EVENT_ROUTE, json=_VALID_PAYLOAD)
        valid = {
            "execution_allowed",
            "execution_review",
            "execution_quarantined",
            "execution_denied",
        }
        assert r.json()["eventtype"] in valid

    def test_severity_valid_literal(self, client: TestClient) -> None:
        r = client.post(_AUDIT_EVENT_ROUTE, json=_VALID_PAYLOAD)
        valid = {"info", "warning", "high", "critical"}
        assert r.json()["severity"] in valid

    def test_high_riskscore_yields_denied_or_quarantined(self, client: TestClient) -> None:
        payload = {**_VALID_PAYLOAD, "riskscore": 95}
        r = client.post(_AUDIT_EVENT_ROUTE, json=payload)
        assert r.status_code == 200
        assert r.json()["eventtype"] in {"execution_denied", "execution_quarantined"}

    def test_zero_riskscore_accepted(self, client: TestClient) -> None:
        payload = {**_VALID_PAYLOAD, "riskscore": 0}
        r = client.post(_AUDIT_EVENT_ROUTE, json=payload)
        assert r.status_code == 200

    def test_riskscore_above_100_returns_422(self, client: TestClient) -> None:
        payload = {**_VALID_PAYLOAD, "riskscore": 101}
        r = client.post(_AUDIT_EVENT_ROUTE, json=payload)
        assert r.status_code == 422

    def test_riskscore_below_0_returns_422(self, client: TestClient) -> None:
        payload = {**_VALID_PAYLOAD, "riskscore": -1}
        r = client.post(_AUDIT_EVENT_ROUTE, json=payload)
        assert r.status_code == 422

    def test_missing_actiontype_returns_422(self, client: TestClient) -> None:
        payload = {k: v for k, v in _VALID_PAYLOAD.items() if k != "actiontype"}
        r = client.post(_AUDIT_EVENT_ROUTE, json=payload)
        assert r.status_code == 422

    def test_missing_target_returns_422(self, client: TestClient) -> None:
        payload = {k: v for k, v in _VALID_PAYLOAD.items() if k != "target"}
        r = client.post(_AUDIT_EVENT_ROUTE, json=payload)
        assert r.status_code == 422

    def test_missing_content_returns_422(self, client: TestClient) -> None:
        payload = {k: v for k, v in _VALID_PAYLOAD.items() if k != "content"}
        r = client.post(_AUDIT_EVENT_ROUTE, json=payload)
        assert r.status_code == 422

    def test_missing_riskscore_returns_422(self, client: TestClient) -> None:
        payload = {k: v for k, v in _VALID_PAYLOAD.items() if k != "riskscore"}
        r = client.post(_AUDIT_EVENT_ROUTE, json=payload)
        assert r.status_code == 422

    def test_extra_fields_rejected(self, client: TestClient) -> None:
        payload = {**_VALID_PAYLOAD, "unknown_field": "should_fail"}
        r = client.post(_AUDIT_EVENT_ROUTE, json=payload)
        assert r.status_code == 422

    def test_empty_actiontype_returns_422(self, client: TestClient) -> None:
        payload = {**_VALID_PAYLOAD, "actiontype": ""}
        r = client.post(_AUDIT_EVENT_ROUTE, json=payload)
        assert r.status_code == 422

    def test_empty_target_returns_422(self, client: TestClient) -> None:
        payload = {**_VALID_PAYLOAD, "target": ""}
        r = client.post(_AUDIT_EVENT_ROUTE, json=payload)
        assert r.status_code == 422

    def test_optional_fields_absent_accepted(self, client: TestClient) -> None:
        payload = {
            "actiontype": "httpfetch",
            "target": "https://example.com",
            "content": "minimal audit",
            "riskscore": 10,
        }
        r = client.post(_AUDIT_EVENT_ROUTE, json=payload)
        assert r.status_code == 200

    def test_metadata_dict_accepted(self, client: TestClient) -> None:
        payload = {**_VALID_PAYLOAD, "metadata": {"key": "value", "count": 3}}
        r = client.post(_AUDIT_EVENT_ROUTE, json=payload)
        assert r.status_code == 200

    def test_two_events_have_distinct_auditeventids(self, client: TestClient) -> None:
        r1 = client.post(_AUDIT_EVENT_ROUTE, json=_VALID_PAYLOAD)
        r2 = client.post(_AUDIT_EVENT_ROUTE, json=_VALID_PAYLOAD)
        assert r1.json()["auditeventid"] != r2.json()["auditeventid"]

    def test_two_events_have_distinct_traceids(self, client: TestClient) -> None:
        r1 = client.post(_AUDIT_EVENT_ROUTE, json=_VALID_PAYLOAD)
        r2 = client.post(_AUDIT_EVENT_ROUTE, json=_VALID_PAYLOAD)
        assert r1.json()["traceid"] != r2.json()["traceid"]

    def test_filepath_defaults_to_empty_string_when_absent(self, client: TestClient) -> None:
        payload = {
            "actiontype": "httpfetch",
            "target": "https://example.com",
            "content": "filepath absent",
            "riskscore": 5,
        }
        r = client.post(_AUDIT_EVENT_ROUTE, json=payload)
        assert "filepath" in r.json()
