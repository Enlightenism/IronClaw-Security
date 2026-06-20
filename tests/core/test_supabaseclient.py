from __future__ import annotations

from unittest.mock import MagicMock

import pytest
import requests

from app.supabaseclient import (
    BILLING_TIER_5K_PRICE_USD,
    BILLING_TIER_5K_UNITS,
    BILLING_TIER_25K_PRICE_USD,
    BILLING_TIER_25K_UNITS,
    BILLING_TIER_60K_PRICE_USD,
    BILLING_TIER_60K_UNITS,
    IRONCLAW_TABLES,
    SUPABASE_TIMEOUT_SECONDS,
    TOKENS_PER_UNIT,
    SupabaseAPIError,
    SupabaseClient,
    SupabaseClientError,
    SupabaseConfig,
    SupabaseConfigurationError,
    SupabaseConnectionError,
    SupabaseRequestError,
    create_supabase_client,
    createsupabaseclient,
    get_supabase_client,
    get_supabase_config,
    is_supabase_configured,
    supabaseclient,
)

# ---------------------------------------------------------------------------
# Shared test constants
# ---------------------------------------------------------------------------

_VALID_URL = "https://test.supabase.co"
_VALID_KEY = "service-role-key-abc123"

_ALL_19_TABLES: frozenset[str] = frozenset(
    {
        "scan_history",
        "scan_patterns",
        "policy_rules",
        "policy_sets",
        "policy_set_memberships",
        "agents",
        "agent_trust_profiles",
        "trust_events",
        "telemetry_events",
        "audit_events",
        "iocs",
        "threat_detections",
        "quarantine_items",
        "review_queue",
        "rate_limit_state",
        "tool_call_log",
        "sandbox_execution_log",
        "webhook_subscriptions",
        "webhook_deliveries",
    }
)


# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------


class TestModuleConstants:
    def test_supabase_timeout_is_positive_float(self) -> None:
        assert isinstance(SUPABASE_TIMEOUT_SECONDS, float)
        assert SUPABASE_TIMEOUT_SECONDS > 0

    def test_tokens_per_unit_value(self) -> None:
        assert TOKENS_PER_UNIT == 25_000

    def test_billing_5k_units(self) -> None:
        assert BILLING_TIER_5K_UNITS == 5_000

    def test_billing_5k_price(self) -> None:
        assert BILLING_TIER_5K_PRICE_USD == 20

    def test_billing_25k_units(self) -> None:
        assert BILLING_TIER_25K_UNITS == 25_000

    def test_billing_25k_price(self) -> None:
        assert BILLING_TIER_25K_PRICE_USD == 90

    def test_billing_60k_units(self) -> None:
        assert BILLING_TIER_60K_UNITS == 60_000

    def test_billing_60k_price(self) -> None:
        assert BILLING_TIER_60K_PRICE_USD == 180


# ---------------------------------------------------------------------------
# IRONCLAW_TABLES — membership contract
# ---------------------------------------------------------------------------


class TestIronclawTables:
    """IRONCLAW_TABLES must be a frozenset containing exactly the 19 canonical table names."""

    def test_is_frozenset(self) -> None:
        assert isinstance(IRONCLAW_TABLES, frozenset)

    def test_exact_count_is_19(self) -> None:
        assert len(IRONCLAW_TABLES) == 19, f"Expected 19 tables, got {len(IRONCLAW_TABLES)}. Present: {sorted(IRONCLAW_TABLES)}"

    def test_matches_canonical_set(self) -> None:
        assert IRONCLAW_TABLES == _ALL_19_TABLES, f"Missing: {_ALL_19_TABLES - IRONCLAW_TABLES}  Extra: {IRONCLAW_TABLES - _ALL_19_TABLES}"

    # --- legacy name must be absent ---

    def test_webhook_delivery_log_is_absent(self) -> None:
        assert "webhook_delivery_log" not in IRONCLAW_TABLES

    # --- correct webhook name must be present ---

    def test_webhook_deliveries_is_present(self) -> None:
        assert "webhook_deliveries" in IRONCLAW_TABLES

    # --- core scan pipeline ---

    def test_scan_history_present(self) -> None:
        assert "scan_history" in IRONCLAW_TABLES

    def test_scan_patterns_present(self) -> None:
        assert "scan_patterns" in IRONCLAW_TABLES

    # --- policy engine ---

    def test_policy_rules_present(self) -> None:
        assert "policy_rules" in IRONCLAW_TABLES

    def test_policy_sets_present(self) -> None:
        assert "policy_sets" in IRONCLAW_TABLES

    def test_policy_set_memberships_present(self) -> None:
        assert "policy_set_memberships" in IRONCLAW_TABLES

    # --- agents ---

    def test_agents_present(self) -> None:
        assert "agents" in IRONCLAW_TABLES

    # --- telemetry ---

    def test_telemetry_events_present(self) -> None:
        assert "telemetry_events" in IRONCLAW_TABLES

    # --- webhook subscriptions ---

    def test_webhook_subscriptions_present(self) -> None:
        assert "webhook_subscriptions" in IRONCLAW_TABLES

    # --- 10 newly added tables ---

    def test_audit_events_present(self) -> None:
        assert "audit_events" in IRONCLAW_TABLES

    def test_quarantine_items_present(self) -> None:
        assert "quarantine_items" in IRONCLAW_TABLES

    def test_review_queue_present(self) -> None:
        assert "review_queue" in IRONCLAW_TABLES

    def test_iocs_present(self) -> None:
        assert "iocs" in IRONCLAW_TABLES

    def test_threat_detections_present(self) -> None:
        assert "threat_detections" in IRONCLAW_TABLES

    def test_tool_call_log_present(self) -> None:
        assert "tool_call_log" in IRONCLAW_TABLES

    def test_sandbox_execution_log_present(self) -> None:
        assert "sandbox_execution_log" in IRONCLAW_TABLES

    def test_rate_limit_state_present(self) -> None:
        assert "rate_limit_state" in IRONCLAW_TABLES

    def test_agent_trust_profiles_present(self) -> None:
        assert "agent_trust_profiles" in IRONCLAW_TABLES

    def test_trust_events_present(self) -> None:
        assert "trust_events" in IRONCLAW_TABLES

    def test_is_immutable(self) -> None:
        with pytest.raises((AttributeError, TypeError)):
            IRONCLAW_TABLES.add("rogue_table")  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------


class TestExceptionHierarchy:
    def test_supabase_client_error_is_runtime_error(self) -> None:
        assert issubclass(SupabaseClientError, RuntimeError)

    def test_configuration_error_is_client_error(self) -> None:
        assert issubclass(SupabaseConfigurationError, SupabaseClientError)

    def test_connection_error_is_client_error(self) -> None:
        assert issubclass(SupabaseConnectionError, SupabaseClientError)

    def test_request_error_is_client_error(self) -> None:
        assert issubclass(SupabaseRequestError, SupabaseClientError)

    def test_api_error_is_client_error(self) -> None:
        assert issubclass(SupabaseAPIError, SupabaseClientError)

    def test_configuration_error_is_raiseable(self) -> None:
        with pytest.raises(SupabaseConfigurationError):
            raise SupabaseConfigurationError("test")

    def test_api_error_is_raiseable(self) -> None:
        with pytest.raises(SupabaseAPIError):
            raise SupabaseAPIError("test")

    def test_connection_error_is_raiseable(self) -> None:
        with pytest.raises(SupabaseConnectionError):
            raise SupabaseConnectionError("test")

    def test_request_error_is_raiseable(self) -> None:
        with pytest.raises(SupabaseRequestError):
            raise SupabaseRequestError("test")


# ---------------------------------------------------------------------------
# SupabaseConfig dataclass
# ---------------------------------------------------------------------------


class TestSupabaseConfig:
    def _make(self, url: str = _VALID_URL, key: str = _VALID_KEY) -> SupabaseConfig:
        return SupabaseConfig(url=url, key=key)

    def test_rest_url_suffix(self) -> None:
        cfg = self._make()
        assert cfg.rest_url == f"{_VALID_URL}/rest/v1"

    def test_auth_url_suffix(self) -> None:
        cfg = self._make()
        assert cfg.auth_url == f"{_VALID_URL}/auth/v1"

    def test_storage_url_suffix(self) -> None:
        cfg = self._make()
        assert cfg.storage_url == f"{_VALID_URL}/storage/v1"

    def test_functions_url_suffix(self) -> None:
        cfg = self._make()
        assert cfg.functions_url == f"{_VALID_URL}/functions/v1"

    def test_trailing_slash_stripped_in_rest_url(self) -> None:
        cfg = self._make(url=_VALID_URL + "/")
        assert cfg.rest_url == f"{_VALID_URL}/rest/v1"

    def test_is_frozen(self) -> None:
        cfg = self._make()
        with pytest.raises((AttributeError, TypeError)):
            cfg.url = "https://mutated.supabase.co"  # type: ignore[misc]

    def test_url_stored_as_provided(self) -> None:
        cfg = self._make()
        assert cfg.url == _VALID_URL

    def test_key_stored_as_provided(self) -> None:
        cfg = self._make()
        assert cfg.key == _VALID_KEY


# ---------------------------------------------------------------------------
# get_supabase_config
# ---------------------------------------------------------------------------


class TestGetSupabaseConfig:
    def test_raises_missing_url(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("SUPABASE_URL", raising=False)
        monkeypatch.delenv("IRONCLAW_SUPABASE_URL", raising=False)
        monkeypatch.delenv("NEXT_PUBLIC_SUPABASE_URL", raising=False)
        monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", _VALID_KEY)
        with pytest.raises(SupabaseConfigurationError, match="missing SUPABASE_URL"):
            get_supabase_config()

    def test_raises_missing_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SUPABASE_URL", _VALID_URL)
        monkeypatch.delenv("SUPABASE_SERVICE_ROLE_KEY", raising=False)
        monkeypatch.delenv("SUPABASE_KEY", raising=False)
        monkeypatch.delenv("IRONCLAW_SUPABASE_KEY", raising=False)
        monkeypatch.delenv("SUPABASE_ANON_KEY", raising=False)
        monkeypatch.delenv("NEXT_PUBLIC_SUPABASE_ANON_KEY", raising=False)
        with pytest.raises(SupabaseConfigurationError, match="missing supabase api key"):
            get_supabase_config()

    def test_raises_invalid_scheme(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SUPABASE_URL", "ftp://bad.supabase.co")
        monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", _VALID_KEY)
        with pytest.raises(SupabaseConfigurationError, match="http"):
            get_supabase_config()

    def test_returns_config_on_valid_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SUPABASE_URL", _VALID_URL)
        monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", _VALID_KEY)
        cfg = get_supabase_config()
        assert isinstance(cfg, SupabaseConfig)
        assert cfg.url == _VALID_URL
        assert cfg.key == _VALID_KEY

    def test_trailing_slash_stripped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SUPABASE_URL", _VALID_URL + "/")
        monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", _VALID_KEY)
        cfg = get_supabase_config()
        assert not cfg.url.endswith("/")

    def test_ironclaw_url_fallback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("SUPABASE_URL", raising=False)
        monkeypatch.setenv("IRONCLAW_SUPABASE_URL", _VALID_URL)
        monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", _VALID_KEY)
        cfg = get_supabase_config()
        assert cfg.url == _VALID_URL

    def test_next_public_url_fallback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("SUPABASE_URL", raising=False)
        monkeypatch.delenv("IRONCLAW_SUPABASE_URL", raising=False)
        monkeypatch.setenv("NEXT_PUBLIC_SUPABASE_URL", _VALID_URL)
        monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", _VALID_KEY)
        cfg = get_supabase_config()
        assert cfg.url == _VALID_URL

    def test_service_role_key_preferred_over_anon_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SUPABASE_URL", _VALID_URL)
        monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", "service-key")
        monkeypatch.setenv("SUPABASE_ANON_KEY", "anon-key")
        cfg = get_supabase_config()
        assert cfg.key == "service-key"

    def test_blank_url_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SUPABASE_URL", "   ")
        monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", _VALID_KEY)
        with pytest.raises(SupabaseConfigurationError):
            get_supabase_config()

    def test_blank_key_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SUPABASE_URL", _VALID_URL)
        monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", "   ")
        monkeypatch.delenv("SUPABASE_KEY", raising=False)
        monkeypatch.delenv("IRONCLAW_SUPABASE_KEY", raising=False)
        monkeypatch.delenv("SUPABASE_ANON_KEY", raising=False)
        monkeypatch.delenv("NEXT_PUBLIC_SUPABASE_ANON_KEY", raising=False)
        with pytest.raises(SupabaseConfigurationError):
            get_supabase_config()


# ---------------------------------------------------------------------------
# is_supabase_configured
# ---------------------------------------------------------------------------


class TestIsSupabaseConfigured:
    def test_returns_true_when_both_present(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SUPABASE_URL", _VALID_URL)
        monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", _VALID_KEY)
        assert is_supabase_configured() is True

    def test_returns_false_when_url_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("SUPABASE_URL", raising=False)
        monkeypatch.delenv("IRONCLAW_SUPABASE_URL", raising=False)
        monkeypatch.delenv("NEXT_PUBLIC_SUPABASE_URL", raising=False)
        monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", _VALID_KEY)
        assert is_supabase_configured() is False

    def test_returns_false_when_key_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SUPABASE_URL", _VALID_URL)
        monkeypatch.delenv("SUPABASE_SERVICE_ROLE_KEY", raising=False)
        monkeypatch.delenv("SUPABASE_KEY", raising=False)
        monkeypatch.delenv("IRONCLAW_SUPABASE_KEY", raising=False)
        monkeypatch.delenv("SUPABASE_ANON_KEY", raising=False)
        monkeypatch.delenv("NEXT_PUBLIC_SUPABASE_ANON_KEY", raising=False)
        assert is_supabase_configured() is False

    def test_returns_false_for_invalid_scheme(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SUPABASE_URL", "ftp://bad.supabase.co")
        monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", _VALID_KEY)
        assert is_supabase_configured() is False

    def test_returns_false_for_blank_url(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SUPABASE_URL", "  ")
        monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", _VALID_KEY)
        assert is_supabase_configured() is False


# ---------------------------------------------------------------------------
# SupabaseClient construction
# ---------------------------------------------------------------------------


class TestSupabaseClientConstruction:
    def test_default_timeout_applied(self) -> None:
        cfg = SupabaseConfig(url=_VALID_URL, key=_VALID_KEY)
        client = SupabaseClient(config=cfg)
        assert client.timeout == SUPABASE_TIMEOUT_SECONDS

    def test_custom_timeout_applied(self) -> None:
        cfg = SupabaseConfig(url=_VALID_URL, key=_VALID_KEY)
        client = SupabaseClient(config=cfg, timeout=30.0)
        assert client.timeout == 30.0

    def test_zero_timeout_raises(self) -> None:
        cfg = SupabaseConfig(url=_VALID_URL, key=_VALID_KEY)
        with pytest.raises(ValueError):
            SupabaseClient(config=cfg, timeout=0)

    def test_negative_timeout_raises(self) -> None:
        cfg = SupabaseConfig(url=_VALID_URL, key=_VALID_KEY)
        with pytest.raises(ValueError):
            SupabaseClient(config=cfg, timeout=-1.0)

    def test_custom_session_stored(self) -> None:
        cfg = SupabaseConfig(url=_VALID_URL, key=_VALID_KEY)
        sess = requests.Session()
        client = SupabaseClient(config=cfg, session=sess)
        assert client.session is sess

    def test_headers_contain_apikey(self) -> None:
        cfg = SupabaseConfig(url=_VALID_URL, key=_VALID_KEY)
        client = SupabaseClient(config=cfg)
        assert client.headers["apikey"] == _VALID_KEY

    def test_headers_contain_bearer(self) -> None:
        cfg = SupabaseConfig(url=_VALID_URL, key=_VALID_KEY)
        client = SupabaseClient(config=cfg)
        assert client.headers["Authorization"] == f"Bearer {_VALID_KEY}"

    def test_is_configured_property(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SUPABASE_URL", _VALID_URL)
        monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", _VALID_KEY)
        cfg = SupabaseConfig(url=_VALID_URL, key=_VALID_KEY)
        client = SupabaseClient(config=cfg)
        assert client.is_configured is True


# ---------------------------------------------------------------------------
# SupabaseClient.request — HTTP error mapping
# ---------------------------------------------------------------------------


def _make_client() -> SupabaseClient:
    cfg = SupabaseConfig(url=_VALID_URL, key=_VALID_KEY)
    return SupabaseClient(config=cfg)


def _mock_response(status: int, body: object = None, content_type: str = "application/json") -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.content = b"body" if body is not None else b""
    resp.headers = {"content-type": content_type}
    if body is not None:
        resp.json.return_value = body
        import json as _json

        resp.text = _json.dumps(body)
    else:
        resp.json.side_effect = ValueError("no content")
        resp.text = ""
    return resp


class TestSupabaseClientRequest:
    def test_raises_connection_error_on_connection_failure(self) -> None:
        client = _make_client()
        client.session.request = MagicMock(side_effect=requests.ConnectionError("refused"))
        with pytest.raises(SupabaseConnectionError, match="connection failed"):
            client.request("GET", f"{_VALID_URL}/rest/v1/scan_history")

    def test_raises_connection_error_on_timeout(self) -> None:
        client = _make_client()
        client.session.request = MagicMock(side_effect=requests.Timeout("timed out"))
        with pytest.raises(SupabaseConnectionError, match="timed out"):
            client.request("GET", f"{_VALID_URL}/rest/v1/scan_history")

    def test_raises_request_error_on_generic_exception(self) -> None:
        client = _make_client()
        client.session.request = MagicMock(side_effect=requests.RequestException("generic"))
        with pytest.raises(SupabaseRequestError):
            client.request("GET", f"{_VALID_URL}/rest/v1/scan_history")

    def test_raises_api_error_on_400(self) -> None:
        client = _make_client()
        client.session.request = MagicMock(return_value=_mock_response(400, {"message": "bad request"}))
        with pytest.raises(SupabaseAPIError, match="400"):
            client.request("GET", f"{_VALID_URL}/rest/v1/scan_history")

    def test_raises_api_error_on_401(self) -> None:
        client = _make_client()
        client.session.request = MagicMock(return_value=_mock_response(401, {"message": "unauthorized"}))
        with pytest.raises(SupabaseAPIError, match="401"):
            client.request("GET", f"{_VALID_URL}/rest/v1/scan_history")

    def test_raises_api_error_on_500(self) -> None:
        client = _make_client()
        client.session.request = MagicMock(return_value=_mock_response(500, {"message": "internal"}))
        with pytest.raises(SupabaseAPIError, match="500"):
            client.request("GET", f"{_VALID_URL}/rest/v1/scan_history")

    def test_returns_none_on_empty_body(self) -> None:
        client = _make_client()
        client.session.request = MagicMock(return_value=_mock_response(200, body=None))
        result = client.request("DELETE", f"{_VALID_URL}/rest/v1/scan_history")
        assert result is None

    def test_returns_parsed_json_list(self) -> None:
        client = _make_client()
        payload = [{"id": "1", "content": "test"}]
        client.session.request = MagicMock(return_value=_mock_response(200, payload))
        result = client.request("GET", f"{_VALID_URL}/rest/v1/scan_history")
        assert result == payload

    def test_returns_parsed_json_dict(self) -> None:
        client = _make_client()
        payload = {"id": "abc", "status": "ok"}
        client.session.request = MagicMock(return_value=_mock_response(200, payload))
        result = client.request("GET", f"{_VALID_URL}/rest/v1/agents")
        assert result == payload

    def test_api_error_message_extracted_from_body(self) -> None:
        client = _make_client()
        client.session.request = MagicMock(return_value=_mock_response(422, {"message": "column not found"}))
        with pytest.raises(SupabaseAPIError, match="column not found"):
            client.request("GET", f"{_VALID_URL}/rest/v1/scan_history")


# ---------------------------------------------------------------------------
# SupabaseClient.select
# ---------------------------------------------------------------------------


class TestSupabaseClientSelect:
    def test_raises_on_empty_table(self) -> None:
        client = _make_client()
        with pytest.raises(ValueError, match="table is required"):
            client.select("")

    def test_raises_on_blank_table(self) -> None:
        client = _make_client()
        with pytest.raises(ValueError, match="table is required"):
            client.select("   ")

    def test_raises_on_zero_limit(self) -> None:
        client = _make_client()
        client.session.request = MagicMock(return_value=_mock_response(200, []))
        with pytest.raises(ValueError, match="limit must be greater than zero"):
            client.select("scan_history", limit=0)

    def test_raises_on_negative_limit(self) -> None:
        client = _make_client()
        client.session.request = MagicMock(return_value=_mock_response(200, []))
        with pytest.raises(ValueError, match="limit must be greater than zero"):
            client.select("scan_history", limit=-5)

    def test_returns_list_on_success(self) -> None:
        client = _make_client()
        rows = [{"id": "1"}, {"id": "2"}]
        client.session.request = MagicMock(return_value=_mock_response(200, rows))
        result = client.select("scan_history")
        assert result == rows

    def test_returns_list_wrapping_dict(self) -> None:
        client = _make_client()
        client.session.request = MagicMock(return_value=_mock_response(200, {"id": "1"}))
        result = client.select("scan_history")
        assert result == [{"id": "1"}]

    def test_returns_empty_list_on_null_body(self) -> None:
        client = _make_client()
        client.session.request = MagicMock(return_value=_mock_response(200, body=None))
        result = client.select("scan_history")
        assert result == []

    def test_passes_select_param(self) -> None:
        client = _make_client()
        client.session.request = MagicMock(return_value=_mock_response(200, []))
        client.select("scan_history", columns="id,content")
        call_kwargs = client.session.request.call_args
        params = call_kwargs.kwargs.get("params") or call_kwargs[1].get("params") or {}
        assert params.get("select") == "id,content"

    def test_passes_limit_param(self) -> None:
        client = _make_client()
        client.session.request = MagicMock(return_value=_mock_response(200, []))
        client.select("scan_history", limit=10)
        call_kwargs = client.session.request.call_args
        params = call_kwargs.kwargs.get("params") or call_kwargs[1].get("params") or {}
        assert params.get("limit") == "10"

    def test_passes_order_asc(self) -> None:
        client = _make_client()
        client.session.request = MagicMock(return_value=_mock_response(200, []))
        client.select("scan_history", order="created_at", ascending=True)
        call_kwargs = client.session.request.call_args
        params = call_kwargs.kwargs.get("params") or call_kwargs[1].get("params") or {}
        assert params.get("order") == "created_at.asc"

    def test_passes_order_desc(self) -> None:
        client = _make_client()
        client.session.request = MagicMock(return_value=_mock_response(200, []))
        client.select("scan_history", order="created_at", ascending=False)
        call_kwargs = client.session.request.call_args
        params = call_kwargs.kwargs.get("params") or call_kwargs[1].get("params") or {}
        assert params.get("order") == "created_at.desc"


# ---------------------------------------------------------------------------
# SupabaseClient.insert
# ---------------------------------------------------------------------------


class TestSupabaseClientInsert:
    def test_raises_on_empty_table(self) -> None:
        client = _make_client()
        with pytest.raises(ValueError, match="table is required"):
            client.insert("", {"col": "val"})

    def test_raises_on_none_payload(self) -> None:
        client = _make_client()
        with pytest.raises(ValueError, match="payload is required"):
            client.insert("scan_history", None)  # type: ignore[arg-type]

    def test_returns_list_on_success(self) -> None:
        client = _make_client()
        rows = [{"id": "new-id"}]
        client.session.request = MagicMock(return_value=_mock_response(201, rows))
        result = client.insert("scan_history", {"content": "test"})
        assert result == rows

    def test_sends_post_method(self) -> None:
        client = _make_client()
        client.session.request = MagicMock(return_value=_mock_response(201, [{"id": "1"}]))
        client.insert("scan_history", {"content": "test"})
        method = client.session.request.call_args[1].get("method") or client.session.request.call_args[0][0]
        assert method.upper() == "POST"


# ---------------------------------------------------------------------------
# SupabaseClient.update
# ---------------------------------------------------------------------------


class TestSupabaseClientUpdate:
    def test_raises_on_empty_table(self) -> None:
        client = _make_client()
        with pytest.raises(ValueError, match="table is required"):
            client.update("", {"status": "ok"}, filters={"id": "eq.1"})

    def test_raises_on_empty_payload(self) -> None:
        client = _make_client()
        with pytest.raises(ValueError, match="payload is required"):
            client.update("scan_history", {}, filters={"id": "eq.1"})

    def test_raises_on_empty_filters(self) -> None:
        client = _make_client()
        with pytest.raises(ValueError, match="filters are required"):
            client.update("scan_history", {"status": "ok"}, filters={})

    def test_returns_list_on_success(self) -> None:
        client = _make_client()
        rows = [{"id": "1", "status": "ok"}]
        client.session.request = MagicMock(return_value=_mock_response(200, rows))
        result = client.update("scan_history", {"status": "ok"}, filters={"id": "eq.1"})
        assert result == rows


# ---------------------------------------------------------------------------
# SupabaseClient.delete
# ---------------------------------------------------------------------------


class TestSupabaseClientDelete:
    def test_raises_on_empty_table(self) -> None:
        client = _make_client()
        with pytest.raises(ValueError, match="table is required"):
            client.delete("", filters={"id": "eq.1"})

    def test_raises_on_empty_filters(self) -> None:
        client = _make_client()
        with pytest.raises(ValueError, match="filters are required"):
            client.delete("scan_history", filters={})

    def test_returns_list_on_success(self) -> None:
        client = _make_client()
        rows = [{"id": "1"}]
        client.session.request = MagicMock(return_value=_mock_response(200, rows))
        result = client.delete("scan_history", filters={"id": "eq.1"})
        assert result == rows

    def test_sends_delete_method(self) -> None:
        client = _make_client()
        client.session.request = MagicMock(return_value=_mock_response(200, [{"id": "1"}]))
        client.delete("scan_history", filters={"id": "eq.1"})
        method = client.session.request.call_args[1].get("method") or client.session.request.call_args[0][0]
        assert method.upper() == "DELETE"


# ---------------------------------------------------------------------------
# SupabaseClient.rpc
# ---------------------------------------------------------------------------


class TestSupabaseClientRpc:
    def test_raises_on_empty_function_name(self) -> None:
        client = _make_client()
        with pytest.raises(ValueError, match="function_name is required"):
            client.rpc("")

    def test_raises_on_blank_function_name(self) -> None:
        client = _make_client()
        with pytest.raises(ValueError, match="function_name is required"):
            client.rpc("   ")

    def test_raises_on_non_serializable_payload(self) -> None:
        client = _make_client()
        with pytest.raises(SupabaseClientError, match="not JSON serializable"):
            client.rpc("my_fn", {"key": object()})

    def test_calls_correct_rpc_url(self) -> None:
        client = _make_client()
        client.session.request = MagicMock(return_value=_mock_response(200, {"result": True}))
        client.rpc("my_function")
        url_called = client.session.request.call_args[1].get("url") or client.session.request.call_args[0][1]
        assert "/rpc/my_function" in url_called

    def test_returns_response_body(self) -> None:
        client = _make_client()
        client.session.request = MagicMock(return_value=_mock_response(200, {"result": True}))
        result = client.rpc("my_function")
        assert result == {"result": True}


# ---------------------------------------------------------------------------
# Domain helpers — fetch_scan_patterns
# ---------------------------------------------------------------------------


class TestFetchScanPatterns:
    def test_queries_scan_patterns_table(self) -> None:
        client = _make_client()
        client.session.request = MagicMock(return_value=_mock_response(200, []))
        client.fetch_scan_patterns()
        url_called = client.session.request.call_args[1].get("url") or client.session.request.call_args[0][1]
        assert "scan_patterns" in url_called

    def test_enabled_filter_applied_by_default(self) -> None:
        client = _make_client()
        client.session.request = MagicMock(return_value=_mock_response(200, []))
        client.fetch_scan_patterns(enabled_only=True)
        call_kwargs = client.session.request.call_args
        params = call_kwargs.kwargs.get("params") or call_kwargs[1].get("params") or {}
        assert params.get("enabled") == "eq.true"

    def test_no_filter_when_enabled_only_false(self) -> None:
        client = _make_client()
        client.session.request = MagicMock(return_value=_mock_response(200, []))
        client.fetch_scan_patterns(enabled_only=False)
        call_kwargs = client.session.request.call_args
        params = call_kwargs.kwargs.get("params") or call_kwargs[1].get("params") or {}
        assert "enabled" not in params

    def test_returns_list(self) -> None:
        client = _make_client()
        rows = [{"id": "1", "pattern": "injection"}]
        client.session.request = MagicMock(return_value=_mock_response(200, rows))
        result = client.fetch_scan_patterns()
        assert result == rows


# ---------------------------------------------------------------------------
# Domain helpers — fetch_policy_rules
# ---------------------------------------------------------------------------


class TestFetchPolicyRules:
    def test_queries_policy_rules_table(self) -> None:
        client = _make_client()
        client.session.request = MagicMock(return_value=_mock_response(200, []))
        client.fetch_policy_rules()
        url_called = client.session.request.call_args[1].get("url") or client.session.request.call_args[0][1]
        assert "policy_rules" in url_called

    def test_enabled_filter_applied_by_default(self) -> None:
        client = _make_client()
        client.session.request = MagicMock(return_value=_mock_response(200, []))
        client.fetch_policy_rules(enabled_only=True)
        call_kwargs = client.session.request.call_args
        params = call_kwargs.kwargs.get("params") or call_kwargs[1].get("params") or {}
        assert params.get("enabled") == "eq.true"

    def test_no_filter_when_enabled_only_false(self) -> None:
        client = _make_client()
        client.session.request = MagicMock(return_value=_mock_response(200, []))
        client.fetch_policy_rules(enabled_only=False)
        call_kwargs = client.session.request.call_args
        params = call_kwargs.kwargs.get("params") or call_kwargs[1].get("params") or {}
        assert "enabled" not in params


# ---------------------------------------------------------------------------
# Domain helpers — fetch_policy_set
# ---------------------------------------------------------------------------


class TestFetchPolicySet:
    def test_raises_on_empty_set_key(self) -> None:
        client = _make_client()
        with pytest.raises(ValueError, match="set_key is required"):
            client.fetch_policy_set("")

    def test_raises_on_blank_set_key(self) -> None:
        client = _make_client()
        with pytest.raises(ValueError, match="set_key is required"):
            client.fetch_policy_set("   ")

    def test_returns_none_when_not_found(self) -> None:
        client = _make_client()
        client.session.request = MagicMock(return_value=_mock_response(200, []))
        result = client.fetch_policy_set("missing-key")
        assert result is None

    def test_returns_first_row_when_found(self) -> None:
        client = _make_client()
        rows = [{"id": "1", "set_key": "default"}]
        client.session.request = MagicMock(return_value=_mock_response(200, rows))
        result = client.fetch_policy_set("default")
        assert result == rows[0]

    def test_queries_policy_sets_table(self) -> None:
        client = _make_client()
        client.session.request = MagicMock(return_value=_mock_response(200, []))
        client.fetch_policy_set("default")
        url_called = client.session.request.call_args[1].get("url") or client.session.request.call_args[0][1]
        assert "policy_sets" in url_called


# ---------------------------------------------------------------------------
# Domain helpers — fetch_policy_set_memberships
# ---------------------------------------------------------------------------


class TestFetchPolicySetMemberships:
    def test_raises_on_empty_id(self) -> None:
        client = _make_client()
        with pytest.raises(ValueError, match="policy_set_id is required"):
            client.fetch_policy_set_memberships("")

    def test_raises_on_blank_id(self) -> None:
        client = _make_client()
        with pytest.raises(ValueError, match="policy_set_id is required"):
            client.fetch_policy_set_memberships("   ")

    def test_queries_policy_set_memberships_table(self) -> None:
        client = _make_client()
        client.session.request = MagicMock(return_value=_mock_response(200, []))
        client.fetch_policy_set_memberships("set-id-1")
        url_called = client.session.request.call_args[1].get("url") or client.session.request.call_args[0][1]
        assert "policy_set_memberships" in url_called

    def test_filter_applied_for_set_id(self) -> None:
        client = _make_client()
        client.session.request = MagicMock(return_value=_mock_response(200, []))
        client.fetch_policy_set_memberships("set-id-1")
        call_kwargs = client.session.request.call_args
        params = call_kwargs.kwargs.get("params") or call_kwargs[1].get("params") or {}
        assert params.get("policy_set_id") == "eq.set-id-1"

    def test_returns_list(self) -> None:
        client = _make_client()
        rows = [{"id": "1", "policy_set_id": "set-id-1", "rule_id": "r1"}]
        client.session.request = MagicMock(return_value=_mock_response(200, rows))
        result = client.fetch_policy_set_memberships("set-id-1")
        assert result == rows


# ---------------------------------------------------------------------------
# Domain helpers — fetch_webhook_subscriptions
# ---------------------------------------------------------------------------


class TestFetchWebhookSubscriptions:
    def test_queries_webhook_subscriptions_table(self) -> None:
        client = _make_client()
        client.session.request = MagicMock(return_value=_mock_response(200, []))
        client.fetch_webhook_subscriptions()
        url_called = client.session.request.call_args[1].get("url") or client.session.request.call_args[0][1]
        assert "webhook_subscriptions" in url_called

    def test_active_filter_applied_by_default(self) -> None:
        client = _make_client()
        client.session.request = MagicMock(return_value=_mock_response(200, []))
        client.fetch_webhook_subscriptions(active_only=True)
        call_kwargs = client.session.request.call_args
        params = call_kwargs.kwargs.get("params") or call_kwargs[1].get("params") or {}
        assert params.get("active") == "eq.true"

    def test_no_filter_when_active_only_false(self) -> None:
        client = _make_client()
        client.session.request = MagicMock(return_value=_mock_response(200, []))
        client.fetch_webhook_subscriptions(active_only=False)
        call_kwargs = client.session.request.call_args
        params = call_kwargs.kwargs.get("params") or call_kwargs[1].get("params") or {}
        assert "active" not in params


# ---------------------------------------------------------------------------
# Domain helpers — fetch_webhook_delivery_log
# (must query webhook_deliveries, NOT webhook_delivery_log)
# ---------------------------------------------------------------------------


class TestFetchWebhookDeliveryLog:
    def test_queries_webhook_deliveries_not_legacy_table(self) -> None:
        client = _make_client()
        client.session.request = MagicMock(return_value=_mock_response(200, []))
        client.fetch_webhook_delivery_log()
        url_called = client.session.request.call_args[1].get("url") or client.session.request.call_args[0][1]
        assert "webhook_deliveries" in url_called
        assert "webhook_delivery_log" not in url_called

    def test_does_not_query_legacy_webhook_delivery_log(self) -> None:
        client = _make_client()
        client.session.request = MagicMock(return_value=_mock_response(200, []))
        client.fetch_webhook_delivery_log()
        url_called = client.session.request.call_args[1].get("url") or client.session.request.call_args[0][1]
        assert "webhook_delivery_log" not in url_called

    def test_subscription_id_filter_applied(self) -> None:
        client = _make_client()
        client.session.request = MagicMock(return_value=_mock_response(200, []))
        client.fetch_webhook_delivery_log(subscription_id="sub-123")
        call_kwargs = client.session.request.call_args
        params = call_kwargs.kwargs.get("params") or call_kwargs[1].get("params") or {}
        assert params.get("subscription_id") == "eq.sub-123"

    def test_no_subscription_filter_when_absent(self) -> None:
        client = _make_client()
        client.session.request = MagicMock(return_value=_mock_response(200, []))
        client.fetch_webhook_delivery_log()
        call_kwargs = client.session.request.call_args
        params = call_kwargs.kwargs.get("params") or call_kwargs[1].get("params") or {}
        assert "subscription_id" not in params

    def test_default_limit_applied(self) -> None:
        client = _make_client()
        client.session.request = MagicMock(return_value=_mock_response(200, []))
        client.fetch_webhook_delivery_log()
        call_kwargs = client.session.request.call_args
        params = call_kwargs.kwargs.get("params") or call_kwargs[1].get("params") or {}
        assert params.get("limit") == "100"

    def test_custom_limit_applied(self) -> None:
        client = _make_client()
        client.session.request = MagicMock(return_value=_mock_response(200, []))
        client.fetch_webhook_delivery_log(limit=25)
        call_kwargs = client.session.request.call_args
        params = call_kwargs.kwargs.get("params") or call_kwargs[1].get("params") or {}
        assert params.get("limit") == "25"

    def test_orders_by_created_at_desc(self) -> None:
        client = _make_client()
        client.session.request = MagicMock(return_value=_mock_response(200, []))
        client.fetch_webhook_delivery_log()
        call_kwargs = client.session.request.call_args
        params = call_kwargs.kwargs.get("params") or call_kwargs[1].get("params") or {}
        assert params.get("order") == "created_at.desc"

    def test_returns_list(self) -> None:
        client = _make_client()
        rows = [{"id": "1", "subscription_id": "sub-1", "status": "delivered"}]
        client.session.request = MagicMock(return_value=_mock_response(200, rows))
        result = client.fetch_webhook_delivery_log()
        assert result == rows


# ---------------------------------------------------------------------------
# Factory functions — aliasing contracts
# ---------------------------------------------------------------------------


class TestFactoryFunctions:
    def test_create_supabase_client_returns_supabase_client(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SUPABASE_URL", _VALID_URL)
        monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", _VALID_KEY)
        client = create_supabase_client()
        assert isinstance(client, SupabaseClient)

    def test_get_supabase_client_returns_supabase_client(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SUPABASE_URL", _VALID_URL)
        monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", _VALID_KEY)
        client = get_supabase_client()
        assert isinstance(client, SupabaseClient)

    def test_createsupabaseclient_alias_returns_supabase_client(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SUPABASE_URL", _VALID_URL)
        monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", _VALID_KEY)
        client = createsupabaseclient()
        assert isinstance(client, SupabaseClient)

    def test_supabaseclient_alias_is_callable(self) -> None:
        assert callable(supabaseclient)

    def test_custom_timeout_forwarded_by_create(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SUPABASE_URL", _VALID_URL)
        monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", _VALID_KEY)
        client = create_supabase_client(timeout=99.0)
        assert client.timeout == 99.0

    def test_custom_session_forwarded_by_create(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SUPABASE_URL", _VALID_URL)
        monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", _VALID_KEY)
        sess = requests.Session()
        client = create_supabase_client(session=sess)
        assert client.session is sess


# ---------------------------------------------------------------------------
# SupabaseClient.table — QueryBuilder smoke test
# ---------------------------------------------------------------------------


class TestQueryBuilderSmoke:
    def test_table_returns_query_builder(self) -> None:
        client = _make_client()
        qb = client.table("scan_history")
        assert qb is not None

    def test_query_builder_select_execute_returns_response(self) -> None:
        client = _make_client()
        rows = [{"id": "1"}]
        client.session.request = MagicMock(return_value=_mock_response(200, rows))
        resp = client.table("scan_history").select("*").execute()
        assert resp.data == rows

    def test_query_builder_eq_filter_sets_param(self) -> None:
        client = _make_client()
        client.session.request = MagicMock(return_value=_mock_response(200, []))
        client.table("agents").select("*").eq("status", "active").execute()
        call_kwargs = client.session.request.call_args
        params = call_kwargs.kwargs.get("params") or call_kwargs[1].get("params") or {}
        assert params.get("status") == "eq.active"

    def test_query_builder_insert_sends_post(self) -> None:
        client = _make_client()
        client.session.request = MagicMock(return_value=_mock_response(201, [{"id": "new"}]))
        client.table("agents").insert({"name": "agent-x"}).execute()
        method = client.session.request.call_args[1].get("method") or client.session.request.call_args[0][0]
        assert method.upper() == "POST"

    def test_query_builder_delete_sends_delete(self) -> None:
        client = _make_client()
        client.session.request = MagicMock(return_value=_mock_response(200, []))
        client.table("agents").delete().eq("id", "old-id").execute()
        method = client.session.request.call_args[1].get("method") or client.session.request.call_args[0][0]
        assert method.upper() == "DELETE"

    def test_query_builder_not_proxy_is_attached(self) -> None:
        client = _make_client()
        qb = client.table("scan_history")
        assert hasattr(qb, "not_")

    def test_query_builder_maybe_single_returns_none_on_406(self) -> None:
        client = _make_client()
        client.session.request = MagicMock(return_value=_mock_response(406, {"message": "not acceptable"}))
        resp = client.table("agents").select("*").maybe_single().execute()
        assert resp.data is None
