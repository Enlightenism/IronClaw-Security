from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

from fastapi import HTTPException, Request
import pytest
from starlette.datastructures import Headers

from app.core.rate_limiter import (
    RateLimitResult,
    build_429_response,
    check_and_increment,
    get_key_state,
    key_composite,
    key_for_agent,
    key_for_api_key,
    key_for_ip,
    raise_429,
    reset_key,
)

# ---------------------------------------------------------------------------
# Patch targets
# ---------------------------------------------------------------------------

# check_and_increment owns its own DB path via _get_client
_PATCH_GET_CLIENT = "app.core.rate_limiter._get_client"

# reset_key and get_key_state use lazy imports inside the function body —
# the names are never module-level attributes on app.core.rate_limiter.
# Patch the canonical persistence module directly.
_PATCH_DELETE_RL = "app.core.supabase_persistence.delete_rate_limit_state"
_PATCH_GET_RL = "app.core.supabase_persistence.get_rate_limit_state"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_row(count: int, window_start: float, window_seconds: int = 60, rate_limit: int = 5) -> dict:
    return {
        "count": count,
        "window_start": window_start,
        "window_seconds": window_seconds,
        "rate_limit": rate_limit,
    }


def _mock_client_with_row(row: dict | None):
    mock_resp = MagicMock()
    mock_resp.data = row

    qb = MagicMock()
    qb.select.return_value = qb
    qb.eq.return_value = qb
    qb.maybe_single.return_value = qb
    qb.execute.return_value = mock_resp

    upsert_resp = MagicMock()
    upsert_resp.data = {}
    upsert_qb = MagicMock()
    upsert_qb.execute.return_value = upsert_resp

    def _table_side_effect(name):
        tb = MagicMock()
        tb.select.return_value = qb
        tb.upsert.return_value = upsert_qb
        tb.delete.return_value = qb
        return tb

    client = MagicMock()
    client.table.side_effect = _table_side_effect
    return client


def _mock_client_raising(exc: Exception):
    qb = MagicMock()
    qb.select.return_value = qb
    qb.eq.return_value = qb
    qb.maybe_single.return_value = qb
    qb.execute.side_effect = exc

    client = MagicMock()
    client.table.return_value = qb
    return client


# ---------------------------------------------------------------------------
# check_and_increment — happy path
# ---------------------------------------------------------------------------


class TestCheckAndIncrementFirstCall:
    def test_allowed_true_and_remaining_4(self):
        mock_client = _mock_client_with_row(None)
        with patch(_PATCH_GET_CLIENT, return_value=mock_client):
            result = check_and_increment("test:key:first", limit=5, window_seconds=60)

        assert result.allowed is True
        assert result.remaining == 4
        assert result.current_count == 1
        assert result.retry_after == 0


class TestCheckAndIncrementAtLimit:
    def test_fifth_call_allowed_with_remaining_zero(self):
        now = time.time()
        mock_client = _mock_client_with_row(_make_row(count=4, window_start=now - 1))
        with patch(_PATCH_GET_CLIENT, return_value=mock_client):
            result = check_and_increment("test:key:limit", limit=5, window_seconds=60)

        assert result.allowed is True
        assert result.remaining == 0
        assert result.current_count == 5
        assert result.retry_after == 0


class TestCheckAndIncrementExceeded:
    def test_sixth_call_blocked(self):
        now = time.time()
        mock_client = _mock_client_with_row(_make_row(count=5, window_start=now - 1))
        with patch(_PATCH_GET_CLIENT, return_value=mock_client):
            result = check_and_increment("test:key:exceed", limit=5, window_seconds=60)

        assert result.allowed is False
        assert result.remaining == 0
        assert result.retry_after >= 1

    def test_retry_after_always_gte_1_when_blocked(self):
        now = time.time()
        mock_client = _mock_client_with_row(_make_row(count=10, window_start=now - 59))
        with patch(_PATCH_GET_CLIENT, return_value=mock_client):
            result = check_and_increment("test:key:retry", limit=5, window_seconds=60)

        assert result.allowed is False
        assert result.retry_after >= 1


class TestCheckAndIncrementRetryAfterZeroWhenAllowed:
    def test_retry_after_zero_on_allowed(self):
        mock_client = _mock_client_with_row(None)
        with patch(_PATCH_GET_CLIENT, return_value=mock_client):
            result = check_and_increment("test:key:allowed", limit=5, window_seconds=60)

        assert result.allowed is True
        assert result.retry_after == 0


# ---------------------------------------------------------------------------
# check_and_increment — window expiry
# ---------------------------------------------------------------------------


class TestCheckAndIncrementWindowExpiry:
    def test_expired_window_resets_count_to_1(self):
        ancient_start = time.time() - 120
        mock_client = _mock_client_with_row(_make_row(count=5, window_start=ancient_start, window_seconds=60))
        with patch(_PATCH_GET_CLIENT, return_value=mock_client):
            result = check_and_increment("test:key:expired", limit=5, window_seconds=60)

        assert result.allowed is True
        assert result.current_count == 1
        assert result.remaining == 4


# ---------------------------------------------------------------------------
# check_and_increment — input validation
# ---------------------------------------------------------------------------


class TestCheckAndIncrementEmptyKey:
    @pytest.mark.parametrize("bad_key", ["", "   ", "\t", "\n"])
    def test_raises_value_error(self, bad_key: str):
        with pytest.raises(ValueError, match="non-empty"):
            check_and_increment(bad_key, limit=5, window_seconds=60)


# ---------------------------------------------------------------------------
# check_and_increment — fail-open on Supabase error
# ---------------------------------------------------------------------------


class TestCheckAndIncrementFailOpen:
    def test_supabase_api_error_returns_allowed_true(self):
        from app.supabaseclient import SupabaseAPIError

        exc = SupabaseAPIError("simulated DB failure")
        mock_client = _mock_client_raising(exc)
        with patch(_PATCH_GET_CLIENT, return_value=mock_client):
            result = check_and_increment("test:key:failopen", limit=5, window_seconds=60)

        assert result.allowed is True

    def test_supabase_api_error_does_not_raise(self):
        from app.supabaseclient import SupabaseAPIError

        exc = SupabaseAPIError("another DB failure")
        mock_client = _mock_client_raising(exc)
        with patch(_PATCH_GET_CLIENT, return_value=mock_client):
            try:
                check_and_increment("test:key:noexc", limit=5, window_seconds=60)
            except Exception as e:
                pytest.fail(f"check_and_increment raised unexpectedly: {e}")


# ---------------------------------------------------------------------------
# raise_429
# ---------------------------------------------------------------------------


class TestRaise429:
    def _blocked_result(self) -> RateLimitResult:
        return RateLimitResult(
            key="ip:1.2.3.4",
            allowed=False,
            limit=5,
            remaining=0,
            window_seconds=60,
            window_start=time.time() - 10,
            current_count=6,
            retry_after=50,
        )

    def test_raises_http_exception_429(self):
        with pytest.raises(HTTPException) as exc_info:
            raise_429(self._blocked_result())

        assert exc_info.value.status_code == 429

    def test_retry_after_header_matches_result(self):
        result = self._blocked_result()
        with pytest.raises(HTTPException) as exc_info:
            raise_429(result)

        assert exc_info.value.headers["Retry-After"] == str(result.retry_after)


# ---------------------------------------------------------------------------
# build_429_response
# ---------------------------------------------------------------------------


class TestBuild429Response:
    def _blocked_result(self, retry_after: int = 30) -> RateLimitResult:
        return RateLimitResult(
            key="ip:9.9.9.9",
            allowed=False,
            limit=10,
            remaining=0,
            window_seconds=60,
            window_start=time.time() - 5,
            current_count=11,
            retry_after=retry_after,
        )

    def test_returns_json_response_status_429(self):
        from fastapi.responses import JSONResponse

        result = self._blocked_result()
        resp = build_429_response(result)

        assert isinstance(resp, JSONResponse)
        assert resp.status_code == 429

    def test_does_not_raise(self):
        result = self._blocked_result()
        try:
            build_429_response(result)
        except Exception as e:
            pytest.fail(f"build_429_response raised: {e}")

    def test_retry_after_header_present(self):
        result = self._blocked_result(retry_after=45)
        resp = build_429_response(result)
        assert resp.headers["retry-after"] == "45"


# ---------------------------------------------------------------------------
# key_for_ip
# ---------------------------------------------------------------------------


def _mock_request(client_host: str = "127.0.0.1", forwarded_for: str | None = None) -> Request:
    headers: dict[str, str] = {}
    if forwarded_for is not None:
        headers["x-forwarded-for"] = forwarded_for

    class _FakeClient:
        host = client_host

    mock_req = MagicMock(spec=Request)
    mock_req.headers = Headers(headers=headers)
    mock_req.client = _FakeClient()
    return mock_req


class TestKeyForIp:
    def test_plain_request_returns_ip_prefix(self):
        req = _mock_request(client_host="10.0.0.1")
        key = key_for_ip(req)
        assert key == "ip:10.0.0.1"
        assert key.startswith("ip:")

    def test_x_forwarded_for_uses_first_ip(self):
        req = _mock_request(forwarded_for="203.0.113.5, 10.0.0.1, 192.168.1.1")
        key = key_for_ip(req)
        assert key == "ip:203.0.113.5"


# ---------------------------------------------------------------------------
# key_for_agent
# ---------------------------------------------------------------------------


class TestKeyForAgent:
    def test_returns_agent_prefix(self):
        assert key_for_agent("agent-123") == "agent:agent-123"

    def test_empty_string_returns_agent_unknown(self):
        assert key_for_agent("") == "agent:unknown"

    def test_blank_string_returns_agent_unknown(self):
        assert key_for_agent("   ") == "agent:unknown"


# ---------------------------------------------------------------------------
# key_for_api_key
# ---------------------------------------------------------------------------


class TestKeyForApiKey:
    def test_contains_only_last_8_chars(self):
        api_key = "sk-abcdef1234567890"
        result = key_for_api_key(api_key)
        assert api_key[-8:] in result
        assert api_key[:-8] not in result

    def test_does_not_contain_full_key(self):
        api_key = "sk-abcdef1234567890"
        result = key_for_api_key(api_key)
        assert api_key not in result

    def test_prefix_is_apikey(self):
        result = key_for_api_key("sk-abcdef1234567890")
        assert result.startswith("apikey:")


# ---------------------------------------------------------------------------
# key_composite
# ---------------------------------------------------------------------------


class TestKeyComposite:
    def test_scan_agent_method(self):
        result = key_composite("scan", "agent-1", "POST")
        assert result == "scan:agent-1:POST"


# ---------------------------------------------------------------------------
# reset_key — delegates to supabase_persistence.delete_rate_limit_state
# ---------------------------------------------------------------------------


class TestResetKey:
    def test_returns_true_on_success(self):
        with patch(_PATCH_DELETE_RL, return_value=None) as mock_delete:
            result = reset_key("ip:1.2.3.4")

        assert result is True
        mock_delete.assert_called_once_with("ip:1.2.3.4")

    def test_key_is_stripped_before_delegation(self):
        with patch(_PATCH_DELETE_RL, return_value=None) as mock_delete:
            result = reset_key("  ip:1.2.3.4  ")

        assert result is True
        mock_delete.assert_called_once_with("ip:1.2.3.4")

    def test_empty_key_returns_false_without_raising(self):
        try:
            result = reset_key("")
        except Exception as e:
            pytest.fail(f"reset_key('') raised: {e}")
        assert result is False

    def test_blank_key_returns_false(self):
        result = reset_key("   ")
        assert result is False

    def test_persistence_error_returns_false(self):
        from app.core.supabase_persistence import PersistenceError

        with patch(_PATCH_DELETE_RL, side_effect=PersistenceError("delete_rate_limit_state", "db down")):
            result = reset_key("ip:1.2.3.4")

        assert result is False

    def test_unexpected_exception_returns_false(self):
        with patch(_PATCH_DELETE_RL, side_effect=RuntimeError("unexpected")):
            result = reset_key("ip:1.2.3.4")

        assert result is False

    def test_does_not_raise_on_persistence_error(self):
        from app.core.supabase_persistence import PersistenceError

        with patch(_PATCH_DELETE_RL, side_effect=PersistenceError("delete_rate_limit_state", "db down")):
            try:
                reset_key("ip:1.2.3.4")
            except Exception as e:
                pytest.fail(f"reset_key raised on PersistenceError: {e}")


# ---------------------------------------------------------------------------
# get_key_state — delegates to supabase_persistence.get_rate_limit_state
# ---------------------------------------------------------------------------


class TestGetKeyState:
    _ROW: dict = {
        "key": "ip:1.2.3.4",
        "count": 3,
        "window_start": 1700000000.0,
        "window_seconds": 60,
        "rate_limit": 5,
    }

    def test_returns_row_dict_when_found(self):
        with patch(_PATCH_GET_RL, return_value=self._ROW) as mock_get:
            result = get_key_state("ip:1.2.3.4")

        assert result == self._ROW
        mock_get.assert_called_once_with("ip:1.2.3.4")

    def test_key_is_stripped_before_delegation(self):
        with patch(_PATCH_GET_RL, return_value=self._ROW) as mock_get:
            result = get_key_state("  ip:1.2.3.4  ")

        assert result == self._ROW
        mock_get.assert_called_once_with("ip:1.2.3.4")

    def test_unknown_key_returns_none(self):
        with patch(_PATCH_GET_RL, return_value=None):
            result = get_key_state("ip:0.0.0.0")

        assert result is None

    def test_unknown_key_does_not_raise(self):
        with patch(_PATCH_GET_RL, return_value=None):
            try:
                get_key_state("ip:0.0.0.0")
            except Exception as e:
                pytest.fail(f"get_key_state raised unexpectedly: {e}")

    def test_empty_key_returns_none(self):
        result = get_key_state("")
        assert result is None

    def test_blank_key_returns_none(self):
        result = get_key_state("   ")
        assert result is None

    def test_persistence_error_returns_none(self):
        from app.core.supabase_persistence import PersistenceError

        with patch(_PATCH_GET_RL, side_effect=PersistenceError("get_rate_limit_state", "db down")):
            result = get_key_state("ip:1.2.3.4")

        assert result is None

    def test_unexpected_exception_returns_none(self):
        with patch(_PATCH_GET_RL, side_effect=RuntimeError("unexpected")):
            result = get_key_state("ip:1.2.3.4")

        assert result is None

    def test_does_not_raise_on_persistence_error(self):
        from app.core.supabase_persistence import PersistenceError

        with patch(_PATCH_GET_RL, side_effect=PersistenceError("get_rate_limit_state", "db down")):
            try:
                get_key_state("ip:1.2.3.4")
            except Exception as e:
                pytest.fail(f"get_key_state raised on PersistenceError: {e}")
