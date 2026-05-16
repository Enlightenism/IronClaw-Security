from __future__ import annotations

import time
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.api.scan import (
    _RATE_LIMIT_MAX_REQUESTS,
    _RATE_LIMIT_WINDOW_SECONDS,
    _client_rate_limit_key,
    _enforce_scan_rate_limit,
    _rate_limit_buckets,
)
from app.core.errors import AppError
from app.main import app

client = TestClient(app)

SAFE_PAYLOAD = {"target_type": "prompt", "target_value": "Hello, how are you?"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _clear_bucket(key: str) -> None:
    _rate_limit_buckets.pop(key, None)


def _fill_bucket(key: str, count: int, at: float | None = None) -> None:
    ts = at if at is not None else time.time()
    for _ in range(count):
        _rate_limit_buckets[key].append(ts)


# ---------------------------------------------------------------------------
# Constants sanity
# ---------------------------------------------------------------------------


def test_rate_limit_max_requests_is_30():
    assert _RATE_LIMIT_MAX_REQUESTS == 30


def test_rate_limit_window_is_60_seconds():
    assert _RATE_LIMIT_WINDOW_SECONDS == 60


# ---------------------------------------------------------------------------
# Unit: _enforce_scan_rate_limit — allow path
# ---------------------------------------------------------------------------


def test_first_request_allowed():
    key = "unit:first-request"
    _clear_bucket(key)
    limit, remaining = _enforce_scan_rate_limit(key)
    assert limit == _RATE_LIMIT_MAX_REQUESTS
    assert remaining == _RATE_LIMIT_MAX_REQUESTS - 1


def test_remaining_decrements_per_request():
    key = "unit:decrement"
    _clear_bucket(key)
    _, r1 = _enforce_scan_rate_limit(key)
    _, r2 = _enforce_scan_rate_limit(key)
    _, r3 = _enforce_scan_rate_limit(key)
    assert r1 == 29
    assert r2 == 28
    assert r3 == 27


def test_remaining_never_goes_below_zero():
    key = "unit:floor"
    _clear_bucket(key)
    _fill_bucket(key, _RATE_LIMIT_MAX_REQUESTS - 1)
    _, remaining = _enforce_scan_rate_limit(key)
    assert remaining == 0


def test_exactly_at_limit_still_allowed():
    key = "unit:at-limit"
    _clear_bucket(key)
    _fill_bucket(key, _RATE_LIMIT_MAX_REQUESTS - 1)
    limit, remaining = _enforce_scan_rate_limit(key)
    assert limit == _RATE_LIMIT_MAX_REQUESTS
    assert remaining == 0


def test_limit_value_always_equals_max():
    key = "unit:limit-constant"
    _clear_bucket(key)
    for _ in range(5):
        limit, _ = _enforce_scan_rate_limit(key)
        assert limit == _RATE_LIMIT_MAX_REQUESTS


# ---------------------------------------------------------------------------
# Unit: _enforce_scan_rate_limit — block path
# ---------------------------------------------------------------------------


def test_exceeding_limit_raises_app_error():
    key = "unit:exceed"
    _clear_bucket(key)
    _fill_bucket(key, _RATE_LIMIT_MAX_REQUESTS)
    with pytest.raises(AppError) as exc_info:
        _enforce_scan_rate_limit(key)
    assert exc_info.value.status_code == 429


def test_block_error_code_is_rate_limit_exceeded():
    key = "unit:error-code"
    _clear_bucket(key)
    _fill_bucket(key, _RATE_LIMIT_MAX_REQUESTS)
    with pytest.raises(AppError) as exc_info:
        _enforce_scan_rate_limit(key)
    assert exc_info.value.error == "scan_rate_limit_exceeded"


def test_block_error_details_contains_window():
    key = "unit:details-window"
    _clear_bucket(key)
    _fill_bucket(key, _RATE_LIMIT_MAX_REQUESTS)
    with pytest.raises(AppError) as exc_info:
        _enforce_scan_rate_limit(key)
    assert exc_info.value.details["window_seconds"] == _RATE_LIMIT_WINDOW_SECONDS


def test_block_error_details_contains_max_requests():
    key = "unit:details-max"
    _clear_bucket(key)
    _fill_bucket(key, _RATE_LIMIT_MAX_REQUESTS)
    with pytest.raises(AppError) as exc_info:
        _enforce_scan_rate_limit(key)
    assert exc_info.value.details["max_requests"] == _RATE_LIMIT_MAX_REQUESTS


def test_block_error_details_contains_key():
    key = "unit:details-key"
    _clear_bucket(key)
    _fill_bucket(key, _RATE_LIMIT_MAX_REQUESTS)
    with pytest.raises(AppError) as exc_info:
        _enforce_scan_rate_limit(key)
    assert exc_info.value.details["rate_limit_key"] == key


def test_block_error_details_retry_after_is_positive():
    key = "unit:retry-after"
    _clear_bucket(key)
    _fill_bucket(key, _RATE_LIMIT_MAX_REQUESTS)
    with pytest.raises(AppError) as exc_info:
        _enforce_scan_rate_limit(key)
    assert exc_info.value.details["retry_after_seconds"] >= 1


def test_one_over_limit_raises():
    key = "unit:one-over"
    _clear_bucket(key)
    _fill_bucket(key, _RATE_LIMIT_MAX_REQUESTS + 5)
    with pytest.raises(AppError):
        _enforce_scan_rate_limit(key)


# ---------------------------------------------------------------------------
# Unit: sliding window expiry
# ---------------------------------------------------------------------------


def test_expired_requests_are_evicted():
    key = "unit:expiry"
    _clear_bucket(key)
    expired_ts = time.time() - (_RATE_LIMIT_WINDOW_SECONDS + 5)
    _fill_bucket(key, _RATE_LIMIT_MAX_REQUESTS, at=expired_ts)
    # All entries are outside the window — should be evicted, request allowed
    limit, remaining = _enforce_scan_rate_limit(key)
    assert limit == _RATE_LIMIT_MAX_REQUESTS
    assert remaining == _RATE_LIMIT_MAX_REQUESTS - 1


def test_mixed_expired_and_fresh_counts_only_fresh():
    key = "unit:mixed-window"
    _clear_bucket(key)
    expired_ts = time.time() - (_RATE_LIMIT_WINDOW_SECONDS + 5)
    fresh_count = 10
    _fill_bucket(key, 15, at=expired_ts)
    _fill_bucket(key, fresh_count, at=time.time())
    limit, remaining = _enforce_scan_rate_limit(key)
    expected_remaining = _RATE_LIMIT_MAX_REQUESTS - fresh_count - 1
    assert remaining == expected_remaining


def test_fresh_at_window_edge_not_evicted():
    key = "unit:edge"
    _clear_bucket(key)
    edge_ts = time.time() - (_RATE_LIMIT_WINDOW_SECONDS - 1)
    _fill_bucket(key, 5, at=edge_ts)
    _, remaining = _enforce_scan_rate_limit(key)
    assert remaining == _RATE_LIMIT_MAX_REQUESTS - 6


def test_expired_fill_then_fresh_fill_blocks_on_fresh():
    key = "unit:expire-then-fill"
    _clear_bucket(key)
    expired_ts = time.time() - (_RATE_LIMIT_WINDOW_SECONDS + 10)
    _fill_bucket(key, _RATE_LIMIT_MAX_REQUESTS, at=expired_ts)
    _fill_bucket(key, _RATE_LIMIT_MAX_REQUESTS, at=time.time())
    with pytest.raises(AppError) as exc_info:
        _enforce_scan_rate_limit(key)
    assert exc_info.value.status_code == 429


# ---------------------------------------------------------------------------
# Unit: key isolation
# ---------------------------------------------------------------------------


def test_separate_keys_do_not_share_quota():
    key_a = "unit:iso-a"
    key_b = "unit:iso-b"
    _clear_bucket(key_a)
    _clear_bucket(key_b)
    _fill_bucket(key_a, _RATE_LIMIT_MAX_REQUESTS)
    with pytest.raises(AppError):
        _enforce_scan_rate_limit(key_a)
    limit, remaining = _enforce_scan_rate_limit(key_b)
    assert remaining == _RATE_LIMIT_MAX_REQUESTS - 1


def test_client_id_key_isolated_from_ip_key():
    key_ip = "ip:10.0.0.1"
    key_client = "client:abc-123"
    _clear_bucket(key_ip)
    _clear_bucket(key_client)
    _fill_bucket(key_ip, _RATE_LIMIT_MAX_REQUESTS)
    with pytest.raises(AppError):
        _enforce_scan_rate_limit(key_ip)
    # client key is untouched
    _, remaining = _enforce_scan_rate_limit(key_client)
    assert remaining == _RATE_LIMIT_MAX_REQUESTS - 1


# ---------------------------------------------------------------------------
# Unit: _client_rate_limit_key
# ---------------------------------------------------------------------------


def test_key_prefers_x_forwarded_for():
    from unittest.mock import MagicMock

    req = MagicMock()
    req.headers = {"x-forwarded-for": "203.0.113.5, 10.0.0.1"}
    req.client = MagicMock(host="127.0.0.1")
    assert _client_rate_limit_key(req) == "203.0.113.5"


def test_key_x_forwarded_for_trims_whitespace():
    from unittest.mock import MagicMock

    req = MagicMock()
    req.headers = {"x-forwarded-for": "  203.0.113.5  , 10.0.0.1"}
    req.client = MagicMock(host="127.0.0.1")
    assert _client_rate_limit_key(req) == "203.0.113.5"


def test_key_falls_back_to_client_id():
    from unittest.mock import MagicMock

    req = MagicMock()
    req.headers = {}
    req.client = MagicMock(host="127.0.0.1")
    payload = MagicMock()
    payload.client_id = "tenant-xyz"
    assert _client_rate_limit_key(req, payload) == "client:tenant-xyz"


def test_key_strips_client_id_whitespace():
    from unittest.mock import MagicMock

    req = MagicMock()
    req.headers = {}
    req.client = MagicMock(host="127.0.0.1")
    payload = MagicMock()
    payload.client_id = "  tenant-xyz  "
    assert _client_rate_limit_key(req, payload) == "client:tenant-xyz"


def test_key_falls_back_to_ip():
    from unittest.mock import MagicMock

    req = MagicMock()
    req.headers = {}
    req.client = MagicMock(host="192.168.1.99")
    assert _client_rate_limit_key(req, None) == "ip:192.168.1.99"


def test_key_no_client_object_returns_unknown():
    from unittest.mock import MagicMock

    req = MagicMock()
    req.headers = {}
    req.client = None
    assert _client_rate_limit_key(req, None) == "ip:unknown"


def test_key_empty_forwarded_for_falls_through():
    from unittest.mock import MagicMock

    req = MagicMock()
    req.headers = {"x-forwarded-for": ""}
    req.client = MagicMock(host="10.0.0.5")
    assert _client_rate_limit_key(req, None) == "ip:10.0.0.5"


def test_key_none_client_id_falls_back_to_ip():
    from unittest.mock import MagicMock

    req = MagicMock()
    req.headers = {}
    req.client = MagicMock(host="10.0.0.7")
    payload = MagicMock()
    payload.client_id = None
    assert _client_rate_limit_key(req, payload) == "ip:10.0.0.7"


# ---------------------------------------------------------------------------
# HTTP: 429 response shape via API
# ---------------------------------------------------------------------------


def test_api_returns_429_when_limit_exceeded():
    key = "api:block-key"
    _clear_bucket(key)
    _fill_bucket(key, _RATE_LIMIT_MAX_REQUESTS)
    with patch("app.api.scan._client_rate_limit_key", return_value=key):
        resp = client.post("/api/scan/", json=SAFE_PAYLOAD)
    assert resp.status_code == 429


def test_api_429_body_contains_error_code():
    key = "api:block-body"
    _clear_bucket(key)
    _fill_bucket(key, _RATE_LIMIT_MAX_REQUESTS)
    with patch("app.api.scan._client_rate_limit_key", return_value=key):
        resp = client.post("/api/scan/", json=SAFE_PAYLOAD)
    data = resp.json()
    assert "error" in data
    assert data["error"] == "scan_rate_limit_exceeded"


def test_api_429_body_contains_message():
    key = "api:block-msg"
    _clear_bucket(key)
    _fill_bucket(key, _RATE_LIMIT_MAX_REQUESTS)
    with patch("app.api.scan._client_rate_limit_key", return_value=key):
        resp = client.post("/api/scan/", json=SAFE_PAYLOAD)
    data = resp.json()
    assert "message" in data
    assert len(data["message"]) > 0


def test_api_429_body_contains_retry_after():
    key = "api:retry-after"
    _clear_bucket(key)
    _fill_bucket(key, _RATE_LIMIT_MAX_REQUESTS)
    with patch("app.api.scan._client_rate_limit_key", return_value=key):
        resp = client.post("/api/scan/", json=SAFE_PAYLOAD)
    data = resp.json()
    assert "details" in data
    assert "retry_after_seconds" in data["details"]


def test_api_rate_limit_headers_present_on_200():
    key = "api:headers-200"
    _clear_bucket(key)
    with patch("app.api.scan._client_rate_limit_key", return_value=key):
        resp = client.post("/api/scan/", json=SAFE_PAYLOAD)
    assert resp.status_code == 200
    assert "x-ratelimit-limit" in resp.headers
    assert "x-ratelimit-remaining" in resp.headers


def test_api_rate_limit_remaining_decrements_across_requests():
    key = "api:decrement"
    _clear_bucket(key)
    with patch("app.api.scan._client_rate_limit_key", return_value=key):
        r1 = client.post("/api/scan/", json=SAFE_PAYLOAD)
        r2 = client.post("/api/scan/", json=SAFE_PAYLOAD)
    rem1 = int(r1.headers["x-ratelimit-remaining"])
    rem2 = int(r2.headers["x-ratelimit-remaining"])
    assert rem2 == rem1 - 1


def test_api_rate_limit_limit_header_is_30():
    key = "api:limit-header"
    _clear_bucket(key)
    with patch("app.api.scan._client_rate_limit_key", return_value=key):
        resp = client.post("/api/scan/", json=SAFE_PAYLOAD)
    assert int(resp.headers["x-ratelimit-limit"]) == 30


# ---------------------------------------------------------------------------
# HTTP: load simulation — 30 allowed, 31st blocked
# ---------------------------------------------------------------------------


def test_exactly_30_requests_all_succeed():
    key = "load:30-succeed"
    _clear_bucket(key)
    responses = []
    with patch("app.api.scan._client_rate_limit_key", return_value=key):
        for _ in range(_RATE_LIMIT_MAX_REQUESTS):
            resp = client.post("/api/scan/", json=SAFE_PAYLOAD)
            responses.append(resp.status_code)
    assert all(sc == 200 for sc in responses), responses


def test_31st_request_is_blocked():
    key = "load:31st-blocked"
    _clear_bucket(key)
    with patch("app.api.scan._client_rate_limit_key", return_value=key):
        for _ in range(_RATE_LIMIT_MAX_REQUESTS):
            client.post("/api/scan/", json=SAFE_PAYLOAD)
        blocked = client.post("/api/scan/", json=SAFE_PAYLOAD)
    assert blocked.status_code == 429


def test_requests_beyond_limit_all_blocked():
    key = "load:beyond-limit"
    _clear_bucket(key)
    with patch("app.api.scan._client_rate_limit_key", return_value=key):
        for _ in range(_RATE_LIMIT_MAX_REQUESTS):
            client.post("/api/scan/", json=SAFE_PAYLOAD)
        blocked_statuses = [client.post("/api/scan/", json=SAFE_PAYLOAD).status_code for _ in range(5)]
    assert all(sc == 429 for sc in blocked_statuses)


def test_remaining_header_reaches_zero_on_last_allowed():
    key = "load:zero-remaining"
    _clear_bucket(key)
    last_resp = None
    with patch("app.api.scan._client_rate_limit_key", return_value=key):
        for _ in range(_RATE_LIMIT_MAX_REQUESTS):
            last_resp = client.post("/api/scan/", json=SAFE_PAYLOAD)
    assert int(last_resp.headers["x-ratelimit-remaining"]) == 0


# ---------------------------------------------------------------------------
# HTTP: per-key isolation under load
# ---------------------------------------------------------------------------


def test_two_clients_have_independent_quotas():
    key_a = "load:client-a"
    key_b = "load:client-b"
    _clear_bucket(key_a)
    _clear_bucket(key_b)

    def post_with_key(k):
        with patch("app.api.scan._client_rate_limit_key", return_value=k):
            return client.post("/api/scan/", json=SAFE_PAYLOAD)

    # Exhaust key_a
    for _ in range(_RATE_LIMIT_MAX_REQUESTS):
        post_with_key(key_a)
    blocked = post_with_key(key_a)
    assert blocked.status_code == 429

    # key_b still has full quota
    ok = post_with_key(key_b)
    assert ok.status_code == 200


# ---------------------------------------------------------------------------
# HTTP: batch endpoint rate limit
# ---------------------------------------------------------------------------


def test_batch_endpoint_applies_rate_limit():
    key = "batch:apply"
    _clear_bucket(key)
    _fill_bucket(key, _RATE_LIMIT_MAX_REQUESTS)
    with patch("app.api.scan._client_rate_limit_key", return_value=key):
        resp = client.post(
            "/api/scan/batch",
            json={"items": [SAFE_PAYLOAD, SAFE_PAYLOAD]},
        )
    assert resp.status_code == 429


def test_batch_endpoint_rate_limit_headers_present():
    key = "batch:headers"
    _clear_bucket(key)
    with patch("app.api.scan._client_rate_limit_key", return_value=key):
        resp = client.post(
            "/api/scan/batch",
            json={"items": [SAFE_PAYLOAD]},
        )
    assert resp.status_code == 200
    assert "x-ratelimit-limit" in resp.headers
    assert "x-ratelimit-remaining" in resp.headers


def test_batch_and_single_share_bucket_for_same_key():
    key = "batch:shared-bucket"
    _clear_bucket(key)
    _fill_bucket(key, _RATE_LIMIT_MAX_REQUESTS - 1)
    # Single scan consumes the last slot
    with patch("app.api.scan._client_rate_limit_key", return_value=key):
        single = client.post("/api/scan/", json=SAFE_PAYLOAD)
    assert single.status_code == 200
    assert int(single.headers["x-ratelimit-remaining"]) == 0
    # Batch now blocked
    with patch("app.api.scan._client_rate_limit_key", return_value=key):
        batch = client.post("/api/scan/batch", json={"items": [SAFE_PAYLOAD]})
    assert batch.status_code == 429


# ---------------------------------------------------------------------------
# Telemetry: rate limit event emitted
# ---------------------------------------------------------------------------


def test_rate_limit_checked_event_emitted_on_single_scan():
    events = []

    def capture(event_type, payload):
        events.append(event_type)

    key = "tel:single"
    _clear_bucket(key)
    with (
        patch("app.api.scan._client_rate_limit_key", return_value=key),
        patch("app.api.scan.append_telemetry_event", side_effect=capture),
    ):
        client.post("/api/scan/", json=SAFE_PAYLOAD)

    assert "scan_rate_limit_checked" in events


def test_batch_rate_limit_checked_event_emitted():
    events = []

    def capture(event_type, payload):
        events.append(event_type)

    key = "tel:batch"
    _clear_bucket(key)
    with (
        patch("app.api.scan._client_rate_limit_key", return_value=key),
        patch("app.api.scan.append_telemetry_event", side_effect=capture),
    ):
        client.post("/api/scan/batch", json={"items": [SAFE_PAYLOAD]})

    assert "scan_batch_rate_limit_checked" in events


def test_rate_limit_event_contains_key_and_counts():
    captured = []

    def capture(event_type, payload):
        if event_type == "scan_rate_limit_checked":
            captured.append(payload)

    key = "tel:payload"
    _clear_bucket(key)
    with (
        patch("app.api.scan._client_rate_limit_key", return_value=key),
        patch("app.api.scan.append_telemetry_event", side_effect=capture),
    ):
        client.post("/api/scan/", json=SAFE_PAYLOAD)

    assert len(captured) == 1
    event = captured[0]
    assert event["rate_limit_key"] == key
    assert event["limit"] == _RATE_LIMIT_MAX_REQUESTS
    assert event["remaining"] == _RATE_LIMIT_MAX_REQUESTS - 1
