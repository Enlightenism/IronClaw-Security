from __future__ import annotations

import httpx
import pytest
import respx

from ironclaw_sdk.client import IronclawClient
from ironclaw_sdk.exceptions import (
    IronclawAPIError,
    IronclawAuthError,
    IronclawRetryExhausted,
    IronclawTimeoutError,
)
from ironclaw_sdk.models import ScanRequest, ScanResponse

_BASE = "http://testserver"
_KEY = "ironclaw-test-key-00000000"

_VALID_SCAN_RESPONSE = {
    "scan_id": "11111111-1111-1111-1111-111111111111",
    "verdict": "allow",
    "summary": "No threats detected.",
    "target_type": "text",
    "target_value": "hello world",
    "risk_score": 0,
    "matched_patterns": [],
    "risky_files": [],
    "checks_loaded": [],
    "failed_checks": [],
    "quarantine_reason": None,
    "review_status": "none",
    "untrusted": False,
    "sandbox_lane": "none",
    "timestamp": "2026-05-22T00:00:00Z",
    "max_severity": None,
    "primary_category": None,
    "explanation": None,
    "client_id": None,
}


def _make_client(api_key: str = _KEY, base_url: str = _BASE) -> IronclawClient:
    return IronclawClient(api_key=api_key, base_url=base_url, connect_timeout=2.0, read_timeout=2.0)


def _make_request() -> ScanRequest:
    return ScanRequest(target_type="text", target_value="hello world")


@pytest.mark.sdk
class TestApiKeyHeader:
    @respx.mock
    def test_api_key_header_present_on_every_request(self):
        route = respx.post(f"{_BASE}/scan/").mock(return_value=httpx.Response(200, json=_VALID_SCAN_RESPONSE))
        client = _make_client()
        client.scan(_make_request())
        assert route.called
        sent_headers = route.calls[0].request.headers
        assert sent_headers.get("x-api-key") == _KEY

    def test_missing_api_key_raises_auth_error(self):
        with pytest.raises(IronclawAuthError):
            IronclawClient(api_key="", base_url=_BASE)

    def test_whitespace_api_key_raises_auth_error(self):
        with pytest.raises(IronclawAuthError):
            IronclawClient(api_key="   ", base_url=_BASE)


@pytest.mark.sdk
class TestAuthErrorHandling:
    @respx.mock
    def test_401_response_raises_auth_error(self):
        respx.post(f"{_BASE}/scan/").mock(return_value=httpx.Response(401, json={"detail": "Unauthorized"}))
        client = _make_client()
        with pytest.raises(IronclawAuthError) as exc_info:
            client.scan(_make_request())
        assert exc_info.value.status_code == 401

    @respx.mock
    def test_403_response_raises_auth_error(self):
        respx.post(f"{_BASE}/scan/").mock(return_value=httpx.Response(403, json={"detail": "Forbidden"}))
        client = _make_client()
        with pytest.raises(IronclawAuthError) as exc_info:
            client.scan(_make_request())
        assert exc_info.value.status_code == 403


@pytest.mark.sdk
class TestRetryBehavior:
    @respx.mock
    def test_500_triggers_retry_exactly_three_calls(self):
        route = respx.post(f"{_BASE}/scan/").mock(return_value=httpx.Response(500, text="error"))
        client = _make_client()
        with pytest.raises(IronclawRetryExhausted):
            client.scan(_make_request())
        assert route.call_count == 3

    @respx.mock
    def test_retry_exhausted_raises_ironclaw_retry_exhausted(self):
        respx.post(f"{_BASE}/scan/").mock(return_value=httpx.Response(503, text="unavailable"))
        client = _make_client()
        with pytest.raises(IronclawRetryExhausted) as exc_info:
            client.scan(_make_request())
        assert exc_info.value.attempts == 3

    @respx.mock
    def test_retry_after_header_respected(self, monkeypatch):
        import time

        sleeps: list[float] = []
        monkeypatch.setattr(time, "sleep", lambda s: sleeps.append(s))
        respx.post(f"{_BASE}/scan/").mock(
            side_effect=[
                httpx.Response(429, headers={"Retry-After": "2"}, text="rate limited"),
                httpx.Response(429, headers={"Retry-After": "2"}, text="rate limited"),
                httpx.Response(429, text="rate limited"),
            ]
        )
        client = _make_client()
        with pytest.raises(IronclawRetryExhausted):
            client.scan(_make_request())
        assert len(sleeps) == 2
        assert sleeps[0] == 2.0
        assert sleeps[1] == 2.0

    @respx.mock
    def test_non_retryable_400_does_not_retry(self):
        route = respx.post(f"{_BASE}/scan/").mock(return_value=httpx.Response(400, json={"detail": "bad request"}))
        client = _make_client()
        with pytest.raises(IronclawAPIError):
            client.scan(_make_request())
        assert route.call_count == 1


@pytest.mark.sdk
class TestTimeoutHandling:
    @respx.mock
    def test_timeout_raises_ironclaw_timeout_error(self):
        respx.post(f"{_BASE}/scan/").mock(side_effect=httpx.TimeoutException("timed out"))
        client = _make_client()
        with pytest.raises(IronclawTimeoutError):
            client.scan(_make_request())


@pytest.mark.sdk
class TestScanResponseBinding:
    @respx.mock
    def test_scan_maps_response_body_to_scan_response_exactly(self):
        respx.post(f"{_BASE}/scan/").mock(return_value=httpx.Response(200, json=_VALID_SCAN_RESPONSE))
        client = _make_client()
        result = client.scan(_make_request())
        assert isinstance(result, ScanResponse)
        assert result.scan_id == _VALID_SCAN_RESPONSE["scan_id"]
        assert result.verdict == _VALID_SCAN_RESPONSE["verdict"]
        assert result.risk_score == _VALID_SCAN_RESPONSE["risk_score"]
        assert result.summary == _VALID_SCAN_RESPONSE["summary"]
        assert result.target_type == _VALID_SCAN_RESPONSE["target_type"]
        assert result.target_value == _VALID_SCAN_RESPONSE["target_value"]
        assert result.review_status == _VALID_SCAN_RESPONSE["review_status"]
        assert result.sandbox_lane == _VALID_SCAN_RESPONSE["sandbox_lane"]
        assert result.untrusted == _VALID_SCAN_RESPONSE["untrusted"]

    @respx.mock
    def test_malformed_response_raises_api_error(self):
        respx.post(f"{_BASE}/scan/").mock(return_value=httpx.Response(200, json={"broken": True}))
        client = _make_client()
        with pytest.raises(IronclawAPIError):
            client.scan(_make_request())

    @respx.mock
    def test_non_json_response_raises_api_error(self):
        respx.post(f"{_BASE}/scan/").mock(return_value=httpx.Response(200, text="not json"))
        client = _make_client()
        with pytest.raises(IronclawAPIError):
            client.scan(_make_request())


@pytest.mark.sdk
class TestBaseUrlOverride:
    @respx.mock
    def test_base_url_override_respected(self):
        alt_base = "http://alt-server:9000"
        route = respx.post(f"{alt_base}/scan/").mock(return_value=httpx.Response(200, json=_VALID_SCAN_RESPONSE))
        client = _make_client(base_url=alt_base)
        client.scan(_make_request())
        assert route.called

    @respx.mock
    def test_trailing_slash_stripped_from_base_url(self):
        route = respx.post(f"{_BASE}/scan/").mock(return_value=httpx.Response(200, json=_VALID_SCAN_RESPONSE))
        client = _make_client(base_url=f"{_BASE}/")
        client.scan(_make_request())
        assert route.called
