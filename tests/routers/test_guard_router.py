from __future__ import annotations

from collections.abc import Generator
from typing import Any
from unittest.mock import AsyncMock, patch

from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
import pytest

import app.guard_router as _gr
from app.guard_router import (
    GuardBundleVerdict,
    router,
)

_app = FastAPI()
_app.include_router(router)


@pytest.fixture()
def client() -> Generator[TestClient, None, None]:
    with TestClient(_app, raise_server_exceptions=False) as c:
        yield c


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_PROXY_URL = "/claude-guard-router/proxy"
_STREAM_URL = "/claude-guard-router/proxy-stream"

_BASE_PAYLOAD: dict[str, Any] = {
    "upstream_url": "http://upstream.test/v1/messages",
    "guard_base_url": "http://guard.test",
    "guard_mode": "enforce",
    "upstreampayload": {"model": "claude-3-5-sonnet", "messages": []},
    "guard_payload": {"prompt": "hello"},
}

_ALLOW_VERDICT = GuardBundleVerdict(verdict="allow", reason="", truncated=False, metadata={})
_BLOCK_VERDICT = GuardBundleVerdict(verdict="block", reason="Blocked by policy.", truncated=True, metadata={})
_WARN_VERDICT = GuardBundleVerdict(verdict="warn", reason="Elevated risk.", truncated=False, metadata={})


def _mock_guard(verdict: GuardBundleVerdict) -> AsyncMock:
    return AsyncMock(return_value=verdict)


# ---------------------------------------------------------------------------
# /proxy — GuardProxyResponse shape
# ---------------------------------------------------------------------------


class TestGuardProxySummaryShape:
    def test_allow_verdict_returns_ok_status(self, client: TestClient):
        with patch.object(_gr, "scan_with_policy_guard", _mock_guard(_ALLOW_VERDICT)):
            resp = client.post(_PROXY_URL, json=_BASE_PAYLOAD)
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_allow_verdict_shape(self, client: TestClient):
        with patch.object(_gr, "scan_with_policy_guard", _mock_guard(_ALLOW_VERDICT)):
            resp = client.post(_PROXY_URL, json=_BASE_PAYLOAD)
        data = resp.json()
        assert data["verdict"] == "allow"
        assert data["mode"] == "enforce"
        assert data["truncated"] is False
        assert "reason" in data
        assert "metadata" in data

    def test_block_verdict_shape(self, client: TestClient):
        with patch.object(_gr, "scan_with_policy_guard", _mock_guard(_BLOCK_VERDICT)):
            resp = client.post(_PROXY_URL, json=_BASE_PAYLOAD)
        data = resp.json()
        assert data["verdict"] == "block"
        assert data["truncated"] is True

    def test_warn_verdict_shape(self, client: TestClient):
        with patch.object(_gr, "scan_with_policy_guard", _mock_guard(_WARN_VERDICT)):
            resp = client.post(_PROXY_URL, json=_BASE_PAYLOAD)
        data = resp.json()
        assert data["verdict"] == "warn"
        assert data["truncated"] is False

    def test_enforce_mode_block_sets_truncated_true(self, client: TestClient):
        verdict = GuardBundleVerdict(verdict="block", reason="blocked", truncated=False, metadata={})
        with patch.object(_gr, "scan_with_policy_guard", _mock_guard(verdict)):
            resp = client.post(_PROXY_URL, json=_BASE_PAYLOAD)
        assert resp.json()["truncated"] is True

    def test_assist_mode_block_does_not_set_truncated(self, client: TestClient):
        payload = {**_BASE_PAYLOAD, "guard_mode": "assist"}
        verdict = GuardBundleVerdict(verdict="block", reason="blocked", truncated=False, metadata={})
        with patch.object(_gr, "scan_with_policy_guard", _mock_guard(verdict)):
            resp = client.post(_PROXY_URL, json=payload)
        assert resp.json()["truncated"] is False

    def test_mode_field_reflects_request_mode(self, client: TestClient):
        payload = {**_BASE_PAYLOAD, "guard_mode": "assist"}
        with patch.object(_gr, "scan_with_policy_guard", _mock_guard(_ALLOW_VERDICT)):
            resp = client.post(_PROXY_URL, json=payload)
        assert resp.json()["mode"] == "assist"

    def test_metadata_propagated(self, client: TestClient):
        verdict = GuardBundleVerdict(verdict="allow", reason="", truncated=False, metadata={"foo": "bar"})
        with patch.object(_gr, "scan_with_policy_guard", _mock_guard(verdict)):
            resp = client.post(_PROXY_URL, json=_BASE_PAYLOAD)
        assert resp.json()["metadata"] == {"foo": "bar"}


# ---------------------------------------------------------------------------
# /proxy — 502 on guard service failure
# ---------------------------------------------------------------------------


class TestGuardProxySummary502:
    def test_502_when_guard_raises_http_exception(self, client: TestClient):
        async def _fail(*_a, **_kw):
            raise HTTPException(status_code=502, detail="Guard service error: connection refused")

        with patch.object(_gr, "scan_with_policy_guard", _fail):
            resp = client.post(_PROXY_URL, json=_BASE_PAYLOAD)
        assert resp.status_code == 502

    def test_502_detail_contains_guard_error(self, client: TestClient):
        async def _fail(*_a, **_kw):
            raise HTTPException(status_code=502, detail="Guard service returned 503")

        with patch.object(_gr, "scan_with_policy_guard", _fail):
            resp = client.post(_PROXY_URL, json=_BASE_PAYLOAD)
        assert "503" in resp.json().get("detail", "")


# ---------------------------------------------------------------------------
# /proxy — rate-limit enforcement (429)
# ---------------------------------------------------------------------------


class TestGuardProxySummaryRateLimit:
    def test_429_when_rate_limit_exceeded(self, client: TestClient):
        def _rate_limit_exceeded(request):
            raise HTTPException(status_code=429, detail="Rate limit exceeded")

        with patch("app.dependencies.rate_limit.limit_guard_routes", _rate_limit_exceeded):
            with patch("app.guard_router.limit_guard_routes", _rate_limit_exceeded):
                resp = client.post(_PROXY_URL, json=_BASE_PAYLOAD)
        assert resp.status_code == 429

    def test_429_does_not_call_guard_when_rate_limited(self, client: TestClient):
        def _rate_limit_exceeded(request):
            raise HTTPException(status_code=429, detail="Rate limit exceeded")

        mock_guard = _mock_guard(_ALLOW_VERDICT)
        with patch("app.guard_router.limit_guard_routes", _rate_limit_exceeded):
            with patch.object(_gr, "scan_with_policy_guard", mock_guard):
                client.post(_PROXY_URL, json=_BASE_PAYLOAD)
        mock_guard.assert_not_called()


# ---------------------------------------------------------------------------
# /proxy-stream — enforce-mode block truncation
# ---------------------------------------------------------------------------


class TestGuardProxyStreamEnforceBlock:
    def test_enforce_block_returns_200(self, client: TestClient):
        with patch.object(_gr, "scan_with_policy_guard", _mock_guard(_BLOCK_VERDICT)):
            resp = client.post(_STREAM_URL, json=_BASE_PAYLOAD)
        assert resp.status_code == 200

    def test_enforce_block_body_contains_block_reason(self, client: TestClient):
        with patch.object(_gr, "scan_with_policy_guard", _mock_guard(_BLOCK_VERDICT)):
            resp = client.post(_STREAM_URL, json=_BASE_PAYLOAD)
        assert b"Blocked by policy." in resp.content

    def test_enforce_block_does_not_call_upstream(self, client: TestClient):
        upstream_called = {"called": False}

        async def _fake_stream(url: str, payload: dict):
            upstream_called["called"] = True
            yield b"upstream data"

        with patch.object(_gr, "scan_with_policy_guard", _mock_guard(_BLOCK_VERDICT)):
            with patch.object(_gr, "_stream_upstream", _fake_stream):
                client.post(_STREAM_URL, json=_BASE_PAYLOAD)

        assert upstream_called["called"] is False

    def test_enforce_block_default_message_when_reason_empty(self, client: TestClient):
        verdict = GuardBundleVerdict(verdict="block", reason="", truncated=True, metadata={})
        with patch.object(_gr, "scan_with_policy_guard", _mock_guard(verdict)):
            resp = client.post(_STREAM_URL, json=_BASE_PAYLOAD)
        assert b"blocked by policy guard" in resp.content.lower()


# ---------------------------------------------------------------------------
# /proxy-stream — assist-mode passthrough
# ---------------------------------------------------------------------------


class TestGuardProxyStreamAssistPassthrough:
    def test_assist_mode_allow_passes_upstream_chunks(self, client: TestClient):
        payload = {**_BASE_PAYLOAD, "guard_mode": "assist"}

        async def _fake_stream(url: str, p: dict):
            yield b"chunk1"
            yield b"chunk2"

        with patch.object(_gr, "scan_with_policy_guard", _mock_guard(_ALLOW_VERDICT)):
            with patch.object(_gr, "_stream_upstream", _fake_stream):
                resp = client.post(_STREAM_URL, json=payload)

        assert resp.content == b"chunk1chunk2"

    def test_assist_mode_block_still_passes_upstream(self, client: TestClient):
        payload = {**_BASE_PAYLOAD, "guard_mode": "assist"}

        async def _fake_stream(url: str, p: dict):
            yield b"upstream_data"

        with patch.object(_gr, "scan_with_policy_guard", _mock_guard(_BLOCK_VERDICT)):
            with patch.object(_gr, "_stream_upstream", _fake_stream):
                resp = client.post(_STREAM_URL, json=payload)

        assert b"upstream_data" in resp.content

    def test_enforce_mode_allow_passes_upstream(self, client: TestClient):
        async def _fake_stream(url: str, p: dict):
            yield b"allowed_data"

        with patch.object(_gr, "scan_with_policy_guard", _mock_guard(_ALLOW_VERDICT)):
            with patch.object(_gr, "_stream_upstream", _fake_stream):
                resp = client.post(_STREAM_URL, json=_BASE_PAYLOAD)

        assert b"allowed_data" in resp.content

    def test_stream_response_content_type_is_json(self, client: TestClient):
        async def _fake_stream(url: str, p: dict):
            yield b"{}"

        with patch.object(_gr, "scan_with_policy_guard", _mock_guard(_ALLOW_VERDICT)):
            with patch.object(_gr, "_stream_upstream", _fake_stream):
                resp = client.post(_STREAM_URL, json=_BASE_PAYLOAD)

        assert "application/json" in resp.headers.get("content-type", "")


# ---------------------------------------------------------------------------
# /proxy-stream — 502 on guard service failure
# ---------------------------------------------------------------------------


class TestGuardProxyStream502:
    def test_502_when_guard_raises(self, client: TestClient):
        async def _fail(*_a, **_kw):
            raise HTTPException(status_code=502, detail="Guard service error: timeout")

        with patch.object(_gr, "scan_with_policy_guard", _fail):
            resp = client.post(_STREAM_URL, json=_BASE_PAYLOAD)
        assert resp.status_code == 502


# ---------------------------------------------------------------------------
# /proxy-stream — rate-limit enforcement (429)
# ---------------------------------------------------------------------------


class TestGuardProxyStreamRateLimit:
    def test_429_when_rate_limit_exceeded(self, client: TestClient):
        def _rate_limit_exceeded(request):
            raise HTTPException(status_code=429, detail="Rate limit exceeded")

        with patch("app.guard_router.limit_guard_routes", _rate_limit_exceeded):
            resp = client.post(_STREAM_URL, json=_BASE_PAYLOAD)
        assert resp.status_code == 429

    def test_429_does_not_call_guard_when_rate_limited(self, client: TestClient):
        def _rate_limit_exceeded(request):
            raise HTTPException(status_code=429, detail="Rate limit exceeded")

        mock_guard = _mock_guard(_ALLOW_VERDICT)
        with patch("app.guard_router.limit_guard_routes", _rate_limit_exceeded):
            with patch.object(_gr, "scan_with_policy_guard", mock_guard):
                client.post(_STREAM_URL, json=_BASE_PAYLOAD)
        mock_guard.assert_not_called()


# ---------------------------------------------------------------------------
# HTTP client lifecycle
# ---------------------------------------------------------------------------


class TestGuardHttpClientLifecycle:
    def test_client_raises_before_startup(self):
        fresh = _gr._GuardHttpClient()
        with pytest.raises(RuntimeError, match="not initialized"):
            _ = fresh.client

    @pytest.mark.anyio
    async def test_client_available_after_startup(self):
        fresh = _gr._GuardHttpClient()
        await fresh.startup()
        try:
            assert fresh.client is not None
        finally:
            await fresh.shutdown()

    @pytest.mark.anyio
    async def test_client_none_after_shutdown(self):
        fresh = _gr._GuardHttpClient()
        await fresh.startup()
        await fresh.shutdown()
        with pytest.raises(RuntimeError, match="not initialized"):
            _ = fresh.client

    @pytest.mark.anyio
    async def test_startup_idempotent(self):
        fresh = _gr._GuardHttpClient()
        await fresh.startup()
        first = fresh._client
        await fresh.startup()
        assert fresh._client is first
        await fresh.shutdown()
