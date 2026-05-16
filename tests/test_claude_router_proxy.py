from __future__ import annotations

from collections.abc import AsyncIterator

from fastapi import FastAPI
from fastapi.testclient import TestClient
import httpx

from app.api.claude_router_proxy import router as claude_router_proxy_router


def _build_test_app() -> FastAPI:
    app = FastAPI()
    app.include_router(claude_router_proxy_router)
    return app


def _headers() -> dict[str, str]:
    return {"X-API-Key": "test-key"}


class _UpstreamStream(httpx.AsyncByteStream):
    def __init__(self, chunks: list[str]) -> None:
        self._chunks = chunks

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for chunk in self._chunks:
            yield chunk.encode("utf-8")


def test_proxy_requires_upstream_url() -> None:
    app = _build_test_app()
    client = TestClient(app)

    response = client.post(
        "/claude/router-proxy/proxy",
        headers=_headers(),
        json={"upstream_payload": {}},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Missing 'upstream_url' in request body."


def test_proxy_streams_upstream_response(monkeypatch) -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            stream=_UpstreamStream(["hello ", "router ", "proxy"]),
        )

    transport = httpx.MockTransport(handler)
    original_async_client = httpx.AsyncClient

    def _mock_async_client(*args, **kwargs):
        kwargs["transport"] = transport
        return original_async_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", _mock_async_client)

    app = _build_test_app()
    client = TestClient(app)

    response = client.post(
        "/claude/router-proxy/proxy",
        headers=_headers(),
        json={
            "upstream_url": "https://upstream.example/router",
            "upstream_payload": {"prompt": "Build next task"},
        },
    )

    assert response.status_code == 200
    assert response.text == "hello router proxy"


def test_proxy_passes_json_payload_to_upstream(monkeypatch) -> None:
    captured: dict[str, object] = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        captured["method"] = request.method
        captured["url"] = str(request.url)
        captured["content_type"] = request.headers.get("Content-Type")
        captured["body"] = request.read().decode("utf-8")
        return httpx.Response(
            200,
            stream=_UpstreamStream(["ok"]),
        )

    transport = httpx.MockTransport(handler)
    original_async_client = httpx.AsyncClient

    def _mock_async_client(*args, **kwargs):
        kwargs["transport"] = transport
        return original_async_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", _mock_async_client)

    app = _build_test_app()
    client = TestClient(app)

    response = client.post(
        "/claude/router-proxy/proxy",
        headers=_headers(),
        json={
            "upstream_url": "https://upstream.example/router",
            "upstream_payload": {"prompt": "hello", "mode": "fast"},
        },
    )

    assert response.status_code == 200
    assert response.text == "ok"
    assert captured["method"] == "POST"
    assert captured["url"] == "https://upstream.example/router"
    assert captured["content_type"] == "application/json"
    assert '"prompt":"hello"' in str(captured["body"])
    assert '"mode":"fast"' in str(captured["body"])


def test_proxy_returns_upstream_error_text(monkeypatch) -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            502,
            text="bad gateway upstream",
        )

    transport = httpx.MockTransport(handler)
    original_async_client = httpx.AsyncClient

    def _mock_async_client(*args, **kwargs):
        kwargs["transport"] = transport
        return original_async_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", _mock_async_client)

    app = _build_test_app()
    client = TestClient(app)

    response = client.post(
        "/claude/router-proxy/proxy",
        headers=_headers(),
        json={
            "upstream_url": "https://upstream.example/router",
            "upstream_payload": {"prompt": "hello"},
        },
    )

    assert response.status_code == 502
    assert "bad gateway upstream" in response.text
