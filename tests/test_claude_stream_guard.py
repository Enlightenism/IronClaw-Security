from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.claude_stream_guard import router as claude_stream_guard_router


def _build_test_app() -> FastAPI:
    app = FastAPI()
    app.include_router(claude_stream_guard_router)
    return app


def _headers() -> dict[str, str]:
    return {"X-API-Key": "test-key"}


class _UpstreamStream(httpx.AsyncByteStream):
    def __init__(self, chunks: list[str]) -> None:
        self._chunks = chunks

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for chunk in self._chunks:
            yield chunk.encode("utf-8")


def test_stream_guard_requires_upstream_url() -> None:
    app = _build_test_app()
    client = TestClient(app)

    response = client.post(
        "/claude/stream-guard/proxy",
        headers=_headers(),
        json={"upstream_payload": {}},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Missing 'upstream_url' in request body."


def test_stream_guard_dryrun_streams_content_without_blocking(monkeypatch) -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url).endswith("/policy/guard-bundle"):
            return httpx.Response(
                200,
                json={"bundle_verdict": "block", "reason": "detected in dryrun"},
            )

        return httpx.Response(
            200,
            stream=_UpstreamStream(["hello ", "world"]),
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
        "/claude/stream-guard/proxy",
        headers=_headers(),
        json={
            "upstream_url": "https://upstream.example/stream",
            "upstream_payload": {
                "user_prompt": "Build code",
                "model_output": "",
            },
            "guard_base_url": "https://guard.example",
            "guard_mode": "dryrun",
        },
    )

    assert response.status_code == 200
    text = response.text
    assert "ironclaw_guard_info" in text
    assert "hello world" in text
    assert "Stream truncated due to high-risk content" not in text


def test_stream_guard_enforce_truncates_on_block_verdict(monkeypatch) -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url).endswith("/policy/guard-bundle"):
            return httpx.Response(
                200,
                json={"bundle_verdict": "block", "reason": "prompt injection detected"},
            )

        return httpx.Response(
            200,
            stream=_UpstreamStream(["unsafe ", "payload ", "continues"]),
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
        "/claude/stream-guard/proxy",
        headers=_headers(),
        json={
            "upstream_url": "https://upstream.example/stream",
            "upstream_payload": {
                "user_prompt": "Summarize this",
            },
            "guard_base_url": "https://guard.example",
            "guard_mode": "enforce",
        },
    )

    assert response.status_code == 200
    text = response.text
    assert "ironclaw_guard_info" in text
    assert "Stream truncated due to high-risk content" in text
    assert "prompt injection detected" in text


def test_stream_guard_assist_does_not_truncate(monkeypatch) -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url).endswith("/policy/guard-bundle"):
            return httpx.Response(
                200,
                json={"bundle_verdict": "quarantine", "reason": "suspicious output"},
            )

        return httpx.Response(
            200,
            stream=_UpstreamStream(["chunk-1 ", "chunk-2"]),
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
        "/claude/stream-guard/proxy",
        headers=_headers(),
        json={
            "upstream_url": "https://upstream.example/stream",
            "upstream_payload": {
                "user_prompt": "Review this",
            },
            "guard_base_url": "https://guard.example",
            "guard_mode": "assist",
        },
    )

    assert response.status_code == 200
    text = response.text
    assert "ironclaw_guard_info" in text
    assert "chunk-1 chunk-2" in text
    assert "Stream truncated due to high-risk content" not in text