from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any, Literal, Optional

import anyio
import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from app.api.routes.billing import PACKAGE_CATALOG  # If you need pricing context
from app.core.unit_wallet import get_unit_wallet_registry


router = APIRouter(prefix="/claude-guard-router", tags=["claude-guard-router"])


GuardMode = Literal["assist", "enforce"]
VerdictType = Literal["allow", "warn", "quarantine", "block"]


class GuardedStreamConfig(BaseModel):
    upstream_url: str
    guard_base_url: str
    guard_mode: GuardMode = Field(description="assist = never truncate, enforce = truncate on block")
    timeout_seconds: float = 30.0
    connect_timeout_seconds: float = 5.0


class GuardBundleVerdict(BaseModel):
    verdict: VerdictType
    reason: str = ""
    truncated: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class GuardProxyRequest(BaseModel):
    upstream_url: str
    guard_base_url: str
    guard_mode: GuardMode = "enforce"
    upstreampayload: dict[str, Any] = Field(default_factory=dict)
    guard_payload: dict[str, Any] = Field(default_factory=dict)


class GuardProxyResponse(BaseModel):
    status: str
    mode: GuardMode
    verdict: VerdictType
    reason: str
    truncated: bool
    metadata: dict[str, Any] = Field(default_factory=dict)


class _GuardHttpClient:
    def __init__(self) -> None:
        self._client: Optional[httpx.AsyncClient] = None

    async def startup(self) -> None:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=httpx.Timeout(30.0))

    async def shutdown(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            raise RuntimeError("Guard HTTP client not initialized")
        return self._client


_guard_http_client = _GuardHttpClient()


@router.on_event("startup")
async def _startup_guard_http_client() -> None:
    await _guard_http_client.startup()


@router.on_event("shutdown")
async def _shutdown_guard_http_client() -> None:
    await _guard_http_client.shutdown()


async def scan_with_policy_guard(
    guard_base_url: str,
    payload: dict[str, Any],
) -> GuardBundleVerdict:
    """
    Call the policy guard bundle route once per request using the shared AsyncClient.
    This function is intentionally small; tests monkeypatch httpx.AsyncClient to
    intercept POSTs to the guard bundle URL.
    """
    client = _guard_http_client.client
    url = guard_base_url.rstrip("/") + "/policy/guard-bundle"

    try:
        response = await client.post(url, json=payload)
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"Guard service error: {exc}") from exc

    if response.status_code != 200:
        raise HTTPException(status_code=502, detail=f"Guard service returned {response.status_code}")

    data = response.json()
    verdict = str(data.get("verdict", "allow"))
    reason = str(data.get("reason", ""))
    truncated = bool(data.get("truncated", False))
    metadata = dict(data.get("metadata") or {})

    return GuardBundleVerdict(
        verdict=verdict,  # type: ignore[arg-type]
        reason=reason,
        truncated=truncated,
        metadata=metadata,
    )


async def _stream_upstream(
    upstream_url: str,
    payload: dict[str, Any],
) -> AsyncIterator[bytes]:
    """
    Minimal upstream streaming helper; tests will usually mock this path, so we
    keep behavior simple and predictable.
    """
    async with httpx.AsyncClient(timeout=httpx.Timeout(30.0)) as client:
        async with client.stream("POST", upstream_url, json=payload) as response:
            async for chunk in response.aiter_bytes():
                if not chunk:
                    continue
                yield chunk


async def _guarded_upstream_stream(
    cfg: GuardedStreamConfig,
    upstreampayload: dict[str, Any],
    guard_payload: dict[str, Any],
) -> AsyncIterator[bytes]:
    """
    Wrap the upstream stream with a policy guard decision.

    - assist mode: never truncates the upstream; just annotates metadata.
    - enforce mode: if guard verdict is block, truncate the stream and yield
      a short blocked message instead of the full upstream payload.
    """
    verdict = await scan_with_policy_guard(cfg.guard_base_url, guard_payload)
    mode = cfg.guard_mode

    if mode == "enforce" and verdict.verdict == "block":
        # Enforce truncation: yield a short blocked message for the stream.
        message = verdict.reason or "Request blocked by policy guard."
        yield message.encode("utf-8")
        return

    async for chunk in _stream_upstream(cfg.upstream_url, upstreampayload):
        yield chunk


@asynccontextmanager
async def _guarded_stream_context(
    cfg: GuardedStreamConfig,
    upstreampayload: dict[str, Any],
    guard_payload: dict[str, Any],
) -> AsyncIterator[AsyncIterator[bytes]]:
    """
    Async context manager to provide a guarded upstream stream suitable for use
    in StreamingResponse, while making it easy to reason about lifecycle in tests.
    """
    gen = _guarded_upstream_stream(cfg, upstreampayload, guard_payload)
    try:
        yield gen
    finally:
        # Make sure the async generator is fully closed even on error.
        await gen.aclose()


@router.post(
    "/proxy",
    response_model=GuardProxyResponse,
)
async def guard_proxy_summary(payload: GuardProxyRequest) -> GuardProxyResponse:
    """
    Non-streaming summary endpoint that simply calls the guard bundle and
    returns the decision in a structured response.
    """
    verdict = await scan_with_policy_guard(payload.guard_base_url, payload.guard_payload)

    truncated = verdict.truncated or (payload.guard_mode == "enforce" and verdict.verdict == "block")

    return GuardProxyResponse(
        status="ok",
        mode=payload.guard_mode,
        verdict=verdict.verdict,
        reason=verdict.reason,
        truncated=truncated,
        metadata=verdict.metadata,
    )


@router.post(
    "/proxy-stream",
    response_class=StreamingResponse,
)
async def guard_proxy_stream(
    payload: GuardProxyRequest,
    request: Request,
) -> StreamingResponse:
    """
    Streaming proxy endpoint used by tests:

    - Calls the guard bundle first to get a verdict.
    - In enforce mode, truncates the upstream stream on block.
    - In assist mode, always passes through the upstream stream.
    """
    cfg = GuardedStreamConfig(
        upstream_url=payload.upstream_url,
        guard_base_url=payload.guard_base_url,
        guard_mode=payload.guard_mode,
    )

    stream_cm = _guarded_stream_context(cfg, payload.upstreampayload, payload.guard_payload)

    async def event_stream() -> AsyncIterator[bytes]:
        async with stream_cm as guarded_stream:
            async for chunk in guarded_stream:
                # Allow client disconnects to gracefully stop iteration
                if await request.is_disconnected():
                    break
                yield chunk

    return StreamingResponse(
        event_stream(),
        media_type="application/json",
    )