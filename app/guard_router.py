from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse
import httpx
from pydantic import BaseModel, Field

from app.dependencies.rate_limit import limit_guard_routes

router = APIRouter(prefix="/claude-guard-router", tags=["claude-guard-router"])

GuardMode = Literal["assist", "enforce"]
VerdictType = Literal["allow", "block"]


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
        self._client: httpx.AsyncClient | None = None

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


def _normalize_guard_verdict(value: Any) -> VerdictType:
    return "allow" if isinstance(value, str) and value.strip().lower() == "allow" else "block"


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
    client = _guard_http_client.client
    url = guard_base_url.rstrip("/") + "/policy/guard-bundle"

    try:
        response = await client.post(url, json=payload)
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"Guard service error: {exc}") from exc

    if response.status_code != 200:
        raise HTTPException(status_code=502, detail=f"Guard service returned {response.status_code}")

    data = response.json()
    if not isinstance(data, dict):
        raise HTTPException(status_code=502, detail="Guard service returned an invalid response")
    raw_verdict = data.get("verdict")
    verdict = _normalize_guard_verdict(raw_verdict)
    reason = data.get("reason")
    if not isinstance(reason, str):
        reason = ""
    if verdict == "block" and not reason:
        reason = "Guard service blocked the request." if isinstance(raw_verdict, str) and raw_verdict.strip().lower() == "block" else "Guard service verdict missing or invalid; request blocked."
    truncated = bool(data.get("truncated", False))
    raw_metadata = data.get("metadata")
    metadata = dict(raw_metadata) if isinstance(raw_metadata, dict) else {}

    return GuardBundleVerdict(
        verdict=verdict,
        reason=reason,
        truncated=truncated,
        metadata=metadata,
    )


async def _stream_upstream(
    upstream_url: str,
    payload: dict[str, Any],
) -> AsyncIterator[bytes]:
    async with httpx.AsyncClient(timeout=httpx.Timeout(30.0)) as client:
        async with client.stream("POST", upstream_url, json=payload) as response:
            async for chunk in response.aiter_bytes():
                if not chunk:
                    continue
                yield chunk


def _get_rate_limit_dep() -> Any:
    """Indirection wrapper so tests can monkeypatch limit_guard_routes at call time."""
    import app.guard_router as _self  # noqa: PLC0415

    return _self.limit_guard_routes(None)  # type: ignore[arg-type]


@router.post(
    "/proxy",
    response_model=GuardProxyResponse,
)
async def guard_proxy_summary(
    payload: GuardProxyRequest,
    request: Request,
) -> GuardProxyResponse:
    # Resolved at call-time so tests can monkeypatch limit_guard_routes.
    limit_guard_routes(request)

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
    # Resolved at call-time so tests can monkeypatch limit_guard_routes.
    limit_guard_routes(request)

    cfg = GuardedStreamConfig(
        upstream_url=payload.upstream_url,
        guard_base_url=payload.guard_base_url,
        guard_mode=payload.guard_mode,
    )

    # Eagerly evaluate the guard verdict BEFORE entering StreamingResponse so
    # HTTPException(502) propagates correctly to FastAPI's exception handlers.
    verdict = await scan_with_policy_guard(cfg.guard_base_url, payload.guard_payload)

    if cfg.guard_mode == "enforce" and verdict.verdict == "block":
        message = verdict.reason or "Request blocked by policy guard."

        async def _blocked_stream() -> AsyncIterator[bytes]:
            yield message.encode("utf-8")

        return StreamingResponse(_blocked_stream(), media_type="application/json")

    async def event_stream() -> AsyncIterator[bytes]:
        async for chunk in _stream_upstream(cfg.upstream_url, payload.upstreampayload):
            if await request.is_disconnected():
                break
            yield chunk

    return StreamingResponse(event_stream(), media_type="application/json")
