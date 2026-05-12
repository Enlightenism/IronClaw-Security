from __future__ import annotations

import json
from collections.abc import AsyncGenerator

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import PlainTextResponse, StreamingResponse
from starlette.background import BackgroundTask

from app.core.auth import require_api_key

router = APIRouter(
    prefix="/claude/router-proxy",
    tags=["claude-router-proxy"],
    dependencies=[Depends(require_api_key)],
)


async def _proxy_upstream_stream(
    upstream: httpx.Response,
) -> AsyncGenerator[bytes, None]:
    async for chunk in upstream.aiter_bytes():
        if chunk:
            yield chunk


async def _close_upstream_and_client(
    upstream: httpx.Response,
    client: httpx.AsyncClient,
) -> None:
    await upstream.aclose()
    await client.aclose()


@router.post(
    "/proxy",
    response_class=StreamingResponse,
    status_code=status.HTTP_200_OK,
)
async def claude_router_proxy(
    request: Request,
) -> Response:
    body = await request.json()

    upstream_url = body.get("upstream_url")
    upstream_payload = body.get("upstream_payload") or {}

    if not upstream_url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing 'upstream_url' in request body.",
        )

    client = httpx.AsyncClient(timeout=None)
    try:
        upstream = await client.send(
            client.build_request(
                "POST",
                upstream_url,
                headers={"Content-Type": "application/json"},
                content=json.dumps(upstream_payload, separators=(",", ":")),
            ),
            stream=True,
        )

        if upstream.status_code != status.HTTP_200_OK:
            error_text = (await upstream.aread()).decode("utf-8", errors="replace")
            await upstream.aclose()
            await client.aclose()
            return PlainTextResponse(
                error_text,
                status_code=upstream.status_code,
            )

        return StreamingResponse(
            _proxy_upstream_stream(upstream),
            media_type="text/plain; charset=utf-8",
            background=BackgroundTask(_close_upstream_and_client, upstream, client),
        )
    except httpx.HTTPError as exc:
        await client.aclose()
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Upstream proxy error: {exc!r}",
        ) from exc