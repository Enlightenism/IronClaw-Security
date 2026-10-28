from __future__ import annotations

from collections.abc import AsyncGenerator
from datetime import UTC, datetime
import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import PlainTextResponse, StreamingResponse
import httpx
from starlette.background import BackgroundTask

from app.core.auth import require_api_key

router = APIRouter(
    prefix="/claude/guard-router",
    tags=["claude-guard-router"],
    dependencies=[Depends(require_api_key)],
)


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


async def _scan_with_policy_guard(
    client: httpx.AsyncClient,
    guard_base_url: str,
    api_key: str,
    partial_text: str,
    *,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "userprompt": context.get("userprompt") if context else None,
        "retrieveddoc": context.get("retrieveddoc") if context else None,
        "tooloutput": context.get("tooloutput") if context else None,
        "modeloutput": partial_text,
    }

    resp = await client.post(
        f"{guard_base_url.rstrip('/')}/policy/guard-bundle",
        headers={"X-API-Key": api_key, "Content-Type": "application/json"},
        json=payload,
        timeout=5.0,
    )
    resp.raise_for_status()
    return resp.json()  # type: ignore[no-any-return]


def _build_guard_warning(reason: str, verdict: str) -> bytes:
    return (f"\n\n[IRONCLAW-GUARD] Stream truncated due to high-risk content. Reason: {reason or 'policy guard verdict: ' + verdict}.\n").encode()


async def _guarded_upstream_stream(
    upstream: httpx.Response,
    *,
    client: httpx.AsyncClient,
    guard_base_url: str,
    api_key: str,
    request_body: dict[str, Any],
    guard_mode: str,
    scan_interval_chars: int = 256,
) -> AsyncGenerator[bytes, None]:
    context = {
        "userprompt": request_body.get("user_prompt"),
        "retrieveddoc": request_body.get("retrieved_docs"),
        "tooloutput": request_body.get("tool_outputs"),
    }

    buffer = ""
    scanned_upto = 0
    blocked = False

    async for chunk in upstream.aiter_text():
        if not chunk:
            continue

        buffer += chunk

        if len(buffer) - scanned_upto >= scan_interval_chars and not blocked:
            verdict_data = await _scan_with_policy_guard(
                client=client,
                guard_base_url=guard_base_url,
                api_key=api_key,
                partial_text=buffer,
                context=context,
            )
            verdict = "allow" if str(verdict_data.get("bundle_verdict", "")).strip().lower() == "allow" else "block"
            reason = str(verdict_data.get("reason", ""))

            if verdict == "block":
                blocked = True
                yield _build_guard_warning(reason, verdict)
                break

            safe_text = buffer[scanned_upto:]
            scanned_upto = len(buffer)
            yield safe_text.encode("utf-8")

    if not blocked and len(buffer) > scanned_upto:
        verdict_data = await _scan_with_policy_guard(
            client=client,
            guard_base_url=guard_base_url,
            api_key=api_key,
            partial_text=buffer,
            context=context,
        )
        verdict = "allow" if str(verdict_data.get("bundle_verdict", "")).strip().lower() == "allow" else "block"
        reason = str(verdict_data.get("reason", ""))

        if verdict == "block":
            yield _build_guard_warning(reason, verdict)
        else:
            yield buffer[scanned_upto:].encode("utf-8")


@router.post(
    "/proxy",
    response_class=StreamingResponse,
    status_code=status.HTTP_200_OK,
)
async def claude_guard_router_proxy(
    request: Request,
) -> Response:
    body = await request.json()

    upstream_url = body.get("upstream_url")
    upstream_payload = body.get("upstream_payload") or {}
    guard_base_url = body.get("guard_base_url") or _infer_guard_base_url(request)
    guard_mode = str(body.get("guard_mode") or "enforce").lower()

    if not upstream_url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing 'upstream_url' in request body.",
        )

    if guard_mode not in {"enforce", "assist", "dryrun"}:
        guard_mode = "enforce"

    api_key = request.headers.get("X-API-Key")
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-API-Key header.",
        )

    client = httpx.AsyncClient(timeout=None)
    upstream: httpx.Response | None = None
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
            return PlainTextResponse(
                error_text,
                status_code=upstream.status_code,
                background=BackgroundTask(_close_client_and_upstream, upstream, client),
            )

        async def event_stream() -> AsyncGenerator[bytes, None]:
            prelude = {
                "type": "ironclaw_guard_info",
                "generated_at": _now_iso(),
                "guard_mode": guard_mode,
            }
            yield (json.dumps(prelude) + "\n").encode("utf-8")

            async for chunk in _guarded_upstream_stream(
                upstream,
                client=client,
                guard_base_url=guard_base_url,
                api_key=api_key,
                request_body=upstream_payload,
                guard_mode=guard_mode,
            ):
                yield chunk

        return StreamingResponse(
            event_stream(),
            media_type="text/plain; charset=utf-8",
            background=BackgroundTask(_close_client_and_upstream, upstream, client),
        )
    except httpx.HTTPError as exc:
        if upstream is not None:
            await upstream.aclose()
        await client.aclose()
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Upstream proxy error: {exc!r}",
        ) from exc
    except Exception:
        if upstream is not None:
            await upstream.aclose()
        await client.aclose()
        raise


async def _close_client_and_upstream(
    upstream: httpx.Response,
    client: httpx.AsyncClient,
) -> None:
    await upstream.aclose()
    await client.aclose()


def _infer_guard_base_url(request: Request) -> str:
    scheme = request.headers.get("X-Forwarded-Proto") or request.url.scheme
    host = request.headers.get("X-Forwarded-Host") or request.headers.get("Host") or request.url.netloc
    return f"{scheme}://{host}".rstrip("/")
