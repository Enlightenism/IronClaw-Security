from __future__ import annotations

from collections.abc import AsyncGenerator
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import StreamingResponse
import httpx

from app.core.auth import require_api_key

router = APIRouter(
    prefix="/claude/stream-guard",
    tags=["claude-stream-guard"],
    dependencies=[Depends(require_api_key)],
)


class StreamGuardError(Exception):
    pass


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


async def _scan_chunk_with_policy_guard(
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

    url = f"{guard_base_url.rstrip('/')}/policy/guard-bundle"
    resp = await client.post(
        url,
        headers={"X-API-Key": api_key, "Content-Type": "application/json"},
        json=payload,
        timeout=5.0,
    )
    resp.raise_for_status()
    return resp.json()  # type: ignore[no-any-return]


def _build_block_warning(reason: str, bundle_verdict: str) -> bytes:
    warning = f"\n\n[IRONCLAW-GUARD] Stream truncated due to high-risk content. Reason: {reason or 'policy guard verdict: ' + bundle_verdict}.\n"
    return warning.encode("utf-8")


async def _proxy_stream_with_guard(
    upstream_url: str,
    *,
    guard_base_url: str,
    api_key: str,
    request_body: dict[str, Any],
    guard_mode: str = "enforce",
    scan_interval_chars: int = 256,
) -> AsyncGenerator[bytes, None]:
    context = {
        "userprompt": request_body.get("user_prompt"),
        "retrieveddoc": request_body.get("retrieved_docs"),
        "tooloutput": request_body.get("tool_outputs"),
    }

    async with httpx.AsyncClient(timeout=None) as client:
        try:
            async with client.stream(
                "POST",
                upstream_url,
                headers={"Content-Type": "application/json"},
                json=request_body,
            ) as upstream:
                if upstream.status_code != status.HTTP_200_OK:
                    text = await upstream.aread()
                    raise StreamGuardError(
                        f"Upstream returned {upstream.status_code}: {text!r}",
                    )

                buffer = ""
                scanned_upto = 0
                blocked = False

                async for chunk in upstream.aiter_text():
                    if not chunk:
                        continue

                    buffer += chunk

                    if len(buffer) - scanned_upto >= scan_interval_chars and not blocked:
                        verdict = await _scan_chunk_with_policy_guard(
                            client=client,
                            guard_base_url=guard_base_url,
                            api_key=api_key,
                            partial_text=buffer,
                            context=context,
                        )

                        bundle_verdict = "allow" if str(verdict.get("bundle_verdict", "")).strip().lower() == "allow" else "block"
                        reason = str(verdict.get("reason", ""))

                        if bundle_verdict == "block":
                            blocked = True
                            yield _build_block_warning(reason, bundle_verdict)
                            break

                        safe_text = buffer[scanned_upto:]
                        scanned_upto = len(buffer)
                        yield safe_text.encode("utf-8")

                if not blocked and len(buffer) > scanned_upto:
                    verdict = await _scan_chunk_with_policy_guard(
                        client=client,
                        guard_base_url=guard_base_url,
                        api_key=api_key,
                        partial_text=buffer,
                        context=context,
                    )

                    bundle_verdict = "allow" if str(verdict.get("bundle_verdict", "")).strip().lower() == "allow" else "block"
                    reason = str(verdict.get("reason", ""))

                    if bundle_verdict == "block":
                        yield _build_block_warning(reason, bundle_verdict)
                    else:
                        yield buffer[scanned_upto:].encode("utf-8")

        except httpx.HTTPError as exc:
            error_msg = f"[IRONCLAW-GUARD] Upstream streaming error: {exc!r}"
            yield error_msg.encode("utf-8")


@router.post(
    "/proxy",
    response_class=StreamingResponse,
    status_code=status.HTTP_200_OK,
)
async def claude_stream_guard_proxy(
    request: Request,
) -> StreamingResponse:
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

    async def event_stream() -> AsyncGenerator[bytes, None]:
        prelude = {
            "type": "ironclaw_guard_info",
            "generated_at": _now_iso(),
            "guard_mode": guard_mode,
        }
        import json

        yield (json.dumps(prelude) + "\n").encode("utf-8")

        async for chunk in _proxy_stream_with_guard(
            upstream_url=upstream_url,
            guard_base_url=guard_base_url,
            api_key=api_key,
            request_body=upstream_payload,
            guard_mode=guard_mode,
        ):
            yield chunk

    return StreamingResponse(
        event_stream(),
        media_type="text/plain; charset=utf-8",
    )


def _infer_guard_base_url(request: Request) -> str:
    scheme = request.headers.get("X-Forwarded-Proto") or request.url.scheme
    host = request.headers.get("X-Forwarded-Host") or request.headers.get("Host") or request.url.netloc
    return f"{scheme}://{host}".rstrip("/")
