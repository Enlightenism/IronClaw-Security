from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
import inspect
import time
from typing import Any, Generic, Literal, TypeVar

from ironclaw_skill.billing import (
    BillingContext,
    BillingHook,
    BillingResult,
    build_billing_context_from_request_context,
    charge_units,
)
from ironclaw_skill.contracts import SkillRequestContext

MiddlewareOperation = Literal["scan", "action_policy", "action_decision", "execute", "unknown"]

RequestT = TypeVar("RequestT")
ResponseT = TypeVar("ResponseT")


class IronClawMiddlewareError(RuntimeError):
    """Raised when middleware execution fails."""


@dataclass(frozen=True, slots=True)
class MiddlewareTrace:
    operation: MiddlewareOperation
    duration_ms: int
    request_id: str | None
    billed: bool
    billing_status: str | None
    units_charged: int
    short_circuited: bool
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "operation": self.operation,
            "duration_ms": self.duration_ms,
            "request_id": self.request_id,
            "billed": self.billed,
            "billing_status": self.billing_status,
            "units_charged": self.units_charged,
            "short_circuited": self.short_circuited,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class MiddlewareResult(Generic[ResponseT]):
    response: ResponseT
    trace: MiddlewareTrace
    billing: BillingResult | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "trace": self.trace.to_dict(),
        }
        if hasattr(self.response, "model_dump"):
            payload["response"] = self.response.model_dump(mode="json")
        elif hasattr(self.response, "to_dict"):
            payload["response"] = self.response.to_dict()
        else:
            payload["response"] = self.response
        if self.billing is not None:
            payload["billing"] = self.billing.to_dict()
        return payload


@dataclass(slots=True)
class MiddlewareConfig:
    enable_billing: bool = True
    fail_open_on_billing_error: bool = True
    include_trace_metadata: bool = True


@dataclass(slots=True)
class SkillMiddleware(Generic[RequestT, ResponseT]):
    operation: MiddlewareOperation
    handler: Callable[[RequestT], ResponseT | Awaitable[ResponseT]]
    billing_hook: BillingHook | None = None
    config: MiddlewareConfig = field(default_factory=MiddlewareConfig)
    metadata_factory: Callable[[RequestT], dict[str, Any]] | None = None

    async def __call__(self, request: RequestT) -> MiddlewareResult[ResponseT]:
        started = time.perf_counter()
        request_context = _extract_request_context(request)
        request_id = getattr(request_context, "request_id", None)
        metadata = self._build_metadata(request)

        billing_result: BillingResult | None = None
        short_circuited = False

        if self.config.enable_billing:
            try:
                billing_result = charge_units(
                    operation=self.operation,
                    hook=self.billing_hook,
                    context=_billing_context_from_request_context(request_context),
                    metadata=metadata,
                )
                if not billing_result.ok:
                    short_circuited = True
                    raise IronClawMiddlewareError(
                        billing_result.reason or "Billing hook rejected the request.",
                    )
            except Exception as exc:
                if not self.config.fail_open_on_billing_error:
                    raise IronClawMiddlewareError(f"Billing middleware failed: {exc}") from exc

        response = await _maybe_await(self.handler(request))
        duration_ms = round((time.perf_counter() - started) * 1000)

        trace = MiddlewareTrace(
            operation=self.operation,
            duration_ms=duration_ms,
            request_id=request_id,
            billed=billing_result is not None,
            billing_status=billing_result.status if billing_result else None,
            units_charged=billing_result.units_charged if billing_result else 0,
            short_circuited=short_circuited,
            metadata=metadata if self.config.include_trace_metadata else {},
        )
        return MiddlewareResult(response=response, trace=trace, billing=billing_result)

    def _build_metadata(self, request: RequestT) -> dict[str, Any]:
        base = {"operation": self.operation}
        if self.metadata_factory is None:
            return base

        extra = self.metadata_factory(request)
        if not isinstance(extra, dict):
            raise IronClawMiddlewareError("metadata_factory must return a dict")
        base.update(extra)
        return base


def create_middleware(
    *,
    operation: MiddlewareOperation,
    handler: Callable[[RequestT], ResponseT | Awaitable[ResponseT]],
    billing_hook: BillingHook | None = None,
    config: MiddlewareConfig | None = None,
    metadata_factory: Callable[[RequestT], dict[str, Any]] | None = None,
) -> SkillMiddleware[RequestT, ResponseT]:
    return SkillMiddleware(
        operation=operation,
        handler=handler,
        billing_hook=billing_hook,
        config=config or MiddlewareConfig(),
        metadata_factory=metadata_factory,
    )


def middleware(
    *,
    operation: MiddlewareOperation,
    billing_hook: BillingHook | None = None,
    config: MiddlewareConfig | None = None,
    metadata_factory: Callable[[RequestT], dict[str, Any]] | None = None,
) -> Callable[[Callable[[RequestT], ResponseT | Awaitable[ResponseT]]], SkillMiddleware[RequestT, ResponseT]]:
    def decorator(
        handler: Callable[[RequestT], ResponseT | Awaitable[ResponseT]],
    ) -> SkillMiddleware[RequestT, ResponseT]:
        return create_middleware(
            operation=operation,
            handler=handler,
            billing_hook=billing_hook,
            config=config,
            metadata_factory=metadata_factory,
        )

    return decorator


def attach_trace(response: Any, trace: MiddlewareTrace) -> Any:
    if response is None:
        return {"trace": trace.to_dict()}

    if hasattr(response, "trace"):
        try:
            response.trace = trace.to_dict()
            return response
        except Exception:
            return response

    if hasattr(response, "model_copy") and hasattr(response, "model_dump"):
        try:
            data = response.model_dump(mode="json")
            data["trace"] = trace.to_dict()
            return data
        except Exception:
            return response

    if isinstance(response, dict):
        enriched = dict(response)
        enriched["trace"] = trace.to_dict()
        return enriched

    return response


def _extract_request_context(request: Any) -> SkillRequestContext | None:
    if request is None:
        return None

    context = getattr(request, "context", None)
    if isinstance(context, SkillRequestContext):
        return context

    if isinstance(request, SkillRequestContext):
        return request

    return None


def _billing_context_from_request_context(
    request_context: SkillRequestContext | None,
) -> BillingContext | None:
    if request_context is None:
        return None
    return build_billing_context_from_request_context(request_context)


async def _maybe_await(value: ResponseT | Awaitable[ResponseT]) -> ResponseT:
    if inspect.isawaitable(value):
        return await value
    return value


def run_middleware(
    middleware_instance: SkillMiddleware[RequestT, ResponseT],
    request: RequestT,
) -> MiddlewareResult[ResponseT]:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(middleware_instance(request))

    raise IronClawMiddlewareError(
        "run_middleware cannot be used inside an active event loop; await the middleware directly.",
    ) from None


__all__ = [
    "IronClawMiddlewareError",
    "MiddlewareConfig",
    "MiddlewareResult",
    "MiddlewareTrace",
    "SkillMiddleware",
    "attach_trace",
    "create_middleware",
    "middleware",
    "run_middleware",
]
