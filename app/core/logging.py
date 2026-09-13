from __future__ import annotations

from collections.abc import Mapping, MutableMapping
import contextvars
from datetime import UTC, datetime
import json
import logging
import sys
import time
from typing import Any

from starlette.datastructures import Headers, MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.requestid import REQUEST_ID_HEADER_NAME
from app.core.settings import Settings

request_id_context: contextvars.ContextVar[str] = contextvars.ContextVar(
    "request_id",
    default="",
)


def get_request_id() -> str:
    return request_id_context.get()


class RequestContextFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = get_request_id() or None
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": getattr(record, "request_id", None),
        }

        extra_fields = _extract_extra_fields(record)
        if extra_fields:
            payload.update(extra_fields)

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(payload, default=str, ensure_ascii=False)


def _extract_extra_fields(record: logging.LogRecord) -> dict[str, Any]:
    standard_fields = {
        "name",
        "msg",
        "args",
        "levelname",
        "levelno",
        "pathname",
        "filename",
        "module",
        "exc_info",
        "exc_text",
        "stack_info",
        "lineno",
        "funcName",
        "created",
        "msecs",
        "relativeCreated",
        "thread",
        "threadName",
        "processName",
        "process",
        "message",
        "asctime",
        "request_id",
    }
    return {key: value for key, value in record.__dict__.items() if key not in standard_fields and not key.startswith("_")}


def configure_logging(settings: Settings) -> None:
    root_logger = logging.getLogger()
    for handler in list(root_logger.handlers):
        try:
            handler.flush()
        except Exception:
            pass
        try:
            handler.close()
        except Exception:
            pass
        root_logger.removeHandler(handler)

    handler = logging.StreamHandler(sys.stdout)
    handler.addFilter(RequestContextFilter())

    if settings.structured_logging_enabled:
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(
            logging.Formatter(
                "%(asctime)s %(levelname)s %(name)s [request_id=%(request_id)s] %(message)s",
            ),
        )

    root_logger.addHandler(handler)
    root_logger.setLevel(settings.log_level)
    root_logger.propagate = False

    for logger_name in ("uvicorn", "uvicorn.error", "uvicorn.access", "fastapi"):
        logger = logging.getLogger(logger_name)
        for child_handler in list(logger.handlers):
            try:
                child_handler.flush()
            except Exception:
                pass
            try:
                child_handler.close()
            except Exception:
                pass
            logger.removeHandler(child_handler)
        logger.propagate = True
        logger.setLevel(settings.log_level)


def get_logger(name: str = "ironclaw") -> logging.Logger:
    return logging.getLogger(name)


class RequestContextMiddleware:
    def __init__(self, app: ASGIApp, logger_name: str = "ironclaw.access") -> None:
        self.app = app
        self.logger = get_logger(logger_name)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)
        state = scope.setdefault("state", {})

        request_id = state.get("request_id") or headers.get(REQUEST_ID_HEADER_NAME)
        if not request_id:
            request_id = "unknown-request-id"

        token = request_id_context.set(str(request_id))
        state["request_id"] = str(request_id)

        method = scope.get("method", "")
        path = scope.get("path", "")
        query_string_bytes = scope.get("query_string", b"")
        query = query_string_bytes.decode("utf-8", errors="replace") if query_string_bytes else ""

        client = scope.get("client")
        client_ip = client[0] if client else None

        start = time.perf_counter()

        self.logger.info(
            "request_started",
            extra={
                "event": "request_started",
                "http_method": method,
                "path": path,
                "query": query,
                "client_ip": client_ip,
            },
        )

        async def send_with_request_context(message: Message) -> None:
            if message["type"] == "http.response.start":
                duration_ms = round((time.perf_counter() - start) * 1000, 2)
                response_headers = MutableHeaders(raw=message["headers"])
                response_headers.setdefault(REQUEST_ID_HEADER_NAME, str(request_id))

                self.logger.info(
                    "request_completed",
                    extra={
                        "event": "request_completed",
                        "http_method": method,
                        "path": path,
                        "client_ip": client_ip,
                        "status_code": message["status"],
                        "duration_ms": duration_ms,
                    },
                )

            await send(message)

        try:
            await self.app(scope, receive, send_with_request_context)
        except Exception as exc:
            duration_ms = round((time.perf_counter() - start) * 1000, 2)
            self.logger.exception(
                "request_failed",
                extra={
                    "event": "request_failed",
                    "http_method": method,
                    "path": path,
                    "client_ip": client_ip,
                    "duration_ms": duration_ms,
                    "error_type": exc.__class__.__name__,
                },
            )
            raise
        finally:
            request_id_context.reset(token)


def bind_security_event(
    logger: logging.Logger,
    event: str,
    *,
    scan_id: str | None = None,
    verdict: str | None = None,
    risk_score: int | None = None,
    target_type: str | None = None,
    target_value: str | None = None,
    action_type: str | None = None,
    review_status: str | None = None,
    matched_patterns: list[str] | None = None,
    extra_metadata: Mapping[str, Any] | None = None,
    level: int = logging.INFO,
) -> None:
    payload: MutableMapping[str, Any] = {
        "event": event,
        "scan_id": scan_id,
        "verdict": verdict,
        "risk_score": risk_score,
        "target_type": target_type,
        "target_value": _truncate_value(target_value),
        "action_type": action_type,
        "review_status": review_status,
        "matched_patterns": matched_patterns or [],
    }

    if extra_metadata:
        payload.update(dict(extra_metadata))

    logger.log(level, event, extra=dict(payload))


def _truncate_value(value: str | None, limit: int = 500) -> str | None:
    if value is None:
        return None
    if len(value) <= limit:
        return value
    return f"{value[:limit]}...[truncated]"
