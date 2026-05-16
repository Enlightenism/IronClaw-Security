from __future__ import annotations

from collections.abc import Mapping, MutableMapping
import contextvars
from datetime import UTC, datetime
import json
import logging
import sys
import time
from typing import Any

from fastapi import FastAPI, Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from app.core.request_id import REQUEST_ID_HEADER_NAME
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
    root_logger.handlers.clear()

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
        logger.handlers.clear()
        logger.propagate = True
        logger.setLevel(settings.log_level)


def get_logger(name: str = "ironclaw") -> logging.Logger:
    return logging.getLogger(name)


class RequestContextMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: FastAPI, logger_name: str = "ironclaw.access") -> None:
        super().__init__(app)
        self.logger = get_logger(logger_name)

    async def dispatch(self, request: Request, call_next) -> Response:
        request_id = getattr(request.state, "request_id", None) or request.headers.get(
            REQUEST_ID_HEADER_NAME,
        )
        if not request_id:
            request_id = "unknown-request-id"

        token = request_id_context.set(str(request_id))
        start = time.perf_counter()

        request.state.request_id = request_id
        client_ip = request.client.host if request.client else None

        self.logger.info(
            "request_started",
            extra={
                "event": "request_started",
                "http_method": request.method,
                "path": request.url.path,
                "query": str(request.url.query) if request.url.query else "",
                "client_ip": client_ip,
            },
        )

        try:
            response = await call_next(request)
        except Exception as exc:
            duration_ms = round((time.perf_counter() - start) * 1000, 2)
            self.logger.exception(
                "request_failed",
                extra={
                    "event": "request_failed",
                    "http_method": request.method,
                    "path": request.url.path,
                    "client_ip": client_ip,
                    "duration_ms": duration_ms,
                    "error_type": exc.__class__.__name__,
                },
            )
            request_id_context.reset(token)
            raise

        duration_ms = round((time.perf_counter() - start) * 1000, 2)
        response.headers[REQUEST_ID_HEADER_NAME] = str(request_id)

        self.logger.info(
            "request_completed",
            extra={
                "event": "request_completed",
                "http_method": request.method,
                "path": request.url.path,
                "client_ip": client_ip,
                "status_code": response.status_code,
                "duration_ms": duration_ms,
            },
        )

        request_id_context.reset(token)
        return response


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
