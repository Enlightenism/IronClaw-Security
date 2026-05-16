from __future__ import annotations

from collections.abc import Mapping
import logging
from typing import Any

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app.core.logging import get_logger, get_request_id


class ErrorResponse(BaseModel):
    error: str
    message: str
    request_id: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class AppError(Exception):
    def __init__(
        self,
        error: str,
        message: str,
        *,
        status_code: int = status.HTTP_400_BAD_REQUEST,
        details: Mapping[str, Any] | None = None,
        log_level: int = logging.WARNING,
    ) -> None:
        super().__init__(message)
        self.error = error
        self.message = message
        self.status_code = int(status_code)
        self.details = dict(details or {})
        self.log_level = int(log_level)


class NotFoundError(AppError):
    def __init__(self, message: str = "Resource not found", **kwargs: Any) -> None:
        super().__init__(
            error="not_found",
            message=message,
            status_code=status.HTTP_404_NOT_FOUND,
            **kwargs,
        )


class ConflictError(AppError):
    def __init__(self, message: str = "Conflict detected", **kwargs: Any) -> None:
        super().__init__(
            error="conflict",
            message=message,
            status_code=status.HTTP_409_CONFLICT,
            **kwargs,
        )


class GuardRejectedError(AppError):
    def __init__(
        self,
        message: str = "Action blocked by security guard",
        *,
        details: Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            error="guard_rejected",
            message=message,
            status_code=status.HTTP_403_FORBIDDEN,
            details=details,
            **kwargs,
        )


def _request_id_from_request(request: Request) -> str | None:
    request_state_id = getattr(request.state, "request_id", None)
    if isinstance(request_state_id, str) and request_state_id.strip():
        return request_state_id.strip()
    global_request_id = get_request_id()
    if isinstance(global_request_id, str) and global_request_id.strip():
        return global_request_id.strip()
    return None


def build_error_response(
    *,
    error: str,
    message: str,
    request_id: str | None = None,
    details: Mapping[str, Any] | None = None,
) -> ErrorResponse:
    return ErrorResponse(
        error=error,
        message=message,
        request_id=request_id or get_request_id() or None,
        details=dict(details or {}),
    )


def _log_exception(
    logger: logging.Logger,
    *,
    level: int,
    event: str,
    request: Request,
    status_code: int,
    message: str,
    error: str,
    details: Mapping[str, Any] | None = None,
    exc_info: bool = False,
) -> None:
    logger.log(
        level,
        message,
        extra={
            "event": event,
            "error": error,
            "status_code": int(status_code),
            "path": request.url.path,
            "http_method": request.method,
            "request_id": _request_id_from_request(request),
            "details": dict(details or {}),
        },
        exc_info=exc_info,
    )


async def app_error_handler(request: Request, exc: AppError) -> JSONResponse:
    logger = get_logger("ironclaw.errors")
    _log_exception(
        logger,
        level=exc.log_level,
        event="app_error",
        request=request,
        status_code=exc.status_code,
        message=exc.message,
        error=exc.error,
        details=exc.details,
    )
    payload = build_error_response(
        error=exc.error,
        message=exc.message,
        request_id=_request_id_from_request(request),
        details=exc.details,
    )
    return JSONResponse(status_code=exc.status_code, content=payload.model_dump())


async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    logger = get_logger("ironclaw.errors")

    if isinstance(exc.detail, str):
        message = exc.detail
        details: dict[str, Any] = {}
    elif isinstance(exc.detail, Mapping):
        details = dict(exc.detail)
        message = str(details.get("message") or "Request failed")
    else:
        message = "Request failed"
        details = {}

    _log_exception(
        logger,
        level=logging.WARNING,
        event="http_exception",
        request=request,
        status_code=exc.status_code,
        message=message,
        error="http_error",
        details=details,
    )
    payload = build_error_response(
        error="http_error",
        message=message,
        request_id=_request_id_from_request(request),
        details=details,
    )
    return JSONResponse(status_code=exc.status_code, content=payload.model_dump())


async def validation_exception_handler(
    request: Request,
    exc: RequestValidationError,
) -> JSONResponse:
    logger = get_logger("ironclaw.errors")
    details = {"errors": exc.errors()}
    _log_exception(
        logger,
        level=logging.WARNING,
        event="validation_error",
        request=request,
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        message="Request validation failed",
        error="validation_error",
        details=details,
    )
    payload = build_error_response(
        error="validation_error",
        message="Request validation failed",
        request_id=_request_id_from_request(request),
        details=details,
    )
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        content=payload.model_dump(),
    )


async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger = get_logger("ironclaw.errors")
    _log_exception(
        logger,
        level=logging.ERROR,
        event="unhandled_exception",
        request=request,
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        message="Internal server error",
        error="internal_error",
        details={},
        exc_info=True,
    )
    payload = build_error_response(
        error="internal_error",
        message="Internal server error",
        request_id=_request_id_from_request(request),
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=payload.model_dump(),
    )


def register_exception_handlers(app: FastAPI) -> None:
    app.add_exception_handler(AppError, app_error_handler)
    app.add_exception_handler(HTTPException, http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(Exception, unhandled_exception_handler)
