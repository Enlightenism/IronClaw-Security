from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.core.errors import AppError


def _build_error_payload(
    request: Request,
    *,
    error: str,
    message: str,
    details,
) -> dict[str, object]:
    request_id = getattr(request.state, "request_id", None)
    payload: dict[str, object] = {
        "error": error,
        "message": message,
        "details": details,
        "path": request.url.path,
    }
    if request_id:
        payload["request_id"] = request_id
    return payload


async def app_error_handler(request: Request, exc: AppError) -> JSONResponse:
    status_code = int(getattr(exc, "status_code", 500) or 500)
    payload = _build_error_payload(
        request,
        error=getattr(exc, "error", "application_error"),
        message=str(exc),
        details=getattr(exc, "details", None),
    )
    return JSONResponse(
        status_code=status_code,
        content=jsonable_encoder(payload),
    )


async def validation_error_handler(
    request: Request,
    exc: RequestValidationError,
) -> JSONResponse:
    payload = _build_error_payload(
        request,
        error="validation_error",
        message="Request validation failed",
        details=exc.errors(),
    )
    return JSONResponse(
        status_code=422,
        content=jsonable_encoder(payload),
    )


def install_exception_handlers(app: FastAPI) -> None:
    app.add_exception_handler(AppError, app_error_handler)
    app.add_exception_handler(RequestValidationError, validation_error_handler)
