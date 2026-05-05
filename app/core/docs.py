from __future__ import annotations

from fastapi import APIRouter, Depends, FastAPI
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
from fastapi.responses import HTMLResponse, JSONResponse

from app.core.auth import require_api_key


def create_docs_router() -> APIRouter:
    router = APIRouter()

    @router.get("/docs", include_in_schema=False, response_class=HTMLResponse)
    def swagger_ui(_: str = Depends(require_api_key)) -> HTMLResponse:
        return get_swagger_ui_html(
            openapi_url="/openapi.json",
            title="IronClaw-Security - Swagger UI",
        )

    @router.get("/openapi.json", include_in_schema=False, response_class=JSONResponse)
    def openapi_schema(_: str = Depends(require_api_key)) -> JSONResponse:
        schema = get_openapi(
            title="IronClaw-Security",
            version="1.0.0",
            description="Local-first security scanning API with reviewed verdict handling.",
            routes=router.routes,
        )
        return JSONResponse(schema)

    return router


def install_protected_docs(app: FastAPI) -> None:
    router = APIRouter()

    @router.get("/docs", include_in_schema=False, response_class=HTMLResponse)
    def swagger_ui(_: str = Depends(require_api_key)) -> HTMLResponse:
        return get_swagger_ui_html(
            openapi_url="/openapi.json",
            title=f"{app.title} - Swagger UI",
        )

    @router.get("/openapi.json", include_in_schema=False, response_class=JSONResponse)
    def openapi_schema(_: str = Depends(require_api_key)) -> JSONResponse:
        schema = get_openapi(
            title=app.title,
            version=app.version,
            description=app.description,
            routes=app.routes,
        )
        return JSONResponse(schema)

    app.include_router(router)