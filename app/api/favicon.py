from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import FileResponse

router = APIRouter(tags=["branding"])

# Same icon files the Cloudflare Pages build serves from frontend/public.
_PUBLIC_DIR = Path(__file__).resolve().parents[2] / "frontend" / "public"
_ICON_CACHE_CONTROL = "public, max-age=3600"


def _icon_response(filename: str, media_type: str) -> FileResponse:
    icon_path = _PUBLIC_DIR / filename
    if not icon_path.is_file():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Icon not found.")
    return FileResponse(
        path=icon_path,
        media_type=media_type,
        headers={"Cache-Control": _ICON_CACHE_CONTROL},
    )


@router.get("/favicon.ico", include_in_schema=False)
def get_favicon() -> FileResponse:
    return _icon_response("favicon.ico", "image/vnd.microsoft.icon")


@router.get("/favicon-96x96.png", include_in_schema=False)
def get_favicon_96x96() -> FileResponse:
    return _icon_response("favicon-96x96.png", "image/png")


@router.get("/apple-touch-icon.png", include_in_schema=False)
def get_apple_touch_icon() -> FileResponse:
    return _icon_response("apple-touch-icon.png", "image/png")
