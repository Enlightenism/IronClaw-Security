from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import FileResponse

from app.core.install_key_formats import (
    SECURITY_GUARDIAN_SKILL_FILE_PATH,
    SECURITY_GUARDIAN_SKILL_ROUTE,
)

router = APIRouter(tags=["skills"])

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_SKILL_FILE = _PROJECT_ROOT.joinpath(*SECURITY_GUARDIAN_SKILL_FILE_PATH.split("/"))


@router.get(SECURITY_GUARDIAN_SKILL_ROUTE, include_in_schema=False)
def get_security_guardian_skill() -> FileResponse:
    if _SKILL_FILE.is_symlink() or not _SKILL_FILE.is_file():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The shared security skill is not available.",
        )

    resolved_skill_file = _SKILL_FILE.resolve()
    if not resolved_skill_file.is_relative_to(_PROJECT_ROOT):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The shared security skill is not available.",
        )

    return FileResponse(
        path=resolved_skill_file,
        media_type="text/markdown",
        headers={"Cache-Control": "public, max-age=300"},
    )
