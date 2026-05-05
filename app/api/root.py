from __future__ import annotations

from typing import Any

from fastapi import APIRouter

router = APIRouter()


@router.get("/", summary="Root")
def root() -> dict[str, Any]:
    """
    Root endpoint for IronClaw-Security.

    Returns a minimal capability and docs pointer payload so that
    clients and humans landing on / have something structured to read.
    """
    return {
        "service": "IronClaw-Security",
        "description": "Local-first security scanning API with reviewed verdict handling.",
        "version": "1.0.0",
        "endpoints": {
            "docs": "/docs",
            "openapi": "/openapi.json",
            "health": "/system/health",
            "policy_status": "/policy/status",
            "guard_execute": "/guard/execute",
            "history": "/history",
            "audit": "/audit/events",
        },
    }