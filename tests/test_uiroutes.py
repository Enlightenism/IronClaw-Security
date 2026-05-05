from __future__ import annotations

from fastapi.routing import APIRoute

from app.main import app


def _paths() -> set[str]:
    return {
        route.path
        for route in app.routes
        if isinstance(route, APIRoute)
    }


def test_ui_runtime_status_route_is_registered() -> None:
    paths = _paths()

    assert "/ui/runtime/status" in paths