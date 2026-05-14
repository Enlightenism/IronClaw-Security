from __future__ import annotations

from fastapi.routing import APIRoute

from app.main import app


def _route_map() -> dict[str, APIRoute]:
    return {route.path: route for route in app.routes if isinstance(route, APIRoute)}


def test_operations_health_routes_are_registered() -> None:
    route_map = _route_map()

    assert "/health" in route_map
    assert "/health/liveness" in route_map
    assert "/health/readiness" in route_map


def test_operations_ui_manifest_is_registered() -> None:
    route_map = _route_map()

    assert "/ui/manifest" in route_map
    assert "/ui/status" in route_map
    assert "/ui/runtime-status" in route_map


def test_operations_system_status_is_registered() -> None:
    route_map = _route_map()

    assert "/system/status" in route_map


def test_operations_access_control_routes_are_registered() -> None:
    route_map = _route_map()

    assert "/api/access-control/context" in route_map


def test_operations_core_routes_support_get() -> None:
    route_map = _route_map()

    required_paths = [
        "/health",
        "/health/liveness",
        "/health/readiness",
        "/system/status",
        "/ui/manifest",
        "/ui/status",
        "/ui/runtime-status",
        "/api/access-control/context",
    ]

    for path in required_paths:
        assert path in route_map, f"route not registered: {path}"
        methods = route_map[path].methods or set()
        assert "GET" in methods, f"GET not registered on {path}"
