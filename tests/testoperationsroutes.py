from __future__ import annotations

from fastapi.routing import APIRoute

from app.main import app


def _route_map() -> dict[str, APIRoute]:
    return {
        route.path: route
        for route in app.routes
        if isinstance(route, APIRoute)
    }


def test_operations_dashboard_route_is_registered() -> None:
    route_map = _route_map()

    assert "/dashboard/overview" in route_map


def test_operations_organizations_route_is_registered() -> None:
    route_map = _route_map()

    assert "/organizations" in route_map


def test_operations_ui_routes_are_registered() -> None:
    route_map = _route_map()

    assert "/ui/routes" in route_map
    assert "/ui/pages" in route_map
    assert "/ui/manifest" in route_map


def test_operations_admin_surfaces_are_registered() -> None:
    route_map = _route_map()

    assert "/admin/request-stream" in route_map
    assert "/admin/system-diagnostics" in route_map
    assert "/admin/execution-test-console" in route_map


def test_operations_core_routes_support_get() -> None:
    route_map = _route_map()

    required_paths = [
        "/dashboard/overview",
        "/organizations",
        "/ui/routes",
        "/ui/pages",
        "/ui/manifest",
        "/admin/request-stream",
        "/admin/system-diagnostics",
        "/admin/execution-test-console",
    ]

    for path in required_paths:
        methods = route_map[path].methods or set()
        assert "GET" in methods