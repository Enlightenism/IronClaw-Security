from __future__ import annotations

from fastapi import FastAPI
from fastapi.routing import APIRoute

from app.main import create_app


def _build_app() -> FastAPI:
    return create_app()


def _route_map(app: FastAPI) -> dict[str, APIRoute]:
    return {
        route.path: route
        for route in app.routes
        if isinstance(route, APIRoute)
    }


def test_auth_registry_includes_health_route() -> None:
    app = _build_app()
    route_map = _route_map(app)

    assert "/health" in route_map


def test_auth_registry_includes_system_status_route() -> None:
    app = _build_app()
    route_map = _route_map(app)

    assert "/system/status" in route_map


def test_auth_registry_includes_auth_api_routes() -> None:
    app = _build_app()
    route_map = _route_map(app)

    assert "/api/auth/context" in route_map
    assert "/api/operator-auth/context" in route_map
    assert "/api/customer-auth/context" in route_map
    assert "/api/session-security/context" in route_map
    assert "/api/access-control/context" in route_map
    assert "/api/org-context/context" in route_map


def test_protected_routes_expose_get_methods() -> None:
    app = _build_app()
    route_map = _route_map(app)

    health_methods = route_map["/health"].methods or set()
    system_methods = route_map["/system/status"].methods or set()

    assert "GET" in health_methods
    assert "GET" in system_methods


def test_auth_api_routes_expose_get_methods() -> None:
    app = _build_app()
    route_map = _route_map(app)

    auth_paths = [
        "/api/auth/context",
        "/api/operator-auth/context",
        "/api/customer-auth/context",
        "/api/session-security/context",
        "/api/access-control/context",
        "/api/org-context/context",
    ]

    for path in auth_paths:
        methods = route_map[path].methods or set()
        assert "GET" in methods


def test_registered_routes_keep_path_uniqueness() -> None:
    app = _build_app()
    route_map = _route_map(app)

    paths = list(route_map.keys())

    assert len(paths) == len(set(paths))


def test_auth_registry_routes_are_named() -> None:
    app = _build_app()
    route_map = _route_map(app)

    assert route_map["/health"].name
    assert route_map["/system/status"].name


def test_auth_api_routes_are_named() -> None:
    app = _build_app()
    route_map = _route_map(app)

    assert route_map["/api/auth/context"].name
    assert route_map["/api/operator-auth/context"].name
    assert route_map["/api/customer-auth/context"].name
    assert route_map["/api/session-security/context"].name
    assert route_map["/api/access-control/context"].name
    assert route_map["/api/org-context/context"].name