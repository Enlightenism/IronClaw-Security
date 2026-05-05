from __future__ import annotations

from fastapi.routing import APIRoute

from app.main import create_app


def test_create_app_registers_core_health_routes() -> None:
    app = create_app()
    route_map = {
        route.path: route
        for route in app.routes
        if isinstance(route, APIRoute)
    }

    assert "/" in route_map
    assert "/health" in route_map

    root_methods = route_map["/"].methods or set()
    health_methods = route_map["/health"].methods or set()

    assert "GET" in root_methods
    assert "GET" in health_methods


def test_create_app_registers_integrations_routes() -> None:
    app = create_app()
    route_paths = {
        route.path
        for route in app.routes
        if isinstance(route, APIRoute)
    }

    expected_paths = {
        "/integrations/installers",
        "/integrations/installers/{integration_id}",
        "/integrations/verifiers",
        "/integrations/verifiers/{integration_id}",
        "/integrations/{integration_id}/compatibility",
        "/integrations/{integration_id}/secrets",
        "/integrations/{integration_id}/rollouts",
        "/integrations/{integration_id}/telemetry",
        "/integrations/{integration_id}/health",
        "/integrations/{integration_id}/lifecycle",
        "/integrations/{integration_id}/readiness",
        "/integrations/{integration_id}/observability",
    }

    missing_paths = expected_paths - route_paths
    assert not missing_paths, f"main app missing integration routes: {sorted(missing_paths)}"


def test_create_app_integrations_routes_are_api_key_protected() -> None:
    app = create_app()

    integration_routes = [
        route
        for route in app.routes
        if isinstance(route, APIRoute) and route.path.startswith("/integrations")
    ]

    assert integration_routes, "expected integrations routes to be registered"

    for route in integration_routes:
        dependency_calls = {
            getattr(dependency.dependency, "__name__", repr(dependency.dependency))
            for dependency in route.dependant.dependencies
            if dependency.dependency is not None
        }
        assert "require_api_key" in dependency_calls, (
            f"route {route.path} is missing require_api_key protection"
        )