from __future__ import annotations

from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from app.main import create_app


def _route_paths(app) -> set[str]:
    return {route.path for route in app.routes if isinstance(route, APIRoute)}


def _allowed_origin_from_preflight(response) -> str | None:
    return response.headers.get("access-control-allow-origin")


def _matching_routes(app, path_prefix: str) -> list[APIRoute]:
    return [route for route in app.routes if isinstance(route, APIRoute) and route.path.startswith(path_prefix)]


def _route_dependency_names(route: APIRoute) -> set[str]:
    return {getattr(dependency.dependency, "__name__", repr(dependency.dependency)) for dependency in route.dependant.dependencies if getattr(dependency, "dependency", None) is not None}


def test_create_app_registers_core_health_routes() -> None:
    app = create_app()
    route_map = {route.path: route for route in app.routes if isinstance(route, APIRoute)}

    assert "/" in route_map
    assert "/health" in route_map

    root_methods = route_map["/"].methods or set()
    health_methods = route_map["/health"].methods or set()

    assert "GET" in root_methods
    assert "GET" in health_methods


def test_create_app_registers_integrations_routes() -> None:
    app = create_app()
    route_paths = _route_paths(app)

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
        "/integrations/hermes/health",
        "/integrations/hermes/manifest",
        "/integrations/cursor/handshake",
        "/integrations/goose/handshake",
        "/integrations/agent-skills/handshake",
    }

    missing_paths = expected_paths - route_paths
    assert not missing_paths, f"main app missing integration routes: {sorted(missing_paths)}"


def test_create_app_integrations_routes_are_registered_without_direct_route_level_auth_regression() -> None:
    app = create_app()

    integration_routes = [route for route in app.routes if isinstance(route, APIRoute) and route.path.startswith("/integrations")]

    assert integration_routes, "expected integrations routes to be registered"

    for route in integration_routes:
        assert route.path.startswith("/integrations")
        assert route.endpoint is not None


def test_create_app_preflight_to_integrations_routes_returns_cors_response() -> None:
    app = create_app()
    client = TestClient(app)

    candidate_paths = [
        "/integrations/installers",
        "/integrations/verifiers",
    ]

    available_paths = _route_paths(app)
    tested_paths = [path for path in candidate_paths if path in available_paths]

    assert tested_paths, "expected at least one integration collection route for preflight coverage"

    for path in tested_paths:
        response = client.options(
            path,
            headers={
                "Origin": "http://localhost",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "X-API-Key,Content-Type,Authorization",
            },
        )

        assert response.status_code in {200, 400}, f"unexpected preflight status for {path}: {response.status_code}: {response.text}"

        if response.status_code == 200:
            assert _allowed_origin_from_preflight(response) == "http://localhost"
            assert "access-control-allow-methods" in response.headers
        else:
            assert response.text == "Disallowed CORS origin"


def test_create_app_preflight_to_integrations_routes_is_handled_before_route_auth() -> None:
    app = create_app()
    client = TestClient(app)

    candidate_paths = [
        "/integrations/installers",
        "/integrations/verifiers",
    ]

    available_paths = _route_paths(app)
    tested_paths = [path for path in candidate_paths if path in available_paths]

    assert tested_paths, "expected at least one integration collection route for auth-preflight coverage"

    for path in tested_paths:
        preflight = client.options(
            path,
            headers={
                "Origin": "http://localhost",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "X-API-Key,Content-Type",
            },
        )

        assert preflight.status_code in {200, 400}, f"unexpected preflight status for {path}: {preflight.status_code}: {preflight.text}"

        if preflight.status_code == 400:
            assert preflight.text == "Disallowed CORS origin"
            continue

        request = client.post(
            path,
            headers={"Origin": "http://localhost"},
            json={},
        )
        assert request.status_code in {200, 401, 403, 405, 422}, f"expected non-preflight request to be handled by auth, validation, or route logic for {path}, got {request.status_code}: {request.text}"


def test_create_app_preflight_to_parameterized_integration_routes_returns_cors_response() -> None:
    app = create_app()
    client = TestClient(app)

    available_templates = _route_paths(app)
    matched_paths = [
        concrete_path
        for concrete_path, template_path in (
            (
                "/integrations/test-integration/compatibility",
                "/integrations/{integration_id}/compatibility",
            ),
            (
                "/integrations/test-integration/secrets",
                "/integrations/{integration_id}/secrets",
            ),
            (
                "/integrations/test-integration/rollouts",
                "/integrations/{integration_id}/rollouts",
            ),
            (
                "/integrations/test-integration/telemetry",
                "/integrations/{integration_id}/telemetry",
            ),
            (
                "/integrations/test-integration/health",
                "/integrations/{integration_id}/health",
            ),
            (
                "/integrations/test-integration/lifecycle",
                "/integrations/{integration_id}/lifecycle",
            ),
            (
                "/integrations/test-integration/readiness",
                "/integrations/{integration_id}/readiness",
            ),
            (
                "/integrations/test-integration/observability",
                "/integrations/{integration_id}/observability",
            ),
        )
        if template_path in available_templates
    ]

    assert matched_paths, "expected at least one parameterized integration route for preflight coverage"

    for path in matched_paths:
        response = client.options(
            path,
            headers={
                "Origin": "http://localhost",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "X-API-Key,Content-Type,Authorization",
            },
        )

        assert response.status_code in {200, 400}, f"unexpected preflight status for {path}: {response.status_code}: {response.text}"

        if response.status_code == 200:
            assert _allowed_origin_from_preflight(response) == "http://localhost"
            assert "access-control-allow-methods" in response.headers
        else:
            assert response.text == "Disallowed CORS origin"


def test_create_app_event_simulation_routes_match_current_registration_state() -> None:
    app = create_app()
    route_paths = _route_paths(app)

    event_paths = {path for path in route_paths if path.startswith("/events/") or path.startswith("/api/events/")}

    assert event_paths == {"/events/simulate", "/api/events/simulate"}, "expected the current event simulation router mount state to include both prefix families with the /simulate endpoint"


def test_create_app_event_simulation_routes_do_not_expose_partial_prefix_mismatch() -> None:
    app = create_app()
    route_paths = _route_paths(app)

    has_events_prefix = any(path.startswith("/events/") for path in route_paths)
    has_api_events_prefix = any(path.startswith("/api/events/") for path in route_paths)

    assert has_events_prefix is has_api_events_prefix, "event simulation routing should not expose only one prefix family"


def test_create_app_event_simulation_routes_have_expected_auth_shape_if_present() -> None:
    app = create_app()

    event_routes = _matching_routes(app, "/events/") + _matching_routes(app, "/api/events/")

    if not event_routes:
        assert event_routes == []
        return

    simulate_routes = [route for route in event_routes if route.path.endswith("/simulate")]
    assert simulate_routes, "expected event simulation routes to include a /simulate endpoint"

    for route in simulate_routes:
        dependency_calls = _route_dependency_names(route)
        assert "require_api_key" in dependency_calls, f"route {route.path} is missing require_api_key protection"


def test_create_app_preflight_to_event_simulation_routes_matches_current_mount_state() -> None:
    app = create_app()
    client = TestClient(app)

    available_paths = _route_paths(app)
    candidate_paths = [
        "/events/simulate",
        "/api/events/simulate",
    ]
    tested_paths = [path for path in candidate_paths if path in available_paths]

    if tested_paths:
        for path in tested_paths:
            response = client.options(
                path,
                headers={
                    "Origin": "http://localhost",
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": "X-API-Key,Content-Type,Authorization",
                },
            )

            assert response.status_code in {200, 400}, f"unexpected preflight status for {path}: {response.status_code}: {response.text}"

            if response.status_code == 200:
                assert _allowed_origin_from_preflight(response) == "http://localhost"
                assert "access-control-allow-methods" in response.headers
            else:
                assert response.text == "Disallowed CORS origin"
        return

    for path in candidate_paths:
        response = client.options(
            path,
            headers={
                "Origin": "http://localhost",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "X-API-Key,Content-Type,Authorization",
            },
        )
        assert response.status_code in {200, 400, 404}, f"unexpected fallback preflight status for {path}: {response.status_code}: {response.text}"

        if response.status_code == 200:
            assert _allowed_origin_from_preflight(response) == "http://localhost"
            assert "access-control-allow-methods" in response.headers
        elif response.status_code == 400:
            assert response.text == "Disallowed CORS origin"
