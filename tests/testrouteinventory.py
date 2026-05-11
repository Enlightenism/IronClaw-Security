from __future__ import annotations

from collections.abc import Iterable
from typing import Final

from fastapi.routing import APIRoute

from app.main import app


EXPECTED_API_PATHS: Final[set[str]] = {
    "/api/actionhistorytest",
    "/api/groq-registry",
    "/api/incidents",
    "/api/integrations",
    "/api/review-queue",
    "/api/ui-manifest",
    "/api/unit-ledger",
    "/api/unit-wallet",
}

EXPECTED_UI_PATHS: Final[set[str]] = {
    "/ui/activity/client-session",
    "/ui/activity/client/{clientid}",
    "/ui/activity/session/{sessionid}",
    "/ui/admin/operators",
    "/ui/admin/roles",
    "/ui/alerts/notifications",
    "/ui/audit/log",
    "/ui/data/retention",
    "/ui/executions/explorer",
    "/ui/executions/test-console",
    "/ui/incidents/triage",
    "/ui/insights/policy",
    "/ui/integrations/settings",
    "/ui/reviews/queue",
    "/ui/runtime/status",
    "/ui/settings/configuration",
    "/ui/system/diagnostics",
}

# Paths registered by multiple router modules at the app wiring level.
# These are known infrastructure duplicates — not inventory test failures.
_KNOWN_DUPLICATE_PATHS: Final[set[str]] = {
    "/api/incidents/",
    "/customer-keys",
    "/organizations",
}


def _api_routes() -> list[APIRoute]:
    return [route for route in app.routes if isinstance(route, APIRoute)]


def _route_paths() -> set[str]:
    return {route.path for route in _api_routes()}


def _route_methods() -> dict[str, set[str]]:
    return {
        route.path: set(route.methods or set())
        for route in _api_routes()
    }


def _paths_with_prefix(prefix: str) -> list[str]:
    return sorted(path for path in _route_paths() if path.startswith(prefix))


def _missing_paths(expected_paths: Iterable[str]) -> set[str]:
    registered_paths = _route_paths()
    return {path for path in expected_paths if path not in registered_paths}


def test_expected_api_routes_are_registered() -> None:
    missing = _missing_paths(EXPECTED_API_PATHS)
    assert missing == set(), f"missing API routes: {sorted(missing)}"


def test_expected_ui_routes_are_registered() -> None:
    missing = _missing_paths(EXPECTED_UI_PATHS)
    assert missing == set(), f"missing UI routes: {sorted(missing)}"


def test_api_route_inventory_contains_core_pages() -> None:
    api_paths = _paths_with_prefix("/api/")
    assert "/api/actionhistorytest" in api_paths
    assert "/api/groq-registry" in api_paths
    assert "/api/incidents" in api_paths
    assert "/api/integrations" in api_paths
    assert "/api/review-queue" in api_paths
    assert "/api/ui-manifest" in api_paths


def test_ui_route_inventory_contains_core_pages() -> None:
    ui_paths = _paths_with_prefix("/ui/")
    assert "/ui/incidents/triage" in ui_paths
    assert "/ui/reviews/queue" in ui_paths
    assert "/ui/runtime/status" in ui_paths


def test_route_inventory_has_no_duplicate_paths() -> None:
    paths = [route.path for route in _api_routes()]
    unexpected_duplicates = [
        p for p in dict.fromkeys(paths)
        if paths.count(p) > 1 and p not in _KNOWN_DUPLICATE_PATHS
    ]
    assert not unexpected_duplicates, (
        f"unexpected duplicate route paths detected: {sorted(unexpected_duplicates)}"
    )


def test_expected_inventory_routes_allow_get() -> None:
    methods = _route_methods()

    for path in EXPECTED_API_PATHS | EXPECTED_UI_PATHS:
        assert path in methods, f"route missing from method map: {path}"
        assert "GET" in methods[path], f"route does not allow GET: {path}"


def test_route_inventory_contains_expected_prefixes() -> None:
    registered_paths = _route_paths()

    assert any(path.startswith("/api/") for path in registered_paths)
    assert any(path.startswith("/ui/") for path in registered_paths)