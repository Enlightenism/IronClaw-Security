from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from app.ui.uimanifest import (
    UIManifestResponse,
    UIManifestRoute,
    router,
)

MANIFEST_PATH: str = "/ui/manifest"

EXPECTED_SLUGS: frozenset[str] = frozenset(
    {
        "manifest",
        "status",
        "routes",
        "request-stream",
        "system-diagnostics",
        "execution-test-console",
        "runtime-status",
        "audit-log",
        "data-retention",
        "incident-triage",
        "operator-management",
        "access-control-roles",
        "integration-settings",
        "customer-keys",
        "customer-key-detail",
        "usage-reports",
        "telemetry-access-summary",
        "docs-authentication",
        "docs-quickstart",
        "docs-api-reference",
        "docs-policy-guide",
        "docs-telemetry-guide",
        "docs-webhooks",
        "docs-changelog",
    }
)

EXPECTED_CATEGORIES: frozenset[str] = frozenset(
    {
        "system",
        "security-admin",
        "integrations",
        "tenant",
        "billing",
        "docs",
    }
)

EXPECTED_ROUTE_COUNT: int = 24


@pytest.fixture(scope="module")
def client() -> TestClient:
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


@pytest.fixture(scope="module")
def manifest_data(client: TestClient) -> dict:  # type: ignore[type-arg]
    return client.get(MANIFEST_PATH).json()


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------


class TestManifestStatus:
    def test_returns_200(self, client: TestClient) -> None:
        response = client.get(MANIFEST_PATH)
        assert response.status_code == 200

    def test_content_type_is_json(self, client: TestClient) -> None:
        response = client.get(MANIFEST_PATH)
        assert "application/json" in response.headers["content-type"]

    def test_response_is_dict(self, manifest_data: dict) -> None:  # type: ignore[type-arg]
        assert isinstance(manifest_data, dict)


# ---------------------------------------------------------------------------
# Top-level shape
# ---------------------------------------------------------------------------


class TestManifestTopLevelShape:
    def test_has_status_field(self, manifest_data: dict) -> None:  # type: ignore[type-arg]
        assert "status" in manifest_data

    def test_has_service_field(self, manifest_data: dict) -> None:  # type: ignore[type-arg]
        assert "service" in manifest_data

    def test_has_timestamp_field(self, manifest_data: dict) -> None:  # type: ignore[type-arg]
        assert "timestamp" in manifest_data

    def test_has_totalroutes_field(self, manifest_data: dict) -> None:  # type: ignore[type-arg]
        assert "totalroutes" in manifest_data

    def test_has_routes_field(self, manifest_data: dict) -> None:  # type: ignore[type-arg]
        assert "routes" in manifest_data

    def test_has_metadata_field(self, manifest_data: dict) -> None:  # type: ignore[type-arg]
        assert "metadata" in manifest_data

    def test_no_unexpected_top_level_keys(self, manifest_data: dict) -> None:  # type: ignore[type-arg]
        allowed = {"status", "service", "timestamp", "totalroutes", "routes", "metadata"}
        assert set(manifest_data.keys()) <= allowed


# ---------------------------------------------------------------------------
# Field value assertions
# ---------------------------------------------------------------------------


class TestManifestFieldValues:
    def test_status_is_ok(self, manifest_data: dict) -> None:  # type: ignore[type-arg]
        assert manifest_data["status"] == "ok"

    def test_service_is_ironclaw_ui(self, manifest_data: dict) -> None:  # type: ignore[type-arg]
        assert manifest_data["service"] == "ironclaw-ui"

    def test_timestamp_is_non_empty_string(self, manifest_data: dict) -> None:  # type: ignore[type-arg]
        assert isinstance(manifest_data["timestamp"], str)
        assert len(manifest_data["timestamp"]) > 0

    def test_timestamp_contains_iso_separator(self, manifest_data: dict) -> None:  # type: ignore[type-arg]
        assert "T" in manifest_data["timestamp"]

    def test_totalroutes_is_int(self, manifest_data: dict) -> None:  # type: ignore[type-arg]
        assert isinstance(manifest_data["totalroutes"], int)

    def test_totalroutes_equals_expected_count(self, manifest_data: dict) -> None:  # type: ignore[type-arg]
        assert manifest_data["totalroutes"] == EXPECTED_ROUTE_COUNT

    def test_totalroutes_matches_routes_list_length(self, manifest_data: dict) -> None:  # type: ignore[type-arg]
        assert manifest_data["totalroutes"] == len(manifest_data["routes"])

    def test_routes_is_list(self, manifest_data: dict) -> None:  # type: ignore[type-arg]
        assert isinstance(manifest_data["routes"], list)

    def test_routes_not_empty(self, manifest_data: dict) -> None:  # type: ignore[type-arg]
        assert len(manifest_data["routes"]) > 0

    def test_metadata_is_dict(self, manifest_data: dict) -> None:  # type: ignore[type-arg]
        assert isinstance(manifest_data["metadata"], dict)

    def test_metadata_has_generatedby(self, manifest_data: dict) -> None:  # type: ignore[type-arg]
        assert manifest_data["metadata"].get("generatedby") == "uimanifest"

    def test_metadata_has_scope(self, manifest_data: dict) -> None:  # type: ignore[type-arg]
        assert manifest_data["metadata"].get("scope") == "ui-surface"


# ---------------------------------------------------------------------------
# Response model parity
# ---------------------------------------------------------------------------


class TestManifestResponseModel:
    def test_parses_into_response_model(self, manifest_data: dict) -> None:  # type: ignore[type-arg]
        model = UIManifestResponse(**manifest_data)
        assert model.status == "ok"
        assert model.service == "ironclaw-ui"
        assert isinstance(model.routes, list)

    def test_routes_parse_into_route_models(self, manifest_data: dict) -> None:  # type: ignore[type-arg]
        for raw in manifest_data["routes"]:
            route = UIManifestRoute(**raw)
            assert isinstance(route.prefix, str)
            assert isinstance(route.slug, str)
            assert isinstance(route.label, str)
            assert isinstance(route.category, str)
            assert isinstance(route.enabled, bool)
            assert isinstance(route.tags, list)
            assert isinstance(route.metadata, dict)


# ---------------------------------------------------------------------------
# Route item shape
# ---------------------------------------------------------------------------


class TestManifestRouteShape:
    def test_each_route_has_prefix(self, manifest_data: dict) -> None:  # type: ignore[type-arg]
        for route in manifest_data["routes"]:
            assert "prefix" in route

    def test_each_route_has_tags(self, manifest_data: dict) -> None:  # type: ignore[type-arg]
        for route in manifest_data["routes"]:
            assert "tags" in route

    def test_each_route_has_slug(self, manifest_data: dict) -> None:  # type: ignore[type-arg]
        for route in manifest_data["routes"]:
            assert "slug" in route

    def test_each_route_has_label(self, manifest_data: dict) -> None:  # type: ignore[type-arg]
        for route in manifest_data["routes"]:
            assert "label" in route

    def test_each_route_has_category(self, manifest_data: dict) -> None:  # type: ignore[type-arg]
        for route in manifest_data["routes"]:
            assert "category" in route

    def test_each_route_has_enabled(self, manifest_data: dict) -> None:  # type: ignore[type-arg]
        for route in manifest_data["routes"]:
            assert "enabled" in route

    def test_each_route_has_metadata(self, manifest_data: dict) -> None:  # type: ignore[type-arg]
        for route in manifest_data["routes"]:
            assert "metadata" in route

    def test_each_route_prefix_starts_with_slash(self, manifest_data: dict) -> None:  # type: ignore[type-arg]
        for route in manifest_data["routes"]:
            assert route["prefix"].startswith("/")

    def test_each_route_slug_is_non_empty(self, manifest_data: dict) -> None:  # type: ignore[type-arg]
        for route in manifest_data["routes"]:
            assert len(route["slug"]) > 0

    def test_each_route_label_is_non_empty(self, manifest_data: dict) -> None:  # type: ignore[type-arg]
        for route in manifest_data["routes"]:
            assert len(route["label"]) > 0

    def test_each_route_enabled_is_bool(self, manifest_data: dict) -> None:  # type: ignore[type-arg]
        for route in manifest_data["routes"]:
            assert isinstance(route["enabled"], bool)

    def test_each_route_tags_is_list(self, manifest_data: dict) -> None:  # type: ignore[type-arg]
        for route in manifest_data["routes"]:
            assert isinstance(route["tags"], list)

    def test_each_route_metadata_is_dict(self, manifest_data: dict) -> None:  # type: ignore[type-arg]
        for route in manifest_data["routes"]:
            assert isinstance(route["metadata"], dict)

    def test_each_route_metadata_has_surface(self, manifest_data: dict) -> None:  # type: ignore[type-arg]
        for route in manifest_data["routes"]:
            assert "surface" in route["metadata"]

    def test_each_route_metadata_has_kind(self, manifest_data: dict) -> None:  # type: ignore[type-arg]
        for route in manifest_data["routes"]:
            assert "kind" in route["metadata"]


# ---------------------------------------------------------------------------
# Slug completeness
# ---------------------------------------------------------------------------


class TestManifestSlugs:
    def test_all_expected_slugs_present(self, manifest_data: dict) -> None:  # type: ignore[type-arg]
        returned_slugs = {r["slug"] for r in manifest_data["routes"]}
        assert EXPECTED_SLUGS == returned_slugs

    def test_slugs_are_unique(self, manifest_data: dict) -> None:  # type: ignore[type-arg]
        slugs = [r["slug"] for r in manifest_data["routes"]]
        assert len(slugs) == len(set(slugs))

    def test_prefixes_are_unique(self, manifest_data: dict) -> None:  # type: ignore[type-arg]
        prefixes = [r["prefix"] for r in manifest_data["routes"]]
        assert len(prefixes) == len(set(prefixes))


# ---------------------------------------------------------------------------
# Category coverage
# ---------------------------------------------------------------------------


class TestManifestCategories:
    def test_all_expected_categories_present(self, manifest_data: dict) -> None:  # type: ignore[type-arg]
        returned_categories = {r["category"] for r in manifest_data["routes"]}
        assert EXPECTED_CATEGORIES <= returned_categories

    def test_system_category_has_at_least_two_routes(self, manifest_data: dict) -> None:  # type: ignore[type-arg]
        system_routes = [r for r in manifest_data["routes"] if r["category"] == "system"]
        assert len(system_routes) >= 2

    def test_docs_category_has_at_least_five_routes(self, manifest_data: dict) -> None:  # type: ignore[type-arg]
        docs_routes = [r for r in manifest_data["routes"] if r["category"] == "docs"]
        assert len(docs_routes) >= 5

    def test_security_admin_category_exists(self, manifest_data: dict) -> None:  # type: ignore[type-arg]
        admin_routes = [r for r in manifest_data["routes"] if r["category"] == "security-admin"]
        assert len(admin_routes) > 0

    def test_each_route_category_is_known(self, manifest_data: dict) -> None:  # type: ignore[type-arg]
        for route in manifest_data["routes"]:
            assert route["category"] in EXPECTED_CATEGORIES


# ---------------------------------------------------------------------------
# Specific known routes
# ---------------------------------------------------------------------------


class TestManifestKnownRoutes:
    def _get_route(
        self,
        manifest_data: dict,
        slug: str,  # type: ignore[type-arg]
    ) -> dict:  # type: ignore[type-arg]
        for route in manifest_data["routes"]:
            if route["slug"] == slug:
                return route
        raise KeyError(slug)

    def test_manifest_route_has_correct_prefix(self, manifest_data: dict) -> None:  # type: ignore[type-arg]
        route = self._get_route(manifest_data, "manifest")
        assert route["prefix"] == "/ui/manifest"

    def test_manifest_route_category_is_system(self, manifest_data: dict) -> None:  # type: ignore[type-arg]
        route = self._get_route(manifest_data, "manifest")
        assert route["category"] == "system"

    def test_usage_reports_route_has_correct_prefix(self, manifest_data: dict) -> None:  # type: ignore[type-arg]
        route = self._get_route(manifest_data, "usage-reports")
        assert route["prefix"] == "/ui/usage-reports"

    def test_usage_reports_category_is_billing(self, manifest_data: dict) -> None:  # type: ignore[type-arg]
        route = self._get_route(manifest_data, "usage-reports")
        assert route["category"] == "billing"

    def test_telemetry_access_summary_has_correct_prefix(self, manifest_data: dict) -> None:  # type: ignore[type-arg]
        route = self._get_route(manifest_data, "telemetry-access-summary")
        assert route["prefix"] == "/ui/telemetry-access-summary"

    def test_telemetry_access_summary_category_is_tenant(self, manifest_data: dict) -> None:  # type: ignore[type-arg]
        route = self._get_route(manifest_data, "telemetry-access-summary")
        assert route["category"] == "tenant"

    def test_customer_keys_metadata_surface(self, manifest_data: dict) -> None:  # type: ignore[type-arg]
        route = self._get_route(manifest_data, "customer-keys")
        assert route["metadata"]["surface"] == "tenant"

    def test_audit_log_metadata_kind(self, manifest_data: dict) -> None:  # type: ignore[type-arg]
        route = self._get_route(manifest_data, "audit-log")
        assert route["metadata"]["kind"] == "audit"

    def test_docs_changelog_has_changelog_kind(self, manifest_data: dict) -> None:  # type: ignore[type-arg]
        route = self._get_route(manifest_data, "docs-changelog")
        assert route["metadata"]["kind"] == "changelog"

    def test_integration_settings_surface_is_integrations(self, manifest_data: dict) -> None:  # type: ignore[type-arg]
        route = self._get_route(manifest_data, "integration-settings")
        assert route["metadata"]["surface"] == "integrations"

    def test_all_routes_enabled_by_default(self, manifest_data: dict) -> None:  # type: ignore[type-arg]
        for route in manifest_data["routes"]:
            assert route["enabled"] is True
