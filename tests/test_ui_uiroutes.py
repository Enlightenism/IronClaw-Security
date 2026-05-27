from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from app.ui.uiroutes import UIRouteRecord, UIRoutesResponse, router

ROUTES_PATH: str = "/ui/routes"

EXPECTED_TOTAL_ROUTES: int = 17

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
    }
)

EXPECTED_CATEGORIES: frozenset[str] = frozenset(
    {
        "system",
        "security-admin",
        "integrations",
        "tenant",
        "billing",
    }
)

SLUG_TO_PREFIX: dict[str, str] = {
    "manifest": "/ui/manifest",
    "status": "/ui/status",
    "routes": "/ui/routes",
    "request-stream": "/ui/request-stream",
    "system-diagnostics": "/ui/system-diagnostics",
    "execution-test-console": "/ui/executions/test-console",
    "runtime-status": "/ui/runtime-status",
    "audit-log": "/ui/audit-log",
    "data-retention": "/ui/data-retention",
    "incident-triage": "/ui/incidents/triage",
    "operator-management": "/ui/admin/operators",
    "access-control-roles": "/ui/admin/roles",
    "integration-settings": "/ui/integrations/settings",
    "customer-keys": "/ui/customer-keys",
    "customer-key-detail": "/ui/customer-keys/detail",
    "usage-reports": "/ui/usage-reports",
    "telemetry-access-summary": "/ui/telemetry-access-summary",
}

SLUG_TO_CATEGORY: dict[str, str] = {
    "manifest": "system",
    "status": "system",
    "routes": "system",
    "request-stream": "security-admin",
    "system-diagnostics": "security-admin",
    "execution-test-console": "security-admin",
    "runtime-status": "security-admin",
    "audit-log": "security-admin",
    "data-retention": "security-admin",
    "incident-triage": "security-admin",
    "operator-management": "security-admin",
    "access-control-roles": "security-admin",
    "integration-settings": "integrations",
    "customer-keys": "tenant",
    "customer-key-detail": "tenant",
    "usage-reports": "billing",
    "telemetry-access-summary": "tenant",
}

SLUG_TO_LABEL: dict[str, str] = {
    "manifest": "UI Manifest",
    "status": "UI Status",
    "routes": "UI Routes",
    "request-stream": "Request Stream",
    "system-diagnostics": "System Diagnostics",
    "execution-test-console": "Execution Test Console",
    "runtime-status": "Runtime Status",
    "audit-log": "Audit Log",
    "data-retention": "Data Retention",
    "incident-triage": "Incident Triage",
    "operator-management": "Operator Management",
    "access-control-roles": "Access Control Roles",
    "integration-settings": "Integration Settings",
    "customer-keys": "Customer Keys",
    "customer-key-detail": "Customer Key Detail",
    "usage-reports": "Usage Reports",
    "telemetry-access-summary": "Telemetry Access Summary",
}


@pytest.fixture(scope="module")
def client() -> TestClient:
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


@pytest.fixture(scope="module")
def routes_data(client: TestClient) -> dict:  # type: ignore[type-arg]
    return client.get(ROUTES_PATH).json()


def _route_by_slug(
    routes_data: dict,  # type: ignore[type-arg]
    slug: str,
) -> dict:  # type: ignore[type-arg]
    for route in routes_data["routes"]:
        if route["slug"] == slug:
            return route
    raise KeyError(slug)


# ---------------------------------------------------------------------------
# HTTP / content-type
# ---------------------------------------------------------------------------


class TestUIRoutesStatus:
    def test_returns_200(self, client: TestClient) -> None:
        response = client.get(ROUTES_PATH)
        assert response.status_code == 200

    def test_content_type_is_json(self, client: TestClient) -> None:
        response = client.get(ROUTES_PATH)
        assert "application/json" in response.headers["content-type"]

    def test_response_is_dict(self, routes_data: dict) -> None:  # type: ignore[type-arg]
        assert isinstance(routes_data, dict)


# ---------------------------------------------------------------------------
# Top-level shape
# ---------------------------------------------------------------------------


class TestUIRoutesTopLevelShape:
    def test_has_status(self, routes_data: dict) -> None:  # type: ignore[type-arg]
        assert "status" in routes_data

    def test_has_service(self, routes_data: dict) -> None:  # type: ignore[type-arg]
        assert "service" in routes_data

    def test_has_timestamp(self, routes_data: dict) -> None:  # type: ignore[type-arg]
        assert "timestamp" in routes_data

    def test_has_totalroutes(self, routes_data: dict) -> None:  # type: ignore[type-arg]
        assert "totalroutes" in routes_data

    def test_has_routes(self, routes_data: dict) -> None:  # type: ignore[type-arg]
        assert "routes" in routes_data

    def test_has_metadata(self, routes_data: dict) -> None:  # type: ignore[type-arg]
        assert "metadata" in routes_data

    def test_no_unexpected_top_level_keys(self, routes_data: dict) -> None:  # type: ignore[type-arg]
        allowed = {"status", "service", "timestamp", "totalroutes", "routes", "metadata"}
        assert set(routes_data.keys()) <= allowed


# ---------------------------------------------------------------------------
# status / service / timestamp
# ---------------------------------------------------------------------------


class TestUIRoutesHeaderFields:
    def test_status_is_ok(self, routes_data: dict) -> None:  # type: ignore[type-arg]
        assert routes_data["status"] == "ok"

    def test_service_is_ironclaw_ui(self, routes_data: dict) -> None:  # type: ignore[type-arg]
        assert routes_data["service"] == "ironclaw-ui"

    def test_timestamp_is_str(self, routes_data: dict) -> None:  # type: ignore[type-arg]
        assert isinstance(routes_data["timestamp"], str)

    def test_timestamp_is_non_empty(self, routes_data: dict) -> None:  # type: ignore[type-arg]
        assert len(routes_data["timestamp"]) > 0

    def test_timestamp_contains_iso_separator(self, routes_data: dict) -> None:  # type: ignore[type-arg]
        assert "T" in routes_data["timestamp"]


# ---------------------------------------------------------------------------
# totalroutes
# ---------------------------------------------------------------------------


class TestUIRoutesTotalRoutes:
    def test_totalroutes_is_int(self, routes_data: dict) -> None:  # type: ignore[type-arg]
        assert isinstance(routes_data["totalroutes"], int)

    def test_totalroutes_equals_expected(self, routes_data: dict) -> None:  # type: ignore[type-arg]
        assert routes_data["totalroutes"] == EXPECTED_TOTAL_ROUTES

    def test_totalroutes_matches_routes_length(self, routes_data: dict) -> None:  # type: ignore[type-arg]
        assert routes_data["totalroutes"] == len(routes_data["routes"])


# ---------------------------------------------------------------------------
# metadata block
# ---------------------------------------------------------------------------


class TestUIRoutesMetadata:
    def test_metadata_is_dict(self, routes_data: dict) -> None:  # type: ignore[type-arg]
        assert isinstance(routes_data["metadata"], dict)

    def test_metadata_surface_is_ui(self, routes_data: dict) -> None:  # type: ignore[type-arg]
        assert routes_data["metadata"].get("surface") == "ui"

    def test_metadata_scope_is_route_inventory(self, routes_data: dict) -> None:  # type: ignore[type-arg]
        assert routes_data["metadata"].get("scope") == "route-inventory"

    def test_metadata_source_is_static_registry(self, routes_data: dict) -> None:  # type: ignore[type-arg]
        assert routes_data["metadata"].get("source") == "static-registry"


# ---------------------------------------------------------------------------
# routes list – structure
# ---------------------------------------------------------------------------


class TestUIRoutesListStructure:
    def test_routes_is_list(self, routes_data: dict) -> None:  # type: ignore[type-arg]
        assert isinstance(routes_data["routes"], list)

    def test_routes_not_empty(self, routes_data: dict) -> None:  # type: ignore[type-arg]
        assert len(routes_data["routes"]) > 0

    def test_routes_count_matches_expected(self, routes_data: dict) -> None:  # type: ignore[type-arg]
        assert len(routes_data["routes"]) == EXPECTED_TOTAL_ROUTES

    def test_each_route_has_prefix(self, routes_data: dict) -> None:  # type: ignore[type-arg]
        for route in routes_data["routes"]:
            assert "prefix" in route

    def test_each_route_has_slug(self, routes_data: dict) -> None:  # type: ignore[type-arg]
        for route in routes_data["routes"]:
            assert "slug" in route

    def test_each_route_has_label(self, routes_data: dict) -> None:  # type: ignore[type-arg]
        for route in routes_data["routes"]:
            assert "label" in route

    def test_each_route_has_category(self, routes_data: dict) -> None:  # type: ignore[type-arg]
        for route in routes_data["routes"]:
            assert "category" in route

    def test_each_route_has_enabled(self, routes_data: dict) -> None:  # type: ignore[type-arg]
        for route in routes_data["routes"]:
            assert "enabled" in route

    def test_each_route_has_metadata(self, routes_data: dict) -> None:  # type: ignore[type-arg]
        for route in routes_data["routes"]:
            assert "metadata" in route

    def test_slugs_are_unique(self, routes_data: dict) -> None:  # type: ignore[type-arg]
        slugs = [r["slug"] for r in routes_data["routes"]]
        assert len(slugs) == len(set(slugs))

    def test_prefixes_are_unique(self, routes_data: dict) -> None:  # type: ignore[type-arg]
        prefixes = [r["prefix"] for r in routes_data["routes"]]
        assert len(prefixes) == len(set(prefixes))


# ---------------------------------------------------------------------------
# routes list – field types
# ---------------------------------------------------------------------------


class TestUIRoutesFieldTypes:
    def test_prefix_is_str(self, routes_data: dict) -> None:  # type: ignore[type-arg]
        for route in routes_data["routes"]:
            assert isinstance(route["prefix"], str)

    def test_slug_is_str(self, routes_data: dict) -> None:  # type: ignore[type-arg]
        for route in routes_data["routes"]:
            assert isinstance(route["slug"], str)

    def test_label_is_str(self, routes_data: dict) -> None:  # type: ignore[type-arg]
        for route in routes_data["routes"]:
            assert isinstance(route["label"], str)

    def test_category_is_str(self, routes_data: dict) -> None:  # type: ignore[type-arg]
        for route in routes_data["routes"]:
            assert isinstance(route["category"], str)

    def test_enabled_is_bool(self, routes_data: dict) -> None:  # type: ignore[type-arg]
        for route in routes_data["routes"]:
            assert isinstance(route["enabled"], bool)

    def test_route_metadata_is_dict(self, routes_data: dict) -> None:  # type: ignore[type-arg]
        for route in routes_data["routes"]:
            assert isinstance(route["metadata"], dict)

    def test_prefix_starts_with_slash(self, routes_data: dict) -> None:  # type: ignore[type-arg]
        for route in routes_data["routes"]:
            assert route["prefix"].startswith("/")

    def test_slug_not_empty(self, routes_data: dict) -> None:  # type: ignore[type-arg]
        for route in routes_data["routes"]:
            assert len(route["slug"]) > 0

    def test_label_not_empty(self, routes_data: dict) -> None:  # type: ignore[type-arg]
        for route in routes_data["routes"]:
            assert len(route["label"]) > 0


# ---------------------------------------------------------------------------
# slug registry completeness
# ---------------------------------------------------------------------------


class TestUIRoutesSlugRegistry:
    def test_all_expected_slugs_present(self, routes_data: dict) -> None:  # type: ignore[type-arg]
        actual_slugs = {r["slug"] for r in routes_data["routes"]}
        assert EXPECTED_SLUGS == actual_slugs

    def test_no_extra_slugs(self, routes_data: dict) -> None:  # type: ignore[type-arg]
        actual_slugs = {r["slug"] for r in routes_data["routes"]}
        assert actual_slugs <= EXPECTED_SLUGS

    def test_no_missing_slugs(self, routes_data: dict) -> None:  # type: ignore[type-arg]
        actual_slugs = {r["slug"] for r in routes_data["routes"]}
        assert EXPECTED_SLUGS <= actual_slugs


# ---------------------------------------------------------------------------
# categories
# ---------------------------------------------------------------------------


class TestUIRoutesCategories:
    def test_all_categories_valid(self, routes_data: dict) -> None:  # type: ignore[type-arg]
        for route in routes_data["routes"]:
            assert route["category"] in EXPECTED_CATEGORIES

    def test_all_expected_categories_represented(self, routes_data: dict) -> None:  # type: ignore[type-arg]
        actual = {r["category"] for r in routes_data["routes"]}
        assert EXPECTED_CATEGORIES == actual

    def test_system_routes_present(self, routes_data: dict) -> None:  # type: ignore[type-arg]
        system = [r for r in routes_data["routes"] if r["category"] == "system"]
        assert len(system) == 3

    def test_security_admin_routes_present(self, routes_data: dict) -> None:  # type: ignore[type-arg]
        sec = [r for r in routes_data["routes"] if r["category"] == "security-admin"]
        assert len(sec) == 9

    def test_integrations_routes_present(self, routes_data: dict) -> None:  # type: ignore[type-arg]
        intg = [r for r in routes_data["routes"] if r["category"] == "integrations"]
        assert len(intg) == 1

    def test_tenant_routes_present(self, routes_data: dict) -> None:  # type: ignore[type-arg]
        tenant = [r for r in routes_data["routes"] if r["category"] == "tenant"]
        assert len(tenant) == 3

    def test_billing_routes_present(self, routes_data: dict) -> None:  # type: ignore[type-arg]
        billing = [r for r in routes_data["routes"] if r["category"] == "billing"]
        assert len(billing) == 1


# ---------------------------------------------------------------------------
# per-slug prefix / label / category correctness
# ---------------------------------------------------------------------------


class TestUIRoutesPerSlugCorrectness:
    @pytest.mark.parametrize("slug", list(SLUG_TO_PREFIX.keys()))
    def test_prefix_matches_registry(
        self,
        routes_data: dict,  # type: ignore[type-arg]
        slug: str,
    ) -> None:
        route = _route_by_slug(routes_data, slug)
        assert route["prefix"] == SLUG_TO_PREFIX[slug]

    @pytest.mark.parametrize("slug", list(SLUG_TO_CATEGORY.keys()))
    def test_category_matches_registry(
        self,
        routes_data: dict,  # type: ignore[type-arg]
        slug: str,
    ) -> None:
        route = _route_by_slug(routes_data, slug)
        assert route["category"] == SLUG_TO_CATEGORY[slug]

    @pytest.mark.parametrize("slug", list(SLUG_TO_LABEL.keys()))
    def test_label_matches_registry(
        self,
        routes_data: dict,  # type: ignore[type-arg]
        slug: str,
    ) -> None:
        route = _route_by_slug(routes_data, slug)
        assert route["label"] == SLUG_TO_LABEL[slug]


# ---------------------------------------------------------------------------
# enabled flag
# ---------------------------------------------------------------------------


class TestUIRoutesEnabledFlag:
    def test_all_routes_enabled(self, routes_data: dict) -> None:  # type: ignore[type-arg]
        for route in routes_data["routes"]:
            assert route["enabled"] is True

    def test_enabled_count_matches_total(self, routes_data: dict) -> None:  # type: ignore[type-arg]
        enabled = sum(1 for r in routes_data["routes"] if r["enabled"])
        assert enabled == EXPECTED_TOTAL_ROUTES


# ---------------------------------------------------------------------------
# Pydantic model round-trip
# ---------------------------------------------------------------------------


class TestUIRoutesModelRoundTrip:
    def test_response_model_parses(self, routes_data: dict) -> None:  # type: ignore[type-arg]
        model = UIRoutesResponse(**routes_data)
        assert model.status == "ok"
        assert model.service == "ironclaw-ui"
        assert model.totalroutes == EXPECTED_TOTAL_ROUTES
        assert len(model.routes) == EXPECTED_TOTAL_ROUTES

    def test_route_record_model_parses(self, routes_data: dict) -> None:  # type: ignore[type-arg]
        for raw in routes_data["routes"]:
            record = UIRouteRecord(**raw)
            assert record.slug in EXPECTED_SLUGS
            assert record.enabled is True

    def test_manifest_route_model(self, routes_data: dict) -> None:  # type: ignore[type-arg]
        raw = _route_by_slug(routes_data, "manifest")
        record = UIRouteRecord(**raw)
        assert record.prefix == "/ui/manifest"
        assert record.category == "system"
        assert record.label == "UI Manifest"

    def test_audit_log_route_model(self, routes_data: dict) -> None:  # type: ignore[type-arg]
        raw = _route_by_slug(routes_data, "audit-log")
        record = UIRouteRecord(**raw)
        assert record.prefix == "/ui/audit-log"
        assert record.category == "security-admin"
        assert record.label == "Audit Log"

    def test_usage_reports_route_model(self, routes_data: dict) -> None:  # type: ignore[type-arg]
        raw = _route_by_slug(routes_data, "usage-reports")
        record = UIRouteRecord(**raw)
        assert record.prefix == "/ui/usage-reports"
        assert record.category == "billing"
        assert record.label == "Usage Reports"
