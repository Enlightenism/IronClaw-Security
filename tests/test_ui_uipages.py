from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from app.ui.uipages import (
    UIPageItem,
    UIPageSection,
    UIPagesResponse,
    UIPageSummary,
    router,
)

PAGES_PATH: str = "/ui/pages"

EXPECTED_TOTAL_PAGES: int = 24
EXPECTED_ENABLED_PAGES: int = 24

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
        "telemetry-access-summary",
        "usage-reports",
        "docs-authentication",
        "docs-quickstart",
        "docs-api-reference",
        "docs-policy-guide",
        "docs-telemetry-guide",
        "docs-webhooks",
        "docs-changelog",
    }
)

EXPECTED_CATEGORIES_ORDERED: list[str] = [
    "system",
    "security-admin",
    "integrations",
    "tenant",
    "billing",
    "docs",
]

EXPECTED_CATEGORY_SET: frozenset[str] = frozenset(EXPECTED_CATEGORIES_ORDERED)

EXPECTED_SECTION_LABELS: dict[str, str] = {
    "system": "System",
    "security-admin": "Security Admin",
    "integrations": "Integrations",
    "tenant": "Tenant",
    "billing": "Billing",
    "docs": "Docs",
}

SLUG_TO_ROUTE: dict[str, str] = {
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
    "telemetry-access-summary": "/ui/telemetry-access-summary",
    "usage-reports": "/ui/usage-reports",
    "docs-authentication": "/ui/docs/authentication",
    "docs-quickstart": "/ui/docs/quickstart",
    "docs-api-reference": "/ui/docs/api-reference",
    "docs-policy-guide": "/ui/docs/policy-guide",
    "docs-telemetry-guide": "/ui/docs/telemetry",
    "docs-webhooks": "/ui/docs/webhooks",
    "docs-changelog": "/ui/docs/changelog",
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
    "telemetry-access-summary": "tenant",
    "usage-reports": "billing",
    "docs-authentication": "docs",
    "docs-quickstart": "docs",
    "docs-api-reference": "docs",
    "docs-policy-guide": "docs",
    "docs-telemetry-guide": "docs",
    "docs-webhooks": "docs",
    "docs-changelog": "docs",
}


@pytest.fixture(scope="module")
def client() -> TestClient:
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


@pytest.fixture(scope="module")
def pages_data(client: TestClient) -> dict:  # type: ignore[type-arg]
    return client.get(PAGES_PATH).json()


def _item_by_slug(
    pages_data: dict,  # type: ignore[type-arg]
    slug: str,
) -> dict:  # type: ignore[type-arg]
    for item in pages_data["items"]:
        if item["slug"] == slug:
            return item
    raise KeyError(slug)


def _section_by_category(
    pages_data: dict,  # type: ignore[type-arg]
    category: str,
) -> dict:  # type: ignore[type-arg]
    for section in pages_data["sections"]:
        if section["category"] == category:
            return section
    raise KeyError(category)


# ---------------------------------------------------------------------------
# HTTP / content-type
# ---------------------------------------------------------------------------


class TestPagesStatus:
    def test_returns_200(self, client: TestClient) -> None:
        response = client.get(PAGES_PATH)
        assert response.status_code == 200

    def test_content_type_is_json(self, client: TestClient) -> None:
        response = client.get(PAGES_PATH)
        assert "application/json" in response.headers["content-type"]

    def test_response_is_dict(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        assert isinstance(pages_data, dict)


# ---------------------------------------------------------------------------
# Top-level shape
# ---------------------------------------------------------------------------


class TestPagesTopLevelShape:
    def test_has_generatedat(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        assert "generatedat" in pages_data

    def test_has_summary(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        assert "summary" in pages_data

    def test_has_sections(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        assert "sections" in pages_data

    def test_has_items(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        assert "items" in pages_data

    def test_has_metadata(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        assert "metadata" in pages_data

    def test_no_unexpected_top_level_keys(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        allowed = {"generatedat", "summary", "sections", "items", "metadata"}
        assert set(pages_data.keys()) <= allowed


# ---------------------------------------------------------------------------
# generatedat
# ---------------------------------------------------------------------------


class TestPagesGeneratedAt:
    def test_generatedat_is_str(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        assert isinstance(pages_data["generatedat"], str)

    def test_generatedat_is_non_empty(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        assert len(pages_data["generatedat"]) > 0

    def test_generatedat_contains_iso_separator(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        assert "T" in pages_data["generatedat"]


# ---------------------------------------------------------------------------
# summary block
# ---------------------------------------------------------------------------


class TestPagesSummary:
    def test_summary_has_totalpages(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        assert "totalpages" in pages_data["summary"]

    def test_summary_has_enabledpages(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        assert "enabledpages" in pages_data["summary"]

    def test_summary_has_categories(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        assert "categories" in pages_data["summary"]

    def test_totalpages_is_int(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        assert isinstance(pages_data["summary"]["totalpages"], int)

    def test_enabledpages_is_int(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        assert isinstance(pages_data["summary"]["enabledpages"], int)

    def test_totalpages_equals_expected(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        assert pages_data["summary"]["totalpages"] == EXPECTED_TOTAL_PAGES

    def test_enabledpages_equals_expected(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        assert pages_data["summary"]["enabledpages"] == EXPECTED_ENABLED_PAGES

    def test_totalpages_matches_items_length(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        assert pages_data["summary"]["totalpages"] == len(pages_data["items"])

    def test_enabledpages_matches_enabled_items(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        enabled_count = sum(1 for i in pages_data["items"] if i["enabled"])
        assert pages_data["summary"]["enabledpages"] == enabled_count

    def test_summary_categories_is_list(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        assert isinstance(pages_data["summary"]["categories"], list)

    def test_summary_categories_match_expected(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        assert set(pages_data["summary"]["categories"]) == EXPECTED_CATEGORY_SET

    def test_summary_categories_ordered(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        assert pages_data["summary"]["categories"] == EXPECTED_CATEGORIES_ORDERED

    def test_summary_parses_into_model(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        model = UIPageSummary(**pages_data["summary"])
        assert model.totalpages == EXPECTED_TOTAL_PAGES
        assert model.enabledpages == EXPECTED_ENABLED_PAGES


# ---------------------------------------------------------------------------
# metadata block
# ---------------------------------------------------------------------------


class TestPagesMetadata:
    def test_metadata_is_dict(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        assert isinstance(pages_data["metadata"], dict)

    def test_metadata_surface_is_ui(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        assert pages_data["metadata"].get("surface") == "ui"

    def test_metadata_scope_is_page_catalog(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        assert pages_data["metadata"].get("scope") == "page-catalog"

    def test_metadata_generatedby_is_uipages(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        assert pages_data["metadata"].get("generatedby") == "uipages"


# ---------------------------------------------------------------------------
# items list
# ---------------------------------------------------------------------------


class TestPagesItems:
    def test_items_is_list(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        assert isinstance(pages_data["items"], list)

    def test_items_not_empty(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        assert len(pages_data["items"]) > 0

    def test_items_count_matches_expected(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        assert len(pages_data["items"]) == EXPECTED_TOTAL_PAGES

    def test_each_item_has_slug(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        for item in pages_data["items"]:
            assert "slug" in item

    def test_each_item_has_label(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        for item in pages_data["items"]:
            assert "label" in item

    def test_each_item_has_route(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        for item in pages_data["items"]:
            assert "route" in item

    def test_each_item_has_category(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        for item in pages_data["items"]:
            assert "category" in item

    def test_each_item_has_summary(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        for item in pages_data["items"]:
            assert "summary" in item

    def test_each_item_has_enabled(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        for item in pages_data["items"]:
            assert "enabled" in item

    def test_each_item_has_tags(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        for item in pages_data["items"]:
            assert "tags" in item

    def test_each_item_has_metadata(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        for item in pages_data["items"]:
            assert "metadata" in item

    def test_each_item_slug_is_non_empty_str(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        for item in pages_data["items"]:
            assert isinstance(item["slug"], str)
            assert len(item["slug"]) > 0

    def test_each_item_label_is_non_empty_str(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        for item in pages_data["items"]:
            assert isinstance(item["label"], str)
            assert len(item["label"]) > 0

    def test_each_item_route_starts_with_slash(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        for item in pages_data["items"]:
            assert item["route"].startswith("/")

    def test_each_item_enabled_is_bool(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        for item in pages_data["items"]:
            assert isinstance(item["enabled"], bool)

    def test_each_item_tags_is_list(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        for item in pages_data["items"]:
            assert isinstance(item["tags"], list)

    def test_each_item_metadata_is_dict(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        for item in pages_data["items"]:
            assert isinstance(item["metadata"], dict)

    def test_each_item_metadata_has_surface(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        for item in pages_data["items"]:
            assert "surface" in item["metadata"]

    def test_each_item_metadata_has_kind(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        for item in pages_data["items"]:
            assert "kind" in item["metadata"]

    def test_each_item_category_is_known(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        for item in pages_data["items"]:
            assert item["category"] in EXPECTED_CATEGORY_SET

    def test_each_item_summary_is_non_empty_str(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        for item in pages_data["items"]:
            assert isinstance(item["summary"], str)
            assert len(item["summary"]) > 0

    def test_slugs_are_unique(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        slugs = [i["slug"] for i in pages_data["items"]]
        assert len(slugs) == len(set(slugs))

    def test_routes_are_unique(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        routes = [i["route"] for i in pages_data["items"]]
        assert len(routes) == len(set(routes))

    def test_all_expected_slugs_present(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        returned = {i["slug"] for i in pages_data["items"]}
        assert returned == EXPECTED_SLUGS

    def test_items_parses_into_models(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        for raw in pages_data["items"]:
            item = UIPageItem(**raw)
            assert isinstance(item.slug, str)
            assert isinstance(item.route, str)
            assert isinstance(item.enabled, bool)


# ---------------------------------------------------------------------------
# sections list
# ---------------------------------------------------------------------------


class TestPagesSections:
    def test_sections_is_list(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        assert isinstance(pages_data["sections"], list)

    def test_sections_not_empty(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        assert len(pages_data["sections"]) > 0

    def test_sections_count_matches_category_count(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        assert len(pages_data["sections"]) == len(EXPECTED_CATEGORIES_ORDERED)

    def test_each_section_has_category(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        for section in pages_data["sections"]:
            assert "category" in section

    def test_each_section_has_label(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        for section in pages_data["sections"]:
            assert "label" in section

    def test_each_section_has_total(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        for section in pages_data["sections"]:
            assert "total" in section

    def test_each_section_has_items(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        for section in pages_data["sections"]:
            assert "items" in section

    def test_each_section_category_is_non_empty_str(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        for section in pages_data["sections"]:
            assert isinstance(section["category"], str)
            assert len(section["category"]) > 0

    def test_each_section_label_is_non_empty_str(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        for section in pages_data["sections"]:
            assert isinstance(section["label"], str)
            assert len(section["label"]) > 0

    def test_each_section_total_is_int(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        for section in pages_data["sections"]:
            assert isinstance(section["total"], int)

    def test_each_section_items_is_list(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        for section in pages_data["sections"]:
            assert isinstance(section["items"], list)

    def test_section_total_matches_items_length(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        for section in pages_data["sections"]:
            assert section["total"] == len(section["items"])

    def test_section_categories_are_unique(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        cats = [s["category"] for s in pages_data["sections"]]
        assert len(cats) == len(set(cats))

    def test_section_order_matches_expected(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        cats = [s["category"] for s in pages_data["sections"]]
        assert cats == EXPECTED_CATEGORIES_ORDERED

    def test_section_labels_match_expected(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        for section in pages_data["sections"]:
            expected_label = EXPECTED_SECTION_LABELS[section["category"]]
            assert section["label"] == expected_label

    def test_section_items_all_share_category(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        for section in pages_data["sections"]:
            for item in section["items"]:
                assert item["category"] == section["category"]

    def test_sections_items_total_equals_total_pages(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        total = sum(s["total"] for s in pages_data["sections"])
        assert total == EXPECTED_TOTAL_PAGES

    def test_sections_parse_into_models(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        for raw in pages_data["sections"]:
            section = UIPageSection(**raw)
            assert isinstance(section.category, str)
            assert isinstance(section.items, list)


# ---------------------------------------------------------------------------
# Full response model
# ---------------------------------------------------------------------------


class TestPagesResponseModel:
    def test_full_response_parses_into_model(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        model = UIPagesResponse(**pages_data)
        assert model.summary.totalpages == EXPECTED_TOTAL_PAGES
        assert model.summary.enabledpages == EXPECTED_ENABLED_PAGES
        assert isinstance(model.items, list)
        assert isinstance(model.sections, list)

    def test_model_items_are_uipageitem(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        model = UIPagesResponse(**pages_data)
        for item in model.items:
            assert isinstance(item, UIPageItem)

    def test_model_sections_are_uipagesection(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        model = UIPagesResponse(**pages_data)
        for section in model.sections:
            assert isinstance(section, UIPageSection)


# ---------------------------------------------------------------------------
# Slug → route accuracy
# ---------------------------------------------------------------------------


class TestPagesSlugRoutes:
    def test_manifest_route(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        assert _item_by_slug(pages_data, "manifest")["route"] == "/ui/manifest"

    def test_status_route(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        assert _item_by_slug(pages_data, "status")["route"] == "/ui/status"

    def test_routes_route(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        assert _item_by_slug(pages_data, "routes")["route"] == "/ui/routes"

    def test_execution_test_console_route(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        assert _item_by_slug(pages_data, "execution-test-console")["route"] == "/ui/executions/test-console"

    def test_incident_triage_route(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        assert _item_by_slug(pages_data, "incident-triage")["route"] == "/ui/incidents/triage"

    def test_operator_management_route(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        assert _item_by_slug(pages_data, "operator-management")["route"] == "/ui/admin/operators"

    def test_access_control_roles_route(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        assert _item_by_slug(pages_data, "access-control-roles")["route"] == "/ui/admin/roles"

    def test_integration_settings_route(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        assert _item_by_slug(pages_data, "integration-settings")["route"] == "/ui/integrations/settings"

    def test_docs_telemetry_guide_route(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        assert _item_by_slug(pages_data, "docs-telemetry-guide")["route"] == "/ui/docs/telemetry"

    def test_usage_reports_route(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        assert _item_by_slug(pages_data, "usage-reports")["route"] == "/ui/usage-reports"

    def test_customer_key_detail_route(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        assert _item_by_slug(pages_data, "customer-key-detail")["route"] == "/ui/customer-keys/detail"

    def test_all_slug_routes_accurate(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        for slug, expected_route in SLUG_TO_ROUTE.items():
            item = _item_by_slug(pages_data, slug)
            assert item["route"] == expected_route, f"slug '{slug}': expected route '{expected_route}', got '{item['route']}'"


# ---------------------------------------------------------------------------
# Slug → category accuracy
# ---------------------------------------------------------------------------


class TestPagesSlugCategories:
    def test_all_slug_categories_accurate(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        for slug, expected_cat in SLUG_TO_CATEGORY.items():
            item = _item_by_slug(pages_data, slug)
            assert item["category"] == expected_cat, f"slug '{slug}': expected category '{expected_cat}', got '{item['category']}'"

    def test_system_slugs_in_system_section(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        section = _section_by_category(pages_data, "system")
        section_slugs = {i["slug"] for i in section["items"]}
        for slug, cat in SLUG_TO_CATEGORY.items():
            if cat == "system":
                assert slug in section_slugs

    def test_docs_slugs_in_docs_section(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        section = _section_by_category(pages_data, "docs")
        section_slugs = {i["slug"] for i in section["items"]}
        for slug, cat in SLUG_TO_CATEGORY.items():
            if cat == "docs":
                assert slug in section_slugs

    def test_security_admin_slugs_in_section(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        section = _section_by_category(pages_data, "security-admin")
        section_slugs = {i["slug"] for i in section["items"]}
        for slug, cat in SLUG_TO_CATEGORY.items():
            if cat == "security-admin":
                assert slug in section_slugs


# ---------------------------------------------------------------------------
# Section-level counts
# ---------------------------------------------------------------------------


class TestPagesSectionCounts:
    def test_system_section_has_three_items(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        section = _section_by_category(pages_data, "system")
        assert section["total"] == 3

    def test_security_admin_section_has_nine_items(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        section = _section_by_category(pages_data, "security-admin")
        assert section["total"] == 9

    def test_integrations_section_has_one_item(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        section = _section_by_category(pages_data, "integrations")
        assert section["total"] == 1

    def test_tenant_section_has_three_items(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        section = _section_by_category(pages_data, "tenant")
        assert section["total"] == 3

    def test_billing_section_has_one_item(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        section = _section_by_category(pages_data, "billing")
        assert section["total"] == 1

    def test_docs_section_has_seven_items(self, pages_data: dict) -> None:  # type: ignore[type-arg]
        section = _section_by_category(pages_data, "docs")
        assert section["total"] == 7
