from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from app.ui.usage import router

BASE = "/ui/usage"
REPORTS_PATH = f"{BASE}/reports"
EVENT_PATH = f"{BASE}/event"
SUMMARY_PATH = f"{BASE}/summary"


@pytest.fixture(scope="module")
def client() -> TestClient:
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


# ---------------------------------------------------------------------------
# GET /ui/usage
# ---------------------------------------------------------------------------


class TestUsageRoot:
    def test_returns_200(self, client: TestClient) -> None:
        response = client.get(BASE)
        assert response.status_code == 200

    def test_content_type_is_html(self, client: TestClient) -> None:
        response = client.get(BASE)
        assert "text/html" in response.headers["content-type"]

    def test_body_is_not_empty(self, client: TestClient) -> None:
        response = client.get(BASE)
        assert len(response.text.strip()) > 0

    def test_has_doctype(self, client: TestClient) -> None:
        assert "<!DOCTYPE html>" in client.get(BASE).text

    def test_has_usage_keyword(self, client: TestClient) -> None:
        assert "usage" in client.get(BASE).text.lower()

    def test_has_units_keyword(self, client: TestClient) -> None:
        assert "units" in client.get(BASE).text.lower()

    def test_has_quota_keyword(self, client: TestClient) -> None:
        assert "quota" in client.get(BASE).text.lower()

    def test_has_remaining_keyword(self, client: TestClient) -> None:
        assert "remaining" in client.get(BASE).text.lower()

    def test_has_billing_keyword(self, client: TestClient) -> None:
        assert "billing" in client.get(BASE).text.lower()

    def test_has_summary_keyword(self, client: TestClient) -> None:
        assert "summary" in client.get(BASE).text.lower()

    def test_has_owner_keyword(self, client: TestClient) -> None:
        assert "owner" in client.get(BASE).text.lower()

    def test_has_data_usage_attribute(self, client: TestClient) -> None:
        assert 'data-usage="true"' in client.get(BASE).text

    def test_has_html_title(self, client: TestClient) -> None:
        assert "<title>" in client.get(BASE).text

    def test_title_contains_usage(self, client: TestClient) -> None:
        assert "usage" in client.get(BASE).text.lower()

    def test_has_main_element(self, client: TestClient) -> None:
        assert "<main>" in client.get(BASE).text


# ---------------------------------------------------------------------------
# GET /ui/usage/reports
# ---------------------------------------------------------------------------


class TestUsageReports:
    def test_returns_200(self, client: TestClient) -> None:
        response = client.get(REPORTS_PATH)
        assert response.status_code == 200

    def test_content_type_is_html(self, client: TestClient) -> None:
        response = client.get(REPORTS_PATH)
        assert "text/html" in response.headers["content-type"]

    def test_body_is_not_empty(self, client: TestClient) -> None:
        assert len(client.get(REPORTS_PATH).text.strip()) > 0

    def test_has_doctype(self, client: TestClient) -> None:
        assert "<!DOCTYPE html>" in client.get(REPORTS_PATH).text

    def test_has_table_element(self, client: TestClient) -> None:
        body = client.get(REPORTS_PATH).text.lower()
        assert "<table" in body

    def test_table_has_thead(self, client: TestClient) -> None:
        assert "<thead>" in client.get(REPORTS_PATH).text.lower()

    def test_table_has_tbody(self, client: TestClient) -> None:
        assert "<tbody>" in client.get(REPORTS_PATH).text.lower()

    def test_table_header_has_owner_column(self, client: TestClient) -> None:
        assert "owner" in client.get(REPORTS_PATH).text.lower()

    def test_table_header_has_units_column(self, client: TestClient) -> None:
        assert "units" in client.get(REPORTS_PATH).text.lower()

    def test_table_header_has_quota_column(self, client: TestClient) -> None:
        assert "quota" in client.get(REPORTS_PATH).text.lower()

    def test_table_header_has_remaining_column(self, client: TestClient) -> None:
        assert "remaining" in client.get(REPORTS_PATH).text.lower()

    def test_has_billing_keyword(self, client: TestClient) -> None:
        assert "billing" in client.get(REPORTS_PATH).text.lower()

    def test_has_summary_keyword(self, client: TestClient) -> None:
        assert "summary" in client.get(REPORTS_PATH).text.lower()

    def test_has_data_usage_table_attribute(self, client: TestClient) -> None:
        assert 'data-usage="table"' in client.get(REPORTS_PATH).text

    def test_title_contains_reports(self, client: TestClient) -> None:
        body = client.get(REPORTS_PATH).text.lower()
        assert "report" in body

    def test_has_main_element(self, client: TestClient) -> None:
        assert "<main>" in client.get(REPORTS_PATH).text


# ---------------------------------------------------------------------------
# GET /ui/usage/event
# ---------------------------------------------------------------------------


class TestUsageEvent:
    def test_returns_200(self, client: TestClient) -> None:
        response = client.get(EVENT_PATH)
        assert response.status_code == 200

    def test_content_type_is_html(self, client: TestClient) -> None:
        response = client.get(EVENT_PATH)
        assert "text/html" in response.headers["content-type"]

    def test_body_is_not_empty(self, client: TestClient) -> None:
        assert len(client.get(EVENT_PATH).text.strip()) > 0

    def test_has_doctype(self, client: TestClient) -> None:
        assert "<!DOCTYPE html>" in client.get(EVENT_PATH).text

    def test_has_event_keyword(self, client: TestClient) -> None:
        assert "event" in client.get(EVENT_PATH).text.lower()

    def test_has_detail_keyword(self, client: TestClient) -> None:
        assert "detail" in client.get(EVENT_PATH).text.lower()

    def test_has_request_keyword(self, client: TestClient) -> None:
        assert "request" in client.get(EVENT_PATH).text.lower()

    def test_has_usage_id_keyword(self, client: TestClient) -> None:
        assert "usage id" in client.get(EVENT_PATH).text.lower()

    def test_has_owner_keyword(self, client: TestClient) -> None:
        assert "owner" in client.get(EVENT_PATH).text.lower()

    def test_has_description_list(self, client: TestClient) -> None:
        body = client.get(EVENT_PATH).text.lower()
        assert "<dl>" in body

    def test_has_dt_elements(self, client: TestClient) -> None:
        assert "<dt>" in client.get(EVENT_PATH).text.lower()

    def test_has_dd_elements(self, client: TestClient) -> None:
        assert "<dd>" in client.get(EVENT_PATH).text.lower()

    def test_title_contains_event(self, client: TestClient) -> None:
        assert "event" in client.get(EVENT_PATH).text.lower()

    def test_has_main_element(self, client: TestClient) -> None:
        assert "<main>" in client.get(EVENT_PATH).text


# ---------------------------------------------------------------------------
# GET /ui/usage/summary
# ---------------------------------------------------------------------------


class TestUsageSummary:
    def test_returns_200(self, client: TestClient) -> None:
        response = client.get(SUMMARY_PATH)
        assert response.status_code == 200

    def test_content_type_is_html(self, client: TestClient) -> None:
        response = client.get(SUMMARY_PATH)
        assert "text/html" in response.headers["content-type"]

    def test_body_is_not_empty(self, client: TestClient) -> None:
        assert len(client.get(SUMMARY_PATH).text.strip()) > 0

    def test_has_doctype(self, client: TestClient) -> None:
        assert "<!DOCTYPE html>" in client.get(SUMMARY_PATH).text

    def test_has_summary_keyword(self, client: TestClient) -> None:
        assert "summary" in client.get(SUMMARY_PATH).text.lower()

    def test_has_totals_keyword(self, client: TestClient) -> None:
        assert "totals" in client.get(SUMMARY_PATH).text.lower()

    def test_has_total_units_keyword(self, client: TestClient) -> None:
        assert "total units" in client.get(SUMMARY_PATH).text.lower()

    def test_has_total_cost_keyword(self, client: TestClient) -> None:
        assert "total cost" in client.get(SUMMARY_PATH).text.lower()

    def test_has_remaining_quota_keyword(self, client: TestClient) -> None:
        assert "remaining quota" in client.get(SUMMARY_PATH).text.lower()

    def test_has_unordered_list(self, client: TestClient) -> None:
        assert "<ul>" in client.get(SUMMARY_PATH).text.lower()

    def test_has_list_items(self, client: TestClient) -> None:
        assert "<li>" in client.get(SUMMARY_PATH).text.lower()

    def test_title_contains_summary(self, client: TestClient) -> None:
        assert "summary" in client.get(SUMMARY_PATH).text.lower()

    def test_has_main_element(self, client: TestClient) -> None:
        assert "<main>" in client.get(SUMMARY_PATH).text

    def test_has_h2_heading(self, client: TestClient) -> None:
        assert "<h2>" in client.get(SUMMARY_PATH).text.lower()
