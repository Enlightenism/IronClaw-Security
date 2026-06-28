from __future__ import annotations

from collections.abc import Generator

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from app.ui.billing.invoices import router

_app = FastAPI()
_app.include_router(router)


@pytest.fixture()
def client() -> Generator[TestClient, None, None]:
    with TestClient(_app, raise_server_exceptions=False) as c:
        yield c


# ---------------------------------------------------------------------------
# GET /ui/billing/invoices — response shape
# ---------------------------------------------------------------------------


class TestBillingInvoicesShape:
    def test_returns_200(self, client: TestClient):
        resp = client.get("/ui/billing/invoices")
        assert resp.status_code == 200

    def test_top_level_keys_present(self, client: TestClient):
        body = client.get("/ui/billing/invoices").json()
        for key in (
            "generatedat",
            "environment",
            "stripe",
            "totalcount",
            "page",
            "pagesize",
            "totalpages",
            "totalrevenuecents",
            "totalrevenuedisplay",
            "filters",
            "invoices",
            "statuscounts",
            "notes",
        ):
            assert key in body, f"missing key: {key}"

    def test_stripe_shape(self, client: TestClient):
        stripe = client.get("/ui/billing/invoices").json()["stripe"]
        assert "configured" in stripe
        assert "mode" in stripe
        assert "note" in stripe

    def test_invoice_item_shape(self, client: TestClient):
        body = client.get("/ui/billing/invoices").json()
        assert body["totalcount"] > 0
        item = body["invoices"][0]
        for key in (
            "invoiceid",
            "organizationid",
            "organizationname",
            "status",
            "statuscolor",
            "issuedat",
            "dueat",
            "periodstart",
            "periodend",
            "total",
        ):
            assert key in item, f"missing invoice key: {key}"

    def test_total_shape(self, client: TestClient):
        item = client.get("/ui/billing/invoices").json()["invoices"][0]
        total = item["total"]
        assert "currency" in total
        assert "amountcents" in total
        assert "displayamount" in total
        assert total["currency"] == "USD"

    def test_statuscount_shape(self, client: TestClient):
        counts = client.get("/ui/billing/invoices").json()["statuscounts"]
        assert len(counts) > 0
        for sc in counts:
            assert "status" in sc
            assert "count" in sc
            assert "statuscolor" in sc

    def test_notes_is_list_of_strings(self, client: TestClient):
        notes = client.get("/ui/billing/invoices").json()["notes"]
        assert isinstance(notes, list)
        assert all(isinstance(n, str) for n in notes)

    def test_totalpages_always_at_least_one(self, client: TestClient):
        body = client.get("/ui/billing/invoices").json()
        assert body["totalpages"] >= 1

    def test_default_page_and_pagesize(self, client: TestClient):
        body = client.get("/ui/billing/invoices").json()
        assert body["page"] == 1
        assert body["pagesize"] == 25


# ---------------------------------------------------------------------------
# GET /ui/billing/invoices — status filter
# ---------------------------------------------------------------------------


class TestBillingInvoicesStatusFilter:
    def test_status_paid_returns_only_paid(self, client: TestClient):
        body = client.get("/ui/billing/invoices?status=paid").json()
        assert body["totalcount"] > 0
        for inv in body["invoices"]:
            assert inv["status"] == "paid"

    def test_status_draft_returns_only_draft(self, client: TestClient):
        body = client.get("/ui/billing/invoices?status=draft").json()
        assert body["totalcount"] > 0
        for inv in body["invoices"]:
            assert inv["status"] == "draft"

    def test_status_past_due_returns_only_past_due(self, client: TestClient):
        body = client.get("/ui/billing/invoices?status=past_due").json()
        assert body["totalcount"] > 0
        for inv in body["invoices"]:
            assert inv["status"] == "past_due"

    def test_status_void_returns_only_void(self, client: TestClient):
        body = client.get("/ui/billing/invoices?status=void").json()
        assert body["totalcount"] > 0
        for inv in body["invoices"]:
            assert inv["status"] == "void"

    def test_unknown_status_returns_zero(self, client: TestClient):
        body = client.get("/ui/billing/invoices?status=nonexistent").json()
        assert body["totalcount"] == 0
        assert body["invoices"] == []

    def test_status_filter_does_not_affect_statuscounts(self, client: TestClient):
        unfiltered = client.get("/ui/billing/invoices").json()["statuscounts"]
        filtered = client.get("/ui/billing/invoices?status=paid").json()["statuscounts"]
        assert unfiltered == filtered


# ---------------------------------------------------------------------------
# GET /ui/billing/invoices — organizationid filter
# ---------------------------------------------------------------------------


class TestBillingInvoicesOrgFilter:
    def test_org_filter_narrows_results(self, client: TestClient):
        body = client.get("/ui/billing/invoices?organizationid=org-001").json()
        assert body["totalcount"] > 0
        for inv in body["invoices"]:
            assert inv["organizationid"] == "org-001"

    def test_org_filter_unknown_returns_zero(self, client: TestClient):
        body = client.get("/ui/billing/invoices?organizationid=org-999").json()
        assert body["totalcount"] == 0

    def test_status_and_org_filters_combine(self, client: TestClient):
        body = client.get("/ui/billing/invoices?status=paid&organizationid=org-001").json()
        for inv in body["invoices"]:
            assert inv["status"] == "paid"
            assert inv["organizationid"] == "org-001"


# ---------------------------------------------------------------------------
# GET /ui/billing/invoices — sorting
# ---------------------------------------------------------------------------


class TestBillingInvoicesSorting:
    def test_sortby_issuedat_desc(self, client: TestClient):
        body = client.get("/ui/billing/invoices?sortby=issuedat&sortdir=desc").json()
        dates = [inv["issuedat"] for inv in body["invoices"]]
        assert dates == sorted(dates, reverse=True)

    def test_sortby_issuedat_asc(self, client: TestClient):
        body = client.get("/ui/billing/invoices?sortby=issuedat&sortdir=asc").json()
        dates = [inv["issuedat"] for inv in body["invoices"]]
        assert dates == sorted(dates)

    def test_sortby_total_desc(self, client: TestClient):
        body = client.get("/ui/billing/invoices?sortby=total&sortdir=desc").json()
        amounts = [inv["total"]["amountcents"] for inv in body["invoices"]]
        assert amounts == sorted(amounts, reverse=True)

    def test_sortby_total_asc(self, client: TestClient):
        body = client.get("/ui/billing/invoices?sortby=total&sortdir=asc").json()
        amounts = [inv["total"]["amountcents"] for inv in body["invoices"]]
        assert amounts == sorted(amounts)

    def test_sortby_status_asc(self, client: TestClient):
        body = client.get("/ui/billing/invoices?sortby=status&sortdir=asc").json()
        statuses = [inv["status"] for inv in body["invoices"]]
        assert statuses == sorted(statuses)

    def test_invalid_sortby_falls_back_to_issuedat(self, client: TestClient):
        body_default = client.get("/ui/billing/invoices?sortby=issuedat&sortdir=desc").json()
        body_invalid = client.get("/ui/billing/invoices?sortby=badfield&sortdir=desc").json()
        assert [i["invoiceid"] for i in body_default["invoices"]] == [i["invoiceid"] for i in body_invalid["invoices"]]


# ---------------------------------------------------------------------------
# GET /ui/billing/invoices — pagination
# ---------------------------------------------------------------------------


class TestBillingInvoicesPagination:
    def test_pagesize_1_returns_one_invoice(self, client: TestClient):
        body = client.get("/ui/billing/invoices?pagesize=1").json()
        assert len(body["invoices"]) == 1
        assert body["pagesize"] == 1

    def test_page_2_pagesize_5_returns_correct_slice(self, client: TestClient):
        all_body = client.get("/ui/billing/invoices?pagesize=100").json()
        all_ids = [i["invoiceid"] for i in all_body["invoices"]]
        page2 = client.get("/ui/billing/invoices?page=2&pagesize=5").json()
        page2_ids = [i["invoiceid"] for i in page2["invoices"]]
        assert page2_ids == all_ids[5:10]

    def test_totalpages_computed_correctly(self, client: TestClient):
        body = client.get("/ui/billing/invoices?pagesize=3").json()
        import math

        expected = math.ceil(body["totalcount"] / 3)
        assert body["totalpages"] == expected

    def test_page_beyond_range_returns_empty(self, client: TestClient):
        body = client.get("/ui/billing/invoices?page=9999&pagesize=25").json()
        assert body["invoices"] == []

    def test_pagesize_capped_at_100(self, client: TestClient):
        body = client.get("/ui/billing/invoices?pagesize=9999").json()
        assert body["pagesize"] == 100

    def test_pagesize_minimum_is_1(self, client: TestClient):
        body = client.get("/ui/billing/invoices?pagesize=0").json()
        assert body["pagesize"] >= 1

    def test_page_minimum_is_1(self, client: TestClient):
        body = client.get("/ui/billing/invoices?page=0").json()
        assert body["page"] >= 1


# ---------------------------------------------------------------------------
# GET /ui/billing/invoices — revenue calculation
# ---------------------------------------------------------------------------


class TestBillingInvoicesRevenue:
    def test_totalrevenuecents_only_sums_paid(self, client: TestClient):
        body = client.get("/ui/billing/invoices").json()
        paid_body = client.get("/ui/billing/invoices?status=paid&pagesize=100").json()
        paid_sum = sum(inv["total"]["amountcents"] for inv in paid_body["invoices"])
        assert body["totalrevenuecents"] == paid_sum

    def test_totalrevenuedisplay_starts_with_dollar(self, client: TestClient):
        body = client.get("/ui/billing/invoices").json()
        assert body["totalrevenuedisplay"].startswith("$")

    def test_revenue_zero_when_no_paid_invoices(self, client: TestClient):
        body = client.get("/ui/billing/invoices?status=draft").json()
        assert body["totalrevenuecents"] == 0

    def test_revenue_filtered_set_only(self, client: TestClient):
        body_org1 = client.get("/ui/billing/invoices?organizationid=org-001").json()
        body_all = client.get("/ui/billing/invoices").json()
        assert body_org1["totalrevenuecents"] <= body_all["totalrevenuecents"]


# ---------------------------------------------------------------------------
# GET /ui/billing/invoices — statuscounts unfiltered
# ---------------------------------------------------------------------------


class TestBillingInvoicesStatusCounts:
    def test_statuscounts_sum_equals_total_unfiltered(self, client: TestClient):
        body = client.get("/ui/billing/invoices").json()
        total = body["totalcount"]
        count_sum = sum(sc["count"] for sc in body["statuscounts"])
        assert count_sum == total

    def test_statuscounts_unaffected_by_status_filter(self, client: TestClient):
        unfiltered = client.get("/ui/billing/invoices").json()["statuscounts"]
        filtered = client.get("/ui/billing/invoices?status=void").json()["statuscounts"]
        assert unfiltered == filtered

    def test_statuscounts_unaffected_by_org_filter(self, client: TestClient):
        unfiltered = client.get("/ui/billing/invoices").json()["statuscounts"]
        filtered = client.get("/ui/billing/invoices?organizationid=org-001").json()["statuscounts"]
        assert unfiltered == filtered

    def test_statuscolor_values_are_valid(self, client: TestClient):
        valid_colors = {"success", "neutral", "error", "warning"}
        counts = client.get("/ui/billing/invoices").json()["statuscounts"]
        for sc in counts:
            assert sc["statuscolor"] in valid_colors


# ---------------------------------------------------------------------------
# GET /ui/billing/invoices/{invoiceid}/download
# ---------------------------------------------------------------------------


class TestInvoiceDownload:
    def test_paid_invoice_with_downloadurl_available_true(self, client: TestClient):
        resp = client.get("/ui/billing/invoices/inv-001/download")
        assert resp.status_code == 200
        body = resp.json()
        assert body["available"] is True
        assert body["downloadurl"] is not None
        assert body["invoiceid"] == "inv-001"

    def test_draft_invoice_available_false(self, client: TestClient):
        resp = client.get("/ui/billing/invoices/inv-002/download")
        assert resp.status_code == 200
        body = resp.json()
        assert body["available"] is False
        assert body["downloadurl"] is None

    def test_void_invoice_available_false(self, client: TestClient):
        resp = client.get("/ui/billing/invoices/inv-007/download")
        assert resp.status_code == 200
        body = resp.json()
        assert body["available"] is False
        assert body["downloadurl"] is None

    def test_past_due_invoice_with_downloadurl_available_true(self, client: TestClient):
        resp = client.get("/ui/billing/invoices/inv-003/download")
        assert resp.status_code == 200
        body = resp.json()
        assert body["available"] is True
        assert body["downloadurl"] is not None

    def test_unknown_invoiceid_available_false(self, client: TestClient):
        resp = client.get("/ui/billing/invoices/inv-999/download")
        assert resp.status_code == 200
        body = resp.json()
        assert body["available"] is False
        assert body["downloadurl"] is None

    def test_unknown_invoiceid_message_contains_id(self, client: TestClient):
        resp = client.get("/ui/billing/invoices/inv-999/download")
        body = resp.json()
        assert "inv-999" in body["message"]

    def test_download_response_shape(self, client: TestClient):
        body = client.get("/ui/billing/invoices/inv-001/download").json()
        for key in ("invoiceid", "downloadurl", "available", "message", "generatedat", "environment"):
            assert key in body, f"missing key: {key}"

    def test_download_generatedat_is_string(self, client: TestClient):
        body = client.get("/ui/billing/invoices/inv-001/download").json()
        assert isinstance(body["generatedat"], str)
        assert len(body["generatedat"]) > 0
