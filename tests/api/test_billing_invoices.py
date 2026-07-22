from __future__ import annotations

import os

from fastapi.testclient import TestClient
import pytest

os.environ.setdefault("IRONCLAW_PERSISTENCE_MODE", "memory")
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("IRONCLAW_API_KEY", "test-api-key")
os.environ.setdefault("AUTH_REQUIRED", "true")
os.environ.setdefault("IRONCLAW_RATE_LIMIT_ENABLED", "false")
os.environ.setdefault("SUPABASE_URL", "")
os.environ.setdefault("SUPABASE_SERVICE_ROLE_KEY", "")
os.environ.setdefault("SUPABASE_KEY", "")
os.environ.setdefault("SUPABASE_ANON_KEY", "")

from app.main import app as _app

_MOCK_API_KEY = "test-api-key"
_AUTH_HEADERS = {"X-API-Key": _MOCK_API_KEY}

# Full unfiltered seed counts (10 invoices):
# paid: inv-001, inv-004, inv-005, inv-008  → 4
# draft: inv-002, inv-006                   → 2
# past_due: inv-003, inv-009                → 2
# void: inv-007, inv-010                    → 2
_TOTAL_SEED = 10
_PAID_COUNT = 4
_DRAFT_COUNT = 2
_PAST_DUE_COUNT = 2
_VOID_COUNT = 2

# paid revenue: 29900 + 29900 + 9900 + 149900 = 219600
_FULL_PAID_REVENUE_CENTS = 219_600

# org-001 invoices: inv-001 (paid), inv-004 (paid)  → 2
_ORG_001_COUNT = 2
_ORG_001_PAID_REVENUE_CENTS = 29_900 + 29_900  # 59800

# org-004 invoices: inv-005 (paid), inv-006 (draft) → 2
_ORG_004_COUNT = 2
_ORG_004_PAID_REVENUE_CENTS = 9_900  # only inv-005 is paid


@pytest.fixture()
def client():
    with TestClient(_app, raise_server_exceptions=True) as c:
        c.headers.update(_AUTH_HEADERS)
        yield c


# ---------------------------------------------------------------------------
# GET /ui/billing/invoices — HTTP contract
# ---------------------------------------------------------------------------


def test_billing_invoices_returns_200(client: TestClient) -> None:
    resp = client.get("/ui/billing/invoices")
    assert resp.status_code == 200


def test_billing_invoices_content_type_json(client: TestClient) -> None:
    resp = client.get("/ui/billing/invoices")
    assert "application/json" in resp.headers["content-type"]


# ---------------------------------------------------------------------------
# Envelope fields
# ---------------------------------------------------------------------------


def test_billing_invoices_envelope_generatedat(client: TestClient) -> None:
    body = client.get("/ui/billing/invoices").json()
    assert isinstance(body["generatedat"], str)
    assert len(body["generatedat"]) > 0


def test_billing_invoices_envelope_environment_is_non_empty_string(
    client: TestClient,
) -> None:
    body = client.get("/ui/billing/invoices").json()
    assert isinstance(body["environment"], str)
    assert len(body["environment"]) > 0


def test_billing_invoices_envelope_has_required_top_level_keys(
    client: TestClient,
) -> None:
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


# ---------------------------------------------------------------------------
# stripe block
# ---------------------------------------------------------------------------


def test_billing_invoices_stripe_key_present(client: TestClient) -> None:
    body = client.get("/ui/billing/invoices").json()
    assert "stripe" in body


def test_billing_invoices_stripe_configured_is_bool(client: TestClient) -> None:
    body = client.get("/ui/billing/invoices").json()
    assert isinstance(body["stripe"]["configured"], bool)


def test_billing_invoices_stripe_mode_is_valid(client: TestClient) -> None:
    body = client.get("/ui/billing/invoices").json()
    assert body["stripe"]["mode"] in {"live", "test", "unconfigured"}


def test_billing_invoices_stripe_note_is_non_empty_string(client: TestClient) -> None:
    body = client.get("/ui/billing/invoices").json()
    assert isinstance(body["stripe"]["note"], str)
    assert len(body["stripe"]["note"]) > 0


def test_billing_invoices_stripe_unconfigured_when_no_key_set(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("STRIPE_SECRET_KEY", raising=False)
    body = client.get("/ui/billing/invoices").json()
    assert body["stripe"]["configured"] is False
    assert body["stripe"]["mode"] == "unconfigured"


def test_billing_invoices_stripe_test_mode_when_test_key(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_abc123")
    body = client.get("/ui/billing/invoices").json()
    assert body["stripe"]["configured"] is True
    assert body["stripe"]["mode"] == "test"


def test_billing_invoices_stripe_live_mode_when_live_key(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_live_abc123")
    body = client.get("/ui/billing/invoices").json()
    assert body["stripe"]["configured"] is True
    assert body["stripe"]["mode"] == "live"


# ---------------------------------------------------------------------------
# statuscounts — full unfiltered set (10 invoices)
# ---------------------------------------------------------------------------


def test_billing_invoices_statuscounts_reflects_full_unfiltered_set(
    client: TestClient,
) -> None:
    body = client.get("/ui/billing/invoices").json()
    status_map = {e["status"]: e["count"] for e in body["statuscounts"]}
    assert status_map.get("paid") == _PAID_COUNT
    assert status_map.get("draft") == _DRAFT_COUNT
    assert status_map.get("past_due") == _PAST_DUE_COUNT
    assert status_map.get("void") == _VOID_COUNT


def test_billing_invoices_statuscounts_unaffected_by_status_filter(
    client: TestClient,
) -> None:
    body = client.get("/ui/billing/invoices?status=paid").json()
    status_map = {e["status"]: e["count"] for e in body["statuscounts"]}
    assert status_map.get("paid") == _PAID_COUNT
    assert status_map.get("draft") == _DRAFT_COUNT


def test_billing_invoices_statuscounts_each_entry_has_statuscolor(
    client: TestClient,
) -> None:
    body = client.get("/ui/billing/invoices").json()
    for entry in body["statuscounts"]:
        assert "statuscolor" in entry
        assert isinstance(entry["statuscolor"], str)
        assert len(entry["statuscolor"]) > 0


# ---------------------------------------------------------------------------
# Filtering — status
# ---------------------------------------------------------------------------


def test_billing_invoices_filter_status_paid_returns_correct_count(
    client: TestClient,
) -> None:
    body = client.get("/ui/billing/invoices?status=paid").json()
    assert body["totalcount"] == _PAID_COUNT
    assert all(inv["status"] == "paid" for inv in body["invoices"])


def test_billing_invoices_filter_status_draft_returns_correct_count(
    client: TestClient,
) -> None:
    body = client.get("/ui/billing/invoices?status=draft").json()
    assert body["totalcount"] == _DRAFT_COUNT
    assert all(inv["status"] == "draft" for inv in body["invoices"])


def test_billing_invoices_filter_status_past_due_returns_correct_count(
    client: TestClient,
) -> None:
    body = client.get("/ui/billing/invoices?status=past_due").json()
    assert body["totalcount"] == _PAST_DUE_COUNT
    assert all(inv["status"] == "past_due" for inv in body["invoices"])


def test_billing_invoices_filter_status_void_returns_correct_count(
    client: TestClient,
) -> None:
    body = client.get("/ui/billing/invoices?status=void").json()
    assert body["totalcount"] == _VOID_COUNT
    assert all(inv["status"] == "void" for inv in body["invoices"])


# ---------------------------------------------------------------------------
# Filtering — organizationid
# ---------------------------------------------------------------------------


def test_billing_invoices_filter_org001_returns_correct_count(
    client: TestClient,
) -> None:
    body = client.get("/ui/billing/invoices?organizationid=org-001").json()
    assert body["totalcount"] == _ORG_001_COUNT
    assert all(inv["organizationid"] == "org-001" for inv in body["invoices"])


def test_billing_invoices_filter_org004_returns_correct_count(
    client: TestClient,
) -> None:
    body = client.get("/ui/billing/invoices?organizationid=org-004").json()
    assert body["totalcount"] == _ORG_004_COUNT
    assert all(inv["organizationid"] == "org-004" for inv in body["invoices"])


def test_billing_invoices_filter_combined_status_and_org(
    client: TestClient,
) -> None:
    body = client.get("/ui/billing/invoices?status=paid&organizationid=org-001").json()
    assert body["totalcount"] == _ORG_001_COUNT
    assert all(inv["status"] == "paid" and inv["organizationid"] == "org-001" for inv in body["invoices"])


def test_billing_invoices_filter_nonexistent_org_returns_zero(
    client: TestClient,
) -> None:
    body = client.get("/ui/billing/invoices?organizationid=org-999").json()
    assert body["totalcount"] == 0
    assert body["invoices"] == []


# ---------------------------------------------------------------------------
# Pagination math
# ---------------------------------------------------------------------------


def test_billing_invoices_default_pagination_values(client: TestClient) -> None:
    body = client.get("/ui/billing/invoices").json()
    assert body["page"] == 1
    assert body["pagesize"] == 25
    assert body["totalcount"] == _TOTAL_SEED
    assert body["totalpages"] == 1


def test_billing_invoices_pagination_pagesize_3_totalpages(client: TestClient) -> None:
    body = client.get("/ui/billing/invoices?pagesize=3").json()
    assert body["pagesize"] == 3
    assert body["totalcount"] == _TOTAL_SEED
    assert body["totalpages"] == 4


def test_billing_invoices_pagination_page2_pagesize3_returns_correct_slice(
    client: TestClient,
) -> None:
    body = client.get("/ui/billing/invoices?page=2&pagesize=3").json()
    assert body["page"] == 2
    assert body["pagesize"] == 3
    assert len(body["invoices"]) == 3


def test_billing_invoices_pagination_last_page_partial_slice(
    client: TestClient,
) -> None:
    body = client.get("/ui/billing/invoices?page=4&pagesize=3").json()
    assert body["page"] == 4
    assert len(body["invoices"]) == 1


def test_billing_invoices_pagination_beyond_last_page_returns_empty(
    client: TestClient,
) -> None:
    body = client.get("/ui/billing/invoices?page=99&pagesize=25").json()
    assert body["invoices"] == []


def test_billing_invoices_pagination_pagesize_capped_at_100(
    client: TestClient,
) -> None:
    body = client.get("/ui/billing/invoices?pagesize=999").json()
    assert body["pagesize"] == 100


def test_billing_invoices_totalpages_minimum_is_1_when_no_results(
    client: TestClient,
) -> None:
    body = client.get("/ui/billing/invoices?organizationid=org-999").json()
    assert body["totalpages"] == 1


def test_billing_invoices_filters_block_reflects_active_filters(
    client: TestClient,
) -> None:
    body = client.get("/ui/billing/invoices?status=paid&organizationid=org-001&page=1&pagesize=10").json()
    f = body["filters"]
    assert f["status"] == "paid"
    assert f["organizationid"] == "org-001"
    assert f["page"] == 1
    assert f["pagesize"] == 10


# ---------------------------------------------------------------------------
# totalrevenuecents — paid only, from filtered (pre-pagination) set
# ---------------------------------------------------------------------------


def test_billing_invoices_totalrevenuecents_full_set_paid_only(
    client: TestClient,
) -> None:
    body = client.get("/ui/billing/invoices").json()
    assert body["totalrevenuecents"] == _FULL_PAID_REVENUE_CENTS


def test_billing_invoices_totalrevenuecents_org001_paid_only(
    client: TestClient,
) -> None:
    body = client.get("/ui/billing/invoices?organizationid=org-001").json()
    assert body["totalrevenuecents"] == _ORG_001_PAID_REVENUE_CENTS


def test_billing_invoices_totalrevenuecents_org004_paid_only(
    client: TestClient,
) -> None:
    body = client.get("/ui/billing/invoices?organizationid=org-004").json()
    assert body["totalrevenuecents"] == _ORG_004_PAID_REVENUE_CENTS


def test_billing_invoices_totalrevenuecents_draft_filter_is_zero(
    client: TestClient,
) -> None:
    body = client.get("/ui/billing/invoices?status=draft").json()
    assert body["totalrevenuecents"] == 0


def test_billing_invoices_totalrevenuecents_void_filter_is_zero(
    client: TestClient,
) -> None:
    body = client.get("/ui/billing/invoices?status=void").json()
    assert body["totalrevenuecents"] == 0


def test_billing_invoices_totalrevenuedisplay_is_usd_formatted(
    client: TestClient,
) -> None:
    body = client.get("/ui/billing/invoices").json()
    assert body["totalrevenuedisplay"].startswith("$")
    assert "." in body["totalrevenuedisplay"]


# ---------------------------------------------------------------------------
# Invoice list item shape
# ---------------------------------------------------------------------------


def test_billing_invoices_items_have_required_fields(client: TestClient) -> None:
    body = client.get("/ui/billing/invoices").json()
    for inv in body["invoices"]:
        for field in (
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
            assert field in inv, f"invoice {inv.get('invoiceid')} missing field: {field}"


def test_billing_invoices_total_block_shape(client: TestClient) -> None:
    body = client.get("/ui/billing/invoices").json()
    inv = body["invoices"][0]
    assert "currency" in inv["total"]
    assert "amountcents" in inv["total"]
    assert "displayamount" in inv["total"]
    assert inv["total"]["currency"] == "USD"
    assert isinstance(inv["total"]["amountcents"], int)
    assert inv["total"]["displayamount"].startswith("$")


def test_billing_invoices_paid_invoices_have_downloadurl(client: TestClient) -> None:
    body = client.get("/ui/billing/invoices?status=paid").json()
    for inv in body["invoices"]:
        assert inv["downloadurl"] is not None
        assert inv["downloadurl"].startswith("/ui/billing/invoices/")


def test_billing_invoices_draft_invoices_have_null_downloadurl(
    client: TestClient,
) -> None:
    body = client.get("/ui/billing/invoices?status=draft").json()
    for inv in body["invoices"]:
        assert inv["downloadurl"] is None


def test_billing_invoices_void_invoices_have_null_downloadurl(
    client: TestClient,
) -> None:
    body = client.get("/ui/billing/invoices?status=void").json()
    for inv in body["invoices"]:
        assert inv["downloadurl"] is None


def test_billing_invoices_statuscolor_valid_values(client: TestClient) -> None:
    valid_colors = {"success", "neutral", "error", "warning"}
    body = client.get("/ui/billing/invoices").json()
    for inv in body["invoices"]:
        assert inv["statuscolor"] in valid_colors, f"invoice {inv['invoiceid']} has unexpected statuscolor: {inv['statuscolor']}"


# ---------------------------------------------------------------------------
# GET /ui/billing/invoices/{invoiceid}/download
# ---------------------------------------------------------------------------


def test_invoice_download_valid_paid_invoice_available_true(
    client: TestClient,
) -> None:
    resp = client.get("/ui/billing/invoices/inv-001/download")
    assert resp.status_code == 200
    body = resp.json()
    assert body["invoiceid"] == "inv-001"
    assert body["available"] is True
    assert body["downloadurl"] is not None
    assert body["downloadurl"] == "/ui/billing/invoices/inv-001/download"


def test_invoice_download_valid_paid_invoice_message_non_empty(
    client: TestClient,
) -> None:
    body = client.get("/ui/billing/invoices/inv-001/download").json()
    assert isinstance(body["message"], str)
    assert len(body["message"]) > 0


def test_invoice_download_unknown_id_available_false(client: TestClient) -> None:
    body = client.get("/ui/billing/invoices/inv-999/download").json()
    assert body["invoiceid"] == "inv-999"
    assert body["available"] is False
    assert body["downloadurl"] is None


def test_invoice_download_unknown_id_message_non_empty(client: TestClient) -> None:
    body = client.get("/ui/billing/invoices/inv-999/download").json()
    assert isinstance(body["message"], str)
    assert len(body["message"]) > 0


def test_invoice_download_draft_invoice_available_false(client: TestClient) -> None:
    body = client.get("/ui/billing/invoices/inv-002/download").json()
    assert body["invoiceid"] == "inv-002"
    assert body["available"] is False
    assert body["downloadurl"] is None


def test_invoice_download_void_invoice_available_false(client: TestClient) -> None:
    body = client.get("/ui/billing/invoices/inv-007/download").json()
    assert body["invoiceid"] == "inv-007"
    assert body["available"] is False
    assert body["downloadurl"] is None


def test_invoice_download_past_due_invoice_available_true(
    client: TestClient,
) -> None:
    body = client.get("/ui/billing/invoices/inv-003/download").json()
    assert body["invoiceid"] == "inv-003"
    assert body["available"] is True
    assert body["downloadurl"] == "/ui/billing/invoices/inv-003/download"


def test_invoice_download_envelope_has_environment(client: TestClient) -> None:
    body = client.get("/ui/billing/invoices/inv-001/download").json()
    assert isinstance(body["environment"], str)
    assert len(body["environment"]) > 0


def test_invoice_download_envelope_has_generatedat(client: TestClient) -> None:
    body = client.get("/ui/billing/invoices/inv-001/download").json()
    assert isinstance(body["generatedat"], str)
    assert len(body["generatedat"]) > 0


# ---------------------------------------------------------------------------
# Sorting
# ---------------------------------------------------------------------------


def test_billing_invoices_default_sort_is_issuedat_desc(client: TestClient) -> None:
    body = client.get("/ui/billing/invoices").json()
    dates = [inv["issuedat"] for inv in body["invoices"]]
    assert dates == sorted(dates, reverse=True)


def test_billing_invoices_sort_issuedat_asc(client: TestClient) -> None:
    body = client.get("/ui/billing/invoices?sortby=issuedat&sortdir=asc").json()
    dates = [inv["issuedat"] for inv in body["invoices"]]
    assert dates == sorted(dates)


def test_billing_invoices_sort_total_desc(client: TestClient) -> None:
    body = client.get("/ui/billing/invoices?sortby=total&sortdir=desc").json()
    amounts = [inv["total"]["amountcents"] for inv in body["invoices"]]
    assert amounts == sorted(amounts, reverse=True)


# ---------------------------------------------------------------------------
# notes
# ---------------------------------------------------------------------------


def test_billing_invoices_notes_non_empty(client: TestClient) -> None:
    body = client.get("/ui/billing/invoices").json()
    assert len(body["notes"]) >= 1


def test_billing_invoices_notes_all_strings(client: TestClient) -> None:
    body = client.get("/ui/billing/invoices").json()
    for note in body["notes"]:
        assert isinstance(note, str)
        assert len(note) > 0
