from __future__ import annotations

from typing import Any
from unittest.mock import patch

from fastapi.testclient import TestClient
import pytest

from app.core.unit_wallet import TOKEN_CHUNK_SIZE
from app.ui.usage_event_detail import (
    _FEATURED_PACKAGE_ID,
    _ORDERED_PACKAGE_IDS,
    _TOKENS_PER_UNIT,
    UsageEventDetailResponse,
    _coerce_bool,
    _coerce_int,
    _package_catalog_metadata,
    _package_snapshot,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_DETAIL_BASE = "/usage-events/detail"


def _get_detail(client: TestClient, event_id: str) -> Any:
    return client.get(f"{_DETAIL_BASE}/{event_id}")


# ---------------------------------------------------------------------------
# Fallback path — Supabase unavailable (conftest baseline: SUPABASE_URL="")
# ---------------------------------------------------------------------------


class TestFallbackPath:
    @pytest.fixture(autouse=True)
    def _client(self, test_client: TestClient) -> None:
        self.client = test_client

    def test_returns_http_200(self) -> None:
        resp = _get_detail(self.client, "evt-fallback-001")
        assert resp.status_code == 200

    def test_status_is_ok(self) -> None:
        resp = _get_detail(self.client, "evt-fallback-001")
        assert resp.json()["status"] == "ok"

    def test_identity_event_id_matches_path_param(self) -> None:
        event_id = "evt-path-check-99"
        resp = _get_detail(self.client, event_id)
        assert resp.json()["identity"]["event_id"] == event_id

    def test_guard_verdict_is_allow(self) -> None:
        resp = _get_detail(self.client, "evt-fallback-002")
        assert resp.json()["guard"]["verdict"] == "allow"

    def test_guard_blocked_is_false(self) -> None:
        resp = _get_detail(self.client, "evt-fallback-003")
        assert resp.json()["guard"]["blocked"] is False

    def test_billing_metadata_billing_state_is_not_charged(self) -> None:
        resp = _get_detail(self.client, "evt-fallback-004")
        meta = resp.json()["billing"]["metadata"]
        assert meta["billing_state"] == "not-charged"

    def test_billing_metadata_tokens_per_unit_equals_token_chunk_size(self) -> None:
        resp = _get_detail(self.client, "evt-fallback-005")
        meta = resp.json()["billing"]["metadata"]
        assert meta["tokens_per_unit"] == TOKEN_CHUNK_SIZE

    def test_billing_metadata_computed_units_for_tokens_is_zero(self) -> None:
        resp = _get_detail(self.client, "evt-fallback-006")
        meta = resp.json()["billing"]["metadata"]
        assert meta["computed_units_for_tokens"] == 0

    def test_billing_metadata_description_contains_25000_formatted(self) -> None:
        resp = _get_detail(self.client, "evt-fallback-007")
        meta = resp.json()["billing"]["metadata"]
        assert "25,000" in meta["description"]

    def test_billing_metadata_description_does_not_use_hardcoded_literal(self) -> None:
        # _TOKENS_PER_UNIT must equal TOKEN_CHUNK_SIZE — not a diverged literal
        assert _TOKENS_PER_UNIT == TOKEN_CHUNK_SIZE

    def test_links_is_a_list(self) -> None:
        resp = _get_detail(self.client, "evt-fallback-008")
        assert isinstance(resp.json()["links"], list)

    def test_links_has_at_least_one_entry(self) -> None:
        resp = _get_detail(self.client, "evt-fallback-008")
        assert len(resp.json()["links"]) >= 1

    def test_notes_is_a_list(self) -> None:
        resp = _get_detail(self.client, "evt-fallback-009")
        assert isinstance(resp.json()["notes"], list)

    def test_notes_has_at_least_one_entry(self) -> None:
        resp = _get_detail(self.client, "evt-fallback-009")
        assert len(resp.json()["notes"]) >= 1

    def test_identity_source_is_fallback(self) -> None:
        resp = _get_detail(self.client, "evt-fallback-010")
        identity_meta = resp.json()["identity"]["metadata"]
        assert identity_meta["source"] == "fallback"

    def test_billing_units_consumed_is_zero(self) -> None:
        resp = _get_detail(self.client, "evt-fallback-011")
        assert resp.json()["billing"]["units_consumed"] == 0

    def test_response_has_timestamp(self) -> None:
        resp = _get_detail(self.client, "evt-fallback-012")
        body = resp.json()
        assert "timestamp" in body
        assert len(body["timestamp"]) > 0

    def test_response_has_service(self) -> None:
        resp = _get_detail(self.client, "evt-fallback-013")
        assert resp.json()["service"] == "IronClaw-Security"


# ---------------------------------------------------------------------------
# _package_snapshot
# ---------------------------------------------------------------------------


class TestPackageSnapshot:
    def test_pkg_5000_included_units(self) -> None:
        snap = _package_snapshot("pkg_5000")
        assert snap["included_units"] == 5_000

    def test_pkg_5000_tokens_per_unit_equals_token_chunk_size(self) -> None:
        snap = _package_snapshot("pkg_5000")
        assert snap["metadata"]["tokens_per_unit"] == TOKEN_CHUNK_SIZE

    def test_pkg_5000_featured_is_false(self) -> None:
        snap = _package_snapshot("pkg_5000")
        assert snap["featured"] is False

    def test_pkg_25000_featured_is_true(self) -> None:
        snap = _package_snapshot("pkg_25000")
        assert snap["featured"] is True

    def test_pkg_60000_featured_is_false(self) -> None:
        snap = _package_snapshot("pkg_60000")
        assert snap["featured"] is False

    def test_none_resolves_to_featured_package(self) -> None:
        snap = _package_snapshot(None)
        assert snap["package_id"] == _FEATURED_PACKAGE_ID

    def test_invalid_id_resolves_to_featured_package(self) -> None:
        snap = _package_snapshot("invalid_id")
        assert snap["package_id"] == _FEATURED_PACKAGE_ID

    def test_invalid_id_resolves_to_pkg_25000(self) -> None:
        snap = _package_snapshot("totally_wrong")
        assert snap["package_id"] == "pkg_25000"

    def test_pkg_25000_included_units(self) -> None:
        snap = _package_snapshot("pkg_25000")
        assert snap["included_units"] == 25_000

    def test_pkg_60000_included_units(self) -> None:
        snap = _package_snapshot("pkg_60000")
        assert snap["included_units"] == 60_000

    def test_snapshot_has_required_keys(self) -> None:
        snap = _package_snapshot("pkg_5000")
        for key in ("package_id", "name", "description", "display_label", "price_usd", "included_units", "featured", "metadata"):
            assert key in snap

    def test_snapshot_metadata_has_tokens_per_unit(self) -> None:
        for pkg_id in _ORDERED_PACKAGE_IDS:
            snap = _package_snapshot(pkg_id)
            assert "tokens_per_unit" in snap["metadata"]

    def test_featured_package_id_constant_is_pkg_25000(self) -> None:
        assert _FEATURED_PACKAGE_ID == "pkg_25000"

    def test_tokens_per_unit_equals_token_chunk_size(self) -> None:
        assert _TOKENS_PER_UNIT == TOKEN_CHUNK_SIZE


# ---------------------------------------------------------------------------
# _package_catalog_metadata
# ---------------------------------------------------------------------------


class TestPackageCatalogMetadata:
    def test_all_three_package_ids_present(self) -> None:
        catalog = _package_catalog_metadata()
        assert set(catalog["packages"].keys()) == {"pkg_5000", "pkg_25000", "pkg_60000"}

    def test_featured_package_id_is_pkg_25000(self) -> None:
        catalog = _package_catalog_metadata()
        assert catalog["featured_package_id"] == "pkg_25000"

    def test_ordered_package_ids_present(self) -> None:
        catalog = _package_catalog_metadata()
        assert "ordered_package_ids" in catalog
        assert catalog["ordered_package_ids"] == list(_ORDERED_PACKAGE_IDS)

    def test_packages_field_is_dict(self) -> None:
        catalog = _package_catalog_metadata()
        assert isinstance(catalog["packages"], dict)

    def test_each_package_has_included_units(self) -> None:
        catalog = _package_catalog_metadata()
        for pkg_id, snap in catalog["packages"].items():
            assert "included_units" in snap, f"missing included_units in {pkg_id}"

    def test_each_package_featured_flag_correct(self) -> None:
        catalog = _package_catalog_metadata()
        for pkg_id, snap in catalog["packages"].items():
            expected = pkg_id == _FEATURED_PACKAGE_ID
            assert snap["featured"] == expected


# ---------------------------------------------------------------------------
# _coerce_int
# ---------------------------------------------------------------------------


class TestCoerceInt:
    def test_none_returns_default(self) -> None:
        assert _coerce_int(None, default=5) == 5

    def test_negative_returns_zero(self) -> None:
        assert _coerce_int(-10) == 0

    def test_non_numeric_string_returns_zero(self) -> None:
        assert _coerce_int("abc") == 0

    def test_positive_int_passthrough(self) -> None:
        assert _coerce_int(42) == 42

    def test_zero_returns_zero(self) -> None:
        assert _coerce_int(0) == 0

    def test_numeric_string_coerced(self) -> None:
        assert _coerce_int("7") == 7

    def test_negative_string_returns_zero(self) -> None:
        assert _coerce_int("-5") == 0

    def test_float_coerced_to_int(self) -> None:
        assert _coerce_int(3.9) == 3

    def test_none_default_zero(self) -> None:
        assert _coerce_int(None) == 0

    def test_none_default_custom(self) -> None:
        assert _coerce_int(None, default=99) == 99


# ---------------------------------------------------------------------------
# _coerce_bool
# ---------------------------------------------------------------------------


class TestCoerceBool:
    def test_blocked_returns_true(self) -> None:
        assert _coerce_bool("blocked") is True

    def test_allow_returns_false(self) -> None:
        assert _coerce_bool("allow") is False

    def test_none_returns_false(self) -> None:
        assert _coerce_bool(None) is False

    def test_true_string_returns_true(self) -> None:
        assert _coerce_bool("true") is True

    def test_false_string_returns_false(self) -> None:
        assert _coerce_bool("false") is False

    def test_bool_true_passthrough(self) -> None:
        assert _coerce_bool(True) is True

    def test_bool_false_passthrough(self) -> None:
        assert _coerce_bool(False) is False

    def test_one_string_returns_true(self) -> None:
        assert _coerce_bool("1") is True

    def test_zero_string_returns_false(self) -> None:
        assert _coerce_bool("0") is False

    def test_truncated_returns_true(self) -> None:
        assert _coerce_bool("truncated") is True

    def test_int_nonzero_returns_true(self) -> None:
        assert _coerce_bool(1) is True

    def test_int_zero_returns_false(self) -> None:
        assert _coerce_bool(0) is False

    def test_unknown_string_returns_default_false(self) -> None:
        assert _coerce_bool("unknown_value") is False

    def test_unknown_string_returns_custom_default(self) -> None:
        assert _coerce_bool("unknown_value", default=True) is True


# ---------------------------------------------------------------------------
# Supabase mocked — verdict="block", units_used=2
# ---------------------------------------------------------------------------


class TestSupabaseMockedPath:
    """
    Patches _fetch_security_event and _fetch_user_by_id at the module level
    to simulate a valid security_events row with verdict='block', units_used=2.
    Supabase is still "unconfigured" via conftest env, so we bypass
    _SUPABASE_AVAILABLE by patching the private fetch functions directly.
    """

    _EVENT_ROW: dict[str, Any] = {
        "id": "evt-sb-001",
        "user_id": "user-mock-001",
        "verdict": "block",
        "units_used": 2,
        "platform": "test-session",
        "timestamp": "2026-06-12T00:00:00Z",
    }

    _USER_ROW: dict[str, Any] = {
        "id": "user-mock-001",
        "email": "test@ironclaw.dev",
        "wallet_units": 50,
        "has_paid": True,
        "last_payment": {"package_id": "pkg_25000"},
        "user_token": "tok-abc",
    }

    @pytest.fixture(autouse=True)
    def _patch_fetch(self, test_client: TestClient) -> None:
        self.client = test_client
        with (
            patch(
                "app.ui.usage_event_detail._fetch_security_event",
                return_value=self._EVENT_ROW,
            ),
            patch(
                "app.ui.usage_event_detail._fetch_user_by_id",
                return_value=self._USER_ROW,
            ),
        ):
            resp = _get_detail(self.client, "evt-sb-001")
            self.body = resp.json()
            self.resp = resp

    def test_status_200(self) -> None:
        assert self.resp.status_code == 200

    def test_guard_blocked_is_true(self) -> None:
        assert self.body["guard"]["blocked"] is True

    def test_guard_verdict_is_block(self) -> None:
        assert self.body["guard"]["verdict"] == "block"

    def test_billing_units_consumed_is_two(self) -> None:
        assert self.body["billing"]["units_consumed"] == 2

    def test_billing_metadata_billing_state_is_charged(self) -> None:
        assert self.body["billing"]["metadata"]["billing_state"] == "charged"

    def test_identity_source_is_supabase(self) -> None:
        assert self.body["identity"]["metadata"]["source"] == "supabase"

    def test_identity_event_id_matches(self) -> None:
        assert self.body["identity"]["event_id"] == "evt-sb-001"

    def test_billing_package_id_is_pkg_25000(self) -> None:
        assert self.body["billing"]["package_id"] == "pkg_25000"

    def test_links_list_present(self) -> None:
        assert isinstance(self.body["links"], list)
        assert len(self.body["links"]) >= 1

    def test_notes_list_present(self) -> None:
        assert isinstance(self.body["notes"], list)
        assert len(self.body["notes"]) >= 1


# ---------------------------------------------------------------------------
# Response shape validates against UsageEventDetailResponse
# ---------------------------------------------------------------------------


class TestResponseShape:
    @pytest.fixture(autouse=True)
    def _client(self, test_client: TestClient) -> None:
        self.client = test_client

    def test_all_top_level_fields_present(self) -> None:
        resp = _get_detail(self.client, "evt-shape-001")
        body = resp.json()
        required_fields = {"status", "service", "timestamp", "identity", "guard", "billing", "context", "links", "notes"}
        assert required_fields.issubset(set(body.keys()))

    def test_identity_required_fields(self) -> None:
        resp = _get_detail(self.client, "evt-shape-002")
        identity = resp.json()["identity"]
        assert "event_id" in identity
        assert "metadata" in identity

    def test_guard_required_fields(self) -> None:
        resp = _get_detail(self.client, "evt-shape-003")
        guard = resp.json()["guard"]
        for field in ("verdict", "guard_mode", "policy_profile", "blocked", "truncated", "metadata"):
            assert field in guard

    def test_billing_required_fields(self) -> None:
        resp = _get_detail(self.client, "evt-shape-004")
        billing = resp.json()["billing"]
        for field in ("units_consumed", "unit_type", "metadata"):
            assert field in billing

    def test_context_required_fields(self) -> None:
        resp = _get_detail(self.client, "evt-shape-005")
        context = resp.json()["context"]
        for field in ("method", "path", "metadata"):
            assert field in context

    def test_links_entries_have_required_fields(self) -> None:
        resp = _get_detail(self.client, "evt-shape-006")
        links = resp.json()["links"]
        assert len(links) >= 1
        for link in links:
            assert "label" in link
            assert "path" in link
            assert "description" in link

    def test_notes_are_non_empty_strings(self) -> None:
        resp = _get_detail(self.client, "evt-shape-007")
        notes = resp.json()["notes"]
        assert len(notes) >= 1
        for note in notes:
            assert isinstance(note, str)
            assert len(note) > 0

    def test_response_validates_pydantic_model(self) -> None:
        resp = _get_detail(self.client, "evt-shape-008")
        body = resp.json()
        model = UsageEventDetailResponse.model_validate(body)
        assert model.status == "ok"
        assert len(model.notes) >= 1
        assert len(model.links) >= 1

    def test_billing_metadata_tokens_per_unit_present(self) -> None:
        resp = _get_detail(self.client, "evt-shape-009")
        meta = resp.json()["billing"]["metadata"]
        assert "tokens_per_unit" in meta
        assert meta["tokens_per_unit"] == TOKEN_CHUNK_SIZE

    def test_billing_metadata_catalog_contains_packages(self) -> None:
        resp = _get_detail(self.client, "evt-shape-010")
        catalog = resp.json()["billing"]["metadata"]["catalog"]
        assert "packages" in catalog
        assert set(catalog["packages"].keys()) == {"pkg_5000", "pkg_25000", "pkg_60000"}

    def test_billing_metadata_catalog_featured_package_id(self) -> None:
        resp = _get_detail(self.client, "evt-shape-011")
        catalog = resp.json()["billing"]["metadata"]["catalog"]
        assert catalog["featured_package_id"] == "pkg_25000"
