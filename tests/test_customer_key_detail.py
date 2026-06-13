from __future__ import annotations

import os

os.environ.setdefault("IRONCLAW_PERSISTENCE_MODE", "memory")
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("IRONCLAW_API_KEY", "test-api-key")
os.environ.setdefault("AUTH_REQUIRED", "false")
os.environ.setdefault("IRONCLAW_RATE_LIMIT_ENABLED", "false")
os.environ.setdefault("SUPABASE_URL", "")
os.environ.setdefault("SUPABASE_SERVICE_ROLE_KEY", "")
os.environ.setdefault("SUPABASE_KEY", "")
os.environ.setdefault("SUPABASE_ANON_KEY", "")

from fastapi.testclient import TestClient
import pytest

from app.core.unit_wallet import TOKEN_CHUNK_SIZE
from app.main import app as _app
from app.ui.customer_key_detail import (
    _ORDERED_PACKAGE_IDS,
    _get_package_metadata,
    _token_coverage_metadata,
)

_TEST_KEY_ID = "test-customer-key-001"


@pytest.fixture()
def client():
    with TestClient(_app, raise_server_exceptions=True) as c:
        yield c


# ---------------------------------------------------------------------------
# _token_coverage_metadata
# ---------------------------------------------------------------------------


def test_token_coverage_metadata_has_tokens_in_wallet_key() -> None:
    result = _token_coverage_metadata(5_000)
    assert "tokens_in_wallet" in result
    assert "max_tokens_covered" not in result


def test_token_coverage_metadata_tokens_in_wallet_value_zero() -> None:
    result = _token_coverage_metadata(0)
    assert result["tokens_in_wallet"] == 0 * TOKEN_CHUNK_SIZE


def test_token_coverage_metadata_tokens_in_wallet_value_5000() -> None:
    result = _token_coverage_metadata(5_000)
    assert result["tokens_in_wallet"] == 5_000 * TOKEN_CHUNK_SIZE


def test_token_coverage_metadata_tokens_in_wallet_value_25000() -> None:
    result = _token_coverage_metadata(25_000)
    assert result["tokens_in_wallet"] == 25_000 * TOKEN_CHUNK_SIZE


def test_token_coverage_metadata_tokens_per_unit_equals_chunk_size() -> None:
    result = _token_coverage_metadata(100)
    assert result["tokens_per_unit"] == TOKEN_CHUNK_SIZE


def test_token_coverage_metadata_wallet_units_field() -> None:
    result = _token_coverage_metadata(42)
    assert result["wallet_units"] == 42


# ---------------------------------------------------------------------------
# _get_package_metadata
# ---------------------------------------------------------------------------


def test_get_package_metadata_pkg_5000_has_tokens_in_wallet() -> None:
    result = _get_package_metadata("pkg_5000")
    assert "tokens_in_wallet" in result
    assert "max_tokens_covered" not in result


def test_get_package_metadata_pkg_5000_tokens_in_wallet_value() -> None:
    result = _get_package_metadata("pkg_5000")
    assert result["tokens_in_wallet"] == 5_000 * TOKEN_CHUNK_SIZE


def test_get_package_metadata_pkg_25000_tokens_in_wallet_value() -> None:
    result = _get_package_metadata("pkg_25000")
    assert result["tokens_in_wallet"] == 25_000 * TOKEN_CHUNK_SIZE


def test_get_package_metadata_pkg_60000_tokens_in_wallet_value() -> None:
    result = _get_package_metadata("pkg_60000")
    assert result["tokens_in_wallet"] == 60_000 * TOKEN_CHUNK_SIZE


def test_get_package_metadata_tokens_in_wallet_formula_all_packages() -> None:
    for pkg_id in _ORDERED_PACKAGE_IDS:
        result = _get_package_metadata(pkg_id)
        included_units = result["included_units"]
        assert result["tokens_in_wallet"] == included_units * TOKEN_CHUNK_SIZE, f"{pkg_id}: tokens_in_wallet {result['tokens_in_wallet']} != {included_units * TOKEN_CHUNK_SIZE}"


def test_get_package_metadata_tokens_per_unit_equals_chunk_size_all_packages() -> None:
    for _pkg_id in _ORDERED_PACKAGE_IDS:
        result = _get_package_metadata("pkg_5000")
        assert result["tokens_per_unit"] == TOKEN_CHUNK_SIZE


def test_get_package_metadata_unknown_returns_empty_dict() -> None:
    result = _get_package_metadata("pkg_unknown_xyz")
    assert result == {}


def test_get_package_metadata_pkg_5000_included_units() -> None:
    result = _get_package_metadata("pkg_5000")
    assert result["included_units"] == 5_000


def test_get_package_metadata_pkg_25000_included_units() -> None:
    result = _get_package_metadata("pkg_25000")
    assert result["included_units"] == 25_000


def test_get_package_metadata_pkg_60000_included_units() -> None:
    result = _get_package_metadata("pkg_60000")
    assert result["included_units"] == 60_000


# ---------------------------------------------------------------------------
# GET /ui/customer-keys/detail/{key_id} — fallback path (Supabase unavailable)
# ---------------------------------------------------------------------------


def test_get_customer_key_detail_returns_200(client: TestClient) -> None:
    resp = client.get(f"/ui/customer-keys/detail/{_TEST_KEY_ID}")
    assert resp.status_code == 200


def test_get_customer_key_detail_status_is_ok(client: TestClient) -> None:
    resp = client.get(f"/ui/customer-keys/detail/{_TEST_KEY_ID}")
    assert resp.json()["status"] == "ok"


def test_get_customer_key_detail_key_status_is_active(client: TestClient) -> None:
    resp = client.get(f"/ui/customer-keys/detail/{_TEST_KEY_ID}")
    assert resp.json()["key_status"] == "active"


def test_get_customer_key_detail_owner_id_is_default_customer(client: TestClient) -> None:
    resp = client.get(f"/ui/customer-keys/detail/{_TEST_KEY_ID}")
    assert resp.json()["owner"]["owner_id"] == "default-customer"


def test_get_customer_key_detail_billing_token_coverage_has_tokens_in_wallet(client: TestClient) -> None:
    resp = client.get(f"/ui/customer-keys/detail/{_TEST_KEY_ID}")
    billing = resp.json()["billing"]
    assert "tokens_in_wallet" in billing["token_coverage"]
    assert "max_tokens_covered" not in billing["token_coverage"]


def test_get_customer_key_detail_billing_token_coverage_tokens_in_wallet_is_zero(client: TestClient) -> None:
    resp = client.get(f"/ui/customer-keys/detail/{_TEST_KEY_ID}")
    billing = resp.json()["billing"]
    assert billing["token_coverage"]["tokens_in_wallet"] == 0


def test_get_customer_key_detail_billing_package_has_tokens_in_wallet(client: TestClient) -> None:
    resp = client.get(f"/ui/customer-keys/detail/{_TEST_KEY_ID}")
    billing = resp.json()["billing"]
    assert "tokens_in_wallet" in billing["package"]
    assert "max_tokens_covered" not in billing["package"]


def test_get_customer_key_detail_billing_package_tokens_in_wallet_value(client: TestClient) -> None:
    resp = client.get(f"/ui/customer-keys/detail/{_TEST_KEY_ID}")
    billing = resp.json()["billing"]
    pkg_included_units = billing["package"]["included_units"]
    assert billing["package"]["tokens_in_wallet"] == pkg_included_units * TOKEN_CHUNK_SIZE


def test_get_customer_key_detail_units_required_example_is_two(client: TestClient) -> None:
    resp = client.get(f"/ui/customer-keys/detail/{_TEST_KEY_ID}")
    example = resp.json()["billing"]["units_required_example"]
    assert example["token_count"] == 50_000
    assert example["units_required"] == 2


def test_get_customer_key_detail_response_shape_complete(client: TestClient) -> None:
    resp = client.get(f"/ui/customer-keys/detail/{_TEST_KEY_ID}")
    body = resp.json()
    for field in ("status", "service", "timestamp", "key_id", "label", "key_status", "masked_key", "created_at", "owner", "usage", "policy", "billing", "actions", "notes"):
        assert field in body, f"response missing field: {field!r}"


def test_get_customer_key_detail_key_id_echoed(client: TestClient) -> None:
    resp = client.get(f"/ui/customer-keys/detail/{_TEST_KEY_ID}")
    assert resp.json()["key_id"] == _TEST_KEY_ID


def test_get_customer_key_detail_service_is_ironclaw(client: TestClient) -> None:
    resp = client.get(f"/ui/customer-keys/detail/{_TEST_KEY_ID}")
    assert resp.json()["service"] == "IronClaw-Security"


def test_get_customer_key_detail_owner_shape(client: TestClient) -> None:
    resp = client.get(f"/ui/customer-keys/detail/{_TEST_KEY_ID}")
    owner = resp.json()["owner"]
    for field in ("owner_type", "owner_id", "owner_display_name", "metadata"):
        assert field in owner, f"owner missing field: {field!r}"


def test_get_customer_key_detail_usage_shape(client: TestClient) -> None:
    resp = client.get(f"/ui/customer-keys/detail/{_TEST_KEY_ID}")
    usage = resp.json()["usage"]
    for field in ("total_requests", "total_scans", "total_blocks", "total_warnings"):
        assert field in usage, f"usage missing field: {field!r}"


def test_get_customer_key_detail_policy_shape(client: TestClient) -> None:
    resp = client.get(f"/ui/customer-keys/detail/{_TEST_KEY_ID}")
    policy = resp.json()["policy"]
    for field in ("scopes", "environment", "rotation_due", "revocable"):
        assert field in policy, f"policy missing field: {field!r}"


def test_get_customer_key_detail_actions_non_empty(client: TestClient) -> None:
    resp = client.get(f"/ui/customer-keys/detail/{_TEST_KEY_ID}")
    assert len(resp.json()["actions"]) >= 1


def test_get_customer_key_detail_billing_wallet_units_is_zero(client: TestClient) -> None:
    resp = client.get(f"/ui/customer-keys/detail/{_TEST_KEY_ID}")
    assert resp.json()["billing"]["wallet_units"] == 0


def test_get_customer_key_detail_billing_packages_catalog_has_all_packages(client: TestClient) -> None:
    resp = client.get(f"/ui/customer-keys/detail/{_TEST_KEY_ID}")
    catalog = resp.json()["billing"]["packages_catalog"]
    for pkg_id in _ORDERED_PACKAGE_IDS:
        assert pkg_id in catalog, f"packages_catalog missing {pkg_id!r}"


def test_get_customer_key_detail_notes_non_empty(client: TestClient) -> None:
    resp = client.get(f"/ui/customer-keys/detail/{_TEST_KEY_ID}")
    assert len(resp.json()["notes"]) >= 1


def test_get_customer_key_detail_masked_key_present(client: TestClient) -> None:
    resp = client.get(f"/ui/customer-keys/detail/{_TEST_KEY_ID}")
    assert resp.json()["masked_key"] != ""


def test_get_customer_key_detail_idempotent_on_repeated_calls(client: TestClient) -> None:
    r1 = client.get(f"/ui/customer-keys/detail/{_TEST_KEY_ID}")
    r2 = client.get(f"/ui/customer-keys/detail/{_TEST_KEY_ID}")
    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r1.json()["key_id"] == r2.json()["key_id"]
    assert r1.json()["owner"]["owner_id"] == r2.json()["owner"]["owner_id"]
