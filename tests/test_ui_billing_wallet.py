from __future__ import annotations

from fastapi.testclient import TestClient

_WALLET_URL = "/billing-wallet"
_PURCHASE_URL = "/billing-purchase"
_OWNER_KEY = "test-owner-wallet-001"


def test_billing_wallet_returns_200(test_client: TestClient) -> None:
    response = test_client.get(_WALLET_URL, params={"owner_key": _OWNER_KEY})
    assert response.status_code == 200


def test_billing_wallet_content_type_json(test_client: TestClient) -> None:
    response = test_client.get(_WALLET_URL, params={"owner_key": _OWNER_KEY})
    assert response.status_code == 200
    assert "application/json" in response.headers["content-type"]


def test_billing_wallet_top_level_fields(test_client: TestClient) -> None:
    response = test_client.get(_WALLET_URL, params={"owner_key": _OWNER_KEY})
    assert response.status_code == 200
    body = response.json()

    assert body["status"] == "ok"
    assert body["service"] == "IronClaw-Security"
    assert isinstance(body["timestamp"], str)
    assert body["timestamp"].endswith("Z")


def test_billing_wallet_shape(test_client: TestClient) -> None:
    response = test_client.get(_WALLET_URL, params={"owner_key": _OWNER_KEY})
    assert response.status_code == 200
    body = response.json()

    assert "wallet" in body
    assert "summary" in body
    assert "recent_entries" in body
    assert "notes" in body


def test_billing_wallet_balance_view_fields(test_client: TestClient) -> None:
    response = test_client.get(_WALLET_URL, params={"owner_key": _OWNER_KEY})
    assert response.status_code == 200
    wallet = response.json()["wallet"]

    assert isinstance(wallet["wallet_id"], str)
    assert len(wallet["wallet_id"]) > 0
    assert isinstance(wallet["owner_key"], str)
    assert wallet["owner_key"] == _OWNER_KEY
    assert isinstance(wallet["balance_units"], int)
    assert isinstance(wallet["total_purchased_units"], int)
    assert isinstance(wallet["total_consumed_units"], int)
    assert isinstance(wallet["updated_at"], str)
    assert wallet["updated_at"].endswith("Z")
    assert isinstance(wallet["metadata"], dict)


def test_billing_wallet_balance_units_non_negative(test_client: TestClient) -> None:
    response = test_client.get(_WALLET_URL, params={"owner_key": _OWNER_KEY})
    assert response.status_code == 200
    wallet = response.json()["wallet"]

    assert wallet["balance_units"] >= 0
    assert wallet["total_purchased_units"] >= 0
    assert wallet["total_consumed_units"] >= 0


def test_billing_wallet_summary_fields(test_client: TestClient) -> None:
    response = test_client.get(_WALLET_URL, params={"owner_key": _OWNER_KEY})
    assert response.status_code == 200
    summary = response.json()["summary"]

    assert isinstance(summary["owner_key"], str)
    assert summary["owner_key"] == _OWNER_KEY
    assert isinstance(summary["has_activity"], bool)
    assert isinstance(summary["ledger_entry_count"], int)
    assert summary["ledger_entry_count"] >= 0


def test_billing_wallet_summary_latest_entry_none_on_fresh_wallet(
    test_client: TestClient,
) -> None:
    response = test_client.get(_WALLET_URL, params={"owner_key": "test-owner-fresh-wallet-x99"})
    assert response.status_code == 200
    summary = response.json()["summary"]

    assert summary["has_activity"] is False
    assert summary["ledger_entry_count"] == 0
    assert summary["latest_entry_type"] is None
    assert summary["latest_entry_at"] is None


def test_billing_wallet_recent_entries_is_list(test_client: TestClient) -> None:
    response = test_client.get(_WALLET_URL, params={"owner_key": _OWNER_KEY})
    assert response.status_code == 200
    recent_entries = response.json()["recent_entries"]

    assert isinstance(recent_entries, list)


def test_billing_wallet_recent_entries_shape_when_present(
    test_client: TestClient,
) -> None:
    response = test_client.get(_WALLET_URL, params={"owner_key": _OWNER_KEY})
    assert response.status_code == 200
    recent_entries = response.json()["recent_entries"]

    for entry in recent_entries:
        assert isinstance(entry["entry_id"], str)
        assert len(entry["entry_id"]) > 0
        assert isinstance(entry["entry_type"], str)
        assert len(entry["entry_type"]) > 0
        assert isinstance(entry["units"], int)
        assert isinstance(entry["balance_after"], int)
        assert isinstance(entry["created_at"], str)
        assert entry["created_at"].endswith("Z")
        assert isinstance(entry["metadata"], dict)


def test_billing_wallet_recent_entries_limit_default(test_client: TestClient) -> None:
    response = test_client.get(_WALLET_URL, params={"owner_key": _OWNER_KEY})
    assert response.status_code == 200
    recent_entries = response.json()["recent_entries"]

    assert len(recent_entries) <= 5


def test_billing_wallet_recent_entries_custom_limit(test_client: TestClient) -> None:
    response = test_client.get(_WALLET_URL, params={"owner_key": _OWNER_KEY, "limit": 3})
    assert response.status_code == 200
    recent_entries = response.json()["recent_entries"]

    assert len(recent_entries) <= 3


def test_billing_wallet_notes_present(test_client: TestClient) -> None:
    response = test_client.get(_WALLET_URL, params={"owner_key": _OWNER_KEY})
    assert response.status_code == 200
    notes = response.json()["notes"]

    assert isinstance(notes, list)
    assert len(notes) >= 1
    for note in notes:
        assert isinstance(note, str)


def test_billing_wallet_owner_key_normalized_to_lowercase(
    test_client: TestClient,
) -> None:
    response = test_client.get(_WALLET_URL, params={"owner_key": "Test-Owner-WALLET-NormCheck-001"})
    assert response.status_code == 200
    body = response.json()

    assert body["wallet"]["owner_key"] == "test-owner-wallet-normcheck-001"
    assert body["summary"]["owner_key"] == "test-owner-wallet-normcheck-001"


def test_billing_wallet_missing_owner_key_returns_422(test_client: TestClient) -> None:
    response = test_client.get(_WALLET_URL)
    assert response.status_code == 422


def test_billing_wallet_empty_owner_key_returns_422(test_client: TestClient) -> None:
    response = test_client.get(_WALLET_URL, params={"owner_key": ""})
    assert response.status_code == 422


def test_billing_wallet_limit_below_minimum_returns_422(
    test_client: TestClient,
) -> None:
    response = test_client.get(_WALLET_URL, params={"owner_key": _OWNER_KEY, "limit": 0})
    assert response.status_code == 422


def test_billing_wallet_limit_above_maximum_returns_422(
    test_client: TestClient,
) -> None:
    response = test_client.get(_WALLET_URL, params={"owner_key": _OWNER_KEY, "limit": 21})
    assert response.status_code == 422


def test_billing_wallet_distinct_owners_have_separate_wallets(
    test_client: TestClient,
) -> None:
    r1 = test_client.get(_WALLET_URL, params={"owner_key": "test-owner-wallet-alpha"})
    r2 = test_client.get(_WALLET_URL, params={"owner_key": "test-owner-wallet-beta"})
    assert r1.status_code == 200
    assert r2.status_code == 200

    w1 = r1.json()["wallet"]
    w2 = r2.json()["wallet"]
    assert w1["wallet_id"] != w2["wallet_id"]
    assert w1["owner_key"] != w2["owner_key"]


def test_billing_wallet_idempotent_for_same_owner(test_client: TestClient) -> None:
    r1 = test_client.get(_WALLET_URL, params={"owner_key": "test-owner-idem-001"})
    r2 = test_client.get(_WALLET_URL, params={"owner_key": "test-owner-idem-001"})
    assert r1.status_code == 200
    assert r2.status_code == 200

    w1 = r1.json()["wallet"]
    w2 = r2.json()["wallet"]
    assert w1["wallet_id"] == w2["wallet_id"]
    assert w1["owner_key"] == w2["owner_key"]


def test_billing_purchase_returns_200(test_client: TestClient) -> None:
    response = test_client.post(
        _PURCHASE_URL,
        json={
            "owner_key": _OWNER_KEY,
            "units": 10000,
            "source": "manual_purchase",
        },
    )
    assert response.status_code == 201


def test_billing_purchase_ledger_shape(test_client: TestClient) -> None:
    response = test_client.post(
        _PURCHASE_URL,
        json={
            "owner_key": _OWNER_KEY,
            "units": 10000,
            "source": "manual_purchase",
        },
    )
    assert response.status_code == 201
    body = response.json()

    assert body["status"] == "ok"
    assert "ledger_entry" in body
    entry = body["ledger_entry"]
    assert isinstance(entry["entry_id"], str)
    assert entry["entry_type"] == "credit"
    assert isinstance(entry["units"], int)
    assert entry["units"] > 0
    assert isinstance(entry["balance_after"], int)
    assert isinstance(entry["created_at"], str)
    assert entry["created_at"].endswith("Z")
