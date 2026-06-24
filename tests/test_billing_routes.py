from __future__ import annotations

import concurrent.futures
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.billing import (
    router as billing_router,
)
from app.core.auth import (
    AuthContext,
    get_auth_context,
    require_api_key,
    require_auth_context,
)
from app.core.install_keys import (
    InstallKeyAlreadyExistsError,
    InstallKeyRecord,
)
from app.core.unit_wallet import (
    UNIT_PACKAGE_CATALOG,
    get_unit_wallet_registry,
)

# ---------------------------------------------------------------------------
# Expected package IDs
# ---------------------------------------------------------------------------

_PKG_5K = "pkg_5000"
_PKG_25K = "pkg_25000"
_PKG_60K = "pkg_60000"
_ALL_PKG_IDS = {_PKG_5K, _PKG_25K, _PKG_60K}

assert _ALL_PKG_IDS <= set(UNIT_PACKAGE_CATALOG.keys()), f"UNIT_PACKAGE_CATALOG is missing expected packages: {_ALL_PKG_IDS - set(UNIT_PACKAGE_CATALOG.keys())}"

# ---------------------------------------------------------------------------
# App factory helpers
# ---------------------------------------------------------------------------

_PERSONAL_API_KEY = "test-personal-key"
_ORG_API_KEY = "test-org-key"
_ORG_ID = "testorg001"
_ORG_OWNER_KEY = f"ic_org_{_ORG_ID}"

_PERSONAL_AUTH_CTX = AuthContext(
    api_key=_PERSONAL_API_KEY,
    principal_type="api_key",
    principal_id=None,
    session_id=None,
    org_id=None,
    authenticated=True,
    auth_source="test",
    auth_method="api_key",
    key_type="personal",
)

_ORG_AUTH_CTX = AuthContext(
    api_key=_ORG_API_KEY,
    principal_type="org_key",
    principal_id=None,
    session_id=None,
    org_id=_ORG_ID,
    authenticated=True,
    auth_source="test",
    auth_method="api_key",
    key_type="org",
)


def _build_app(*, auth_ctx: AuthContext | None = None) -> FastAPI:
    app = FastAPI()
    app.state.settings = SimpleNamespace(
        auth_required=True,
        api_key=_PERSONAL_API_KEY,
        admin_api_key=None,
    )
    app.include_router(billing_router)
    if auth_ctx is not None:
        app.dependency_overrides[require_api_key] = lambda: auth_ctx.api_key
        app.dependency_overrides[get_auth_context] = lambda: auth_ctx
        app.dependency_overrides[require_auth_context] = lambda: auth_ctx
    return app


def _personal_client() -> TestClient:
    return TestClient(_build_app(auth_ctx=_PERSONAL_AUTH_CTX))


def _org_client() -> TestClient:
    return TestClient(_build_app(auth_ctx=_ORG_AUTH_CTX))


def _unauthed_client() -> TestClient:
    return TestClient(_build_app(), raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# Install key mock factory
# ---------------------------------------------------------------------------


def _make_mock_install_key_record(
    program: str,
    owner_key: str,
    purchase_id: str,
    raw_key: str,
) -> InstallKeyRecord:
    from datetime import UTC, datetime

    return InstallKeyRecord(
        key_id=f"ik_test_{program}",
        owner_key=owner_key,
        subscription_id=purchase_id,
        program=program,  # type: ignore[arg-type]
        raw_key=raw_key,
        raw_key_hash="fakehash",
        masked_key=f"{raw_key[:10]}...",
        label=f"auto-provisioned on purchase {purchase_id}",
        active=True,
        units_consumed=0,
        created_at=datetime.now(UTC),
        metadata={"purchase_id": purchase_id, "auto_provisioned": True},
    )


# ---------------------------------------------------------------------------
# GET /billing/packages
# ---------------------------------------------------------------------------


def test_list_packages_returns_200_with_all_three_packages() -> None:
    response = _personal_client().get("/billing/packages")
    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "ok"
    assert data["service"] in {"ironclaw-billing", "IronClaw-Security"}
    assert "timestamp" in data

    returned_ids = {p["package_id"] for p in data["packages"]}
    assert returned_ids == _ALL_PKG_IDS, f"Expected packages {_ALL_PKG_IDS}, got {returned_ids}"

    for pkg in data["packages"]:
        assert pkg["included_units"] > 0
        assert pkg["price_usd"] > 0
        assert pkg["tokens_per_unit"] > 0
        assert pkg["token_coverage"] > 0
        assert isinstance(pkg["description"], str)

    policy = data["unit_policy"]
    assert isinstance(policy["unit_definition"], str)
    assert isinstance(policy["delivery_model"], str)
    assert isinstance(policy["buyer_positioning"], str)
    assert policy["token_chunk_size"] > 0
    assert isinstance(policy["protection_layers"], list)
    assert len(policy["protection_layers"]) > 0
    assert isinstance(policy["market_context"], list)
    assert len(policy["market_context"]) > 0


def test_list_packages_returns_401_unauthenticated() -> None:
    response = _unauthed_client().get("/billing/packages")
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# POST /billing/packages/purchase — install key provisioning
# ---------------------------------------------------------------------------


def test_purchase_provisions_both_install_keys_on_success() -> None:
    buyer_email = "installkey-happy@ironclaw.test"
    purchase_id_seen: list[str] = []

    openclaw_raw = "ic_install_openclaw_TESTKEY00000000001"
    claude_raw = "ic_install_claude_code_TESTKEY0000000001"

    def _fake_generate(owner_key: str, subscription_id: str, program: str, **kwargs: object) -> InstallKeyRecord:
        purchase_id_seen.append(subscription_id)
        raw = openclaw_raw if program == "openclaw" else claude_raw
        return _make_mock_install_key_record(program, owner_key, subscription_id, raw)

    mock_registry = MagicMock()
    mock_registry.generate_install_key.side_effect = _fake_generate

    with patch("app.api.billing.get_install_key_registry", return_value=mock_registry):
        response = _personal_client().post(
            "/billing/packages/purchase",
            json={
                "package_id": _PKG_5K,
                "buyer_name": "Install Key Buyer",
                "buyer_email": buyer_email,
                "metadata": {},
            },
        )

    assert response.status_code == 201
    data = response.json()
    assert data["status"] == "ok"

    purchase = data["purchase"]
    assert purchase["openclaw_install_key"] == openclaw_raw
    assert purchase["claude_code_install_key"] == claude_raw
    assert purchase["package_id"] == _PKG_5K
    assert purchase["buyer_email"] == buyer_email.lower()

    assert mock_registry.generate_install_key.call_count == 2
    call_programs = {call.kwargs.get("program") or call.args[2] for call in mock_registry.generate_install_key.call_args_list}
    assert call_programs == {"openclaw", "claude_code"}


def test_purchase_install_key_already_exists_returns_none_keys_purchase_still_succeeds() -> None:
    buyer_email = "installkey-exists@ironclaw.test"

    def _fake_generate(owner_key: str, subscription_id: str, program: str, **kwargs: object) -> InstallKeyRecord:
        raise InstallKeyAlreadyExistsError(owner_key, program)  # type: ignore[arg-type]

    mock_registry = MagicMock()
    mock_registry.generate_install_key.side_effect = _fake_generate

    with patch("app.api.billing.get_install_key_registry", return_value=mock_registry):
        response = _personal_client().post(
            "/billing/packages/purchase",
            json={
                "package_id": _PKG_5K,
                "buyer_name": "Existing Key Buyer",
                "buyer_email": buyer_email,
                "metadata": {},
            },
        )

    assert response.status_code == 201
    data = response.json()
    assert data["status"] == "ok"

    purchase = data["purchase"]
    assert purchase["openclaw_install_key"] is None
    assert purchase["claude_code_install_key"] is None

    wallet = data["wallet"]
    assert wallet["owner_key"] == buyer_email.lower()
    assert wallet["balance_units"] >= UNIT_PACKAGE_CATALOG[_PKG_5K]["unit_amount"]


def test_purchase_install_key_provisioning_exception_returns_none_keys_purchase_still_succeeds() -> None:
    buyer_email = "installkey-exc@ironclaw.test"

    def _fake_generate(owner_key: str, subscription_id: str, program: str, **kwargs: object) -> InstallKeyRecord:
        raise RuntimeError("simulated Supabase outage")

    mock_registry = MagicMock()
    mock_registry.generate_install_key.side_effect = _fake_generate

    with patch("app.api.billing.get_install_key_registry", return_value=mock_registry):
        response = _personal_client().post(
            "/billing/packages/purchase",
            json={
                "package_id": _PKG_5K,
                "buyer_name": "Exception Key Buyer",
                "buyer_email": buyer_email,
                "metadata": {},
            },
        )

    assert response.status_code == 201
    data = response.json()
    assert data["status"] == "ok"

    purchase = data["purchase"]
    assert purchase["openclaw_install_key"] is None
    assert purchase["claude_code_install_key"] is None

    wallet = data["wallet"]
    assert wallet["owner_key"] == buyer_email.lower()
    assert wallet["balance_units"] >= UNIT_PACKAGE_CATALOG[_PKG_5K]["unit_amount"]


def test_purchase_install_key_partial_success_one_key_already_exists() -> None:
    buyer_email = "installkey-partial@ironclaw.test"
    claude_raw = "ic_install_claude_code_PARTIALTEST00001"

    def _fake_generate(owner_key: str, subscription_id: str, program: str, **kwargs: object) -> InstallKeyRecord:
        if program == "openclaw":
            raise InstallKeyAlreadyExistsError(owner_key, program)  # type: ignore[arg-type]
        return _make_mock_install_key_record(program, owner_key, subscription_id, claude_raw)

    mock_registry = MagicMock()
    mock_registry.generate_install_key.side_effect = _fake_generate

    with patch("app.api.billing.get_install_key_registry", return_value=mock_registry):
        response = _personal_client().post(
            "/billing/packages/purchase",
            json={
                "package_id": _PKG_5K,
                "buyer_name": "Partial Key Buyer",
                "buyer_email": buyer_email,
                "metadata": {},
            },
        )

    assert response.status_code == 201
    purchase = response.json()["purchase"]
    assert purchase["openclaw_install_key"] is None
    assert purchase["claude_code_install_key"] == claude_raw


def test_purchase_response_schema_includes_install_key_fields() -> None:
    mock_registry = MagicMock()
    mock_registry.generate_install_key.side_effect = RuntimeError("no db in unit test")

    with patch("app.api.billing.get_install_key_registry", return_value=mock_registry):
        response = _personal_client().post(
            "/billing/packages/purchase",
            json={
                "package_id": _PKG_5K,
                "buyer_name": "Schema Check Buyer",
                "buyer_email": "schema-check@ironclaw.test",
                "metadata": {},
            },
        )

    assert response.status_code == 201
    purchase = response.json()["purchase"]
    assert "openclaw_install_key" in purchase
    assert "claude_code_install_key" in purchase


# ---------------------------------------------------------------------------
# POST /billing/packages/purchase — email validator
# ---------------------------------------------------------------------------


def test_purchase_malformed_email_no_at_sign_returns_422() -> None:
    response = _personal_client().post(
        "/billing/packages/purchase",
        json={
            "package_id": _PKG_5K,
            "buyer_name": "Bad Email Buyer",
            "buyer_email": "notanemail",
            "metadata": {},
        },
    )
    assert response.status_code == 422


def test_purchase_malformed_email_missing_domain_returns_422() -> None:
    response = _personal_client().post(
        "/billing/packages/purchase",
        json={
            "package_id": _PKG_5K,
            "buyer_name": "Bad Email Buyer",
            "buyer_email": "missing@",
            "metadata": {},
        },
    )
    assert response.status_code == 422


def test_purchase_malformed_email_no_tld_returns_422() -> None:
    response = _personal_client().post(
        "/billing/packages/purchase",
        json={
            "package_id": _PKG_5K,
            "buyer_name": "Bad Email Buyer",
            "buyer_email": "user@nodot",
            "metadata": {},
        },
    )
    assert response.status_code == 422


def test_purchase_email_is_normalized_to_lowercase() -> None:
    mock_registry = MagicMock()
    mock_registry.generate_install_key.side_effect = RuntimeError("no db")

    with patch("app.api.billing.get_install_key_registry", return_value=mock_registry):
        response = _personal_client().post(
            "/billing/packages/purchase",
            json={
                "package_id": _PKG_5K,
                "buyer_name": "Case Buyer",
                "buyer_email": "UPPER@IronClaw.TEST",
                "metadata": {},
            },
        )

    assert response.status_code == 201
    purchase = response.json()["purchase"]
    assert purchase["buyer_email"] == "upper@ironclaw.test"
    assert purchase["owner_key"] == "upper@ironclaw.test"


# ---------------------------------------------------------------------------
# POST /billing/packages/purchase — personal key (happy path)
# ---------------------------------------------------------------------------


def test_purchase_personal_key_returns_201_and_owner_key_is_buyer_email() -> None:
    buyer_email = "buyer@ironclaw.test"

    mock_registry = MagicMock()
    mock_registry.generate_install_key.side_effect = RuntimeError("no db")

    with patch("app.api.billing.get_install_key_registry", return_value=mock_registry):
        response = _personal_client().post(
            "/billing/packages/purchase",
            json={
                "package_id": _PKG_5K,
                "buyer_name": "Test Buyer",
                "buyer_email": buyer_email,
                "metadata": {},
            },
        )

    assert response.status_code == 201
    data = response.json()
    assert data["status"] == "ok"

    purchase = data["purchase"]
    assert purchase["package_id"] == _PKG_5K
    assert purchase["buyer_email"] == buyer_email.lower()
    assert purchase["owner_key"] == buyer_email.lower()
    assert purchase["granted_units"] > 0
    assert purchase["token_coverage"] > 0
    assert "purchase_id" in purchase
    assert "created_at" in purchase

    wallet = data["wallet"]
    assert wallet["owner_key"] == buyer_email.lower()
    assert wallet["balance_units"] >= purchase["granted_units"]


def test_purchase_personal_key_pkg_25k_returns_201() -> None:
    mock_registry = MagicMock()
    mock_registry.generate_install_key.side_effect = RuntimeError("no db")

    with patch("app.api.billing.get_install_key_registry", return_value=mock_registry):
        response = _personal_client().post(
            "/billing/packages/purchase",
            json={
                "package_id": _PKG_25K,
                "buyer_name": "Team Buyer",
                "buyer_email": "team@ironclaw.test",
                "metadata": {"team": "engineering"},
            },
        )

    assert response.status_code == 201
    data = response.json()
    assert data["purchase"]["package_id"] == _PKG_25K
    assert data["purchase"]["granted_units"] == UNIT_PACKAGE_CATALOG[_PKG_25K]["unit_amount"]


def test_purchase_personal_key_pkg_60k_returns_201() -> None:
    mock_registry = MagicMock()
    mock_registry.generate_install_key.side_effect = RuntimeError("no db")

    with patch("app.api.billing.get_install_key_registry", return_value=mock_registry):
        response = _personal_client().post(
            "/billing/packages/purchase",
            json={
                "package_id": _PKG_60K,
                "buyer_name": "Enterprise Buyer",
                "buyer_email": "enterprise@ironclaw.test",
                "metadata": {},
            },
        )

    assert response.status_code == 201
    data = response.json()
    assert data["purchase"]["package_id"] == _PKG_60K
    assert data["purchase"]["granted_units"] == UNIT_PACKAGE_CATALOG[_PKG_60K]["unit_amount"]


# ---------------------------------------------------------------------------
# POST /billing/packages/purchase — purchase_id uniqueness
# ---------------------------------------------------------------------------


def test_purchase_id_uniqueness_across_concurrent_purchases() -> None:
    # Patch is hoisted outside the thread closure so the mock context is
    # established once before the ThreadPoolExecutor starts. This prevents
    # the patch context from exiting mid-flight while threads are still in
    # their request cycle, eliminating the RuntimeError side_effect race.
    mock_registry = MagicMock()
    mock_registry.generate_install_key.side_effect = RuntimeError("no db")

    app = _build_app(auth_ctx=_PERSONAL_AUTH_CTX)
    client = TestClient(app)

    def _do_purchase(i: int) -> str:
        resp = client.post(
            "/billing/packages/purchase",
            json={
                "package_id": _PKG_5K,
                "buyer_name": f"Concurrent Buyer {i}",
                "buyer_email": f"concurrent{i}@ironclaw.test",
                "metadata": {},
            },
        )
        assert resp.status_code == 201, f"Purchase {i} failed: {resp.text}"
        return resp.json()["purchase"]["purchase_id"]

    with patch("app.api.billing.get_install_key_registry", return_value=mock_registry):
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
            futures = [pool.submit(_do_purchase, i) for i in range(20)]
            purchase_ids = [f.result() for f in concurrent.futures.as_completed(futures)]

    assert len(purchase_ids) == len(set(purchase_ids)), f"Duplicate purchase_ids detected: {purchase_ids}"
    for pid in purchase_ids:
        assert pid.startswith("purch_"), f"purchase_id missing purch_ prefix: {pid!r}"
        hex_part = pid[len("purch_"):]
        assert len(hex_part) == 16, f"purchase_id hex part wrong length: {pid!r}"
        assert all(c in "0123456789abcdef" for c in hex_part), f"purchase_id contains non-hex characters: {pid!r}"


# ---------------------------------------------------------------------------
# POST /billing/packages/purchase — auth enforcement
# ---------------------------------------------------------------------------


def test_purchase_no_api_key_returns_401() -> None:
    response = _unauthed_client().post(
        "/billing/packages/purchase",
        json={
            "package_id": _PKG_5K,
            "buyer_name": "Attacker",
            "buyer_email": "attacker@evil.test",
            "metadata": {},
        },
    )
    assert response.status_code == 401


def test_purchase_unknown_package_id_returns_404() -> None:
    mock_registry = MagicMock()
    mock_registry.generate_install_key.side_effect = RuntimeError("no db")

    with patch("app.api.billing.get_install_key_registry", return_value=mock_registry):
        response = _personal_client().post(
            "/billing/packages/purchase",
            json={
                "package_id": "pkg_does_not_exist",
                "buyer_name": "Test Buyer",
                "buyer_email": "buyer@ironclaw.test",
                "metadata": {},
            },
        )

    assert response.status_code == 404


def test_purchase_empty_package_id_returns_422() -> None:
    response = _personal_client().post(
        "/billing/packages/purchase",
        json={
            "package_id": "",
            "buyer_name": "Test Buyer",
            "buyer_email": "buyer@ironclaw.test",
            "metadata": {},
        },
    )
    assert response.status_code == 422


# ---------------------------------------------------------------------------
# POST /billing/packages/purchase — org key
# ---------------------------------------------------------------------------


def test_purchase_org_key_returns_201_and_owner_key_is_ic_org() -> None:
    mock_registry = MagicMock()
    mock_registry.generate_install_key.side_effect = RuntimeError("no db")

    with patch("app.api.billing.get_install_key_registry", return_value=mock_registry):
        response = _org_client().post(
            "/billing/packages/purchase",
            json={
                "package_id": _PKG_5K,
                "buyer_name": "Org Admin",
                "buyer_email": "admin@ironclaw-org.test",
                "metadata": {"org": _ORG_ID},
            },
        )

    assert response.status_code == 201
    data = response.json()
    assert data["status"] == "ok"

    purchase = data["purchase"]
    assert purchase["package_id"] == _PKG_5K
    assert purchase["owner_key"] == _ORG_OWNER_KEY, f"Expected org wallet key {_ORG_OWNER_KEY!r}, got {purchase['owner_key']!r}"
    assert purchase["granted_units"] > 0

    wallet = data["wallet"]
    assert wallet["owner_key"] == _ORG_OWNER_KEY


# ---------------------------------------------------------------------------
# GET /billing/wallet/{owner_key} — personal key
# ---------------------------------------------------------------------------


def test_get_wallet_personal_key_returns_200() -> None:
    registry = get_unit_wallet_registry()
    registry.credit_units(
        owner_key="wallet-read-personal@ironclaw.test",
        units=100,
        metadata={"package_id": _PKG_5K},
    )
    response = _personal_client().get("/billing/wallet/wallet-read-personal@ironclaw.test")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    wallet = data["wallet"]
    assert wallet["owner_key"] == "wallet-read-personal@ironclaw.test"
    assert wallet["balance_units"] >= 100
    assert "wallet_id" in wallet
    assert "updated_at" in wallet


def test_get_wallet_personal_key_cannot_access_org_wallet_returns_403() -> None:
    response = _personal_client().get(f"/billing/wallet/{_ORG_OWNER_KEY}")
    assert response.status_code == 403
    detail = response.json()["detail"]
    assert detail["reason"] == "org_wallet_requires_org_key"


def test_get_wallet_unauthenticated_returns_401() -> None:
    response = _unauthed_client().get("/billing/wallet/some-owner@test.com")
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# GET /billing/wallet/{owner_key} — org key isolation
# ---------------------------------------------------------------------------


def test_get_wallet_org_key_reads_own_org_wallet_returns_200() -> None:
    registry = get_unit_wallet_registry()
    registry.credit_units(
        owner_key=_ORG_OWNER_KEY,
        units=500,
        metadata={"package_id": _PKG_25K},
    )
    response = _org_client().get(f"/billing/wallet/{_ORG_OWNER_KEY}")
    assert response.status_code == 200
    data = response.json()
    assert data["wallet"]["owner_key"] == _ORG_OWNER_KEY
    assert data["wallet"]["balance_units"] >= 500


def test_get_wallet_org_key_cannot_access_personal_wallet_returns_403() -> None:
    response = _org_client().get("/billing/wallet/personal@ironclaw.test")
    assert response.status_code == 403
    detail = response.json()["detail"]
    assert detail["reason"] == "org_key_cannot_access_personal_wallet"


def test_get_wallet_org_key_cannot_access_different_org_wallet_returns_403() -> None:
    other_org_wallet = "ic_org_differentorg999"
    response = _org_client().get(f"/billing/wallet/{other_org_wallet}")
    assert response.status_code == 403


# ---------------------------------------------------------------------------
# POST /billing/wallet/{owner_key}/debit — personal key
# ---------------------------------------------------------------------------


def test_debit_personal_wallet_by_units_returns_200() -> None:
    registry = get_unit_wallet_registry()
    registry.credit_units(
        owner_key="debit-personal@ironclaw.test",
        units=500,
        metadata={"package_id": _PKG_5K},
    )
    response = _personal_client().post(
        "/billing/wallet/debit-personal@ironclaw.test/debit",
        json={"units": 10, "reason": "test debit"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["units_debited"] == 10
    assert data["owner_key"] == "debit-personal@ironclaw.test"
    assert data["wallet"]["balance_units"] == 490


def test_debit_personal_wallet_by_token_count_returns_200() -> None:
    registry = get_unit_wallet_registry()
    registry.credit_units(
        owner_key="debit-tokens@ironclaw.test",
        units=500,
        metadata={"package_id": _PKG_5K},
    )
    response = _personal_client().post(
        "/billing/wallet/debit-tokens@ironclaw.test/debit",
        json={"token_count": 50_000},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["units_debited"] == 2
    assert data["token_count"] == 50_000


def test_debit_wallet_returns_402_on_insufficient_units() -> None:
    response = _personal_client().post(
        "/billing/wallet/empty-wallet-noexist@ironclaw.test/debit",
        json={"units": 999_999_999},
    )
    assert response.status_code == 402
    detail = response.json()["detail"]
    assert detail["status"] == "insufficient_units"
    assert "have" in detail
    assert "need" in detail


def test_debit_wallet_returns_422_when_no_units_or_token_count() -> None:
    response = _personal_client().post(
        "/billing/wallet/debit-personal@ironclaw.test/debit",
        json={"reason": "missing amount"},
    )
    assert response.status_code == 422


def test_debit_wallet_returns_401_unauthenticated() -> None:
    response = _unauthed_client().post(
        "/billing/wallet/debit-personal@ironclaw.test/debit",
        json={"units": 1},
    )
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# POST /billing/wallet/{owner_key}/debit — org key isolation
# ---------------------------------------------------------------------------


def test_debit_org_wallet_via_org_key_returns_200_and_routes_to_org_wallet() -> None:
    registry = get_unit_wallet_registry()
    registry.credit_units(
        owner_key=_ORG_OWNER_KEY,
        units=1000,
        metadata={"package_id": _PKG_25K},
    )
    response = _org_client().post(
        f"/billing/wallet/{_ORG_OWNER_KEY}/debit",
        json={"units": 5, "reason": "org debit test"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["owner_key"] == _ORG_OWNER_KEY
    assert data["units_debited"] == 5
    assert data["wallet"]["owner_key"] == _ORG_OWNER_KEY


def test_debit_org_key_personal_url_redirects_to_org_wallet() -> None:
    registry = get_unit_wallet_registry()
    registry.credit_units(
        owner_key=_ORG_OWNER_KEY,
        units=200,
        metadata={"package_id": _PKG_5K},
    )
    response = _org_client().post(
        f"/billing/wallet/{_ORG_OWNER_KEY}/debit",
        json={"units": 1, "reason": "redirect test"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["owner_key"] == _ORG_OWNER_KEY
    assert data["wallet"]["owner_key"] == _ORG_OWNER_KEY


def test_debit_org_key_cannot_target_different_org_wallet_returns_403() -> None:
    other_org = "ic_org_attackerorg"
    response = _org_client().post(
        f"/billing/wallet/{other_org}/debit",
        json={"units": 1},
    )
    assert response.status_code == 403
    detail = response.json()["detail"]
    assert "match" in str(detail).lower() or "forbidden" in str(detail).lower()


def test_debit_personal_key_cannot_target_org_wallet_returns_403() -> None:
    response = _personal_client().post(
        f"/billing/wallet/{_ORG_OWNER_KEY}/debit",
        json={"units": 1},
    )
    assert response.status_code == 403
    detail = response.json()["detail"]
    assert detail["reason"] == "org_wallet_requires_org_key"


# ---------------------------------------------------------------------------
# POST /billing/wallet/{owner_key}/refund — personal key
# ---------------------------------------------------------------------------


def test_refund_personal_wallet_path_key_used_directly_as_owner_key() -> None:
    registry = get_unit_wallet_registry()
    registry.credit_units(
        owner_key="refund-pathkey@ironclaw.test",
        units=100,
        metadata={"package_id": _PKG_5K},
    )
    registry.debit_units(
        owner_key="refund-pathkey@ironclaw.test",
        units=30,
        metadata={"reason": "setup"},
    )
    response = _personal_client().post(
        "/billing/wallet/refund-pathkey@ironclaw.test/refund",
        json={"units": 10, "reason": "path key regression test"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["units_refunded"] == 10
    assert data["owner_key"] == "refund-pathkey@ironclaw.test"
    assert data["wallet"]["balance_units"] == 80


def test_refund_personal_wallet_returns_200() -> None:
    registry = get_unit_wallet_registry()
    registry.credit_units(
        owner_key="refund-personal@ironclaw.test",
        units=200,
        metadata={"package_id": _PKG_5K},
    )
    registry.debit_units(
        owner_key="refund-personal@ironclaw.test",
        units=50,
        metadata={"reason": "setup"},
    )
    response = _personal_client().post(
        "/billing/wallet/refund-personal@ironclaw.test/refund",
        json={"units": 20, "reason": "test refund"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["units_refunded"] == 20
    assert data["owner_key"] == "refund-personal@ironclaw.test"
    assert data["wallet"]["balance_units"] == 170


def test_refund_zero_units_returns_422() -> None:
    response = _personal_client().post(
        "/billing/wallet/refund-personal@ironclaw.test/refund",
        json={"units": 0},
    )
    assert response.status_code == 422


def test_refund_wallet_returns_401_unauthenticated() -> None:
    response = _unauthed_client().post(
        "/billing/wallet/refund-personal@ironclaw.test/refund",
        json={"units": 5},
    )
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# POST /billing/wallet/{owner_key}/refund — org key isolation
# ---------------------------------------------------------------------------


def test_refund_org_wallet_via_org_key_returns_200() -> None:
    registry = get_unit_wallet_registry()
    registry.credit_units(
        owner_key=_ORG_OWNER_KEY,
        units=300,
        metadata={"package_id": _PKG_25K},
    )
    registry.debit_units(
        owner_key=_ORG_OWNER_KEY,
        units=100,
        metadata={"reason": "setup"},
    )
    response = _org_client().post(
        f"/billing/wallet/{_ORG_OWNER_KEY}/refund",
        json={"units": 30, "reason": "org refund test"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["units_refunded"] == 30
    assert data["owner_key"] == _ORG_OWNER_KEY


def test_refund_org_key_different_org_wallet_returns_403() -> None:
    other_org_wallet = "ic_org_completelyotherorg"
    response = _org_client().post(
        f"/billing/wallet/{other_org_wallet}/refund",
        json={"units": 1, "reason": "cross-org refund attempt"},
    )
    assert response.status_code == 403
    detail = response.json()["detail"]
    assert isinstance(detail, str)
    assert len(detail) > 0


def test_refund_personal_key_cannot_refund_org_wallet_returns_403() -> None:
    response = _personal_client().post(
        f"/billing/wallet/{_ORG_OWNER_KEY}/refund",
        json={"units": 1},
    )
    assert response.status_code == 403
    detail = response.json()["detail"]
    assert detail["reason"] == "org_wallet_requires_org_key"


# ---------------------------------------------------------------------------
# GET /billing/ledger — personal key
# ---------------------------------------------------------------------------


def test_get_ledger_personal_key_returns_200() -> None:
    registry = get_unit_wallet_registry()
    registry.credit_units(
        owner_key="ledger-personal@ironclaw.test",
        units=1000,
        metadata={"package_id": _PKG_5K},
    )
    registry.debit_units(
        owner_key="ledger-personal@ironclaw.test",
        units=25,
        metadata={"reason": "test_debit", "route": "/guard/execute"},
    )
    response = _personal_client().get(
        "/billing/ledger",
        params={"owner_key": "ledger-personal@ironclaw.test", "limit": 10},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["owner_key"] == "ledger-personal@ironclaw.test"
    assert data["limit"] == 10
    assert isinstance(data["entries"], list)
    assert len(data["entries"]) >= 2

    entry = data["entries"][-1]
    assert entry["owner_key"] == "ledger-personal@ironclaw.test"
    assert entry["entry_type"] in {"credit", "debit"}
    assert "units" in entry
    assert "balance_after" in entry
    assert "created_at" in entry


def test_get_ledger_returns_401_unauthenticated() -> None:
    response = _unauthed_client().get("/billing/ledger")
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# GET /billing/ledger — org key isolation
# ---------------------------------------------------------------------------


def test_get_ledger_org_key_can_read_own_org_wallet_entries() -> None:
    registry = get_unit_wallet_registry()
    registry.credit_units(
        owner_key=_ORG_OWNER_KEY,
        units=200,
        metadata={"package_id": _PKG_25K},
    )
    response = _org_client().get(
        "/billing/ledger",
        params={"owner_key": _ORG_OWNER_KEY, "limit": 5},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["owner_key"] == _ORG_OWNER_KEY
    assert isinstance(data["entries"], list)


def test_get_ledger_org_key_cannot_query_personal_wallet_entries_returns_403() -> None:
    response = _org_client().get(
        "/billing/ledger",
        params={"owner_key": "personal@ironclaw.test"},
    )
    assert response.status_code == 403


def test_get_ledger_personal_key_cannot_query_org_wallet_entries_returns_403() -> None:
    response = _personal_client().get(
        "/billing/ledger",
        params={"owner_key": _ORG_OWNER_KEY},
    )
    assert response.status_code == 403


def test_get_ledger_org_key_cannot_query_different_org_wallet_returns_403() -> None:
    response = _org_client().get(
        "/billing/ledger",
        params={"owner_key": "ic_org_otherorg999"},
    )
    assert response.status_code == 403


# ---------------------------------------------------------------------------
# GET /billing/packages — service field
# ---------------------------------------------------------------------------


def test_list_packages_returns_200_service_field() -> None:
    response = _personal_client().get("/billing/packages")
    assert response.status_code == 200
    assert response.json()["service"] in {"ironclaw-billing", "IronClaw-Security"}
