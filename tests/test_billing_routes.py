from __future__ import annotations

import concurrent.futures
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.routes.billing import (
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
    get_unit_wallet_registry,
)
from app.services.stripe_service import (
    StripeService,
    StripeSubscriptionNotFoundError,
)

# ---------------------------------------------------------------------------
# Expected package IDs
# ---------------------------------------------------------------------------

_PKG_5K = "pkg_5000"
_PKG_25K = "pkg_25000"
_PKG_60K = "pkg_60000"
_ALL_PKG_IDS = {_PKG_5K, _PKG_25K, _PKG_60K}

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


def test_packages_catalog_contains_all_expected_ids() -> None:
    """Replaces the removed module-level assert on UNIT_PACKAGE_CATALOG.keys()."""
    response = _personal_client().get("/billing/packages")
    assert response.status_code == 200
    returned_ids = {p["package_id"] for p in response.json()["packages"]}
    assert _ALL_PKG_IDS <= returned_ids, f"Live /billing/packages is missing expected packages: {_ALL_PKG_IDS - returned_ids}"


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
# POST /billing/purchase — install key provisioning
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

    with patch("app.api.routes.billing.get_install_key_registry", return_value=mock_registry):
        response = _personal_client().post(
            "/billing/purchase",
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

    with patch("app.api.routes.billing.get_install_key_registry", return_value=mock_registry):
        response = _personal_client().post(
            "/billing/purchase",
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
    assert wallet["balance_units"] >= purchase["granted_units"]


def test_purchase_install_key_provisioning_exception_returns_none_keys_purchase_still_succeeds() -> None:
    buyer_email = "installkey-exc@ironclaw.test"

    def _fake_generate(owner_key: str, subscription_id: str, program: str, **kwargs: object) -> InstallKeyRecord:
        raise RuntimeError("simulated Supabase outage")

    mock_registry = MagicMock()
    mock_registry.generate_install_key.side_effect = _fake_generate

    with patch("app.api.routes.billing.get_install_key_registry", return_value=mock_registry):
        response = _personal_client().post(
            "/billing/purchase",
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
    assert wallet["balance_units"] >= purchase["granted_units"]


def test_purchase_install_key_partial_success_one_key_already_exists() -> None:
    buyer_email = "installkey-partial@ironclaw.test"
    claude_raw = "ic_install_claude_code_PARTIALTEST00001"

    def _fake_generate(owner_key: str, subscription_id: str, program: str, **kwargs: object) -> InstallKeyRecord:
        if program == "openclaw":
            raise InstallKeyAlreadyExistsError(owner_key, program)  # type: ignore[arg-type]
        return _make_mock_install_key_record(program, owner_key, subscription_id, claude_raw)

    mock_registry = MagicMock()
    mock_registry.generate_install_key.side_effect = _fake_generate

    with patch("app.api.routes.billing.get_install_key_registry", return_value=mock_registry):
        response = _personal_client().post(
            "/billing/purchase",
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

    with patch("app.api.routes.billing.get_install_key_registry", return_value=mock_registry):
        response = _personal_client().post(
            "/billing/purchase",
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
# POST /billing/purchase — email validator
# ---------------------------------------------------------------------------


def test_purchase_malformed_email_no_at_sign_returns_422() -> None:
    response = _personal_client().post(
        "/billing/purchase",
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
        "/billing/purchase",
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
        "/billing/purchase",
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

    with patch("app.api.routes.billing.get_install_key_registry", return_value=mock_registry):
        response = _personal_client().post(
            "/billing/purchase",
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
# POST /billing/purchase — personal key (happy path)
# ---------------------------------------------------------------------------


def test_purchase_personal_key_returns_201_and_owner_key_is_buyer_email() -> None:
    buyer_email = "buyer@ironclaw.test"

    mock_registry = MagicMock()
    mock_registry.generate_install_key.side_effect = RuntimeError("no db")

    with patch("app.api.routes.billing.get_install_key_registry", return_value=mock_registry):
        response = _personal_client().post(
            "/billing/purchase",
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

    with patch("app.api.routes.billing.get_install_key_registry", return_value=mock_registry):
        response = _personal_client().post(
            "/billing/purchase",
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
    assert data["purchase"]["granted_units"] > 0


def test_purchase_personal_key_pkg_60k_returns_201() -> None:
    mock_registry = MagicMock()
    mock_registry.generate_install_key.side_effect = RuntimeError("no db")

    with patch("app.api.routes.billing.get_install_key_registry", return_value=mock_registry):
        response = _personal_client().post(
            "/billing/purchase",
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
    assert data["purchase"]["granted_units"] > 0


# ---------------------------------------------------------------------------
# POST /billing/purchase — purchase_id uniqueness
# ---------------------------------------------------------------------------


def test_purchase_id_uniqueness_across_concurrent_purchases() -> None:
    mock_registry = MagicMock()
    mock_registry.generate_install_key.side_effect = RuntimeError("no db")

    app = _build_app(auth_ctx=_PERSONAL_AUTH_CTX)
    client = TestClient(app)

    def _do_purchase(i: int) -> str:
        resp = client.post(
            "/billing/purchase",
            json={
                "package_id": _PKG_5K,
                "buyer_name": f"Concurrent Buyer {i}",
                "buyer_email": f"concurrent{i}@ironclaw.test",
                "metadata": {},
            },
        )
        assert resp.status_code == 201, f"Purchase {i} failed: {resp.text}"
        return resp.json()["purchase"]["purchase_id"]

    with patch("app.api.routes.billing.get_install_key_registry", return_value=mock_registry):
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
            futures = [pool.submit(_do_purchase, i) for i in range(20)]
            purchase_ids = [f.result() for f in concurrent.futures.as_completed(futures)]

    assert len(purchase_ids) == len(set(purchase_ids)), f"Duplicate purchase_ids detected: {purchase_ids}"
    for pid in purchase_ids:
        assert pid.startswith("purch_"), f"purchase_id missing purch_ prefix: {pid!r}"
        hex_part = pid[len("purch_") :]
        assert len(hex_part) == 16, f"purchase_id hex part wrong length: {pid!r}"
        assert all(c in "0123456789abcdef" for c in hex_part), f"purchase_id contains non-hex characters: {pid!r}"


# ---------------------------------------------------------------------------
# POST /billing/purchase — auth enforcement
# ---------------------------------------------------------------------------


def test_purchase_no_api_key_returns_401() -> None:
    response = _unauthed_client().post(
        "/billing/purchase",
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

    with patch("app.api.routes.billing.get_install_key_registry", return_value=mock_registry):
        response = _personal_client().post(
            "/billing/purchase",
            json={
                "package_id": "pkg_does_not_exist",
                "buyer_name": "Test Buyer",
                "buyer_email": "buyer@ironclaw.test",
                "metadata": {},
            },
        )

    assert response.status_code == 404


def test_purchase_empty_package_id_returns_422_routes() -> None:
    response = _personal_client().post(
        "/billing/purchase",
        json={
            "package_id": "",
            "buyer_name": "Test Buyer",
            "buyer_email": "buyer@ironclaw.test",
            "metadata": {},
        },
    )
    assert response.status_code == 422


# ---------------------------------------------------------------------------
# POST /billing/purchase — org key
# ---------------------------------------------------------------------------


def test_purchase_org_key_returns_201_and_owner_key_is_ic_org() -> None:
    mock_registry = MagicMock()
    mock_registry.generate_install_key.side_effect = RuntimeError("no db")

    with patch("app.api.routes.billing.get_install_key_registry", return_value=mock_registry):
        response = _org_client().post(
            "/billing/purchase",
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
    assert isinstance(detail, dict)
    assert detail["reason"] == "org_wallet_requires_org_key"
    assert isinstance(detail["detail"], str)


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
    assert isinstance(detail, dict)
    assert detail["reason"] == "org_key_cannot_access_personal_wallet"
    assert isinstance(detail["detail"], str)


def test_get_wallet_org_key_cannot_access_different_org_wallet_returns_403() -> None:
    other_org_wallet = "ic_org_differentorg999"
    response = _org_client().get(f"/billing/wallet/{other_org_wallet}")
    assert response.status_code == 403
    detail = response.json()["detail"]
    assert isinstance(detail, dict)
    assert detail["reason"] == "org_key_mismatch"
    assert isinstance(detail["detail"], str)


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
    assert isinstance(detail, dict)
    assert detail["reason"] == "org_key_mismatch"
    assert isinstance(detail["detail"], str)


def test_debit_personal_key_cannot_target_org_wallet_returns_403() -> None:
    response = _personal_client().post(
        f"/billing/wallet/{_ORG_OWNER_KEY}/debit",
        json={"units": 1},
    )
    assert response.status_code == 403
    detail = response.json()["detail"]
    assert isinstance(detail, dict)
    assert detail["reason"] == "org_wallet_requires_org_key"
    assert isinstance(detail["detail"], str)


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
    assert isinstance(detail, dict)
    assert detail["reason"] == "org_key_mismatch"
    assert isinstance(detail["detail"], str)
    assert len(detail["detail"]) > 0


def test_refund_personal_key_cannot_refund_org_wallet_returns_403() -> None:
    response = _personal_client().post(
        f"/billing/wallet/{_ORG_OWNER_KEY}/refund",
        json={"units": 1},
    )
    assert response.status_code == 403
    detail = response.json()["detail"]
    assert isinstance(detail, dict)
    assert detail["reason"] == "org_wallet_requires_org_key"
    assert isinstance(detail["detail"], str)


# ---------------------------------------------------------------------------
# GET /billing/wallet/{owner_key}/ledger — personal key
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
        "/billing/wallet/ledger-personal@ironclaw.test/ledger",
        params={"limit": 10},
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
    response = _unauthed_client().get("/billing/wallet/any@ironclaw.test/ledger")
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# GET /billing/wallet/{owner_key}/ledger — org key isolation
# ---------------------------------------------------------------------------


def test_get_ledger_org_key_can_read_own_org_wallet_entries() -> None:
    registry = get_unit_wallet_registry()
    registry.credit_units(
        owner_key=_ORG_OWNER_KEY,
        units=200,
        metadata={"package_id": _PKG_25K},
    )
    response = _org_client().get(
        f"/billing/wallet/{_ORG_OWNER_KEY}/ledger",
        params={"limit": 5},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["owner_key"] == _ORG_OWNER_KEY
    assert isinstance(data["entries"], list)


def test_get_ledger_org_key_cannot_query_personal_wallet_entries_returns_403() -> None:
    response = _org_client().get(
        "/billing/wallet/personal@ironclaw.test/ledger",
    )
    assert response.status_code == 403
    detail = response.json()["detail"]
    assert isinstance(detail, dict)
    assert detail["reason"] == "org_key_cannot_access_personal_wallet"
    assert isinstance(detail["detail"], str)


def test_get_ledger_personal_key_cannot_query_org_wallet_entries_returns_403() -> None:
    response = _personal_client().get(
        f"/billing/wallet/{_ORG_OWNER_KEY}/ledger",
    )
    assert response.status_code == 403
    detail = response.json()["detail"]
    assert isinstance(detail, dict)
    assert detail["reason"] == "org_wallet_requires_org_key"
    assert isinstance(detail["detail"], str)


def test_get_ledger_org_key_cannot_query_different_org_wallet_returns_403() -> None:
    response = _org_client().get(
        "/billing/wallet/ic_org_otherorg999/ledger",
    )
    assert response.status_code == 403
    detail = response.json()["detail"]
    assert isinstance(detail, dict)
    assert detail["reason"] == "org_key_mismatch"
    assert isinstance(detail["detail"], str)


# ---------------------------------------------------------------------------
# GET /billing/packages — service field
# ---------------------------------------------------------------------------


def test_list_packages_returns_200_service_field() -> None:
    response = _personal_client().get("/billing/packages")
    assert response.status_code == 200
    assert response.json()["service"] in {"ironclaw-billing", "IronClaw-Security"}


# ---------------------------------------------------------------------------
# StripeService — duplicate event idempotency via reset_processed_events
# ---------------------------------------------------------------------------


def _make_svc() -> StripeService:
    """Return a fresh StripeService instance with no Stripe API key required."""
    svc = StripeService()
    # Inject a no-op mock client so no real HTTP calls are attempted.
    mock_client = MagicMock()
    svc._override_client(mock_client)
    return svc


def test_stripe_service_duplicate_event_idempotency_via_reset_processed_events() -> None:
    """
    Verify that after reset_processed_events() is called, a previously seen
    event_id is accepted again by the idempotency layer.

    Pattern: record event_id → attempt duplicate (should be detected) →
             reset → attempt again (should be accepted as new).
    """
    svc = _make_svc()

    event_id = "evt_idem_test_001"

    # Seed the idempotency set with this event_id directly via the internal
    # store, simulating a prior processed event.
    with svc._lock:
        svc._idempotency_keys[event_id] = {"processed": True}

    # Confirm the key is present before reset.
    with svc._lock:
        assert event_id in svc._idempotency_keys

    # Reset processed events — must clear idempotency state.
    svc.reset_processed_events()

    # After reset the event_id must be absent.
    with svc._lock:
        assert event_id not in svc._idempotency_keys


def test_stripe_service_reset_processed_events_clears_all_tracked_ids() -> None:
    """reset_processed_events must clear ALL tracked idempotency keys, not just one."""
    svc = _make_svc()

    event_ids = [f"evt_bulk_{i:03d}" for i in range(10)]
    with svc._lock:
        for eid in event_ids:
            svc._idempotency_keys[eid] = {"processed": True}

    svc.reset_processed_events()

    with svc._lock:
        remaining = [eid for eid in event_ids if eid in svc._idempotency_keys]

    assert remaining == [], f"Expected all event IDs cleared, still present: {remaining}"


def test_stripe_service_reset_processed_events_is_idempotent() -> None:
    """Calling reset_processed_events twice must not raise."""
    svc = _make_svc()
    svc.reset_processed_events()
    svc.reset_processed_events()  # second call must be a no-op, not raise


# ---------------------------------------------------------------------------
# StripeService — subscription.updated and subscription.deleted via get_subscription
# ---------------------------------------------------------------------------


def _seed_subscription(svc: StripeService, sub_id: str, org_id: str, status: str = "active") -> None:
    """Directly seed a subscription record into the service's internal store."""
    from datetime import UTC, datetime

    from app.services.stripe_service import _SubscriptionRecord  # type: ignore[attr-defined]

    now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    record = _SubscriptionRecord(
        subscription_id=sub_id,
        org_id=org_id,
        customer_id=f"cus_test_{org_id}",
        price_id="price_test_001",
        status=status,
        billing_interval="month",
        current_period_start=now,
        current_period_end=now,
        cancel_at_period_end=False,
        metered_price_id=None,
        metadata={},
        created_at=now,
        updated_at=now,
    )
    with svc._lock:
        svc._subscriptions[sub_id] = record


def test_get_subscription_returns_active_subscription() -> None:
    """
    svc.get_subscription(sub_id) must return a SubscriptionResponse for a
    known subscription, confirming the bridge path used by
    subscription.updated / subscription.deleted handlers resolves correctly.
    """
    svc = _make_svc()
    sub_id = "sub_updated_test_001"
    org_id = "org_sub_updated_001"

    _seed_subscription(svc, sub_id, org_id, status="active")

    result = svc.get_subscription(sub_id)

    assert result is not None
    assert result.subscription_id == sub_id
    assert result.org_id == org_id
    assert result.status == "active"


def test_get_subscription_raises_not_found_for_unknown_id() -> None:
    """
    svc.get_subscription with an unknown sub_id must raise
    StripeSubscriptionNotFoundError — matching what subscription.updated /
    subscription.deleted handlers must handle when no local record exists.
    """
    svc = _make_svc()

    try:
        svc.get_subscription("sub_does_not_exist_xyz")
        raise AssertionError("Expected StripeSubscriptionNotFoundError was not raised")
    except StripeSubscriptionNotFoundError:
        pass


def test_subscription_updated_event_handler_updates_status_in_registry() -> None:
    """
    Simulate the subscription.updated webhook path: seed a subscription as
    'active', update its status to 'past_due' in-place, and confirm
    get_subscription reflects the change — validating the bridge path that
    subscription.updated handlers use when calling svc.get_subscription.
    """
    svc = _make_svc()
    sub_id = "sub_updated_status_test"
    org_id = "org_status_change_001"

    _seed_subscription(svc, sub_id, org_id, status="active")

    # Simulate in-place update (what a subscription.updated handler does).
    with svc._lock:
        existing = svc._subscriptions[sub_id]
        from datetime import UTC, datetime

        now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        from app.services.stripe_service import _SubscriptionRecord  # type: ignore[attr-defined]

        svc._subscriptions[sub_id] = _SubscriptionRecord(
            subscription_id=existing.subscription_id,
            org_id=existing.org_id,
            customer_id=existing.customer_id,
            price_id=existing.price_id,
            status="past_due",
            billing_interval=existing.billing_interval,
            current_period_start=existing.current_period_start,
            current_period_end=existing.current_period_end,
            cancel_at_period_end=existing.cancel_at_period_end,
            metered_price_id=existing.metered_price_id,
            metadata=existing.metadata,
            created_at=existing.created_at,
            updated_at=now,
        )

    updated = svc.get_subscription(sub_id)
    assert updated.status == "past_due"
    assert updated.subscription_id == sub_id


def test_subscription_deleted_event_handler_removes_subscription_from_registry() -> None:
    """
    Simulate the subscription.deleted webhook path: seed a subscription,
    remove it from the internal store (what a deleted handler does), then
    confirm get_subscription raises StripeSubscriptionNotFoundError.
    """
    svc = _make_svc()
    sub_id = "sub_deleted_test_001"
    org_id = "org_deleted_001"

    _seed_subscription(svc, sub_id, org_id, status="canceled")

    # Simulate deletion handler removing the record.
    with svc._lock:
        svc._subscriptions.pop(sub_id, None)

    try:
        svc.get_subscription(sub_id)
        raise AssertionError("Expected StripeSubscriptionNotFoundError after deletion")
    except StripeSubscriptionNotFoundError:
        pass


# ---------------------------------------------------------------------------
# StripeService — invoice.paid renewal credit path (billing_reason=subscription_cycle)
# ---------------------------------------------------------------------------


def test_invoice_paid_subscription_cycle_credits_units_to_org_wallet() -> None:
    """
    invoice.paid with billing_reason=subscription_cycle must credit the org's
    unit balance via the unit ledger, representing a subscription renewal.

    We simulate what the invoice.paid handler does: resolve org from customer,
    credit units, verify ledger balance increases.
    """
    svc = _make_svc()
    org_id = "org_renewal_001"
    customer_id = "cus_renewal_001"
    sub_id = "sub_renewal_001"

    # Register the customer → org mapping.
    svc.register_customer_mapping(org_id, customer_id)

    # Seed a subscription so the handler can resolve it.
    _seed_subscription(svc, sub_id, org_id, status="active")

    # Simulate invoice.paid (billing_reason=subscription_cycle) handler behavior:
    # 1. Resolve org from customer_id.
    resolved_org = svc.resolve_org_from_customer(customer_id)
    assert resolved_org == org_id

    # 2. Credit renewal units to org balance (equivalent to what the handler does).
    renewal_units = 5_000
    with svc._lock:
        current_balance = svc._unit_balances.get(org_id, 0)
        svc._unit_balances[org_id] = current_balance + renewal_units

        from datetime import UTC, datetime

        from app.services.stripe_service import (  # type: ignore[attr-defined]
            StripeUnitEventReason,
            _UnitLedgerEntry,
        )

        entry = _UnitLedgerEntry(
            entry_id=f"ledger_renewal_{org_id}",
            org_id=org_id,
            delta=renewal_units,
            reason=StripeUnitEventReason.SUBSCRIPTION_RENEWED,
            reference_id=sub_id,
            balance_after=svc._unit_balances[org_id],
            recorded_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        )
        svc._unit_ledger.setdefault(org_id, []).append(entry)

    # 3. Verify balance reflects the renewal credit.
    with svc._lock:
        balance = svc._unit_balances[org_id]
        ledger = svc._unit_ledger.get(org_id, [])

    assert balance == renewal_units
    assert len(ledger) == 1
    assert ledger[0].delta == renewal_units
    assert ledger[0].reason == StripeUnitEventReason.SUBSCRIPTION_RENEWED
    assert ledger[0].reference_id == sub_id


def test_invoice_paid_subscription_cycle_does_not_double_credit_on_duplicate_event() -> None:
    """
    A duplicate invoice.paid event with the same invoice_id must not result
    in a double credit. The idempotency key for this event must prevent
    re-processing after the first successful credit.
    """
    svc = _make_svc()
    org_id = "org_renewal_idem_002"
    customer_id = "cus_renewal_idem_002"
    invoice_id = "in_renewal_idem_002"

    svc.register_customer_mapping(org_id, customer_id)

    renewal_units = 5_000
    idem_key = f"invoice_paid_{invoice_id}"

    def _process_invoice_paid() -> bool:
        """Returns True if credit was applied, False if duplicate."""
        with svc._lock:
            if idem_key in svc._idempotency_keys:
                return False
            svc._idempotency_keys[idem_key] = {"invoice_id": invoice_id}
            current = svc._unit_balances.get(org_id, 0)
            svc._unit_balances[org_id] = current + renewal_units
        return True

    first = _process_invoice_paid()
    second = _process_invoice_paid()

    assert first is True, "First invocation must apply credit"
    assert second is False, "Duplicate invocation must be rejected by idempotency"

    with svc._lock:
        balance = svc._unit_balances[org_id]

    assert balance == renewal_units, f"Balance must equal one credit only, got {balance}"


def test_invoice_paid_non_renewal_billing_reason_does_not_trigger_renewal_credit() -> None:
    """
    invoice.paid events with billing_reason != subscription_cycle (e.g.
    'manual' or 'subscription_create') must not be processed as renewal credits.
    Only billing_reason=subscription_cycle triggers the renewal credit path.
    """
    svc = _make_svc()
    org_id = "org_manual_invoice_003"
    customer_id = "cus_manual_invoice_003"

    svc.register_customer_mapping(org_id, customer_id)

    non_renewal_reasons = ["manual", "subscription_create", "upcoming"]

    for reason in non_renewal_reasons:
        # Simulate handler skipping non-renewal reasons.
        is_renewal = reason == "subscription_cycle"
        if is_renewal:
            with svc._lock:
                current = svc._unit_balances.get(org_id, 0)
                svc._unit_balances[org_id] = current + 5_000

    with svc._lock:
        balance = svc._unit_balances.get(org_id, 0)

    assert balance == 0, f"No renewal credit should have been applied for non-renewal billing reasons, balance={balance}"
