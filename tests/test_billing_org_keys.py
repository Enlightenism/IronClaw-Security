from __future__ import annotations

import os

os.environ.setdefault("IRONCLAW_PERSISTENCE_MODE", "memory")
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("IRONCLAW_API_KEY", "test-api-key")
os.environ.setdefault("AUTH_REQUIRED", "true")
os.environ.setdefault("IRONCLAW_RATE_LIMIT_ENABLED", "false")
os.environ.setdefault("SUPABASE_URL", "")
os.environ.setdefault("SUPABASE_SERVICE_ROLE_KEY", "")
os.environ.setdefault("SUPABASE_KEY", "")
os.environ.setdefault("SUPABASE_ANON_KEY", "")

from fastapi.testclient import TestClient
import pytest

from app.core.auth import (
    AuthContext,
    get_api_key,
    get_auth_context,
    require_api_key,
    require_auth_context,
)
import app.core.unit_wallet as _unit_wallet_module
from app.core.unit_wallet import (
    ORG_KEY_PREFIX,
    TOKEN_CHUNK_SIZE,
    UnitWalletRegistry,
    is_org_key,
)
from app.main import app as _app

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MOCK_API_KEY = "test-api-key"
_AUTH_HEADERS = {"X-API-Key": _MOCK_API_KEY}

_ORG_ID = "test-org-123"
_ORG_OWNER_KEY = f"{ORG_KEY_PREFIX}{_ORG_ID}"

_PERSONAL_EMAIL = "personal@ironclaw.test"
_MEMBER_A_EMAIL = "member-a@ironclaw.test"
_MEMBER_B_EMAIL = "member-b@ironclaw.test"

# ---------------------------------------------------------------------------
# Auth context factories
# ---------------------------------------------------------------------------


def _make_personal_auth_ctx() -> AuthContext:
    return AuthContext(
        api_key=_MOCK_API_KEY,
        principal_type="api_key",
        principal_id=None,
        session_id=None,
        org_id=None,
        authenticated=True,
        auth_source="test",
        auth_method="api_key",
        key_type="personal",
    )


def _make_org_auth_ctx(org_id: str = _ORG_ID) -> AuthContext:
    return AuthContext(
        api_key=_MOCK_API_KEY,
        principal_type="org_key",
        principal_id=f"{ORG_KEY_PREFIX}{org_id}",
        session_id=None,
        org_id=org_id,
        authenticated=True,
        auth_source="test",
        auth_method="api_key",
        key_type="org",
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_wallet_registry():
    """Guarantee a clean registry before AND after every test."""
    _unit_wallet_module._unit_wallet_registry = UnitWalletRegistry()
    yield
    _unit_wallet_module._unit_wallet_registry = UnitWalletRegistry()


def _install_overrides(auth_ctx_factory) -> None:
    _app.dependency_overrides[require_auth_context] = auth_ctx_factory
    _app.dependency_overrides[get_auth_context] = auth_ctx_factory
    _app.dependency_overrides[require_api_key] = lambda: _MOCK_API_KEY
    _app.dependency_overrides[get_api_key] = lambda: _MOCK_API_KEY


def _clear_overrides() -> None:
    for dep in (require_auth_context, get_auth_context, require_api_key, get_api_key):
        _app.dependency_overrides.pop(dep, None)


@pytest.fixture()
def client(_reset_wallet_registry):
    # Save nothing — _reset_wallet_registry guarantees isolation.
    # raise_server_exceptions=False so 4xx responses are returned, not raised.
    _install_overrides(_make_personal_auth_ctx)
    with TestClient(_app, raise_server_exceptions=False) as c:
        c.headers.update(_AUTH_HEADERS)
        yield c
    _clear_overrides()


@pytest.fixture()
def org_client(_reset_wallet_registry):
    _install_overrides(lambda: _make_org_auth_ctx(_ORG_ID))
    with TestClient(_app, raise_server_exceptions=False) as c:
        c.headers.update(_AUTH_HEADERS)
        yield c
    _clear_overrides()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _purchase(client: TestClient, *, buyer_email: str, package_id: str = "pkg_5000") -> dict:
    resp = client.post(
        "/billing/purchase",
        json={
            "package_id": package_id,
            "buyer_name": "Test Buyer",
            "buyer_email": buyer_email,
            "metadata": {},
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def _purchase_org(client: TestClient, *, package_id: str = "pkg_5000") -> dict:
    return _purchase(client, buyer_email=_ORG_OWNER_KEY, package_id=package_id)


def _debit(client: TestClient, *, owner_key: str, units: int = 100) -> tuple[int, dict]:
    resp = client.post(
        f"/billing/wallet/{owner_key}/debit",
        json={"units": units, "reason": "test_debit"},
    )
    return resp.status_code, resp.json()


def _wallet(client: TestClient, *, owner_key: str) -> tuple[int, dict]:
    resp = client.get(f"/billing/wallet/{owner_key}")
    return resp.status_code, resp.json()


def _ledger(client: TestClient, *, owner_key: str, limit: int = 50) -> dict:
    resp = client.get(f"/billing/wallet/{owner_key}/ledger", params={"limit": limit})
    assert resp.status_code == 200, resp.text
    return resp.json()


# ---------------------------------------------------------------------------
# Regression guard: stale route must never resolve
# ---------------------------------------------------------------------------


def test_stale_purchase_path_404_405_org_key(client: TestClient) -> None:
    """POST /billing/packages/purchase is NOT a valid route and must never resolve."""
    resp = client.post(
        "/billing/packages/purchase",
        json={
            "package_id": "pkg_5000",
            "buyer_name": "Ghost",
            "buyer_email": "ghost@ironclaw.test",
        },
    )
    assert resp.status_code in (404, 405)


# ---------------------------------------------------------------------------
# No-auth guard
# ---------------------------------------------------------------------------


def test_purchase_no_auth_returns_401() -> None:
    _app.dependency_overrides.clear()
    with TestClient(_app, raise_server_exceptions=False) as c:
        resp = c.post(
            "/billing/purchase",
            json={
                "package_id": "pkg_5000",
                "buyer_name": "No Auth",
                "buyer_email": "noauth@ironclaw.test",
            },
        )
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Sanity: ORG_KEY_PREFIX / is_org_key
# ---------------------------------------------------------------------------


def test_org_key_prefix_is_ic_org() -> None:
    assert ORG_KEY_PREFIX == "ic_org_"


def test_is_org_key_returns_true_for_org_prefix() -> None:
    assert is_org_key(_ORG_OWNER_KEY) is True


def test_is_org_key_returns_false_for_personal_email() -> None:
    assert is_org_key(_PERSONAL_EMAIL) is False


# ---------------------------------------------------------------------------
# test_org_purchase_creates_shared_wallet
# ---------------------------------------------------------------------------


def test_org_purchase_creates_shared_wallet(org_client: TestClient) -> None:
    body = _purchase_org(org_client)
    wallet = body["wallet"]

    assert wallet["owner_key"] == _ORG_OWNER_KEY
    assert wallet["balance_units"] == 5_000
    assert wallet["total_purchased_units"] == 5_000
    assert is_org_key(wallet["owner_key"]) is True


def test_org_purchase_wallet_id_is_stable_across_lookups(org_client: TestClient) -> None:
    body1 = _purchase_org(org_client)
    status_code, body2 = _wallet(org_client, owner_key=_ORG_OWNER_KEY)

    assert status_code == 200
    assert body1["wallet"]["wallet_id"] == body2["wallet"]["wallet_id"]


# ---------------------------------------------------------------------------
# test_two_members_debit_same_org_wallet
# ---------------------------------------------------------------------------


def test_two_members_purchase_pool_under_same_org_wallet(org_client: TestClient) -> None:
    body_a = _purchase(org_client, buyer_email=_ORG_OWNER_KEY, package_id="pkg_5000")
    body_b = _purchase(org_client, buyer_email=_ORG_OWNER_KEY, package_id="pkg_5000")

    assert body_a["wallet"]["wallet_id"] == body_b["wallet"]["wallet_id"]
    assert body_b["wallet"]["balance_units"] == 10_000
    assert body_b["wallet"]["total_purchased_units"] == 10_000
    assert body_b["wallet"]["owner_key"] == _ORG_OWNER_KEY


def test_two_members_debit_same_org_wallet(org_client: TestClient) -> None:
    _purchase_org(org_client, package_id="pkg_5000")

    status1, body1 = _debit(org_client, owner_key=_ORG_OWNER_KEY, units=1_000)
    assert status1 == 200
    assert body1["wallet"]["balance_units"] == 4_000

    status2, body2 = _debit(org_client, owner_key=_ORG_OWNER_KEY, units=500)
    assert status2 == 200
    assert body2["wallet"]["balance_units"] == 3_500

    assert body1["wallet"]["wallet_id"] == body2["wallet"]["wallet_id"]
    assert body1["wallet"]["owner_key"] == _ORG_OWNER_KEY
    assert body2["wallet"]["owner_key"] == _ORG_OWNER_KEY


def test_shared_org_wallet_balance_reflects_cumulative_debits(org_client: TestClient) -> None:
    _purchase_org(org_client, package_id="pkg_5000")

    _debit(org_client, owner_key=_ORG_OWNER_KEY, units=200)
    _debit(org_client, owner_key=_ORG_OWNER_KEY, units=300)

    _, wallet_body = _wallet(org_client, owner_key=_ORG_OWNER_KEY)
    w = wallet_body["wallet"]
    assert w["balance_units"] == 4_500
    assert w["total_consumed_units"] == 500
    assert w["owner_key"] == _ORG_OWNER_KEY


# ---------------------------------------------------------------------------
# Org key isolation — cannot touch personal wallet
# ---------------------------------------------------------------------------


def test_org_key_cannot_debit_personal_wallet_returns_402_insufficient(
    _reset_wallet_registry,
) -> None:
    # Personal wallet setup
    _install_overrides(_make_personal_auth_ctx)
    with TestClient(_app, raise_server_exceptions=False) as personal_c:
        personal_c.headers.update(_AUTH_HEADERS)
        _purchase(personal_c, buyer_email=_PERSONAL_EMAIL, package_id="pkg_5000")

    # Org wallet setup
    _install_overrides(lambda: _make_org_auth_ctx(_ORG_ID))
    with TestClient(_app, raise_server_exceptions=False) as org_c:
        org_c.headers.update(_AUTH_HEADERS)
        _purchase(org_c, buyer_email=_ORG_OWNER_KEY, package_id="pkg_5000")

    # Org key attempts to debit personal wallet — must be rejected
    _install_overrides(lambda: _make_org_auth_ctx(_ORG_ID))
    with TestClient(_app, raise_server_exceptions=False) as org_c:
        org_c.headers.update(_AUTH_HEADERS)
        status, body = _debit(org_c, owner_key=_PERSONAL_EMAIL, units=100)
        assert status in (402, 403)

        _, org_wallet_body = _wallet(org_c, owner_key=_ORG_OWNER_KEY)
        assert org_wallet_body["wallet"]["balance_units"] == 5_000
        assert org_wallet_body["wallet"]["total_consumed_units"] == 0

    _clear_overrides()


def test_org_key_debit_own_org_wallet_not_personal_wallet(
    _reset_wallet_registry,
) -> None:
    _install_overrides(_make_personal_auth_ctx)
    with TestClient(_app, raise_server_exceptions=False) as personal_c:
        personal_c.headers.update(_AUTH_HEADERS)
        _purchase(personal_c, buyer_email=_PERSONAL_EMAIL, package_id="pkg_5000")

    _install_overrides(lambda: _make_org_auth_ctx(_ORG_ID))
    with TestClient(_app, raise_server_exceptions=False) as org_c:
        org_c.headers.update(_AUTH_HEADERS)
        _purchase(org_c, buyer_email=_ORG_OWNER_KEY, package_id="pkg_5000")
        status, body = _debit(org_c, owner_key=_ORG_OWNER_KEY, units=250)
        assert status == 200
        assert body["wallet"]["owner_key"] == _ORG_OWNER_KEY
        assert body["wallet"]["balance_units"] == 4_750

    _install_overrides(_make_personal_auth_ctx)
    with TestClient(_app, raise_server_exceptions=False) as personal_c:
        personal_c.headers.update(_AUTH_HEADERS)
        _, personal_body = _wallet(personal_c, owner_key=_PERSONAL_EMAIL)
        assert personal_body["wallet"]["balance_units"] == 5_000
        assert personal_body["wallet"]["total_consumed_units"] == 0

    _clear_overrides()


# ---------------------------------------------------------------------------
# Personal key isolation — cannot touch org wallet
# ---------------------------------------------------------------------------


def test_personal_key_cannot_debit_org_wallet_returns_402(
    _reset_wallet_registry,
) -> None:
    _install_overrides(lambda: _make_org_auth_ctx(_ORG_ID))
    with TestClient(_app, raise_server_exceptions=False) as org_c:
        org_c.headers.update(_AUTH_HEADERS)
        _purchase(org_c, buyer_email=_ORG_OWNER_KEY, package_id="pkg_5000")

    _install_overrides(_make_personal_auth_ctx)
    with TestClient(_app, raise_server_exceptions=False) as personal_c:
        personal_c.headers.update(_AUTH_HEADERS)
        status, body = _debit(personal_c, owner_key=_PERSONAL_EMAIL, units=100)
        assert status == 402
        assert body["detail"]["have"] == 0
        assert body["detail"]["need"] == 100
        assert body["detail"]["owner_key"] == _PERSONAL_EMAIL

    _install_overrides(lambda: _make_org_auth_ctx(_ORG_ID))
    with TestClient(_app, raise_server_exceptions=False) as org_c:
        org_c.headers.update(_AUTH_HEADERS)
        _, org_body = _wallet(org_c, owner_key=_ORG_OWNER_KEY)
        assert org_body["wallet"]["balance_units"] == 5_000
        assert org_body["wallet"]["total_consumed_units"] == 0

    _clear_overrides()


def test_personal_key_debit_does_not_touch_org_wallet(
    _reset_wallet_registry,
) -> None:
    _install_overrides(lambda: _make_org_auth_ctx(_ORG_ID))
    with TestClient(_app, raise_server_exceptions=False) as org_c:
        org_c.headers.update(_AUTH_HEADERS)
        _purchase(org_c, buyer_email=_ORG_OWNER_KEY, package_id="pkg_5000")

    _install_overrides(_make_personal_auth_ctx)
    with TestClient(_app, raise_server_exceptions=False) as personal_c:
        personal_c.headers.update(_AUTH_HEADERS)
        _purchase(personal_c, buyer_email=_PERSONAL_EMAIL, package_id="pkg_5000")
        status, body = _debit(personal_c, owner_key=_PERSONAL_EMAIL, units=100)
        assert status == 200
        assert body["wallet"]["owner_key"] == _PERSONAL_EMAIL

    _install_overrides(lambda: _make_org_auth_ctx(_ORG_ID))
    with TestClient(_app, raise_server_exceptions=False) as org_c:
        org_c.headers.update(_AUTH_HEADERS)
        _, org_body = _wallet(org_c, owner_key=_ORG_OWNER_KEY)
        assert org_body["wallet"]["balance_units"] == 5_000
        assert org_body["wallet"]["total_consumed_units"] == 0

    _clear_overrides()


# ---------------------------------------------------------------------------
# Ledger — org wallet entries
# ---------------------------------------------------------------------------


def test_org_ledger_shows_all_member_debits(org_client: TestClient) -> None:
    _purchase_org(org_client, package_id="pkg_5000")

    _debit(org_client, owner_key=_ORG_OWNER_KEY, units=100)
    _debit(org_client, owner_key=_ORG_OWNER_KEY, units=200)

    ledger = _ledger(org_client, owner_key=_ORG_OWNER_KEY)
    entries = ledger["entries"]
    assert len(entries) >= 3

    debit_entries = [e for e in entries if e["entry_type"] == "debit"]
    assert len(debit_entries) == 2

    debit_units = sorted(e["units"] for e in debit_entries)
    assert debit_units == [100, 200]

    for entry in entries:
        assert entry["owner_key"] == _ORG_OWNER_KEY


def test_org_ledger_does_not_include_personal_wallet_entries(
    _reset_wallet_registry,
) -> None:
    _install_overrides(lambda: _make_org_auth_ctx(_ORG_ID))
    with TestClient(_app, raise_server_exceptions=False) as org_c:
        org_c.headers.update(_AUTH_HEADERS)
        _purchase(org_c, buyer_email=_ORG_OWNER_KEY, package_id="pkg_5000")
        _debit(org_c, owner_key=_ORG_OWNER_KEY, units=50)

    _install_overrides(_make_personal_auth_ctx)
    with TestClient(_app, raise_server_exceptions=False) as personal_c:
        personal_c.headers.update(_AUTH_HEADERS)
        _purchase(personal_c, buyer_email=_PERSONAL_EMAIL, package_id="pkg_5000")
        _debit(personal_c, owner_key=_PERSONAL_EMAIL, units=75)

    _install_overrides(lambda: _make_org_auth_ctx(_ORG_ID))
    with TestClient(_app, raise_server_exceptions=False) as org_c:
        org_c.headers.update(_AUTH_HEADERS)
        org_ledger = _ledger(org_c, owner_key=_ORG_OWNER_KEY)
        for entry in org_ledger["entries"]:
            assert entry["owner_key"] == _ORG_OWNER_KEY

    _install_overrides(_make_personal_auth_ctx)
    with TestClient(_app, raise_server_exceptions=False) as personal_c:
        personal_c.headers.update(_AUTH_HEADERS)
        personal_ledger = _ledger(personal_c, owner_key=_PERSONAL_EMAIL)
        for entry in personal_ledger["entries"]:
            assert entry["owner_key"] == _PERSONAL_EMAIL

    _clear_overrides()


# ---------------------------------------------------------------------------
# Ledger auto-scope behavior
# ---------------------------------------------------------------------------


def test_ledger_no_owner_key_uses_org_wallet(org_client: TestClient) -> None:
    _purchase_org(org_client, package_id="pkg_5000")
    ledger = _ledger(org_client, owner_key=_ORG_OWNER_KEY)
    assert any(e["owner_key"] == _ORG_OWNER_KEY for e in ledger["entries"])


def test_ledger_scoped_to_org_key_excludes_personal_entries(
    _reset_wallet_registry,
) -> None:
    _install_overrides(lambda: _make_org_auth_ctx(_ORG_ID))
    with TestClient(_app, raise_server_exceptions=False) as org_c:
        org_c.headers.update(_AUTH_HEADERS)
        _purchase(org_c, buyer_email=_ORG_OWNER_KEY, package_id="pkg_5000")
        _debit(org_c, owner_key=_ORG_OWNER_KEY, units=10)

    _install_overrides(_make_personal_auth_ctx)
    with TestClient(_app, raise_server_exceptions=False) as personal_c:
        personal_c.headers.update(_AUTH_HEADERS)
        _purchase(personal_c, buyer_email=_PERSONAL_EMAIL, package_id="pkg_5000")
        _debit(personal_c, owner_key=_PERSONAL_EMAIL, units=20)

    _install_overrides(lambda: _make_org_auth_ctx(_ORG_ID))
    with TestClient(_app, raise_server_exceptions=False) as org_c:
        org_c.headers.update(_AUTH_HEADERS)
        ledger = _ledger(org_c, owner_key=_ORG_OWNER_KEY)
        assert len(ledger["entries"]) >= 1
        for entry in ledger["entries"]:
            assert entry["owner_key"] == _ORG_OWNER_KEY
            assert entry["owner_key"] != _PERSONAL_EMAIL

    _clear_overrides()


def test_ledger_scoped_to_personal_key_excludes_org_entries(org_client: TestClient, client: TestClient) -> None:
    _purchase_org(org_client, package_id="pkg_5000")
    _purchase(client, buyer_email=_PERSONAL_EMAIL, package_id="pkg_5000")

    _debit(org_client, owner_key=_ORG_OWNER_KEY, units=10)
    _debit(client, owner_key=_PERSONAL_EMAIL, units=20)

    ledger = _ledger(client, owner_key=_PERSONAL_EMAIL)
    assert len(ledger["entries"]) >= 1
    for entry in ledger["entries"]:
        assert entry["owner_key"] == _PERSONAL_EMAIL
        assert not is_org_key(entry["owner_key"])


def test_personal_ledger_does_not_scope_to_org_wallet(
    _reset_wallet_registry,
) -> None:
    _install_overrides(_make_personal_auth_ctx)
    with TestClient(_app, raise_server_exceptions=False) as personal_c:
        personal_c.headers.update(_AUTH_HEADERS)
        _purchase(personal_c, buyer_email=_PERSONAL_EMAIL, package_id="pkg_5000")
        _debit(personal_c, owner_key=_PERSONAL_EMAIL, units=50)

    _install_overrides(lambda: _make_org_auth_ctx(_ORG_ID))
    with TestClient(_app, raise_server_exceptions=False) as org_c:
        org_c.headers.update(_AUTH_HEADERS)
        _purchase(org_c, buyer_email=_ORG_OWNER_KEY, package_id="pkg_5000")
        _debit(org_c, owner_key=_ORG_OWNER_KEY, units=75)

    _install_overrides(_make_personal_auth_ctx)
    with TestClient(_app, raise_server_exceptions=False) as personal_c:
        personal_c.headers.update(_AUTH_HEADERS)
        personal_ledger = _ledger(personal_c, owner_key=_PERSONAL_EMAIL)
        for entry in personal_ledger["entries"]:
            assert not is_org_key(entry["owner_key"])
            assert entry["owner_key"] == _PERSONAL_EMAIL

    _clear_overrides()


# ---------------------------------------------------------------------------
# Cross-org isolation
# ---------------------------------------------------------------------------


def test_org_key_cannot_debit_different_org_wallet_returns_402(
    _reset_wallet_registry,
) -> None:
    org_key_a = f"{ORG_KEY_PREFIX}alpha-org"
    org_key_b = f"{ORG_KEY_PREFIX}beta-org"

    def _auth_a() -> AuthContext:
        return AuthContext(
            api_key=_MOCK_API_KEY,
            principal_type="org_key",
            principal_id=org_key_a,
            session_id=None,
            org_id="alpha-org",
            authenticated=True,
            auth_source="test",
            auth_method="api_key",
            key_type="org",
        )

    def _auth_b() -> AuthContext:
        return AuthContext(
            api_key=_MOCK_API_KEY,
            principal_type="org_key",
            principal_id=org_key_b,
            session_id=None,
            org_id="beta-org",
            authenticated=True,
            auth_source="test",
            auth_method="api_key",
            key_type="org",
        )

    _install_overrides(_auth_a)
    with TestClient(_app, raise_server_exceptions=False) as ca:
        ca.headers.update(_AUTH_HEADERS)
        _purchase(ca, buyer_email=org_key_a, package_id="pkg_5000")

    # org_b attempts to debit org_b wallet (which has no balance) — 402 or 403
    _install_overrides(_auth_b)
    with TestClient(_app, raise_server_exceptions=False) as cb:
        cb.headers.update(_AUTH_HEADERS)
        status, body = _debit(cb, owner_key=org_key_b, units=100)
        assert status in (402, 403)

    # org_a wallet must be untouched
    _install_overrides(_auth_a)
    with TestClient(_app, raise_server_exceptions=False) as ca:
        ca.headers.update(_AUTH_HEADERS)
        _, body_a = _wallet(ca, owner_key=org_key_a)
        assert body_a["wallet"]["balance_units"] == 5_000
        assert body_a["wallet"]["total_consumed_units"] == 0

    _clear_overrides()


def test_org_a_and_org_b_have_independent_wallets(_reset_wallet_registry) -> None:
    org_key_a = f"{ORG_KEY_PREFIX}org-aaa"
    org_key_b = f"{ORG_KEY_PREFIX}org-bbb"

    def _auth_a() -> AuthContext:
        return AuthContext(
            api_key=_MOCK_API_KEY,
            principal_type="org_key",
            principal_id=org_key_a,
            session_id=None,
            org_id="org-aaa",
            authenticated=True,
            auth_source="test",
            auth_method="api_key",
            key_type="org",
        )

    def _auth_b() -> AuthContext:
        return AuthContext(
            api_key=_MOCK_API_KEY,
            principal_type="org_key",
            principal_id=org_key_b,
            session_id=None,
            org_id="org-bbb",
            authenticated=True,
            auth_source="test",
            auth_method="api_key",
            key_type="org",
        )

    _install_overrides(_auth_a)
    with TestClient(_app, raise_server_exceptions=False) as ca:
        ca.headers.update(_AUTH_HEADERS)
        _purchase(ca, buyer_email=org_key_a, package_id="pkg_5000")

    _install_overrides(_auth_b)
    with TestClient(_app, raise_server_exceptions=False) as cb:
        cb.headers.update(_AUTH_HEADERS)
        _purchase(cb, buyer_email=org_key_b, package_id="pkg_25000")

    _install_overrides(_auth_a)
    with TestClient(_app, raise_server_exceptions=False) as ca:
        ca.headers.update(_AUTH_HEADERS)
        _, body_a = _wallet(ca, owner_key=org_key_a)
        assert body_a["wallet"]["balance_units"] == 5_000
        _debit(ca, owner_key=org_key_a, units=1_000)
        _, body_a_after = _wallet(ca, owner_key=org_key_a)
        assert body_a_after["wallet"]["balance_units"] == 4_000

    _install_overrides(_auth_b)
    with TestClient(_app, raise_server_exceptions=False) as cb:
        cb.headers.update(_AUTH_HEADERS)
        _, body_b_after = _wallet(cb, owner_key=org_key_b)
        assert body_b_after["wallet"]["balance_units"] == 25_000

    _clear_overrides()


# ---------------------------------------------------------------------------
# Insufficient units — org wallet
# ---------------------------------------------------------------------------


def test_org_wallet_debit_exceeding_balance_returns_402(org_client: TestClient) -> None:
    _purchase_org(org_client, package_id="pkg_5000")

    status, body = _debit(org_client, owner_key=_ORG_OWNER_KEY, units=10_000)
    assert status == 402
    assert body["detail"]["have"] == 5_000
    assert body["detail"]["need"] == 10_000
    assert body["detail"]["owner_key"] == _ORG_OWNER_KEY


def test_org_wallet_debit_exact_balance_succeeds(org_client: TestClient) -> None:
    _purchase_org(org_client, package_id="pkg_5000")

    status, body = _debit(org_client, owner_key=_ORG_OWNER_KEY, units=5_000)
    assert status == 200
    assert body["wallet"]["balance_units"] == 0
    assert body["wallet"]["total_consumed_units"] == 5_000


# ---------------------------------------------------------------------------
# Wallet field shape
# ---------------------------------------------------------------------------


def test_org_wallet_response_shape_is_complete(org_client: TestClient) -> None:
    _purchase_org(org_client, package_id="pkg_5000")
    _, body = _wallet(org_client, owner_key=_ORG_OWNER_KEY)
    wallet = body["wallet"]

    required_fields = {
        "wallet_id",
        "owner_key",
        "balance_units",
        "total_purchased_units",
        "total_consumed_units",
        "total_refunded_units",
        "updated_at",
        "metadata",
    }
    for f in required_fields:
        assert f in wallet, f"Missing field: {f!r}"

    assert isinstance(wallet["wallet_id"], str)
    assert wallet["wallet_id"].startswith("wallet_")
    assert wallet["owner_key"] == _ORG_OWNER_KEY
    assert isinstance(wallet["balance_units"], int)
    assert isinstance(wallet["total_purchased_units"], int)
    assert isinstance(wallet["total_consumed_units"], int)
    assert isinstance(wallet["total_refunded_units"], int)


def test_org_purchase_response_wallet_owner_key_equals_org_owner_key(
    org_client: TestClient,
) -> None:
    body = _purchase_org(org_client)
    assert body["wallet"]["owner_key"] == _ORG_OWNER_KEY


def test_org_purchase_response_purchase_buyer_email_is_org_key(
    org_client: TestClient,
) -> None:
    body = _purchase_org(org_client)
    purchase = body["purchase"]
    assert purchase["buyer_email"] == _ORG_OWNER_KEY
    assert purchase["granted_units"] == 5_000
    assert purchase["tokens_per_unit"] == TOKEN_CHUNK_SIZE
    assert purchase["token_coverage"] == 5_000 * TOKEN_CHUNK_SIZE
