from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from app.core.apikeys import (
    APIKeyRecord,
    APIKeyRegistry,
    fingerprint_api_key,
    mask_api_key,
    utc_now_iso,
)
from app.main import app

# ---------------------------------------------------------------------------
# Stub out supabase_persistence before any route import resolves it
# ---------------------------------------------------------------------------
_persistence_stub = types.ModuleType("app.supabase_persistence")
_persistence_stub.upsert_install_key = MagicMock(return_value=None)
_persistence_stub.get_install_key = MagicMock(return_value=None)
_persistence_stub.list_install_keys_for_owner = MagicMock(return_value=[])
_persistence_stub.increment_install_key_units = MagicMock(return_value=None)
sys.modules.setdefault("app.supabase_persistence", _persistence_stub)

CLIENT = TestClient(app, raise_server_exceptions=True)
_ROUTE_PREFIX = "/customer-keys"
_TEST_API_KEY = "ic_test_ironclaw_internal_key"
_AUTH_HEADERS = {"X-API-Key": _TEST_API_KEY}

# ---------------------------------------------------------------------------
# Auth bypass
# ---------------------------------------------------------------------------


def _no_auth(request):  # type: ignore[override]
    return False


_auth_patch = patch("app.core.auth._is_auth_required", side_effect=_no_auth)


def setup_module(module):  # type: ignore[override]
    _auth_patch.start()


def teardown_module(module):  # type: ignore[override]
    _auth_patch.stop()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_record(
    *,
    key_id: str = "key_test0001",
    api_key: str = "ic_testkey_aaaabbbbccccdddd",
    display_name: str = "Test Customer Key",
    active: bool = True,
    scopes: tuple[str, ...] = ("read", "write"),
    owner_id: str = "customer-001",
    owner_type: str = "customer",
    environment: str = "production",
    extra_metadata: dict | None = None,
) -> APIKeyRecord:
    metadata: dict = {
        "owner_id": owner_id,
        "owner_type": owner_type,
        "environment": environment,
        "rotation_due": False,
    }
    if extra_metadata:
        metadata.update(extra_metadata)
    raw = api_key
    return APIKeyRecord(
        key_id=key_id,
        api_key=raw,
        masked_key=mask_api_key(raw),
        fingerprint=fingerprint_api_key(raw),
        display_name=display_name,
        scopes=scopes,
        active=active,
        created_at=utc_now_iso(),
        last_used_at=None,
        metadata=metadata,
    )


def _make_registry(records: list[APIKeyRecord]) -> APIKeyRegistry:
    registry = APIKeyRegistry()
    for record in records:
        registry.upsert_record(record)
    return registry


# ---------------------------------------------------------------------------
# POST /customer-keys — create
# ---------------------------------------------------------------------------


_PATCH_TARGET = "app.routes.customerkeys.get_api_key_registry"


class TestCreateCustomerKey:
    def test_create_returns_200_and_revealed_once_key(self) -> None:
        created_record: list[APIKeyRecord] = []
        real_registry = APIKeyRegistry()

        def _create_key(display_name: str, **kwargs):  # type: ignore[override]
            record = APIKeyRegistry.create_key(real_registry, display_name, **kwargs)
            created_record.append(record)
            return record

        mock_registry = MagicMock(spec=APIKeyRegistry)
        mock_registry.create_key.side_effect = _create_key

        with patch(_PATCH_TARGET, return_value=mock_registry):
            response = CLIENT.post(
                _ROUTE_PREFIX,
                json={
                    "label": "Integration Key",
                    "owner_type": "customer",
                    "owner_id": "customer-001",
                    "scopes": ["read", "write"],
                    "environment": "production",
                },
                headers=_AUTH_HEADERS,
            )

        assert response.status_code == 200
        body = response.json()
        assert body["operation"] == "create"
        assert body["key_status"] == "active"
        assert len(created_record) == 1
        assert body["revealed_once_key"] == created_record[0].api_key
        assert body["masked_key"] != body["revealed_once_key"]
        assert body["owner_type"] == "customer"
        assert body["owner_id"] == "customer-001"
        assert "read" in body["scopes"]
        assert "write" in body["scopes"]
        assert body["label"] == "Integration Key"

    def test_create_missing_label_returns_422(self) -> None:
        response = CLIENT.post(
            _ROUTE_PREFIX,
            json={"owner_type": "customer", "owner_id": "customer-001"},
            headers=_AUTH_HEADERS,
        )
        assert response.status_code == 422

    def test_create_sets_environment_in_metadata(self) -> None:
        created_record: list[APIKeyRecord] = []
        real_registry = APIKeyRegistry()

        def _create_key(display_name: str, **kwargs):  # type: ignore[override]
            record = APIKeyRegistry.create_key(real_registry, display_name, **kwargs)
            created_record.append(record)
            return record

        mock_registry = MagicMock(spec=APIKeyRegistry)
        mock_registry.create_key.side_effect = _create_key

        with patch(_PATCH_TARGET, return_value=mock_registry):
            response = CLIENT.post(
                _ROUTE_PREFIX,
                json={
                    "label": "Staging Key",
                    "owner_type": "org",
                    "owner_id": "org-999",
                    "scopes": ["admin"],
                    "environment": "staging",
                },
                headers=_AUTH_HEADERS,
            )

        assert response.status_code == 200
        body = response.json()
        assert body["metadata"]["environment"] == "staging"
        assert body["owner_id"] == "org-999"
        assert body["owner_type"] == "org"

    def test_create_notes_warn_about_single_reveal(self) -> None:
        real_registry = APIKeyRegistry()
        mock_registry = MagicMock(spec=APIKeyRegistry)
        mock_registry.create_key.side_effect = lambda dn, **kw: APIKeyRegistry.create_key(real_registry, dn, **kw)

        with patch(_PATCH_TARGET, return_value=mock_registry):
            response = CLIENT.post(
                _ROUTE_PREFIX,
                json={"label": "Note Check Key", "owner_id": "u1"},
                headers=_AUTH_HEADERS,
            )

        assert response.status_code == 200
        notes = response.json()["notes"]
        assert any("only" in n.lower() or "once" in n.lower() for n in notes)


# ---------------------------------------------------------------------------
# GET /customer-keys — list
# ---------------------------------------------------------------------------


class TestListCustomerKeys:
    def test_list_returns_all_keys(self) -> None:
        records = [
            _make_record(key_id="key_001", display_name="Key One", owner_id="owner-a"),
            _make_record(key_id="key_002", display_name="Key Two", owner_id="owner-b"),
        ]
        mock_registry = MagicMock(spec=APIKeyRegistry)
        mock_registry.list_keys.return_value = records

        with patch(_PATCH_TARGET, return_value=mock_registry):
            response = CLIENT.get(_ROUTE_PREFIX, headers=_AUTH_HEADERS)

        assert response.status_code == 200
        body = response.json()
        assert body["total"] == 2
        ids = [k["key_id"] for k in body["keys"]]
        assert "key_001" in ids
        assert "key_002" in ids

    def test_list_active_only_passes_flag(self) -> None:
        active_record = _make_record(key_id="key_active", active=True)
        mock_registry = MagicMock(spec=APIKeyRegistry)
        mock_registry.list_keys.return_value = [active_record]

        with patch(_PATCH_TARGET, return_value=mock_registry):
            response = CLIENT.get(
                _ROUTE_PREFIX,
                params={"active_only": True},
                headers=_AUTH_HEADERS,
            )

        assert response.status_code == 200
        mock_registry.list_keys.assert_called_once_with(active_only=True)
        assert response.json()["total"] == 1

    def test_list_filter_by_owner_id(self) -> None:
        records = [
            _make_record(key_id="key_a", owner_id="alpha"),
            _make_record(key_id="key_b", owner_id="beta"),
            _make_record(key_id="key_c", owner_id="alpha"),
        ]
        mock_registry = MagicMock(spec=APIKeyRegistry)
        mock_registry.list_keys.return_value = records

        with patch(_PATCH_TARGET, return_value=mock_registry):
            response = CLIENT.get(
                _ROUTE_PREFIX,
                params={"owner_id": "alpha"},
                headers=_AUTH_HEADERS,
            )

        assert response.status_code == 200
        body = response.json()
        assert body["total"] == 2
        for key in body["keys"]:
            assert key["owner_id"] == "alpha"

    def test_list_empty_registry_returns_zero(self) -> None:
        mock_registry = MagicMock(spec=APIKeyRegistry)
        mock_registry.list_keys.return_value = []

        with patch(_PATCH_TARGET, return_value=mock_registry):
            response = CLIENT.get(_ROUTE_PREFIX, headers=_AUTH_HEADERS)

        assert response.status_code == 200
        body = response.json()
        assert body["total"] == 0
        assert body["keys"] == []

    def test_list_revealed_once_key_is_none_for_existing(self) -> None:
        records = [_make_record(key_id="key_x")]
        mock_registry = MagicMock(spec=APIKeyRegistry)
        mock_registry.list_keys.return_value = records

        with patch(_PATCH_TARGET, return_value=mock_registry):
            response = CLIENT.get(_ROUTE_PREFIX, headers=_AUTH_HEADERS)

        assert response.status_code == 200
        for k in response.json()["keys"]:
            assert k["revealed_once_key"] is None


# ---------------------------------------------------------------------------
# GET /customer-keys/{key_id} — get single
# ---------------------------------------------------------------------------


class TestGetCustomerKey:
    def test_get_existing_key_returns_200(self) -> None:
        record = _make_record(key_id="key_get001", display_name="Fetchable Key")
        mock_registry = MagicMock(spec=APIKeyRegistry)
        mock_registry.get_by_id.return_value = record

        with patch(_PATCH_TARGET, return_value=mock_registry):
            response = CLIENT.get(
                f"{_ROUTE_PREFIX}/key_get001",
                headers=_AUTH_HEADERS,
            )

        assert response.status_code == 200
        body = response.json()
        assert body["key_id"] == "key_get001"
        assert body["label"] == "Fetchable Key"
        assert body["operation"] == "get"
        assert body["revealed_once_key"] is None

    def test_get_missing_key_returns_404(self) -> None:
        mock_registry = MagicMock(spec=APIKeyRegistry)
        mock_registry.get_by_id.return_value = None

        with patch(_PATCH_TARGET, return_value=mock_registry):
            response = CLIENT.get(
                f"{_ROUTE_PREFIX}/key_nonexistent",
                headers=_AUTH_HEADERS,
            )

        assert response.status_code == 404
        assert "not found" in response.json()["detail"].lower()

    def test_get_calls_registry_with_stripped_key_id(self) -> None:
        mock_registry = MagicMock(spec=APIKeyRegistry)
        mock_registry.get_by_id.return_value = None

        with patch(_PATCH_TARGET, return_value=mock_registry):
            CLIENT.get(
                f"{_ROUTE_PREFIX}/key_abc123",
                headers=_AUTH_HEADERS,
            )

        mock_registry.get_by_id.assert_called_once_with("key_abc123")


# ---------------------------------------------------------------------------
# POST /customer-keys/{key_id}/rotate
# ---------------------------------------------------------------------------


class TestRotateCustomerKey:
    def test_rotate_returns_new_key_and_reveals_it(self) -> None:
        old_raw = "ic_oldkey_xxxxyyyyzzzz0000"
        new_raw = "ic_newkey_aaaabbbbcccc1111"

        new_record = _make_record(
            key_id="key_rot001",
            api_key=new_raw,
            extra_metadata={
                "rotated_by": "system",
                "rotated_from_fingerprint": fingerprint_api_key(old_raw),
            },
        )

        mock_registry = MagicMock(spec=APIKeyRegistry)
        mock_registry.rotate_key.return_value = new_record

        with patch(_PATCH_TARGET, return_value=mock_registry):
            response = CLIENT.post(
                f"{_ROUTE_PREFIX}/key_rot001/rotate",
                headers=_AUTH_HEADERS,
            )

        assert response.status_code == 200
        body = response.json()
        assert body["operation"] == "rotate"
        assert body["key_status"] == "active"
        assert body["revealed_once_key"] == new_raw
        assert old_raw not in str(body)
        mock_registry.rotate_key.assert_called_once_with(
            "key_rot001",
            metadata={"rotation_due": False},
        )

    def test_rotate_missing_key_returns_404(self) -> None:
        mock_registry = MagicMock(spec=APIKeyRegistry)
        mock_registry.rotate_key.return_value = None

        with patch(_PATCH_TARGET, return_value=mock_registry):
            response = CLIENT.post(
                f"{_ROUTE_PREFIX}/key_missing/rotate",
                headers=_AUTH_HEADERS,
            )

        assert response.status_code == 404

    def test_rotate_old_key_no_longer_resolves(self) -> None:
        real_registry = APIKeyRegistry()
        old_raw = "ic_prerotate_aabbccdd1122"
        record = real_registry.create_key(
            "Rotatable",
            api_key=old_raw,
            scopes=["read"],
            metadata={"owner_id": "u1", "owner_type": "customer", "environment": "test"},
        )
        key_id = record.key_id

        with patch(_PATCH_TARGET, return_value=real_registry):
            response = CLIENT.post(
                f"{_ROUTE_PREFIX}/{key_id}/rotate",
                headers=_AUTH_HEADERS,
            )

        assert response.status_code == 200
        new_raw = response.json()["revealed_once_key"]
        assert new_raw != old_raw
        assert real_registry.authenticate(old_raw, touch=False) is None
        assert real_registry.authenticate(new_raw, touch=False) is not None


# ---------------------------------------------------------------------------
# POST /customer-keys/{key_id}/revoke
# ---------------------------------------------------------------------------


class TestRevokeCustomerKey:
    def test_revoke_returns_revoked_status(self) -> None:
        record = _make_record(key_id="key_rev001", active=True)
        revoked = APIKeyRecord(
            **{
                **record.__dict__,
                "active": False,
                "revoked_at": utc_now_iso(),
                "revoked_by": "system",
            }
        )

        mock_registry = MagicMock(spec=APIKeyRegistry)
        mock_registry.revoke_key.return_value = revoked

        with patch(_PATCH_TARGET, return_value=mock_registry):
            response = CLIENT.post(
                f"{_ROUTE_PREFIX}/key_rev001/revoke",
                headers=_AUTH_HEADERS,
            )

        assert response.status_code == 200
        body = response.json()
        assert body["operation"] == "revoke"
        assert body["key_status"] == "revoked"
        assert body["revealed_once_key"] is None

    def test_revoke_missing_key_returns_404(self) -> None:
        mock_registry = MagicMock(spec=APIKeyRegistry)
        mock_registry.revoke_key.return_value = None

        with patch(_PATCH_TARGET, return_value=mock_registry):
            response = CLIENT.post(
                f"{_ROUTE_PREFIX}/key_ghost/revoke",
                headers=_AUTH_HEADERS,
            )

        assert response.status_code == 404

    def test_revoke_idempotent_already_revoked(self) -> None:
        already_revoked = _make_record(key_id="key_rev002", active=False)

        mock_registry = MagicMock(spec=APIKeyRegistry)
        mock_registry.revoke_key.return_value = already_revoked

        with patch(_PATCH_TARGET, return_value=mock_registry):
            response = CLIENT.post(
                f"{_ROUTE_PREFIX}/key_rev002/revoke",
                headers=_AUTH_HEADERS,
            )

        assert response.status_code == 200
        assert response.json()["key_status"] == "revoked"

    def test_revoke_calls_registry_with_correct_key_id(self) -> None:
        record = _make_record(key_id="key_rev003", active=False)
        mock_registry = MagicMock(spec=APIKeyRegistry)
        mock_registry.revoke_key.return_value = record

        with patch(_PATCH_TARGET, return_value=mock_registry):
            CLIENT.post(
                f"{_ROUTE_PREFIX}/key_rev003/revoke",
                headers=_AUTH_HEADERS,
            )

        mock_registry.revoke_key.assert_called_once_with("key_rev003")


# ---------------------------------------------------------------------------
# Response shape contract
# ---------------------------------------------------------------------------


class TestResponseShapeContract:
    def test_create_response_has_required_fields(self) -> None:
        real_registry = APIKeyRegistry()
        mock_registry = MagicMock(spec=APIKeyRegistry)
        mock_registry.create_key.side_effect = lambda dn, **kw: APIKeyRegistry.create_key(real_registry, dn, **kw)

        with patch(_PATCH_TARGET, return_value=mock_registry):
            response = CLIENT.post(
                _ROUTE_PREFIX,
                json={"label": "Shape Check", "owner_id": "u1"},
                headers=_AUTH_HEADERS,
            )

        body = response.json()
        for field in (
            "status",
            "service",
            "timestamp",
            "operation",
            "key_id",
            "label",
            "key_status",
            "masked_key",
            "revealed_once_key",
            "created_at",
            "owner_type",
            "owner_id",
            "scopes",
            "metadata",
            "notes",
        ):
            assert field in body, f"Missing field: {field}"

        assert body["status"] == "ok"
        assert body["service"] == "IronClaw-Security"

    def test_list_response_has_required_fields(self) -> None:
        mock_registry = MagicMock(spec=APIKeyRegistry)
        mock_registry.list_keys.return_value = []

        with patch(_PATCH_TARGET, return_value=mock_registry):
            response = CLIENT.get(_ROUTE_PREFIX, headers=_AUTH_HEADERS)

        body = response.json()
        for field in ("status", "service", "timestamp", "total", "keys"):
            assert field in body, f"Missing field: {field}"
