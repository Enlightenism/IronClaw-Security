from __future__ import annotations

from types import SimpleNamespace

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
import pytest

from app.core import auth as auth_module
from app.core.apikeys import (
    _ORG_KEY_PREFIX,
    APIKeyRegistry,
    create_org_key,
    fingerprint_api_key,
    generate_org_api_key,
    mask_api_key,
)
from app.core.auth import API_KEY_HEADER_NAME, get_api_key, require_api_key
from app.core.errors import AppError


def _build_app(
    *,
    auth_required: bool = True,
    api_key: str | None = None,
    admin_api_key: str | None = None,
) -> FastAPI:
    app = FastAPI()
    app.state.settings = SimpleNamespace(
        auth_required=auth_required,
        api_key=api_key,
        admin_api_key=admin_api_key,
    )
    return app


# ---------------------------------------------------------------------------
# Basic auth flow
# ---------------------------------------------------------------------------


def test_get_api_key_accepts_registry_key_when_auth_required() -> None:
    app = _build_app(auth_required=True)

    @app.get("/protected")
    def protected_route(value: str | None = Depends(get_api_key)) -> dict[str, str | None]:
        return {"api_key": value}

    registry = APIKeyRegistry()
    record = registry.create_key("Registry Test Key")

    original_get_registry = auth_module.get_api_key_registry
    auth_module.get_api_key_registry = lambda: registry
    try:
        client = TestClient(app)
        response = client.get("/protected", headers={API_KEY_HEADER_NAME: record.api_key})
    finally:
        auth_module.get_api_key_registry = original_get_registry

    assert response.status_code == 200
    assert response.json() == {"api_key": record.api_key}


def test_require_api_key_accepts_registry_key_when_auth_required() -> None:
    app = _build_app(auth_required=True)

    @app.get("/protected")
    def protected_route(value: str = Depends(require_api_key)) -> dict[str, str]:
        return {"api_key": value}

    registry = APIKeyRegistry()
    record = registry.create_key("Registry Require Key")

    original_get_registry = auth_module.get_api_key_registry
    auth_module.get_api_key_registry = lambda: registry
    try:
        client = TestClient(app)
        response = client.get("/protected", headers={API_KEY_HEADER_NAME: record.api_key})
    finally:
        auth_module.get_api_key_registry = original_get_registry

    assert response.status_code == 200
    assert response.json() == {"api_key": record.api_key}


def test_get_api_key_raises_auth_not_configured_when_required_without_any_keys() -> None:
    app = _build_app(auth_required=True)

    @app.get("/protected")
    def protected_route(value: str | None = Depends(get_api_key)) -> dict[str, str | None]:
        return {"api_key": value}

    original_get_registry = auth_module.get_api_key_registry
    auth_module.get_api_key_registry = lambda: APIKeyRegistry()
    try:
        client = TestClient(app)
        with pytest.raises(AppError) as exc_info:
            client.get("/protected", headers={API_KEY_HEADER_NAME: "some-key"})
    finally:
        auth_module.get_api_key_registry = original_get_registry

    assert exc_info.value.status_code == 503
    assert exc_info.value.error == "auth_not_configured"


def test_get_api_key_prefers_configured_key_over_invalid_registry_lookup() -> None:
    app = _build_app(auth_required=True, api_key="configured-secret")

    @app.get("/protected")
    def protected_route(value: str | None = Depends(get_api_key)) -> dict[str, str | None]:
        return {"api_key": value}

    original_get_registry = auth_module.get_api_key_registry
    auth_module.get_api_key_registry = lambda: APIKeyRegistry()
    try:
        client = TestClient(app)
        response = client.get("/protected", headers={API_KEY_HEADER_NAME: "configured-secret"})
    finally:
        auth_module.get_api_key_registry = original_get_registry

    assert response.status_code == 200
    assert response.json() == {"api_key": "configured-secret"}


def test_require_api_key_rejects_invalid_registry_key() -> None:
    app = _build_app(auth_required=True)

    @app.get("/protected")
    def protected_route(value: str = Depends(require_api_key)) -> dict[str, str]:
        return {"api_key": value}

    registry = APIKeyRegistry()
    registry.create_key("Valid Registry Key")

    original_get_registry = auth_module.get_api_key_registry
    auth_module.get_api_key_registry = lambda: registry
    try:
        client = TestClient(app)
        with pytest.raises(AppError) as exc_info:
            client.get("/protected", headers={API_KEY_HEADER_NAME: "invalid-registry-key"})
    finally:
        auth_module.get_api_key_registry = original_get_registry

    assert exc_info.value.status_code == 401
    assert exc_info.value.error == "invalid_api_key"


# ---------------------------------------------------------------------------
# generate_org_api_key
# ---------------------------------------------------------------------------


def test_generate_org_api_key_uses_org_prefix() -> None:
    key = generate_org_api_key()
    assert key.startswith(_ORG_KEY_PREFIX)


def test_system_api_key_registry_rejects_install_key_prefixes() -> None:
    with pytest.raises(ValueError, match="not install keys|install-key"):
        APIKeyRegistry().create_key("Paid Install Token", prefix="ic_install_openclaw_")

    with pytest.raises(ValueError, match="not install keys|install-key"):
        APIKeyRegistry().create_key("Install token", api_key="ic_install_claude_code_fake_key")


def test_api_key_classification_distinguishes_install_and_system_key_types() -> None:
    from app.core.apikeys import classify_api_key

    assert classify_api_key("ic_install_openclaw_secret_123") == "install"
    assert classify_api_key("ic_org_team_abc") == "org"
    assert classify_api_key("ic_system_secret_abc") == "system"
    assert classify_api_key("sk_live_abc") == "unknown"


def test_generate_org_api_key_is_unique() -> None:
    keys = {generate_org_api_key() for _ in range(20)}
    assert len(keys) == 20


# ---------------------------------------------------------------------------
# create_org_key (module-level factory)
# ---------------------------------------------------------------------------


def test_create_org_key_sets_key_type_org() -> None:
    record = create_org_key("org-test-001", "Shared Team Key")
    assert record.key_type == "org"


def test_create_org_key_sets_org_id() -> None:
    record = create_org_key("org-test-002", "Shared Team Key")
    assert record.org_id == "org-test-002"


def test_create_org_key_uses_org_prefix() -> None:
    record = create_org_key("org-test-003", "Shared Team Key")
    assert record.api_key.startswith(_ORG_KEY_PREFIX)


def test_create_org_key_masked_key_derived_from_raw() -> None:
    record = create_org_key("org-mask-001", "Mask Check Key")
    assert record.masked_key == mask_api_key(record.api_key)


def test_create_org_key_fingerprint_derived_from_raw() -> None:
    record = create_org_key("org-fp-001", "Fingerprint Check Key")
    assert record.fingerprint == fingerprint_api_key(record.api_key)


# ---------------------------------------------------------------------------
# APIKeyRegistry.create_key — org path
# ---------------------------------------------------------------------------


def test_registry_create_org_key_stores_key_type_and_org_id() -> None:
    registry = APIKeyRegistry()
    record = registry.create_key(
        "Team Key",
        key_type="org",
        org_id="org-registry-001",
    )
    assert record.key_type == "org"
    assert record.org_id == "org-registry-001"


def test_registry_create_org_key_authenticates_successfully() -> None:
    registry = APIKeyRegistry()
    record = registry.create_key(
        "Auth Org Key",
        key_type="org",
        org_id="org-auth-001",
    )
    authed = registry.authenticate(record.api_key, touch=False)
    assert authed is not None
    assert authed.key_id == record.key_id


# ---------------------------------------------------------------------------
# list_keys_by_org
# ---------------------------------------------------------------------------


def test_list_keys_by_org_returns_only_matching_org() -> None:
    registry = APIKeyRegistry()
    r1 = registry.create_key("Key A", key_type="org", org_id="org-alpha")
    r2 = registry.create_key("Key B", key_type="org", org_id="org-alpha")
    registry.create_key("Key C", key_type="org", org_id="org-beta")
    registry.create_key("Key D")  # personal, no org

    results = registry.list_keys_by_org("org-alpha")
    ids = {r.key_id for r in results}
    assert r1.key_id in ids
    assert r2.key_id in ids
    assert len(results) == 2


def test_list_keys_by_org_active_only_filters_revoked() -> None:
    registry = APIKeyRegistry()
    active = registry.create_key("Active Org Key", key_type="org", org_id="org-filter")
    revoked = registry.create_key("Revoked Org Key", key_type="org", org_id="org-filter")
    registry.revoke_key(revoked.key_id)

    results = registry.list_keys_by_org("org-filter", active_only=True)
    ids = {r.key_id for r in results}
    assert active.key_id in ids
    assert revoked.key_id not in ids


def test_list_keys_by_org_returns_empty_for_unknown_org() -> None:
    registry = APIKeyRegistry()
    registry.create_key("Personal Key")
    results = registry.list_keys_by_org("org-nonexistent")
    assert results == []


def test_list_keys_by_org_sorted_newest_first() -> None:
    registry = APIKeyRegistry()
    r1 = registry.create_key("First", key_type="org", org_id="org-sort")
    r2 = registry.create_key("Second", key_type="org", org_id="org-sort")
    results = registry.list_keys_by_org("org-sort")
    assert results[0].key_id == r2.key_id
    assert results[1].key_id == r1.key_id


# ---------------------------------------------------------------------------
# APIKeyRecord.key_type / org_id fields
# ---------------------------------------------------------------------------


def test_personal_key_defaults_to_personal_key_type() -> None:
    registry = APIKeyRegistry()
    record = registry.create_key("Personal Default")
    assert record.key_type == "personal"
    assert record.org_id is None


def test_org_key_record_fields_are_correct() -> None:
    registry = APIKeyRegistry()
    record = registry.create_key(
        "Team Shared Key",
        key_type="org",
        org_id="org-fields-001",
        owner_key="team@ironclaw.test",
    )
    assert record.key_type == "org"
    assert record.org_id == "org-fields-001"
    assert record.owner_key == "team@ironclaw.test"
    assert record.active is True


# ---------------------------------------------------------------------------
# public_dict() shape — key_type and org_id present
# ---------------------------------------------------------------------------


def test_public_dict_contains_key_type_and_org_id_for_personal() -> None:
    registry = APIKeyRegistry()
    record = registry.create_key("Public Dict Personal")
    d = record.public_dict()
    assert "key_type" in d
    assert "org_id" in d
    assert d["key_type"] == "personal"
    assert d["org_id"] is None


def test_public_dict_contains_key_type_and_org_id_for_org() -> None:
    registry = APIKeyRegistry()
    record = registry.create_key(
        "Public Dict Org",
        key_type="org",
        org_id="org-pubdict-001",
    )
    d = record.public_dict()
    assert d["key_type"] == "org"
    assert d["org_id"] == "org-pubdict-001"


def test_public_dict_does_not_expose_raw_api_key() -> None:
    registry = APIKeyRegistry()
    record = registry.create_key("No Raw Key Leak", key_type="org", org_id="org-leak-001")
    d = record.public_dict()
    assert "api_key" not in d
    assert "fingerprint" not in d


def test_public_dict_shape_is_complete() -> None:
    registry = APIKeyRegistry()
    record = registry.create_key("Shape Check", key_type="org", org_id="org-shape-001")
    d = record.public_dict()
    for field in (
        "key_id",
        "display_name",
        "masked_key",
        "created_at",
        "last_used_at",
        "active",
        "owner_key",
        "scopes",
        "rate_plan",
        "metadata",
        "key_type",
        "org_id",
    ):
        assert field in d, f"public_dict() missing field: {field!r}"


# ---------------------------------------------------------------------------
# rotate_key — prefix preservation for org keys
# ---------------------------------------------------------------------------


def test_rotate_key_preserves_org_prefix_for_org_key() -> None:
    registry = APIKeyRegistry()
    record = registry.create_key(
        "Rotate Org Key",
        key_type="org",
        org_id="org-rotate-001",
        prefix=_ORG_KEY_PREFIX,
    )
    rotated = registry.rotate_key(record.key_id)
    assert rotated is not None
    assert rotated.api_key.startswith(_ORG_KEY_PREFIX)


def test_rotate_key_preserves_personal_prefix_for_personal_key() -> None:
    from app.core.apikeys import _API_KEY_PREFIX

    registry = APIKeyRegistry()
    record = registry.create_key("Rotate Personal Key")
    rotated = registry.rotate_key(record.key_id)
    assert rotated is not None
    assert rotated.api_key.startswith(_API_KEY_PREFIX)


def test_rotate_key_old_secret_no_longer_authenticates() -> None:
    registry = APIKeyRegistry()
    record = registry.create_key("Rotate Auth Check", key_type="org", org_id="org-rot-auth")
    old_key = record.api_key
    registry.rotate_key(record.key_id)
    assert registry.authenticate(old_key, touch=False) is None


def test_rotate_key_new_secret_authenticates() -> None:
    registry = APIKeyRegistry()
    record = registry.create_key("Rotate New Auth", key_type="org", org_id="org-rot-new")
    rotated = registry.rotate_key(record.key_id)
    assert rotated is not None
    authed = registry.authenticate(rotated.api_key, touch=False)
    assert authed is not None
    assert authed.key_id == record.key_id


def test_rotate_key_preserves_org_id_and_key_type() -> None:
    registry = APIKeyRegistry()
    record = registry.create_key(
        "Rotate Preserve Fields",
        key_type="org",
        org_id="org-rot-preserve",
    )
    rotated = registry.rotate_key(record.key_id)
    assert rotated is not None
    assert rotated.key_type == "org"
    assert rotated.org_id == "org-rot-preserve"


def test_rotate_key_records_rotation_metadata() -> None:
    registry = APIKeyRegistry()
    record = registry.create_key("Rotate Meta", key_type="org", org_id="org-rot-meta")
    rotated = registry.rotate_key(record.key_id, rotated_by="admin-user")
    assert rotated is not None
    assert rotated.metadata.get("rotated_by") == "admin-user"
    assert "rotated_from_fingerprint" in rotated.metadata


# ---------------------------------------------------------------------------
# summary() — org_keys count
# ---------------------------------------------------------------------------


def test_summary_org_keys_count_is_zero_when_no_org_keys() -> None:
    registry = APIKeyRegistry()
    registry.create_key("Personal Only")
    s = registry.summary()
    assert s["org_keys"] == 0


def test_summary_org_keys_counts_only_org_key_type() -> None:
    registry = APIKeyRegistry()
    registry.create_key("Personal A")
    registry.create_key("Personal B")
    registry.create_key("Org Key A", key_type="org", org_id="org-sum-001")
    registry.create_key("Org Key B", key_type="org", org_id="org-sum-002")
    s = registry.summary()
    assert s["org_keys"] == 2
    assert s["total"] == 4


def test_summary_org_keys_includes_revoked_org_keys() -> None:
    registry = APIKeyRegistry()
    active_org = registry.create_key("Active Org", key_type="org", org_id="org-sum-rev")
    revoked_org = registry.create_key("Revoked Org", key_type="org", org_id="org-sum-rev")
    registry.revoke_key(revoked_org.key_id)
    s = registry.summary()
    assert s["org_keys"] == 2
    assert s["active"] == 1
    assert s["revoked"] == 1
    _ = active_org  # suppress unused warning


def test_summary_shape_is_complete() -> None:
    registry = APIKeyRegistry()
    s = registry.summary()
    for key in ("total", "active", "revoked", "org_keys"):
        assert key in s, f"summary() missing key: {key!r}"
