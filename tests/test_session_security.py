from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.core.session_security import (
    SessionPolicy,
    SessionPrincipal,
    SessionRecord,
    SessionValidationResult,
    build_session_principal,
    constant_time_equals,
    create_session_record,
    fingerprint_session_secret,
    generate_session_id,
    generate_session_secret,
    revoke_session_record,
    rotate_session_secret,
    session_is_active,
    touch_session_record,
    validate_session_record,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_DEFAULT_POLICY = SessionPolicy()


def _principal(
    *,
    principal_id: str = "p-001",
    principal_type: str = "api_key",
    org_id: str | None = "org-001",
    roles: tuple[str, ...] = (),
    permissions: tuple[str, ...] = (),
) -> SessionPrincipal:
    return SessionPrincipal(
        principal_id=principal_id,
        principal_type=principal_type,
        org_id=org_id,
        roles=roles,
        permissions=permissions,
    )


def _now() -> datetime:
    return datetime.now(UTC)


def _record_and_secret(
    *,
    policy: SessionPolicy | None = None,
    ip_address: str | None = None,
    user_agent: str | None = "TestAgent/1.0",
    now: datetime | None = None,
    metadata: dict[str, object] | None = None,
) -> tuple[SessionRecord, str]:
    principal = _principal()
    return create_session_record(
        principal=principal,
        policy=policy,
        ip_address=ip_address,
        user_agent=user_agent,
        now=now,
        metadata=metadata,
    )


# ---------------------------------------------------------------------------
# generate_session_id
# ---------------------------------------------------------------------------


def test_generate_session_id_default_prefix() -> None:
    sid = generate_session_id()
    assert sid.startswith("sess_")


def test_generate_session_id_custom_prefix() -> None:
    sid = generate_session_id(prefix="tok")
    assert sid.startswith("tok_")


def test_generate_session_id_normalizes_prefix_to_lower() -> None:
    sid = generate_session_id(prefix="SESS")
    assert sid.startswith("sess_")


def test_generate_session_id_empty_prefix_uses_default() -> None:
    sid = generate_session_id(prefix="  ")
    assert sid.startswith("sess_")


def test_generate_session_id_uniqueness() -> None:
    ids = {generate_session_id() for _ in range(50)}
    assert len(ids) == 50


def test_generate_session_id_min_length() -> None:
    sid = generate_session_id()
    assert len(sid) > 10


# ---------------------------------------------------------------------------
# generate_session_secret
# ---------------------------------------------------------------------------


def test_generate_session_secret_default_length() -> None:
    secret = generate_session_secret()
    assert len(secret) >= 32


def test_generate_session_secret_custom_length() -> None:
    secret = generate_session_secret(length=96)
    assert len(secret) >= 80


def test_generate_session_secret_floor_enforced() -> None:
    secret = generate_session_secret(length=1)
    assert len(secret) >= 32


def test_generate_session_secret_uniqueness() -> None:
    secrets = {generate_session_secret() for _ in range(50)}
    assert len(secrets) == 50


def test_generate_session_secret_url_safe_chars() -> None:
    import re

    secret = generate_session_secret()
    assert re.fullmatch(r"[A-Za-z0-9_\-]+", secret)


# ---------------------------------------------------------------------------
# fingerprint_session_secret
# ---------------------------------------------------------------------------


def test_fingerprint_session_secret_deterministic() -> None:
    fp1 = fingerprint_session_secret("my-secret")
    fp2 = fingerprint_session_secret("my-secret")
    assert fp1 == fp2


def test_fingerprint_session_secret_different_inputs_differ() -> None:
    fp1 = fingerprint_session_secret("secret-a")
    fp2 = fingerprint_session_secret("secret-b")
    assert fp1 != fp2


def test_fingerprint_session_secret_empty_returns_empty() -> None:
    assert fingerprint_session_secret("") == ""
    assert fingerprint_session_secret("   ") == ""


def test_fingerprint_session_secret_strips_whitespace() -> None:
    fp1 = fingerprint_session_secret("secret")
    fp2 = fingerprint_session_secret(" secret ")
    assert fp1 == fp2


def test_fingerprint_session_secret_hex_output() -> None:
    fp = fingerprint_session_secret("x")
    assert len(fp) == 64
    assert all(c in "0123456789abcdef" for c in fp)


# ---------------------------------------------------------------------------
# constant_time_equals
# ---------------------------------------------------------------------------


def test_constant_time_equals_same() -> None:
    assert constant_time_equals("abc", "abc") is True


def test_constant_time_equals_different() -> None:
    assert constant_time_equals("abc", "xyz") is False


def test_constant_time_equals_strips_whitespace() -> None:
    assert constant_time_equals(" abc ", " abc ") is True


def test_constant_time_equals_empty_strings() -> None:
    assert constant_time_equals("", "") is True


def test_constant_time_equals_empty_vs_nonempty() -> None:
    assert constant_time_equals("", "abc") is False


# ---------------------------------------------------------------------------
# SessionPolicy
# ---------------------------------------------------------------------------


def test_session_policy_defaults() -> None:
    p = SessionPolicy()
    assert p.idle_timeout_seconds == 1800
    assert p.absolute_timeout_seconds == 43200
    assert p.renewal_window_seconds == 300
    assert p.require_ip_binding is False
    assert p.require_user_agent_binding is True
    assert p.enforce_secret_rotation is True


def test_session_policy_to_dict_shape() -> None:
    d = SessionPolicy().to_dict()
    assert set(d.keys()) == {
        "idle_timeout_seconds",
        "absolute_timeout_seconds",
        "renewal_window_seconds",
        "require_ip_binding",
        "require_user_agent_binding",
        "enforce_secret_rotation",
    }


def test_session_policy_to_dict_values() -> None:
    p = SessionPolicy(
        idle_timeout_seconds=900,
        absolute_timeout_seconds=3600,
        renewal_window_seconds=60,
        require_ip_binding=True,
        require_user_agent_binding=False,
        enforce_secret_rotation=False,
    )
    d = p.to_dict()
    assert d["idle_timeout_seconds"] == 900
    assert d["absolute_timeout_seconds"] == 3600
    assert d["renewal_window_seconds"] == 60
    assert d["require_ip_binding"] is True
    assert d["require_user_agent_binding"] is False
    assert d["enforce_secret_rotation"] is False


# ---------------------------------------------------------------------------
# SessionPrincipal
# ---------------------------------------------------------------------------


def test_session_principal_to_dict_shape() -> None:
    p = _principal(roles=("admin",), permissions=("read",))
    d = p.to_dict()
    assert set(d.keys()) == {
        "principal_id",
        "principal_type",
        "org_id",
        "roles",
        "permissions",
    }
    assert isinstance(d["roles"], list)
    assert isinstance(d["permissions"], list)


def test_session_principal_to_dict_values() -> None:
    p = _principal(
        principal_id="p-abc",
        principal_type="user",
        org_id="org-xyz",
        roles=("admin", "viewer"),
        permissions=("read", "write"),
    )
    d = p.to_dict()
    assert d["principal_id"] == "p-abc"
    assert d["principal_type"] == "user"
    assert d["org_id"] == "org-xyz"
    assert set(d["roles"]) == {"admin", "viewer"}
    assert set(d["permissions"]) == {"read", "write"}


# ---------------------------------------------------------------------------
# build_session_principal
# ---------------------------------------------------------------------------


def test_build_session_principal_basic() -> None:
    p = build_session_principal(principal_id="p-1", principal_type="api_key")
    assert p.principal_id == "p-1"
    assert p.principal_type == "api_key"
    assert p.org_id is None
    assert p.roles == ()
    assert p.permissions == ()


def test_build_session_principal_normalizes_type_to_lower() -> None:
    p = build_session_principal(principal_id="p-1", principal_type="API_KEY")
    assert p.principal_type == "api_key"


def test_build_session_principal_strips_principal_id() -> None:
    p = build_session_principal(principal_id=" p-1 ", principal_type="api_key")
    assert p.principal_id == "p-1"


def test_build_session_principal_org_id_stripped() -> None:
    p = build_session_principal(principal_id="p-1", principal_type="api_key", org_id=" org-a ")
    assert p.org_id == "org-a"


def test_build_session_principal_empty_org_id_becomes_none() -> None:
    p = build_session_principal(principal_id="p-1", principal_type="api_key", org_id="  ")
    assert p.org_id is None


def test_build_session_principal_deduplicates_roles() -> None:
    p = build_session_principal(
        principal_id="p-1",
        principal_type="api_key",
        roles=["admin", "admin", "viewer"],
    )
    assert len(p.roles) == 2
    assert "admin" in p.roles
    assert "viewer" in p.roles


def test_build_session_principal_normalizes_roles_lower() -> None:
    p = build_session_principal(
        principal_id="p-1",
        principal_type="api_key",
        roles=["ADMIN", "Viewer"],
    )
    assert "admin" in p.roles
    assert "viewer" in p.roles


def test_build_session_principal_empty_type_becomes_unknown() -> None:
    p = build_session_principal(principal_id="p-1", principal_type="  ")
    assert p.principal_type == "unknown"


# ---------------------------------------------------------------------------
# create_session_record
# ---------------------------------------------------------------------------


def test_create_session_record_returns_tuple() -> None:
    record, secret = _record_and_secret()
    assert isinstance(record, SessionRecord)
    assert isinstance(secret, str)
    assert len(secret) >= 32


def test_create_session_record_secret_fingerprinted() -> None:
    record, secret = _record_and_secret()
    assert record.secret_fingerprint == fingerprint_session_secret(secret)


def test_create_session_record_timestamps_utc() -> None:
    now = _now()
    record, _ = _record_and_secret(now=now)
    assert record.issued_at.tzinfo is not None
    assert record.expires_at.tzinfo is not None
    assert record.idle_expires_at.tzinfo is not None
    assert record.last_seen_at.tzinfo is not None


def test_create_session_record_expires_at_absolute_timeout() -> None:
    now = _now()
    policy = SessionPolicy(absolute_timeout_seconds=3600)
    record, _ = _record_and_secret(policy=policy, now=now)
    delta = (record.expires_at - now).total_seconds()
    assert abs(delta - 3600) < 2


def test_create_session_record_idle_expires_at_idle_timeout() -> None:
    now = _now()
    policy = SessionPolicy(idle_timeout_seconds=600)
    record, _ = _record_and_secret(policy=policy, now=now)
    delta = (record.idle_expires_at - now).total_seconds()
    assert abs(delta - 600) < 2


def test_create_session_record_issued_at_equals_last_seen_at() -> None:
    now = _now()
    record, _ = _record_and_secret(now=now)
    assert record.issued_at == record.last_seen_at


def test_create_session_record_active_on_creation() -> None:
    record, _ = _record_and_secret()
    assert record.active is True
    assert record.revoked_at is None
    assert record.revocation_reason is None


def test_create_session_record_ip_stored() -> None:
    record, _ = _record_and_secret(ip_address="1.2.3.4")
    assert record.created_ip == "1.2.3.4"
    assert record.last_ip == "1.2.3.4"


def test_create_session_record_user_agent_stored() -> None:
    record, _ = _record_and_secret(user_agent="Mozilla/5.0")
    assert record.user_agent == "Mozilla/5.0"


def test_create_session_record_metadata_stringified() -> None:
    record, _ = _record_and_secret(metadata={"count": 5, "flag": True})
    assert record.metadata["count"] == "5"
    assert record.metadata["flag"] == "True"


def test_create_session_record_no_metadata_empty_dict() -> None:
    record, _ = _record_and_secret()
    assert record.metadata == {}


def test_create_session_record_session_id_prefixed() -> None:
    record, _ = _record_and_secret()
    assert record.session_id.startswith("sess_")


def test_create_session_record_explicit_session_id() -> None:
    principal = _principal()
    record, _ = create_session_record(principal=principal, session_id="sess_custom-123")
    assert record.session_id == "sess_custom-123"


def test_create_session_record_explicit_secret_respected() -> None:
    principal = _principal()
    record, returned_secret = create_session_record(principal=principal, secret="my-fixed-secret")
    assert returned_secret == "my-fixed-secret"
    assert record.secret_fingerprint == fingerprint_session_secret("my-fixed-secret")


# ---------------------------------------------------------------------------
# SessionRecord.to_dict
# ---------------------------------------------------------------------------


def test_session_record_to_dict_shape() -> None:
    record, _ = _record_and_secret()
    d = record.to_dict()
    expected_keys = {
        "session_id",
        "principal",
        "secret_fingerprint",
        "issued_at",
        "expires_at",
        "idle_expires_at",
        "last_seen_at",
        "created_ip",
        "last_ip",
        "user_agent",
        "rotated_at",
        "revoked_at",
        "revocation_reason",
        "active",
        "metadata",
    }
    assert expected_keys.issubset(set(d.keys()))


def test_session_record_to_dict_isoformat_timestamps() -> None:
    record, _ = _record_and_secret()
    d = record.to_dict()
    for key in ("issued_at", "expires_at", "idle_expires_at", "last_seen_at"):
        assert isinstance(d[key], str)
        datetime.fromisoformat(d[key])


def test_session_record_to_dict_revoked_at_none() -> None:
    record, _ = _record_and_secret()
    assert record.to_dict()["revoked_at"] is None


def test_session_record_to_dict_rotated_at_none() -> None:
    record, _ = _record_and_secret()
    assert record.to_dict()["rotated_at"] is None


# ---------------------------------------------------------------------------
# validate_session_record — valid
# ---------------------------------------------------------------------------


def test_validate_session_record_valid() -> None:
    now = _now()
    record, secret = _record_and_secret(now=now)
    result = validate_session_record(record, presented_secret=secret, now=now, user_agent="TestAgent/1.0")
    assert result.valid is True
    assert result.reason == "valid"
    assert result.session_id == record.session_id
    assert result.principal_id == record.principal.principal_id
    assert result.org_id == record.principal.org_id


# ---------------------------------------------------------------------------
# validate_session_record — revoked
# ---------------------------------------------------------------------------


def test_validate_session_record_revoked() -> None:
    now = _now()
    record, secret = _record_and_secret(now=now)
    revoked = revoke_session_record(record, reason="admin_logout", now=now)
    result = validate_session_record(revoked, presented_secret=secret, now=now, user_agent="TestAgent/1.0")
    assert result.valid is False
    assert result.reason == "session_revoked"


# ---------------------------------------------------------------------------
# validate_session_record — absolute expiry
# ---------------------------------------------------------------------------


def test_validate_session_record_expired_absolute() -> None:
    now = _now()
    policy = SessionPolicy(absolute_timeout_seconds=10, idle_timeout_seconds=3600)
    record, secret = _record_and_secret(policy=policy, now=now)
    future = now + timedelta(seconds=20)
    result = validate_session_record(
        record,
        presented_secret=secret,
        policy=policy,
        now=future,
        user_agent="TestAgent/1.0",
    )
    assert result.valid is False
    assert result.reason == "session_expired"


# ---------------------------------------------------------------------------
# validate_session_record — idle timeout
# ---------------------------------------------------------------------------


def test_validate_session_record_idle_timeout() -> None:
    now = _now()
    policy = SessionPolicy(idle_timeout_seconds=10, absolute_timeout_seconds=3600)
    record, secret = _record_and_secret(policy=policy, now=now)
    future = now + timedelta(seconds=20)
    result = validate_session_record(
        record,
        presented_secret=secret,
        policy=policy,
        now=future,
        user_agent="TestAgent/1.0",
    )
    assert result.valid is False
    assert result.reason == "session_idle_timeout"


# ---------------------------------------------------------------------------
# validate_session_record — invalid secret
# ---------------------------------------------------------------------------


def test_validate_session_record_invalid_secret() -> None:
    now = _now()
    record, _ = _record_and_secret(now=now)
    result = validate_session_record(
        record,
        presented_secret="wrong-secret",
        now=now,
        user_agent="TestAgent/1.0",
    )
    assert result.valid is False
    assert result.reason == "invalid_session_secret"


def test_validate_session_record_empty_secret_rejected() -> None:
    now = _now()
    record, _ = _record_and_secret(now=now)
    result = validate_session_record(
        record,
        presented_secret="",
        now=now,
        user_agent="TestAgent/1.0",
    )
    assert result.valid is False
    assert result.reason == "invalid_session_secret"


# ---------------------------------------------------------------------------
# validate_session_record — IP binding
# ---------------------------------------------------------------------------


def test_validate_session_record_ip_binding_match() -> None:
    now = _now()
    policy = SessionPolicy(require_ip_binding=True, require_user_agent_binding=False)
    record, secret = _record_and_secret(policy=policy, ip_address="10.0.0.1", now=now)
    result = validate_session_record(
        record,
        presented_secret=secret,
        policy=policy,
        now=now,
        ip_address="10.0.0.1",
    )
    assert result.valid is True


def test_validate_session_record_ip_binding_mismatch() -> None:
    now = _now()
    policy = SessionPolicy(require_ip_binding=True, require_user_agent_binding=False)
    record, secret = _record_and_secret(policy=policy, ip_address="10.0.0.1", now=now)
    result = validate_session_record(
        record,
        presented_secret=secret,
        policy=policy,
        now=now,
        ip_address="10.0.0.2",
    )
    assert result.valid is False
    assert result.reason == "ip_binding_mismatch"
    assert result.metadata["expected_ip"] == "10.0.0.1"
    assert result.metadata["presented_ip"] == "10.0.0.2"


def test_validate_session_record_ip_binding_disabled_mismatch_ignored() -> None:
    now = _now()
    policy = SessionPolicy(require_ip_binding=False, require_user_agent_binding=False)
    record, secret = _record_and_secret(policy=policy, ip_address="10.0.0.1", now=now)
    result = validate_session_record(
        record,
        presented_secret=secret,
        policy=policy,
        now=now,
        ip_address="10.0.0.99",
    )
    assert result.valid is True


# ---------------------------------------------------------------------------
# validate_session_record — user agent binding
# ---------------------------------------------------------------------------


def test_validate_session_record_user_agent_binding_match() -> None:
    now = _now()
    policy = SessionPolicy(require_user_agent_binding=True, require_ip_binding=False)
    record, secret = _record_and_secret(policy=policy, user_agent="Mozilla/5.0", now=now)
    result = validate_session_record(
        record,
        presented_secret=secret,
        policy=policy,
        now=now,
        user_agent="Mozilla/5.0",
    )
    assert result.valid is True


def test_validate_session_record_user_agent_mismatch() -> None:
    now = _now()
    policy = SessionPolicy(require_user_agent_binding=True, require_ip_binding=False)
    record, secret = _record_and_secret(policy=policy, user_agent="Mozilla/5.0", now=now)
    result = validate_session_record(
        record,
        presented_secret=secret,
        policy=policy,
        now=now,
        user_agent="curl/7.x",
    )
    assert result.valid is False
    assert result.reason == "user_agent_mismatch"
    assert result.metadata["expected_user_agent"] == "Mozilla/5.0"
    assert result.metadata["presented_user_agent"] == "curl/7.x"


def test_validate_session_record_user_agent_binding_disabled_mismatch_ignored() -> None:
    now = _now()
    policy = SessionPolicy(require_user_agent_binding=False, require_ip_binding=False)
    record, secret = _record_and_secret(policy=policy, user_agent="Mozilla/5.0", now=now)
    result = validate_session_record(
        record,
        presented_secret=secret,
        policy=policy,
        now=now,
        user_agent="curl/7.x",
    )
    assert result.valid is True


# ---------------------------------------------------------------------------
# validate_session_record — should_rotate
# ---------------------------------------------------------------------------


def test_validate_session_record_should_rotate_in_renewal_window() -> None:
    now = _now()
    policy = SessionPolicy(
        absolute_timeout_seconds=100,
        renewal_window_seconds=60,
        idle_timeout_seconds=3600,
        enforce_secret_rotation=True,
        require_user_agent_binding=False,
    )
    record, secret = _record_and_secret(policy=policy, now=now)
    within_window = now + timedelta(seconds=50)
    result = validate_session_record(record, presented_secret=secret, policy=policy, now=within_window)
    assert result.valid is True
    assert result.should_rotate is True


def test_validate_session_record_should_not_rotate_outside_renewal_window() -> None:
    now = _now()
    policy = SessionPolicy(
        absolute_timeout_seconds=3600,
        renewal_window_seconds=300,
        idle_timeout_seconds=7200,
        enforce_secret_rotation=True,
        require_user_agent_binding=False,
    )
    record, secret = _record_and_secret(policy=policy, now=now)
    early = now + timedelta(seconds=10)
    result = validate_session_record(record, presented_secret=secret, policy=policy, now=early)
    assert result.valid is True
    assert result.should_rotate is False


def test_validate_session_record_rotation_disabled_never_rotates() -> None:
    now = _now()
    policy = SessionPolicy(
        absolute_timeout_seconds=100,
        renewal_window_seconds=60,
        idle_timeout_seconds=3600,
        enforce_secret_rotation=False,
        require_user_agent_binding=False,
    )
    record, secret = _record_and_secret(policy=policy, now=now)
    within_window = now + timedelta(seconds=50)
    result = validate_session_record(record, presented_secret=secret, policy=policy, now=within_window)
    assert result.valid is True
    assert result.should_rotate is False


# ---------------------------------------------------------------------------
# validate_session_record — revocation checked before expiry
# ---------------------------------------------------------------------------


def test_validate_session_record_revocation_before_expiry_check() -> None:
    now = _now()
    policy = SessionPolicy(absolute_timeout_seconds=1, idle_timeout_seconds=1)
    record, secret = _record_and_secret(policy=policy, now=now)
    revoked = revoke_session_record(record, reason="test_order", now=now)
    future = now + timedelta(seconds=10)
    result = validate_session_record(
        revoked,
        presented_secret=secret,
        policy=policy,
        now=future,
        user_agent="TestAgent/1.0",
    )
    assert result.valid is False
    assert result.reason == "session_revoked"


# ---------------------------------------------------------------------------
# SessionValidationResult.to_dict
# ---------------------------------------------------------------------------


def test_session_validation_result_to_dict_shape() -> None:
    result = SessionValidationResult(
        valid=True,
        reason="valid",
        session_id="sess_abc",
        principal_id="p-001",
        org_id="org-001",
        should_rotate=False,
        metadata={},
    )
    d = result.to_dict()
    assert set(d.keys()) == {
        "valid",
        "reason",
        "session_id",
        "principal_id",
        "org_id",
        "should_rotate",
        "metadata",
    }


def test_session_validation_result_to_dict_values() -> None:
    result = SessionValidationResult(
        valid=False,
        reason="session_expired",
        session_id="sess_x",
        principal_id="p-002",
        org_id=None,
        should_rotate=False,
        metadata={"detail": "past"},
    )
    d = result.to_dict()
    assert d["valid"] is False
    assert d["reason"] == "session_expired"
    assert d["org_id"] is None
    assert d["metadata"] == {"detail": "past"}


# ---------------------------------------------------------------------------
# touch_session_record
# ---------------------------------------------------------------------------


def test_touch_session_record_updates_last_seen_at() -> None:
    now = _now()
    record, _ = _record_and_secret(now=now)
    future = now + timedelta(seconds=30)
    touched = touch_session_record(record, now=future)
    assert touched.last_seen_at == future


def test_touch_session_record_extends_idle_expiry() -> None:
    now = _now()
    policy = SessionPolicy(idle_timeout_seconds=600)
    record, _ = _record_and_secret(policy=policy, now=now)
    future = now + timedelta(seconds=100)
    touched = touch_session_record(record, policy=policy, now=future)
    expected_idle = future + timedelta(seconds=600)
    delta = abs((touched.idle_expires_at - expected_idle).total_seconds())
    assert delta < 2


def test_touch_session_record_does_not_change_absolute_expiry() -> None:
    now = _now()
    record, _ = _record_and_secret(now=now)
    future = now + timedelta(seconds=60)
    touched = touch_session_record(record, now=future)
    assert touched.expires_at == record.expires_at


def test_touch_session_record_updates_last_ip() -> None:
    now = _now()
    record, _ = _record_and_secret(ip_address="1.1.1.1", now=now)
    future = now + timedelta(seconds=10)
    touched = touch_session_record(record, now=future, ip_address="2.2.2.2")
    assert touched.last_ip == "2.2.2.2"


def test_touch_session_record_keeps_last_ip_if_none_presented() -> None:
    now = _now()
    record, _ = _record_and_secret(ip_address="1.1.1.1", now=now)
    future = now + timedelta(seconds=10)
    touched = touch_session_record(record, now=future, ip_address=None)
    assert touched.last_ip == "1.1.1.1"


def test_touch_session_record_preserves_session_id() -> None:
    record, _ = _record_and_secret()
    touched = touch_session_record(record)
    assert touched.session_id == record.session_id


def test_touch_session_record_preserves_principal() -> None:
    record, _ = _record_and_secret()
    touched = touch_session_record(record)
    assert touched.principal == record.principal


def test_touch_session_record_preserves_metadata() -> None:
    record, _ = _record_and_secret(metadata={"k": "v"})
    touched = touch_session_record(record)
    assert touched.metadata == {"k": "v"}


# ---------------------------------------------------------------------------
# rotate_session_secret
# ---------------------------------------------------------------------------


def test_rotate_session_secret_returns_new_secret() -> None:
    now = _now()
    record, original_secret = _record_and_secret(now=now)
    rotated, new_secret = rotate_session_secret(record, now=now)
    assert new_secret != original_secret
    assert rotated.secret_fingerprint == fingerprint_session_secret(new_secret)


def test_rotate_session_secret_explicit_new_secret() -> None:
    now = _now()
    record, _ = _record_and_secret(now=now)
    rotated, returned = rotate_session_secret(record, new_secret="my-new-secret", now=now)
    assert returned == "my-new-secret"
    assert rotated.secret_fingerprint == fingerprint_session_secret("my-new-secret")


def test_rotate_session_secret_updates_rotated_at() -> None:
    now = _now()
    record, _ = _record_and_secret(now=now)
    future = now + timedelta(seconds=60)
    rotated, _ = rotate_session_secret(record, now=future)
    assert rotated.rotated_at == future


def test_rotate_session_secret_extends_absolute_expiry() -> None:
    now = _now()
    policy = SessionPolicy(absolute_timeout_seconds=3600)
    record, _ = _record_and_secret(policy=policy, now=now)
    future = now + timedelta(seconds=100)
    rotated, _ = rotate_session_secret(record, policy=policy, now=future)
    expected = future + timedelta(seconds=3600)
    delta = abs((rotated.expires_at - expected).total_seconds())
    assert delta < 2


def test_rotate_session_secret_preserves_session_id() -> None:
    record, _ = _record_and_secret()
    rotated, _ = rotate_session_secret(record)
    assert rotated.session_id == record.session_id


def test_rotate_session_secret_preserves_principal() -> None:
    record, _ = _record_and_secret()
    rotated, _ = rotate_session_secret(record)
    assert rotated.principal == record.principal


def test_rotate_session_secret_preserves_created_ip() -> None:
    record, _ = _record_and_secret(ip_address="5.5.5.5")
    rotated, _ = rotate_session_secret(record)
    assert rotated.created_ip == "5.5.5.5"


def test_rotate_session_secret_old_secret_invalid_after_rotation() -> None:
    now = _now()
    policy = SessionPolicy(require_user_agent_binding=False, require_ip_binding=False)
    record, old_secret = _record_and_secret(policy=policy, now=now)
    rotated, new_secret = rotate_session_secret(record, policy=policy, now=now)
    result = validate_session_record(rotated, presented_secret=old_secret, policy=policy, now=now)
    assert result.valid is False
    assert result.reason == "invalid_session_secret"


def test_rotate_session_secret_new_secret_valid_after_rotation() -> None:
    now = _now()
    policy = SessionPolicy(require_user_agent_binding=False, require_ip_binding=False)
    record, _ = _record_and_secret(policy=policy, now=now)
    rotated, new_secret = rotate_session_secret(record, policy=policy, now=now)
    result = validate_session_record(rotated, presented_secret=new_secret, policy=policy, now=now)
    assert result.valid is True


# ---------------------------------------------------------------------------
# revoke_session_record
# ---------------------------------------------------------------------------


def test_revoke_session_record_sets_revoked_at() -> None:
    now = _now()
    record, _ = _record_and_secret(now=now)
    revoked = revoke_session_record(record, reason="admin_logout", now=now)
    assert revoked.revoked_at == now


def test_revoke_session_record_sets_reason() -> None:
    now = _now()
    record, _ = _record_and_secret(now=now)
    revoked = revoke_session_record(record, reason="user_request", now=now)
    assert revoked.revocation_reason == "user_request"


def test_revoke_session_record_default_reason() -> None:
    record, _ = _record_and_secret()
    revoked = revoke_session_record(record)
    assert revoked.revocation_reason == "revoked"


def test_revoke_session_record_active_becomes_false() -> None:
    record, _ = _record_and_secret()
    revoked = revoke_session_record(record)
    assert revoked.active is False


def test_revoke_session_record_preserves_session_id() -> None:
    record, _ = _record_and_secret()
    revoked = revoke_session_record(record)
    assert revoked.session_id == record.session_id


def test_revoke_session_record_preserves_principal() -> None:
    record, _ = _record_and_secret()
    revoked = revoke_session_record(record)
    assert revoked.principal == record.principal


def test_revoke_session_record_idempotent_reason_preserved() -> None:
    now = _now()
    record, _ = _record_and_secret(now=now)
    revoked_once = revoke_session_record(record, reason="first_reason", now=now)
    revoked_twice = revoke_session_record(revoked_once, reason="second_reason", now=now)
    assert revoked_twice.revocation_reason == "second_reason"
    assert revoked_twice.active is False


# ---------------------------------------------------------------------------
# session_is_active
# ---------------------------------------------------------------------------


def test_session_is_active_fresh_session() -> None:
    now = _now()
    record, _ = _record_and_secret(now=now)
    assert session_is_active(record, now=now) is True


def test_session_is_active_revoked_returns_false() -> None:
    now = _now()
    record, _ = _record_and_secret(now=now)
    revoked = revoke_session_record(record, now=now)
    assert session_is_active(revoked, now=now) is False


def test_session_is_active_absolute_expired_returns_false() -> None:
    now = _now()
    policy = SessionPolicy(absolute_timeout_seconds=10, idle_timeout_seconds=3600)
    record, _ = _record_and_secret(policy=policy, now=now)
    future = now + timedelta(seconds=20)
    assert session_is_active(record, now=future) is False


def test_session_is_active_idle_expired_returns_false() -> None:
    now = _now()
    policy = SessionPolicy(idle_timeout_seconds=5, absolute_timeout_seconds=3600)
    record, _ = _record_and_secret(policy=policy, now=now)
    future = now + timedelta(seconds=10)
    assert session_is_active(record, now=future) is False


def test_session_is_active_touch_extends_idle_window() -> None:
    now = _now()
    policy = SessionPolicy(idle_timeout_seconds=30, absolute_timeout_seconds=3600)
    record, _ = _record_and_secret(policy=policy, now=now)
    touch_time = now + timedelta(seconds=20)
    touched = touch_session_record(record, policy=policy, now=touch_time)
    check_time = now + timedelta(seconds=40)
    assert session_is_active(touched, now=check_time) is True


def test_session_is_active_no_now_uses_real_clock() -> None:
    record, _ = _record_and_secret()
    assert session_is_active(record) is True


# ---------------------------------------------------------------------------
# Integration: full lifecycle
# ---------------------------------------------------------------------------


def test_session_lifecycle_create_validate_touch_rotate_revoke() -> None:
    now = _now()
    policy = SessionPolicy(
        idle_timeout_seconds=600,
        absolute_timeout_seconds=3600,
        renewal_window_seconds=300,
        require_ip_binding=False,
        require_user_agent_binding=False,
        enforce_secret_rotation=True,
    )
    principal = build_session_principal(
        principal_id="p-lifecycle",
        principal_type="user",
        org_id="org-lifecycle",
        roles=["admin"],
        permissions=["read", "write"],
    )

    record, secret = create_session_record(
        principal=principal,
        policy=policy,
        ip_address="192.168.1.1",
        user_agent="TestClient/2.0",
        now=now,
    )
    assert session_is_active(record, now=now)

    t1 = now + timedelta(seconds=30)
    result1 = validate_session_record(record, presented_secret=secret, policy=policy, now=t1)
    assert result1.valid is True
    assert result1.should_rotate is False

    touched = touch_session_record(record, policy=policy, now=t1, ip_address="192.168.1.1")
    assert touched.last_seen_at == t1

    t2 = now + timedelta(seconds=3400)
    rotated, new_secret = rotate_session_secret(record, policy=policy, now=t2)
    assert rotated.rotated_at == t2
    result_old = validate_session_record(rotated, presented_secret=secret, policy=policy, now=t2)
    assert result_old.valid is False
    assert result_old.reason == "invalid_session_secret"

    result_new = validate_session_record(rotated, presented_secret=new_secret, policy=policy, now=t2)
    assert result_new.valid is True

    revoked = revoke_session_record(rotated, reason="logout", now=t2)
    assert session_is_active(revoked, now=t2) is False
    result_revoked = validate_session_record(revoked, presented_secret=new_secret, policy=policy, now=t2)
    assert result_revoked.valid is False
    assert result_revoked.reason == "session_revoked"


def test_session_lifecycle_idle_timeout_then_touch_then_expire() -> None:
    now = _now()
    policy = SessionPolicy(
        idle_timeout_seconds=60,
        absolute_timeout_seconds=3600,
        require_user_agent_binding=False,
        require_ip_binding=False,
        enforce_secret_rotation=False,
    )
    record, secret = _record_and_secret(policy=policy, now=now)

    mid = now + timedelta(seconds=30)
    touched = touch_session_record(record, policy=policy, now=mid)
    assert session_is_active(touched, now=mid) is True

    after_original_idle = now + timedelta(seconds=70)
    assert session_is_active(touched, now=after_original_idle) is True

    after_touched_idle = mid + timedelta(seconds=70)
    assert session_is_active(touched, now=after_touched_idle) is False
