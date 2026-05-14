from __future__ import annotations

from datetime import timedelta

from app.core.session_security import (
    SessionPolicy,
    build_session_principal,
    constant_time_equals,
    create_session_record,
    fingerprint_session_secret,
    revoke_session_record,
    rotate_session_secret,
    session_is_active,
    touch_session_record,
    validate_session_record,
)


def test_fingerprint_session_secret_returns_hash() -> None:
    fingerprint = fingerprint_session_secret("secret-value")

    assert isinstance(fingerprint, str)
    assert fingerprint
    assert fingerprint != "secret-value"


def test_constant_time_equals_matches_identical_values() -> None:
    assert constant_time_equals("abc", "abc") is True
    assert constant_time_equals("abc", "xyz") is False


def test_create_session_record_issues_active_session() -> None:
    principal = build_session_principal(
        principal_id="principal-test",
        principal_type="operator",
        org_id="org-test",
        roles=("operator_admin",),
        permissions=("operator:read",),
    )

    record, secret = create_session_record(
        principal=principal,
        secret="session-secret",
        ip_address="127.0.0.1",
        user_agent="pytest",
    )

    assert record.session_id
    assert secret == "session-secret"
    assert record.active is True
    assert record.principal.principal_id == "principal-test"
    assert record.secret_fingerprint == fingerprint_session_secret("session-secret")


def test_validate_session_record_allows_valid_secret() -> None:
    principal = build_session_principal(
        principal_id="principal-test",
        principal_type="operator",
        org_id="org-test",
    )
    record, secret = create_session_record(
        principal=principal,
        secret="session-secret",
        ip_address="127.0.0.1",
        user_agent="pytest",
    )

    result = validate_session_record(
        record,
        presented_secret=secret,
        ip_address="127.0.0.1",
        user_agent="pytest",
    )

    assert result.valid is True
    assert result.reason == "valid"


def test_validate_session_record_rejects_invalid_secret() -> None:
    principal = build_session_principal(
        principal_id="principal-test",
        principal_type="operator",
        org_id="org-test",
    )
    record, _ = create_session_record(
        principal=principal,
        secret="session-secret",
    )

    result = validate_session_record(
        record,
        presented_secret="wrong-secret",
    )

    assert result.valid is False
    assert result.reason == "invalid_session_secret"


def test_touch_session_record_extends_idle_timeout() -> None:
    principal = build_session_principal(
        principal_id="principal-test",
        principal_type="operator",
        org_id="org-test",
    )
    policy = SessionPolicy(idle_timeout_seconds=60)
    record, _ = create_session_record(
        principal=principal,
        secret="session-secret",
        policy=policy,
    )

    touched = touch_session_record(
        record,
        policy=policy,
        ip_address="10.0.0.2",
        user_agent="pytest-touch",
    )

    assert touched.last_seen_at >= record.last_seen_at
    assert touched.idle_expires_at >= record.idle_expires_at
    assert touched.last_ip == "10.0.0.2"
    assert touched.user_agent == "pytest-touch"


def test_rotate_session_secret_replaces_secret_fingerprint() -> None:
    principal = build_session_principal(
        principal_id="principal-test",
        principal_type="operator",
        org_id="org-test",
    )
    record, _ = create_session_record(
        principal=principal,
        secret="old-secret",
    )

    rotated, new_secret = rotate_session_secret(
        record,
        new_secret="new-secret",
    )

    assert new_secret == "new-secret"
    assert rotated.secret_fingerprint == fingerprint_session_secret("new-secret")
    assert rotated.secret_fingerprint != record.secret_fingerprint


def test_revoke_session_record_marks_session_inactive() -> None:
    principal = build_session_principal(
        principal_id="principal-test",
        principal_type="operator",
        org_id="org-test",
    )
    record, _ = create_session_record(
        principal=principal,
        secret="session-secret",
    )

    revoked = revoke_session_record(record, reason="manual_logout")

    assert revoked.active is False
    assert revoked.revocation_reason == "manual_logout"
    assert revoked.revoked_at is not None


def test_session_is_active_reflects_revoked_state() -> None:
    principal = build_session_principal(
        principal_id="principal-test",
        principal_type="operator",
        org_id="org-test",
    )
    record, _ = create_session_record(
        principal=principal,
        secret="session-secret",
    )
    revoked = revoke_session_record(record)

    assert session_is_active(record) is True
    assert session_is_active(revoked) is False


def test_validate_session_record_can_require_user_agent_binding() -> None:
    principal = build_session_principal(
        principal_id="principal-test",
        principal_type="operator",
        org_id="org-test",
    )
    policy = SessionPolicy(require_user_agent_binding=True)
    record, secret = create_session_record(
        principal=principal,
        secret="session-secret",
        policy=policy,
        user_agent="pytest-agent",
    )

    result = validate_session_record(
        record,
        presented_secret=secret,
        policy=policy,
        user_agent="different-agent",
    )

    assert result.valid is False
    assert result.reason == "user_agent_mismatch"


def test_validate_session_record_can_require_ip_binding() -> None:
    principal = build_session_principal(
        principal_id="principal-test",
        principal_type="operator",
        org_id="org-test",
    )
    policy = SessionPolicy(require_ip_binding=True)
    record, secret = create_session_record(
        principal=principal,
        secret="session-secret",
        policy=policy,
        ip_address="127.0.0.1",
    )

    result = validate_session_record(
        record,
        presented_secret=secret,
        policy=policy,
        ip_address="10.10.10.10",
    )

    assert result.valid is False
    assert result.reason == "ip_binding_mismatch"


def test_validate_session_record_flags_rotation_inside_renewal_window() -> None:
    principal = build_session_principal(
        principal_id="principal-test",
        principal_type="operator",
        org_id="org-test",
    )
    policy = SessionPolicy(
        idle_timeout_seconds=600,
        absolute_timeout_seconds=600,
        renewal_window_seconds=300,
        enforce_secret_rotation=True,
    )
    record, secret = create_session_record(
        principal=principal,
        secret="session-secret",
        policy=policy,
    )

    near_expiry = record.expires_at - timedelta(seconds=299)

    result = validate_session_record(
        record,
        presented_secret=secret,
        policy=policy,
        now=near_expiry,
    )

    assert result.valid is True
    assert result.should_rotate is True
