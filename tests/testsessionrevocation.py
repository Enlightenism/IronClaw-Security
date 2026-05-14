from __future__ import annotations

from app.core.session_security import (
    build_session_principal,
    create_session_record,
    revoke_session_record,
    session_is_active,
    validate_session_record,
)
from app.services.sessionservice import build_session_service


def test_revoked_session_fails_validation() -> None:
    principal = build_session_principal(
        principal_id="principal-test",
        principal_type="operator",
        org_id="org-test",
    )
    record, secret = create_session_record(
        principal=principal,
        secret="session-secret",
    )
    revoked = revoke_session_record(record, reason="manual_logout")

    result = validate_session_record(
        revoked,
        presented_secret=secret,
    )

    assert result.valid is False
    assert result.reason == "session_revoked"


def test_revoked_session_is_not_active() -> None:
    principal = build_session_principal(
        principal_id="principal-test",
        principal_type="operator",
        org_id="org-test",
    )
    record, _ = create_session_record(
        principal=principal,
        secret="session-secret",
    )
    revoked = revoke_session_record(record, reason="security_event")

    assert session_is_active(revoked) is False


def test_revocation_preserves_session_identity() -> None:
    principal = build_session_principal(
        principal_id="principal-test",
        principal_type="operator",
        org_id="org-test",
    )
    record, _ = create_session_record(
        principal=principal,
        secret="session-secret",
        session_id="sess-fixed",
    )

    revoked = revoke_session_record(record, reason="manual_logout")

    assert revoked.session_id == "sess-fixed"
    assert revoked.principal.principal_id == "principal-test"


def test_revocation_sets_reason_and_timestamp() -> None:
    principal = build_session_principal(
        principal_id="principal-test",
        principal_type="operator",
        org_id="org-test",
    )
    record, _ = create_session_record(
        principal=principal,
        secret="session-secret",
    )

    revoked = revoke_session_record(record, reason="compromised_session")

    assert revoked.revocation_reason == "compromised_session"
    assert revoked.revoked_at is not None


def test_session_service_revoke_session_returns_revoked_record() -> None:
    principal = build_session_principal(
        principal_id="principal-test",
        principal_type="operator",
        org_id="org-test",
    )
    record, _ = create_session_record(
        principal=principal,
        secret="session-secret",
    )
    service = build_session_service()

    result = service.revoke_session(
        session=record,
        reason="operator_forced_logout",
    )

    assert result.ok is True
    assert result.reason == "session_revoked"
    assert result.session is not None
    assert result.session.revocation_reason == "operator_forced_logout"
    assert result.session.revoked_at is not None


def test_revoked_session_cannot_be_validated_through_service_flow() -> None:
    principal = build_session_principal(
        principal_id="principal-test",
        principal_type="operator",
        org_id="org-test",
    )
    session_service = build_session_service()

    create_result = session_service.create_session(
        principal=principal,
        secret="session-secret",
    )
    assert create_result.session is not None

    revoke_result = session_service.revoke_session(
        session=create_result.session,
        reason="manual_logout",
    )
    assert revoke_result.session is not None

    validate_result = session_service.validate_session(
        principal=session_service.auth_service.build_principal(
            principal_id="principal-test",
            principal_type="operator",
            org_id="org-test",
        ),
        session=revoke_result.session,
        presented_secret="session-secret",
    )

    assert validate_result.ok is False
    assert validate_result.reason == "session_revoked"
    assert validate_result.validation is not None
    assert validate_result.validation.valid is False
