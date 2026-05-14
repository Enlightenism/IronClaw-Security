from __future__ import annotations

from app.core.auth import AuthContext
from app.core.org_isolation import (
    DEFAULT_BYPASS_ROLES,
    evaluate_org_isolation,
    org_ids_match,
)
from app.services.orgisolationservice import build_org_isolation_service


def _context(
    *,
    authenticated: bool = True,
    principal_id: str = "principal-test",
    principal_type: str = "customer",
    org_id: str | None = "org-test",
    roles: tuple[str, ...] = (),
    permissions: tuple[str, ...] = (),
) -> AuthContext:
    return AuthContext(
        authenticated=authenticated,
        principal_id=principal_id,
        principal_type=principal_type,
        org_id=org_id,
        roles=roles,
        permissions=permissions,
        session_id="sess-test",
        auth_method="api_key",
        metadata={},
    )


def test_org_ids_match_returns_true_for_same_values() -> None:
    assert org_ids_match("org-test", "org-test") is True


def test_org_ids_match_returns_false_for_different_values() -> None:
    assert org_ids_match("org-a", "org-b") is False


def test_org_isolation_allows_same_org_access() -> None:
    context = _context(org_id="org-test")

    decision = evaluate_org_isolation(
        context,
        target_org_id="org-test",
    )

    assert decision.allowed is True
    assert decision.reason == "org_match"


def test_org_isolation_rejects_cross_org_access_without_bypass() -> None:
    context = _context(
        org_id="org-a",
        roles=("customer_admin",),
    )

    decision = evaluate_org_isolation(
        context,
        target_org_id="org-b",
        bypass_roles=(),
    )

    assert decision.allowed is False
    assert decision.reason == "org_mismatch"


def test_org_isolation_allows_bypass_role_for_cross_org_access() -> None:
    context = _context(
        principal_type="operator",
        org_id="org-a",
        roles=("platform_admin",),
    )

    decision = evaluate_org_isolation(
        context,
        target_org_id="org-b",
        bypass_roles=DEFAULT_BYPASS_ROLES,
    )

    assert decision.allowed is True
    assert "platform_admin" in decision.matched_roles


def test_org_isolation_rejects_unauthenticated_context() -> None:
    context = _context(
        authenticated=False,
        org_id="org-test",
    )

    decision = evaluate_org_isolation(
        context,
        target_org_id="org-test",
    )

    assert decision.allowed is False


def test_org_isolation_service_authorize_same_org() -> None:
    service = build_org_isolation_service()
    context = _context(org_id="org-test")

    result = service.authorize_same_org(
        context,
        target_org_id="org-test",
    )

    assert result.allowed is True
    assert result.scope == "org_isolation"


def test_org_isolation_service_authorize_with_default_bypass() -> None:
    service = build_org_isolation_service()
    context = _context(
        principal_type="operator",
        org_id="org-a",
        roles=("platform_admin",),
    )

    result = service.authorize_with_default_bypass(
        context,
        target_org_id="org-b",
    )

    assert result.allowed is True
    assert result.scope == "org_isolation"


def test_org_isolation_service_compare_org_ids() -> None:
    service = build_org_isolation_service()

    result = service.compare_org_ids(
        actor_org_id="org-a",
        target_org_id="org-b",
    )

    assert result.allowed is False
    assert result.reason == "org_mismatch"


def test_org_isolation_service_summarize_context() -> None:
    service = build_org_isolation_service()
    context = _context(
        principal_type="customer",
        org_id="org-test",
        roles=("customer_admin",),
    )

    result = service.summarize_context(context)

    assert result.allowed is True
    assert result.actor_org_id == "org-test"
    assert result.target_org_id == "org-test"
    assert "customer_admin" in result.matched_roles
