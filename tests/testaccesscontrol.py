from __future__ import annotations

from app.core.access_control import evaluate_access
from app.core.auth import AuthContext


def _context(
    *,
    authenticated: bool = True,
    principal_id: str = "principal-test",
    principal_type: str = "operator",
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


def test_access_control_allows_direct_permission_match() -> None:
    context = _context(permissions=("reports:read",))

    decision = evaluate_access(
        context,
        action="read_reports",
        required_permission="reports:read",
        resource_org_id="org-test",
    )

    assert decision.allowed is True
    assert decision.permission == "reports:read"


def test_access_control_rejects_missing_permission() -> None:
    context = _context(permissions=())

    decision = evaluate_access(
        context,
        action="read_reports",
        required_permission="reports:read",
        resource_org_id="org-test",
    )

    assert decision.allowed is False


def test_access_control_rejects_unauthenticated_context() -> None:
    context = _context(
        authenticated=False,
        permissions=("reports:read",),
    )

    decision = evaluate_access(
        context,
        action="read_reports",
        required_permission="reports:read",
        resource_org_id="org-test",
    )

    assert decision.allowed is False


def test_access_control_allows_required_role_match() -> None:
    context = _context(roles=("operator_admin",))

    decision = evaluate_access(
        context,
        action="manage_operator",
        required_roles=("operator_admin",),
        resource_org_id="org-test",
    )

    assert decision.allowed is True
    assert "operator_admin" in decision.matched_roles


def test_access_control_rejects_missing_required_role() -> None:
    context = _context(roles=("auditor",))

    decision = evaluate_access(
        context,
        action="manage_operator",
        required_roles=("operator_admin",),
        resource_org_id="org-test",
    )

    assert decision.allowed is False


def test_access_control_allows_when_permission_and_role_match() -> None:
    context = _context(
        roles=("operator_admin",),
        permissions=("reports:read",),
    )

    decision = evaluate_access(
        context,
        action="read_reports",
        required_permission="reports:read",
        required_roles=("operator_admin",),
        resource_org_id="org-test",
    )

    assert decision.allowed is True
    assert decision.permission == "reports:read"
    assert "operator_admin" in decision.matched_roles


def test_access_control_rejects_cross_org_access_when_enforced() -> None:
    context = _context(
        roles=("customer_admin",),
        permissions=("reports:read",),
        org_id="org-a",
    )

    decision = evaluate_access(
        context,
        action="read_reports",
        required_permission="reports:read",
        resource_org_id="org-b",
    )

    assert decision.allowed is False


def test_access_control_result_contains_action_and_reason() -> None:
    context = _context(permissions=())

    decision = evaluate_access(
        context,
        action="read_reports",
        required_permission="reports:read",
        resource_org_id="org-test",
    )

    assert decision.action == "read_reports"
    assert isinstance(decision.reason, str)
    assert decision.reason != ""