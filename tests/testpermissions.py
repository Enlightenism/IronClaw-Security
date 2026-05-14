from __future__ import annotations

from app.core.auth import AuthContext
from app.core.permissions import (
    evaluate_permission,
    expand_role_permissions,
    resolve_effective_permissions,
)
from app.core.roles import (
    describe_roles,
    get_role_permissions,
    normalize_roles,
)
from app.services.permissionservice import build_permission_service


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


def test_normalize_roles_returns_unique_lowercase_values() -> None:
    roles = normalize_roles(["Operator_Admin", "operator_admin", " AUDITOR "])

    assert roles == ("operator_admin", "auditor")


def test_get_role_permissions_returns_tuple() -> None:
    permissions = get_role_permissions("operator_admin")

    assert isinstance(permissions, tuple)


def test_expand_role_permissions_returns_permissions_for_roles() -> None:
    permissions = expand_role_permissions(("operator_admin",))

    assert isinstance(permissions, tuple)
    assert len(permissions) >= 1


def test_resolve_effective_permissions_merges_direct_and_role_permissions() -> None:
    permissions = resolve_effective_permissions(
        direct_permissions=("custom:read",),
        roles=("operator_admin",),
    )

    assert "custom:read" in permissions
    assert len(permissions) >= 1


def test_evaluate_permission_allows_direct_permission() -> None:
    context = _context(permissions=("reports:read",))

    decision = evaluate_permission(context, "reports:read", resource_org_id="org-test")

    assert decision.allowed is True
    assert decision.permission == "reports:read"


def test_evaluate_permission_rejects_missing_permission() -> None:
    context = _context(permissions=())

    decision = evaluate_permission(context, "reports:read", resource_org_id="org-test")

    assert decision.allowed is False


def test_evaluate_permission_rejects_unauthenticated_context() -> None:
    context = _context(authenticated=False, permissions=("reports:read",))

    decision = evaluate_permission(context, "reports:read", resource_org_id="org-test")

    assert decision.allowed is False


def test_describe_roles_returns_list_of_role_descriptions() -> None:
    descriptions = describe_roles(("operator_admin", "auditor"))

    assert isinstance(descriptions, list)
    assert len(descriptions) >= 1
    assert all(isinstance(item, dict) for item in descriptions)


def test_permission_service_resolves_permissions() -> None:
    service = build_permission_service()

    result = service.resolve_permissions(
        direct_permissions=("custom:read",),
        roles=("operator_admin",),
    )

    assert result.allowed is True
    assert "custom:read" in result.permissions


def test_permission_service_expands_roles() -> None:
    service = build_permission_service()

    result = service.expand_roles(roles=("operator_admin",))

    assert result.allowed is True
    assert len(result.permissions) >= 1


def test_permission_service_gets_permissions_for_known_role() -> None:
    service = build_permission_service()

    result = service.get_permissions_for_role("operator_admin")

    assert result.allowed is True
    assert result.roles == ("operator_admin",)


def test_permission_service_summarizes_context_permissions() -> None:
    service = build_permission_service()
    context = _context(
        roles=("operator_admin",),
        permissions=("custom:read",),
    )

    result = service.summarize_context_permissions(context)

    assert result.allowed is True
    assert result.principal_id == "principal-test"
    assert "custom:read" in result.permissions
