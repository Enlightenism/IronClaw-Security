from __future__ import annotations

import pytest

from app.core.access_control import AccessControlDecision, evaluate_access, require_access
from app.core.auth import AuthContext
from app.core.errors import AppError
from app.core.permissions import (
    ROLE_PERMISSIONS,
    PermissionDecision,
    evaluate_permission,
    expand_role_permissions,
    has_permission,
    require_permission,
    resolve_effective_permissions,
)
from app.core.roles import (
    ROLE_DEFINITIONS,
    RoleDefinition,
    describe_roles,
    get_role_definition,
    get_role_permissions,
    is_customer_role,
    is_operator_role,
    is_service_role,
    list_roles,
    normalize_roles,
    role_exists,
    roles_for_principal_type,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ctx(
    *,
    authenticated: bool = True,
    principal_type: str = "api_key",
    principal_id: str | None = "p-001",
    org_id: str | None = "org-001",
    roles: tuple[str, ...] = (),
    permissions: tuple[str, ...] = (),
) -> AuthContext:
    return AuthContext(
        api_key="test-key",
        principal_type=principal_type,
        principal_id=principal_id,
        session_id=None,
        org_id=org_id,
        roles=roles,
        permissions=permissions,
        authenticated=authenticated,
        auth_source="test",
        auth_method="api_key",
    )


def _anon() -> AuthContext:
    return AuthContext(
        api_key=None,
        principal_type="anonymous",
        principal_id=None,
        session_id=None,
        org_id=None,
        roles=(),
        permissions=(),
        authenticated=False,
        auth_source="disabled",
        auth_method=None,
    )


def _platform() -> AuthContext:
    return _ctx(principal_type="platform", roles=())


def _system() -> AuthContext:
    return _ctx(principal_type="system", roles=())


def _platform_admin_ctx() -> AuthContext:
    return _ctx(principal_type="platform", roles=("platform_admin",))


# ---------------------------------------------------------------------------
# AuthContext shape
# ---------------------------------------------------------------------------


def test_auth_context_authenticated_shape() -> None:
    ctx = _ctx(roles=("operator_admin",), permissions=("operator:read",))
    assert ctx.authenticated is True
    assert ctx.principal_type == "api_key"
    assert ctx.roles == ("operator_admin",)
    assert ctx.permissions == ("operator:read",)


def test_auth_context_anonymous_shape() -> None:
    ctx = _anon()
    assert ctx.authenticated is False
    assert ctx.principal_type == "anonymous"
    assert ctx.principal_id is None
    assert ctx.roles == ()
    assert ctx.permissions == ()


# ---------------------------------------------------------------------------
# RoleDefinition / roles registry
# ---------------------------------------------------------------------------


def test_all_expected_roles_defined() -> None:
    expected = {
        "platform_admin",
        "system_admin",
        "operator_admin",
        "operator_analyst",
        "customer_admin",
        "customer_user",
        "auditor",
        "service",
    }
    assert expected == set(ROLE_DEFINITIONS.keys())


def test_get_role_definition_returns_correct_shape() -> None:
    for role_name in ROLE_DEFINITIONS:
        defn = get_role_definition(role_name)
        assert isinstance(defn, RoleDefinition)
        assert defn.name == role_name
        assert isinstance(defn.permissions, tuple)
        assert isinstance(defn.principal_type, str)
        assert isinstance(defn.description, str)
        assert isinstance(defn.system_role, bool)


def test_get_role_definition_unknown_returns_none() -> None:
    assert get_role_definition("nonexistent_role") is None
    assert get_role_definition("") is None
    assert get_role_definition("  ") is None


def test_role_exists_known_roles() -> None:
    for role_name in ROLE_DEFINITIONS:
        assert role_exists(role_name) is True


def test_role_exists_unknown_returns_false() -> None:
    assert role_exists("made_up_role") is False


def test_list_roles_all() -> None:
    roles = list_roles()
    assert len(roles) == len(ROLE_DEFINITIONS)
    names = [r.name for r in roles]
    assert names == sorted(names)


def test_list_roles_by_principal_type_operator() -> None:
    roles = list_roles(principal_type="operator")
    for r in roles:
        assert r.principal_type == "operator"
    names = {r.name for r in roles}
    assert "platform_admin" in names
    assert "system_admin" in names
    assert "operator_admin" in names
    assert "operator_analyst" in names
    assert "auditor" in names


def test_list_roles_by_principal_type_customer() -> None:
    roles = list_roles(principal_type="customer")
    for r in roles:
        assert r.principal_type == "customer"
    names = {r.name for r in roles}
    assert "customer_admin" in names
    assert "customer_user" in names


def test_list_roles_by_principal_type_service() -> None:
    roles = list_roles(principal_type="service")
    for r in roles:
        assert r.principal_type == "service"
    names = {r.name for r in roles}
    assert "service" in names


def test_is_operator_role() -> None:
    assert is_operator_role("platform_admin") is True
    assert is_operator_role("operator_admin") is True
    assert is_operator_role("operator_analyst") is True
    assert is_operator_role("auditor") is True
    assert is_operator_role("customer_admin") is False
    assert is_operator_role("customer_user") is False
    assert is_operator_role("service") is False
    assert is_operator_role("unknown") is False


def test_is_customer_role() -> None:
    assert is_customer_role("customer_admin") is True
    assert is_customer_role("customer_user") is True
    assert is_customer_role("operator_admin") is False
    assert is_customer_role("service") is False


def test_is_service_role() -> None:
    assert is_service_role("service") is True
    assert is_service_role("operator_admin") is False
    assert is_service_role("customer_user") is False


def test_roles_for_principal_type_operator() -> None:
    result = roles_for_principal_type("operator")
    assert "platform_admin" in result
    assert "operator_admin" in result
    assert "customer_user" not in result


def test_normalize_roles_filters_unknown() -> None:
    result = normalize_roles(["operator_admin", "nonexistent", "auditor"])
    assert "operator_admin" in result
    assert "auditor" in result
    assert "nonexistent" not in result


def test_normalize_roles_deduplicates() -> None:
    result = normalize_roles(["operator_admin", "operator_admin"])
    assert result.count("operator_admin") == 1


def test_normalize_roles_none_returns_empty() -> None:
    assert normalize_roles(None) == ()


def test_get_role_permissions_returns_tuple() -> None:
    for role_name in ROLE_DEFINITIONS:
        perms = get_role_permissions(role_name)
        assert isinstance(perms, tuple)


def test_get_role_permissions_unknown_returns_empty() -> None:
    assert get_role_permissions("ghost_role") == ()


def test_describe_roles_shape() -> None:
    result = describe_roles(["operator_admin", "auditor"])
    assert len(result) == 2
    for entry in result:
        assert "name" in entry
        assert "principal_type" in entry
        assert "description" in entry
        assert "permissions" in entry
        assert isinstance(entry["permissions"], list)


def test_describe_roles_empty_input() -> None:
    assert describe_roles([]) == []
    assert describe_roles(None) == []


# ---------------------------------------------------------------------------
# ROLE_PERMISSIONS coverage
# ---------------------------------------------------------------------------


def test_platform_admin_has_wildcard() -> None:
    assert "*" in ROLE_PERMISSIONS["platform_admin"]


def test_system_admin_has_wildcard() -> None:
    assert "*" in ROLE_PERMISSIONS["system_admin"]


def test_operator_admin_permissions() -> None:
    perms = set(ROLE_PERMISSIONS["operator_admin"])
    assert "operator:read" in perms
    assert "operator:write" in perms
    assert "operator:manage" in perms
    assert "permissions:write" in perms


def test_operator_analyst_read_only() -> None:
    perms = set(ROLE_PERMISSIONS["operator_analyst"])
    assert "operator:read" in perms
    write_perms = {p for p in perms if ":write" in p or ":manage" in p}
    assert not write_perms


def test_customer_admin_permissions() -> None:
    perms = set(ROLE_PERMISSIONS["customer_admin"])
    assert "customer:read" in perms
    assert "customer:write" in perms
    assert "operator:read" not in perms
    assert "operator:write" not in perms


def test_customer_user_permissions() -> None:
    perms = set(ROLE_PERMISSIONS["customer_user"])
    assert "customer:read" in perms
    write_perms = {p for p in perms if ":write" in p}
    assert not write_perms


def test_auditor_read_only() -> None:
    perms = set(ROLE_PERMISSIONS["auditor"])
    write_perms = {p for p in perms if ":write" in p or ":manage" in p}
    assert not write_perms


def test_service_role_permissions() -> None:
    perms = set(ROLE_PERMISSIONS["service"])
    assert "system:read" in perms
    assert "system:write" in perms


# ---------------------------------------------------------------------------
# expand_role_permissions / resolve_effective_permissions
# ---------------------------------------------------------------------------


def test_expand_role_permissions_operator_admin() -> None:
    perms = expand_role_permissions(["operator_admin"])
    assert "operator:read" in perms
    assert "operator:write" in perms


def test_expand_role_permissions_unknown_role_skipped() -> None:
    perms = expand_role_permissions(["operator_admin", "ghost_role"])
    assert "operator:read" in perms


def test_expand_role_permissions_deduplicates() -> None:
    perms = expand_role_permissions(["operator_admin", "operator_admin"])
    assert perms.count("operator:read") == 1


def test_resolve_effective_permissions_direct_plus_role() -> None:
    perms = resolve_effective_permissions(
        direct_permissions=["custom:action"],
        roles=["operator_analyst"],
    )
    assert "custom:action" in perms
    assert "operator:read" in perms


def test_resolve_effective_permissions_deduplication() -> None:
    perms = resolve_effective_permissions(
        direct_permissions=["operator:read"],
        roles=["operator_analyst"],
    )
    assert perms.count("operator:read") == 1


def test_resolve_effective_permissions_none_inputs() -> None:
    perms = resolve_effective_permissions(direct_permissions=None, roles=None)
    assert perms == ()


# ---------------------------------------------------------------------------
# has_permission
# ---------------------------------------------------------------------------


def test_has_permission_direct_match() -> None:
    assert has_permission("operator:read", permissions=["operator:read"]) is True


def test_has_permission_wildcard_star() -> None:
    assert has_permission("operator:read", permissions=["*"]) is True
    assert has_permission("anything:here", permissions=["*"]) is True


def test_has_permission_namespace_wildcard() -> None:
    assert has_permission("operator:read", permissions=["operator:*"]) is True
    assert has_permission("operator:write", permissions=["operator:*"]) is True
    assert has_permission("customer:read", permissions=["operator:*"]) is False


def test_has_permission_via_role() -> None:
    assert has_permission("operator:read", roles=["operator_admin"]) is True
    assert has_permission("operator:manage", roles=["operator_admin"]) is True


def test_has_permission_missing_returns_false() -> None:
    assert has_permission("operator:write", permissions=["operator:read"]) is False
    assert has_permission("operator:write", roles=["customer_user"]) is False


def test_has_permission_empty_permission_returns_false() -> None:
    assert has_permission("", permissions=["*"]) is False
    assert has_permission("  ", permissions=["*"]) is False


# ---------------------------------------------------------------------------
# evaluate_permission
# ---------------------------------------------------------------------------


def test_evaluate_permission_allowed_direct() -> None:
    ctx = _ctx(permissions=("operator:read",))
    decision = evaluate_permission(ctx, "operator:read")
    assert isinstance(decision, PermissionDecision)
    assert decision.allowed is True
    assert decision.reason == "allowed"
    assert "operator:read" in decision.matched_permissions


def test_evaluate_permission_allowed_via_role() -> None:
    ctx = _ctx(roles=("operator_admin",))
    decision = evaluate_permission(ctx, "operator:manage")
    assert decision.allowed is True
    assert decision.reason == "allowed"


def test_evaluate_permission_denied_missing() -> None:
    ctx = _ctx(roles=("customer_user",))
    decision = evaluate_permission(ctx, "operator:write")
    assert decision.allowed is False
    assert decision.reason == "missing_permission"
    assert decision.matched_permissions == ()


def test_evaluate_permission_denied_unauthenticated() -> None:
    ctx = _anon()
    decision = evaluate_permission(ctx, "operator:read")
    assert decision.allowed is False
    assert decision.reason == "authentication_required"


def test_evaluate_permission_invalid_empty_string() -> None:
    ctx = _ctx()
    decision = evaluate_permission(ctx, "")
    assert decision.allowed is False
    assert decision.reason == "invalid_permission"


def test_evaluate_permission_org_scope_mismatch() -> None:
    ctx = _ctx(org_id="org-a")
    decision = evaluate_permission(ctx, "customer:read", resource_org_id="org-b")
    assert decision.allowed is False
    assert decision.reason == "org_scope_mismatch"


def test_evaluate_permission_org_scope_match() -> None:
    ctx = _ctx(org_id="org-a", roles=("customer_admin",))
    decision = evaluate_permission(ctx, "customer:read", resource_org_id="org-a")
    assert decision.allowed is True


def test_evaluate_permission_wildcard_platform_admin() -> None:
    ctx = _ctx(roles=("platform_admin",))
    for permission in ("operator:write", "customer:write", "session:revoke"):
        decision = evaluate_permission(ctx, permission)
        assert decision.allowed is True, f"Expected allowed for {permission}"


def test_evaluate_permission_to_dict_shape() -> None:
    ctx = _ctx(roles=("operator_analyst",))
    decision = evaluate_permission(ctx, "operator:read")
    d = decision.to_dict()
    assert "allowed" in d
    assert "permission" in d
    assert "principal_id" in d
    assert "principal_type" in d
    assert "org_id" in d
    assert "reason" in d
    assert isinstance(d["matched_permissions"], list)
    assert isinstance(d["matched_roles"], list)


def test_require_permission_passes_when_allowed() -> None:
    ctx = _ctx(roles=("operator_admin",))
    result = require_permission(ctx, "operator:read")
    assert result is ctx


def test_require_permission_raises_403_when_denied() -> None:
    ctx = _ctx(roles=("customer_user",))
    with pytest.raises(AppError) as exc_info:
        require_permission(ctx, "operator:write")
    assert exc_info.value.status_code == 403
    assert exc_info.value.error == "permission_denied"


def test_require_permission_raises_401_when_unauthenticated() -> None:
    ctx = _anon()
    with pytest.raises(AppError) as exc_info:
        require_permission(ctx, "operator:read")
    assert exc_info.value.status_code == 401


# ---------------------------------------------------------------------------
# evaluate_access
# ---------------------------------------------------------------------------


def test_evaluate_access_allowed_no_constraints() -> None:
    ctx = _ctx()
    decision = evaluate_access(ctx, action="read:resource")
    assert isinstance(decision, AccessControlDecision)
    assert decision.allowed is True
    assert decision.action == "read:resource"
    assert decision.reason == "allowed"


def test_evaluate_access_denied_unauthenticated() -> None:
    ctx = _anon()
    decision = evaluate_access(ctx, action="read:resource")
    assert decision.allowed is False
    assert decision.reason == "authentication_required"


def test_evaluate_access_denied_empty_action() -> None:
    ctx = _ctx()
    decision = evaluate_access(ctx, action="")
    assert decision.allowed is False
    assert decision.reason == "invalid_action"


def test_evaluate_access_denied_whitespace_action() -> None:
    ctx = _ctx()
    decision = evaluate_access(ctx, action="   ")
    assert decision.allowed is False
    assert decision.reason == "invalid_action"


def test_evaluate_access_platform_bypass() -> None:
    ctx = _platform()
    decision = evaluate_access(ctx, action="any:action", required_permission="operator:write")
    assert decision.allowed is True
    assert decision.reason == "platform_bypass"


def test_evaluate_access_system_bypass() -> None:
    ctx = _system()
    decision = evaluate_access(ctx, action="any:action", required_permission="session:revoke")
    assert decision.allowed is True
    assert decision.reason == "platform_bypass"


def test_evaluate_access_denied_missing_role() -> None:
    ctx = _ctx(roles=("customer_user",))
    decision = evaluate_access(ctx, action="admin:op", required_roles=("operator_admin",))
    assert decision.allowed is False
    assert decision.reason == "missing_role"
    assert "operator_admin" in decision.required_roles


def test_evaluate_access_allowed_matching_role() -> None:
    ctx = _ctx(roles=("operator_admin",))
    decision = evaluate_access(ctx, action="admin:op", required_roles=("operator_admin",))
    assert decision.allowed is True
    assert "operator_admin" in decision.matched_roles


def test_evaluate_access_denied_missing_permission() -> None:
    ctx = _ctx(roles=("customer_user",))
    decision = evaluate_access(ctx, action="write:resource", required_permission="operator:write")
    assert decision.allowed is False
    assert decision.reason == "missing_permission"


def test_evaluate_access_allowed_with_permission() -> None:
    ctx = _ctx(roles=("operator_admin",))
    decision = evaluate_access(ctx, action="write:resource", required_permission="operator:write")
    assert decision.allowed is True


def test_evaluate_access_denied_org_scope_mismatch() -> None:
    ctx = _ctx(org_id="org-a")
    decision = evaluate_access(ctx, action="read:resource", resource_org_id="org-b")
    assert decision.allowed is False
    assert decision.reason == "org_scope_mismatch"


def test_evaluate_access_allowed_same_org() -> None:
    ctx = _ctx(org_id="org-a", roles=("customer_admin",))
    decision = evaluate_access(
        ctx,
        action="read:resource",
        required_permission="customer:read",
        resource_org_id="org-a",
    )
    assert decision.allowed is True


def test_evaluate_access_unknown_role_ignored_in_required() -> None:
    ctx = _ctx(roles=("operator_admin",))
    decision = evaluate_access(ctx, action="read:resource", required_roles=("ghost_role",))
    assert decision.allowed is True


def test_evaluate_access_to_dict_shape() -> None:
    ctx = _ctx(roles=("operator_analyst",))
    decision = evaluate_access(ctx, action="read:resource")
    d = decision.to_dict()
    assert "allowed" in d
    assert "action" in d
    assert "principal_id" in d
    assert "principal_type" in d
    assert "org_id" in d
    assert "reason" in d
    assert "permission" in d
    assert isinstance(d["required_roles"], list)
    assert isinstance(d["matched_roles"], list)
    assert isinstance(d["metadata"], dict)


def test_evaluate_access_metadata_stringified() -> None:
    ctx = _ctx()
    decision = evaluate_access(ctx, action="read:resource", metadata={"key": 42, "flag": True})
    assert decision.metadata["key"] == "42"
    assert decision.metadata["flag"] == "True"


# ---------------------------------------------------------------------------
# require_access
# ---------------------------------------------------------------------------


def test_require_access_returns_context_when_allowed() -> None:
    ctx = _ctx()
    result = require_access(ctx, action="read:resource")
    assert result is ctx


def test_require_access_raises_403_when_denied() -> None:
    ctx = _ctx(roles=("customer_user",))
    with pytest.raises(AppError) as exc_info:
        require_access(ctx, action="admin:op", required_permission="operator:write")
    assert exc_info.value.status_code == 403
    assert exc_info.value.error == "access_denied"


def test_require_access_raises_401_when_unauthenticated() -> None:
    ctx = _anon()
    with pytest.raises(AppError) as exc_info:
        require_access(ctx, action="read:resource")
    assert exc_info.value.status_code == 401
    assert exc_info.value.error == "access_denied"


def test_require_access_platform_never_raises() -> None:
    ctx = _platform()
    result = require_access(
        ctx,
        action="destroy:everything",
        required_permission="operator:manage",
        required_roles=("platform_admin",),
    )
    assert result is ctx


# ---------------------------------------------------------------------------
# Permission boundary matrix
# ---------------------------------------------------------------------------


_PERMISSION_MATRIX: list[tuple[str, str, bool]] = [
    # (role, permission, expected_allowed)
    ("platform_admin", "operator:write", True),
    ("platform_admin", "customer:write", True),
    ("platform_admin", "session:revoke", True),
    ("system_admin", "operator:write", True),
    ("system_admin", "session:revoke", True),
    ("operator_admin", "operator:read", True),
    ("operator_admin", "operator:write", True),
    ("operator_admin", "operator:manage", True),
    ("operator_admin", "permissions:write", True),
    ("operator_admin", "customer:read", True),
    ("operator_analyst", "operator:read", True),
    ("operator_analyst", "customer:read", True),
    ("operator_analyst", "operator:write", False),
    ("operator_analyst", "permissions:write", False),
    ("customer_admin", "customer:read", True),
    ("customer_admin", "customer:write", True),
    ("customer_admin", "operator:read", False),
    ("customer_admin", "operator:write", False),
    ("customer_user", "customer:read", True),
    ("customer_user", "customer:write", False),
    ("customer_user", "operator:read", False),
    ("auditor", "operator:read", True),
    ("auditor", "customer:read", True),
    ("auditor", "operator:write", False),
    ("auditor", "permissions:write", False),
    ("service", "system:read", True),
    ("service", "system:write", True),
    ("service", "operator:write", False),
    ("service", "customer:write", False),
]


def test_permission_boundary_matrix() -> None:
    for role, permission, expected in _PERMISSION_MATRIX:
        ctx = _ctx(roles=(role,))
        decision = evaluate_permission(ctx, permission)
        assert decision.allowed is expected, f"Role={role!r} permission={permission!r} " f"expected={expected} got={decision.allowed} reason={decision.reason!r}"


# ---------------------------------------------------------------------------
# Cross-org isolation
# ---------------------------------------------------------------------------


def test_cross_org_access_denied_different_orgs() -> None:
    ctx = _ctx(org_id="org-tenant-a", roles=("customer_admin",))
    decision = evaluate_access(
        ctx,
        action="read:data",
        required_permission="customer:read",
        resource_org_id="org-tenant-b",
    )
    assert decision.allowed is False
    assert decision.reason == "org_scope_mismatch"


def test_cross_org_access_allowed_same_org() -> None:
    ctx = _ctx(org_id="org-tenant-a", roles=("customer_admin",))
    decision = evaluate_access(
        ctx,
        action="read:data",
        required_permission="customer:read",
        resource_org_id="org-tenant-a",
    )
    assert decision.allowed is True


def test_cross_org_no_resource_org_passes_scope() -> None:
    ctx = _ctx(org_id="org-tenant-a", roles=("customer_user",))
    decision = evaluate_access(
        ctx,
        action="read:data",
        required_permission="customer:read",
        resource_org_id=None,
    )
    assert decision.allowed is True


def test_platform_principal_bypasses_org_scope() -> None:
    ctx = _platform()
    decision = evaluate_access(
        ctx,
        action="read:data",
        resource_org_id="any-other-org",
    )
    assert decision.allowed is True
    assert decision.reason == "platform_bypass"


# ---------------------------------------------------------------------------
# Role escalation prevention
# ---------------------------------------------------------------------------


def test_customer_user_cannot_escalate_to_operator() -> None:
    ctx = _ctx(roles=("customer_user",))
    for permission in ("operator:read", "operator:write", "operator:manage"):
        decision = evaluate_permission(ctx, permission)
        assert decision.allowed is False, f"customer_user must not have {permission}"


def test_customer_admin_cannot_access_operator_surfaces() -> None:
    ctx = _ctx(roles=("customer_admin",))
    blocked = ("operator:read", "operator:write", "operator:manage", "permissions:write")
    for permission in blocked:
        decision = evaluate_permission(ctx, permission)
        assert decision.allowed is False, f"customer_admin must not have {permission}"


def test_auditor_cannot_write() -> None:
    ctx = _ctx(roles=("auditor",))
    write_perms = ("operator:write", "customer:write", "session:write", "permissions:write", "org:write")
    for permission in write_perms:
        decision = evaluate_permission(ctx, permission)
        assert decision.allowed is False, f"auditor must not have {permission}"


def test_service_cannot_access_customer_or_operator() -> None:
    ctx = _ctx(roles=("service",))
    blocked = ("operator:read", "operator:write", "customer:read", "customer:write")
    for permission in blocked:
        decision = evaluate_permission(ctx, permission)
        assert decision.allowed is False, f"service must not have {permission}"
