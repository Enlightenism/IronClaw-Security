from __future__ import annotations

import pytest

from app.core.auth import AuthContext
from app.core.errors import AppError
from app.core.org_isolation import (
    DEFAULT_BYPASS_ROLES,
    OrgIsolationDecision,
    evaluate_org_isolation,
    org_ids_match,
    require_matching_org_ids,
    require_same_org,
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


# ---------------------------------------------------------------------------
# OrgIsolationDecision shape
# ---------------------------------------------------------------------------


def test_org_isolation_decision_to_dict_shape() -> None:
    decision = OrgIsolationDecision(
        allowed=True,
        principal_id="p-001",
        principal_type="api_key",
        actor_org_id="org-a",
        target_org_id="org-a",
        reason="org_match",
        bypass_roles=(),
        matched_roles=(),
        metadata={},
    )
    d = decision.to_dict()
    assert "allowed" in d
    assert "principal_id" in d
    assert "principal_type" in d
    assert "actor_org_id" in d
    assert "target_org_id" in d
    assert "reason" in d
    assert isinstance(d["bypass_roles"], list)
    assert isinstance(d["matched_roles"], list)
    assert isinstance(d["metadata"], dict)


def test_org_isolation_decision_denied_shape() -> None:
    decision = OrgIsolationDecision(
        allowed=False,
        principal_id="p-002",
        principal_type="api_key",
        actor_org_id="org-a",
        target_org_id="org-b",
        reason="org_isolation_violation",
        bypass_roles=DEFAULT_BYPASS_ROLES,
        matched_roles=(),
        metadata={"resource": "record-x"},
    )
    d = decision.to_dict()
    assert d["allowed"] is False
    assert d["reason"] == "org_isolation_violation"
    assert d["actor_org_id"] == "org-a"
    assert d["target_org_id"] == "org-b"
    assert d["metadata"] == {"resource": "record-x"}


# ---------------------------------------------------------------------------
# DEFAULT_BYPASS_ROLES
# ---------------------------------------------------------------------------


def test_default_bypass_roles_contains_expected() -> None:
    assert "platform_admin" in DEFAULT_BYPASS_ROLES
    assert "system_admin" in DEFAULT_BYPASS_ROLES
    assert "operator_admin" in DEFAULT_BYPASS_ROLES


def test_default_bypass_roles_excludes_customer_roles() -> None:
    assert "customer_admin" not in DEFAULT_BYPASS_ROLES
    assert "customer_user" not in DEFAULT_BYPASS_ROLES
    assert "auditor" not in DEFAULT_BYPASS_ROLES


# ---------------------------------------------------------------------------
# org_ids_match
# ---------------------------------------------------------------------------


def test_org_ids_match_same_value() -> None:
    assert org_ids_match("org-a", "org-a") is True


def test_org_ids_match_different_values() -> None:
    assert org_ids_match("org-a", "org-b") is False


def test_org_ids_match_none_left() -> None:
    assert org_ids_match(None, "org-a") is False


def test_org_ids_match_none_right() -> None:
    assert org_ids_match("org-a", None) is False


def test_org_ids_match_both_none() -> None:
    assert org_ids_match(None, None) is False


def test_org_ids_match_whitespace_treated_as_empty() -> None:
    assert org_ids_match("  ", "org-a") is False
    assert org_ids_match("org-a", "  ") is False


def test_org_ids_match_case_sensitive() -> None:
    assert org_ids_match("Org-A", "org-a") is False


def test_org_ids_match_strips_whitespace() -> None:
    assert org_ids_match(" org-a ", " org-a ") is True


# ---------------------------------------------------------------------------
# evaluate_org_isolation — unauthenticated
# ---------------------------------------------------------------------------


def test_evaluate_org_isolation_unauthenticated_denied() -> None:
    ctx = _anon()
    decision = evaluate_org_isolation(ctx, target_org_id="org-a")
    assert decision.allowed is False
    assert decision.reason == "authentication_required"
    assert decision.actor_org_id is None
    assert decision.target_org_id == "org-a"


# ---------------------------------------------------------------------------
# evaluate_org_isolation — bypass roles
# ---------------------------------------------------------------------------


def test_evaluate_org_isolation_platform_admin_bypasses() -> None:
    ctx = _ctx(org_id="org-a", roles=("platform_admin",))
    decision = evaluate_org_isolation(ctx, target_org_id="org-b")
    assert decision.allowed is True
    assert decision.reason == "bypass_role"
    assert "platform_admin" in decision.matched_roles


def test_evaluate_org_isolation_system_admin_bypasses() -> None:
    ctx = _ctx(org_id="org-a", roles=("system_admin",))
    decision = evaluate_org_isolation(ctx, target_org_id="org-z")
    assert decision.allowed is True
    assert decision.reason == "bypass_role"
    assert "system_admin" in decision.matched_roles


def test_evaluate_org_isolation_operator_admin_bypasses() -> None:
    ctx = _ctx(org_id="org-a", roles=("operator_admin",))
    decision = evaluate_org_isolation(ctx, target_org_id="org-b")
    assert decision.allowed is True
    assert decision.reason == "bypass_role"
    assert "operator_admin" in decision.matched_roles


def test_evaluate_org_isolation_bypass_with_null_target() -> None:
    ctx = _ctx(org_id="org-a", roles=("platform_admin",))
    decision = evaluate_org_isolation(ctx, target_org_id=None)
    assert decision.allowed is True
    assert decision.reason == "bypass_role"


def test_evaluate_org_isolation_custom_bypass_roles() -> None:
    ctx = _ctx(org_id="org-a", roles=("auditor",))
    decision = evaluate_org_isolation(ctx, target_org_id="org-b", bypass_roles=["auditor"])
    assert decision.allowed is True
    assert decision.reason == "bypass_role"
    assert "auditor" in decision.matched_roles


def test_evaluate_org_isolation_custom_bypass_excludes_defaults() -> None:
    ctx = _ctx(org_id="org-a", roles=("platform_admin",))
    decision = evaluate_org_isolation(ctx, target_org_id="org-b", bypass_roles=["auditor"])
    assert decision.allowed is False
    assert decision.reason == "org_isolation_violation"


# ---------------------------------------------------------------------------
# evaluate_org_isolation — target org required
# ---------------------------------------------------------------------------


def test_evaluate_org_isolation_null_target_denied() -> None:
    ctx = _ctx(org_id="org-a")
    decision = evaluate_org_isolation(ctx, target_org_id=None)
    assert decision.allowed is False
    assert decision.reason == "target_org_required"
    assert decision.target_org_id is None


def test_evaluate_org_isolation_whitespace_target_denied() -> None:
    ctx = _ctx(org_id="org-a")
    decision = evaluate_org_isolation(ctx, target_org_id="   ")
    assert decision.allowed is False
    assert decision.reason == "target_org_required"


# ---------------------------------------------------------------------------
# evaluate_org_isolation — actor org required
# ---------------------------------------------------------------------------


def test_evaluate_org_isolation_null_actor_org_denied() -> None:
    ctx = _ctx(org_id=None)
    decision = evaluate_org_isolation(ctx, target_org_id="org-b")
    assert decision.allowed is False
    assert decision.reason == "actor_org_required"
    assert decision.actor_org_id is None
    assert decision.target_org_id == "org-b"


def test_evaluate_org_isolation_whitespace_actor_org_denied() -> None:
    ctx = _ctx(org_id="  ")
    decision = evaluate_org_isolation(ctx, target_org_id="org-b")
    assert decision.allowed is False
    assert decision.reason == "actor_org_required"


# ---------------------------------------------------------------------------
# evaluate_org_isolation — org match / mismatch
# ---------------------------------------------------------------------------


def test_evaluate_org_isolation_same_org_allowed() -> None:
    ctx = _ctx(org_id="org-tenant-a")
    decision = evaluate_org_isolation(ctx, target_org_id="org-tenant-a")
    assert decision.allowed is True
    assert decision.reason == "org_match"
    assert decision.actor_org_id == "org-tenant-a"
    assert decision.target_org_id == "org-tenant-a"


def test_evaluate_org_isolation_different_org_denied() -> None:
    ctx = _ctx(org_id="org-tenant-a")
    decision = evaluate_org_isolation(ctx, target_org_id="org-tenant-b")
    assert decision.allowed is False
    assert decision.reason == "org_isolation_violation"
    assert decision.actor_org_id == "org-tenant-a"
    assert decision.target_org_id == "org-tenant-b"


def test_evaluate_org_isolation_case_sensitive_mismatch() -> None:
    ctx = _ctx(org_id="Org-A")
    decision = evaluate_org_isolation(ctx, target_org_id="org-a")
    assert decision.allowed is False
    assert decision.reason == "org_isolation_violation"


def test_evaluate_org_isolation_whitespace_stripped_match() -> None:
    ctx = _ctx(org_id=" org-a ")
    decision = evaluate_org_isolation(ctx, target_org_id=" org-a ")
    assert decision.allowed is True
    assert decision.reason == "org_match"


# ---------------------------------------------------------------------------
# evaluate_org_isolation — metadata
# ---------------------------------------------------------------------------


def test_evaluate_org_isolation_metadata_stringified() -> None:
    ctx = _ctx(org_id="org-a")
    decision = evaluate_org_isolation(
        ctx,
        target_org_id="org-a",
        metadata={"record_id": 99, "flag": True},
    )
    assert decision.metadata["record_id"] == "99"
    assert decision.metadata["flag"] == "True"


def test_evaluate_org_isolation_no_metadata_defaults_empty() -> None:
    ctx = _ctx(org_id="org-a")
    decision = evaluate_org_isolation(ctx, target_org_id="org-a")
    assert decision.metadata == {}


# ---------------------------------------------------------------------------
# evaluate_org_isolation — bypass_roles field propagated
# ---------------------------------------------------------------------------


def test_evaluate_org_isolation_bypass_roles_propagated_to_decision() -> None:
    ctx = _ctx(org_id="org-a")
    decision = evaluate_org_isolation(ctx, target_org_id="org-a")
    assert set(DEFAULT_BYPASS_ROLES).issubset(set(decision.bypass_roles))


def test_evaluate_org_isolation_custom_bypass_roles_propagated() -> None:
    ctx = _ctx(org_id="org-a")
    decision = evaluate_org_isolation(ctx, target_org_id="org-a", bypass_roles=["auditor", "operator_analyst"])
    assert "auditor" in decision.bypass_roles
    assert "operator_analyst" in decision.bypass_roles


# ---------------------------------------------------------------------------
# require_same_org
# ---------------------------------------------------------------------------


def test_require_same_org_passes_same_org() -> None:
    ctx = _ctx(org_id="org-a")
    result = require_same_org(ctx, target_org_id="org-a")
    assert result is ctx


def test_require_same_org_passes_bypass_role() -> None:
    ctx = _ctx(org_id="org-a", roles=("platform_admin",))
    result = require_same_org(ctx, target_org_id="org-b")
    assert result is ctx


def test_require_same_org_raises_403_org_mismatch() -> None:
    ctx = _ctx(org_id="org-a")
    with pytest.raises(AppError) as exc_info:
        require_same_org(ctx, target_org_id="org-b")
    exc = exc_info.value
    assert exc.status_code == 403
    assert exc.error == "org_isolation_denied"
    assert exc.details["reason"] == "org_isolation_violation"


def test_require_same_org_raises_401_unauthenticated() -> None:
    ctx = _anon()
    with pytest.raises(AppError) as exc_info:
        require_same_org(ctx, target_org_id="org-b")
    assert exc_info.value.status_code == 401
    assert exc_info.value.error == "org_isolation_denied"


def test_require_same_org_raises_403_null_target() -> None:
    ctx = _ctx(org_id="org-a")
    with pytest.raises(AppError) as exc_info:
        require_same_org(ctx, target_org_id=None)
    exc = exc_info.value
    assert exc.status_code == 403
    assert exc.details["reason"] == "target_org_required"


def test_require_same_org_raises_403_null_actor_org() -> None:
    ctx = _ctx(org_id=None)
    with pytest.raises(AppError) as exc_info:
        require_same_org(ctx, target_org_id="org-b")
    exc = exc_info.value
    assert exc.status_code == 403
    assert exc.details["reason"] == "actor_org_required"


def test_require_same_org_details_shape() -> None:
    ctx = _ctx(org_id="org-a")
    with pytest.raises(AppError) as exc_info:
        require_same_org(ctx, target_org_id="org-b")
    details = exc_info.value.details
    assert "allowed" in details
    assert "actor_org_id" in details
    assert "target_org_id" in details
    assert "reason" in details
    assert isinstance(details["bypass_roles"], list)
    assert isinstance(details["matched_roles"], list)
    assert isinstance(details["metadata"], dict)


# ---------------------------------------------------------------------------
# require_matching_org_ids
# ---------------------------------------------------------------------------


def test_require_matching_org_ids_same_returns_org_id() -> None:
    result = require_matching_org_ids("org-a", "org-a")
    assert result == "org-a"


def test_require_matching_org_ids_mismatch_raises_403() -> None:
    with pytest.raises(AppError) as exc_info:
        require_matching_org_ids("org-a", "org-b")
    exc = exc_info.value
    assert exc.status_code == 403
    assert exc.error == "org_isolation_denied"
    assert exc.details["reason"] == "org_isolation_violation"


def test_require_matching_org_ids_null_actor_raises_403() -> None:
    with pytest.raises(AppError) as exc_info:
        require_matching_org_ids(None, "org-b")
    exc = exc_info.value
    assert exc.status_code == 403
    assert exc.details["reason"] == "actor_org_required"
    assert exc.details["actor_org_id"] is None


def test_require_matching_org_ids_null_target_raises_403() -> None:
    with pytest.raises(AppError) as exc_info:
        require_matching_org_ids("org-a", None)
    exc = exc_info.value
    assert exc.status_code == 403
    assert exc.details["reason"] == "target_org_required"
    assert exc.details["target_org_id"] is None


def test_require_matching_org_ids_both_none_actor_check_first() -> None:
    with pytest.raises(AppError) as exc_info:
        require_matching_org_ids(None, None)
    assert exc_info.value.details["reason"] == "actor_org_required"


def test_require_matching_org_ids_whitespace_actor_raises() -> None:
    with pytest.raises(AppError) as exc_info:
        require_matching_org_ids("  ", "org-b")
    assert exc_info.value.details["reason"] == "actor_org_required"


def test_require_matching_org_ids_whitespace_target_raises() -> None:
    with pytest.raises(AppError) as exc_info:
        require_matching_org_ids("org-a", "  ")
    assert exc_info.value.details["reason"] == "target_org_required"


def test_require_matching_org_ids_metadata_in_details() -> None:
    with pytest.raises(AppError) as exc_info:
        require_matching_org_ids("org-a", "org-b", metadata={"op": "delete"})
    assert exc_info.value.details["metadata"] == {"op": "delete"}


def test_require_matching_org_ids_returns_normalized_value() -> None:
    result = require_matching_org_ids(" org-clean ", " org-clean ")
    assert result == "org-clean"


# ---------------------------------------------------------------------------
# Multi-tenant isolation matrix
# ---------------------------------------------------------------------------


_TENANT_MATRIX: list[tuple[str, str, tuple[str, ...], bool, str]] = [
    # (actor_org, target_org, roles, expected_allowed, expected_reason)
    ("org-a", "org-a", (), True, "org_match"),
    ("org-a", "org-b", (), False, "org_isolation_violation"),
    ("org-a", "org-b", ("platform_admin",), True, "bypass_role"),
    ("org-a", "org-b", ("system_admin",), True, "bypass_role"),
    ("org-a", "org-b", ("operator_admin",), True, "bypass_role"),
    ("org-a", "org-b", ("operator_analyst",), False, "org_isolation_violation"),
    ("org-a", "org-b", ("customer_admin",), False, "org_isolation_violation"),
    ("org-a", "org-b", ("customer_user",), False, "org_isolation_violation"),
    ("org-a", "org-b", ("auditor",), False, "org_isolation_violation"),
    ("org-a", "org-b", ("service",), False, "org_isolation_violation"),
    ("org-tenant-x", "org-tenant-x", ("customer_user",), True, "org_match"),
    ("org-tenant-x", "org-tenant-y", ("customer_user",), False, "org_isolation_violation"),
]


def test_tenant_isolation_matrix() -> None:
    for actor_org, target_org, roles, expected_allowed, expected_reason in _TENANT_MATRIX:
        ctx = _ctx(org_id=actor_org, roles=roles)
        decision = evaluate_org_isolation(ctx, target_org_id=target_org)
        assert decision.allowed is expected_allowed, f"actor={actor_org!r} target={target_org!r} roles={roles!r} expected={expected_allowed} got={decision.allowed} reason={decision.reason!r}"
        assert decision.reason == expected_reason, f"actor={actor_org!r} target={target_org!r} roles={roles!r} expected_reason={expected_reason!r} got={decision.reason!r}"


# ---------------------------------------------------------------------------
# Cross-tenant data leakage prevention
# ---------------------------------------------------------------------------


def test_different_tenants_are_always_isolated() -> None:
    tenants = ["org-alpha", "org-beta", "org-gamma", "org-delta"]
    for i, actor in enumerate(tenants):
        for j, target in enumerate(tenants):
            ctx = _ctx(org_id=actor)
            decision = evaluate_org_isolation(ctx, target_org_id=target)
            if i == j:
                assert decision.allowed is True, f"{actor} → {target} should be allowed"
                assert decision.reason == "org_match"
            else:
                assert decision.allowed is False, f"{actor} → {target} should be denied"
                assert decision.reason == "org_isolation_violation"


def test_platform_admin_sees_all_tenants() -> None:
    ctx = _ctx(org_id="org-platform", roles=("platform_admin",))
    for target in ("org-alpha", "org-beta", "org-gamma", "org-delta"):
        decision = evaluate_org_isolation(ctx, target_org_id=target)
        assert decision.allowed is True
        assert decision.reason == "bypass_role"


def test_customer_user_locked_to_own_org() -> None:
    ctx = _ctx(org_id="org-mine", roles=("customer_user",))
    decision_same = evaluate_org_isolation(ctx, target_org_id="org-mine")
    assert decision_same.allowed is True

    for other in ("org-other-1", "org-other-2", "org-other-3"):
        decision = evaluate_org_isolation(ctx, target_org_id=other)
        assert decision.allowed is False
        assert decision.reason == "org_isolation_violation"


def test_auditor_locked_to_own_org_by_default() -> None:
    ctx = _ctx(org_id="org-audit", roles=("auditor",))
    decision = evaluate_org_isolation(ctx, target_org_id="org-other")
    assert decision.allowed is False
    assert decision.reason == "org_isolation_violation"


def test_operator_analyst_locked_to_own_org_by_default() -> None:
    ctx = _ctx(org_id="org-ops", roles=("operator_analyst",))
    decision = evaluate_org_isolation(ctx, target_org_id="org-other")
    assert decision.allowed is False
    assert decision.reason == "org_isolation_violation"


# ---------------------------------------------------------------------------
# Unauthenticated cross-tenant attempts
# ---------------------------------------------------------------------------


def test_anonymous_cannot_access_any_org() -> None:
    ctx = _anon()
    for target in ("org-a", "org-b", "org-c"):
        decision = evaluate_org_isolation(ctx, target_org_id=target)
        assert decision.allowed is False
        assert decision.reason == "authentication_required"


def test_anonymous_require_same_org_raises_401() -> None:
    ctx = _anon()
    with pytest.raises(AppError) as exc_info:
        require_same_org(ctx, target_org_id="org-a")
    assert exc_info.value.status_code == 401
