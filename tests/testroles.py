from __future__ import annotations

from app.core.roles import (
    ROLE_REGISTRY,
    describe_roles,
    get_role_permissions,
    normalize_roles,
)


def test_role_registry_is_not_empty() -> None:
    assert isinstance(ROLE_REGISTRY, dict)
    assert ROLE_REGISTRY


def test_normalize_roles_returns_unique_lowercase_values() -> None:
    roles = normalize_roles(["Operator_Admin", "operator_admin", " AUDITOR ", "", None])

    assert roles == ("operator_admin", "auditor")


def test_normalize_roles_ignores_unknown_object_shapes() -> None:
    roles = normalize_roles(["operator_admin", 123, object(), None])

    assert roles == ("operator_admin",)


def test_get_role_permissions_returns_tuple_for_known_role() -> None:
    permissions = get_role_permissions("operator_admin")

    assert isinstance(permissions, tuple)


def test_get_role_permissions_returns_empty_tuple_for_unknown_role() -> None:
    permissions = get_role_permissions("role_that_does_not_exist")

    assert permissions == ()


def test_describe_roles_returns_metadata_for_known_roles() -> None:
    descriptions = describe_roles(("operator_admin", "auditor"))

    assert isinstance(descriptions, list)
    assert len(descriptions) >= 1
    assert all(isinstance(item, dict) for item in descriptions)
    assert all("role_name" in item for item in descriptions)


def test_describe_roles_skips_unknown_roles() -> None:
    descriptions = describe_roles(("operator_admin", "unknown_role"))

    role_names = {item["role_name"] for item in descriptions}

    assert "operator_admin" in role_names
    assert "unknown_role" not in role_names


def test_role_registry_entries_expose_permissions_collections() -> None:
    for role_name, definition in ROLE_REGISTRY.items():
        assert isinstance(role_name, str)
        assert role_name
        assert hasattr(definition, "permissions")
        assert isinstance(definition.permissions, tuple)


def test_operator_admin_role_contains_permissions() -> None:
    permissions = get_role_permissions("operator_admin")

    assert len(permissions) >= 1


def test_role_descriptions_remain_unique_by_role_name() -> None:
    descriptions = describe_roles(("operator_admin", "operator_admin", "auditor"))

    role_names = [item["role_name"] for item in descriptions]

    assert len(role_names) == len(set(role_names))