from __future__ import annotations

import pytest

from app.services.integrationregistry import build_integration_registry


def test_build_integration_registry_returns_dictionary() -> None:
    registry = build_integration_registry()

    assert isinstance(registry, dict)
    assert registry


def test_build_integration_registry_contains_stable_top_level_fields() -> None:
    registry = build_integration_registry()

    assert "generatedat" in registry
    assert "totalintegrations" in registry
    assert "enabledintegrations" in registry
    assert "defaultguardmode" in registry
    assert "integrations" in registry


def test_build_integration_registry_exposes_integrations_list() -> None:
    registry = build_integration_registry()

    integrations = registry["integrations"]
    assert isinstance(integrations, list)
    assert integrations


def test_each_integration_contains_stable_fields() -> None:
    registry = build_integration_registry()

    integrations = registry["integrations"]
    for integration in integrations:
        assert isinstance(integration, dict)
        assert "provider" in integration
        assert "displayname" in integration
        assert "enabled" in integration
        assert "guardmode" in integration
        assert "status" in integration


def test_registry_contains_expected_provider_entries() -> None:
    registry = build_integration_registry()

    providers = {item["provider"] for item in registry["integrations"]}
    assert "claude" in providers
    assert "openclaw" in providers
    assert "groq" in providers


def test_total_integrations_matches_integrations_length() -> None:
    registry = build_integration_registry()

    integrations = registry["integrations"]
    assert registry["totalintegrations"] == len(integrations)


def test_enabled_integrations_matches_enabled_entries() -> None:
    registry = build_integration_registry()

    integrations = registry["integrations"]
    enabled_count = sum(1 for item in integrations if item["enabled"] is True)
    assert registry["enabledintegrations"] == enabled_count


def test_registry_generatedat_is_present_and_non_empty() -> None:
    registry = build_integration_registry()

    assert isinstance(registry["generatedat"], str)
    assert registry["generatedat"].strip()


def test_default_guard_mode_is_string() -> None:
    registry = build_integration_registry()

    assert isinstance(registry["defaultguardmode"], str)
    assert registry["defaultguardmode"].strip()


def test_provider_names_are_unique() -> None:
    registry = build_integration_registry()

    providers = [item["provider"] for item in registry["integrations"]]
    assert len(providers) == len(set(providers))


def test_each_provider_name_is_normalized() -> None:
    registry = build_integration_registry()

    for integration in registry["integrations"]:
        provider = integration["provider"]
        assert isinstance(provider, str)
        assert provider == provider.strip()
        assert provider == provider.lower()


def test_each_integration_uses_json_friendly_value_types() -> None:
    registry = build_integration_registry()

    for integration in registry["integrations"]:
        for key, value in integration.items():
            assert isinstance(key, str)
            assert value is None or isinstance(
                value,
                (str, int, float, bool, list, dict),
            )


def test_registry_supports_cross_platform_policy_targets() -> None:
    registry = build_integration_registry()

    providers = {item["provider"] for item in registry["integrations"]}
    assert "openclaw" in providers
    assert "claude" in providers
    assert "groq" in providers


def test_integrations_expose_policy_related_metadata_when_present() -> None:
    registry = build_integration_registry()

    found_policy_shape = False
    for integration in registry["integrations"]:
        keys = set(integration.keys())
        if {
            "supportedbundlesigning",
            "supportsrolloutcontrols",
            "supportsoverrides",
        }.issubset(keys):
            found_policy_shape = True
            assert isinstance(integration["supportedbundlesigning"], bool)
            assert isinstance(integration["supportsrolloutcontrols"], bool)
            assert isinstance(integration["supportsoverrides"], bool)

    assert found_policy_shape is True


def test_enabled_integrations_are_not_marked_missing_when_health_fields_exist() -> None:
    registry = build_integration_registry()

    for integration in registry["integrations"]:
        if integration["enabled"] is True and "installed" in integration:
            assert isinstance(integration["installed"], bool)
            if integration["installed"] is True:
                assert integration["status"] not in {"missing", "not_installed"}


def test_registry_is_stable_across_multiple_calls_for_provider_set() -> None:
    first = build_integration_registry()
    second = build_integration_registry()

    first_providers = {item["provider"] for item in first["integrations"]}
    second_providers = {item["provider"] for item in second["integrations"]}

    assert first_providers == second_providers


@pytest.mark.parametrize("required_provider", ["openclaw", "claude", "groq"])
def test_required_policy_runtime_exists(required_provider: str) -> None:
    registry = build_integration_registry()

    providers = {item["provider"] for item in registry["integrations"]}
    assert required_provider in providers


def test_each_integration_display_name_is_non_empty_string() -> None:
    registry = build_integration_registry()

    for integration in registry["integrations"]:
        assert isinstance(integration["displayname"], str)
        assert integration["displayname"].strip()


def test_each_integration_status_is_non_empty_string() -> None:
    registry = build_integration_registry()

    for integration in registry["integrations"]:
        assert isinstance(integration["status"], str)
        assert integration["status"].strip()


def test_each_integration_guard_mode_is_non_empty_string() -> None:
    registry = build_integration_registry()

    for integration in registry["integrations"]:
        assert isinstance(integration["guardmode"], str)
        assert integration["guardmode"].strip()
