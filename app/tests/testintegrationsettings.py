from __future__ import annotations

from unittest.mock import MagicMock, patch

from app.ui.integrationsettings import (
    _INSTALL_PLACEHOLDER,
    _PLATFORM_INSTALL_COMMANDS,
    _resolve_install_command,
    build_ui_integration_settings_page,
    get_ui_integration_settings_page,
)

_KNOWN_PLATFORM = "claude_code"
_UNKNOWN_PLATFORM = "custom_platform_xyz"


def _make_record(platform: str = _KNOWN_PLATFORM) -> MagicMock:
    record = MagicMock()
    record.integrationid = f"id-{platform}"
    record.displayname = platform.replace("_", " ").title()
    record.platform = platform
    record.status = "active"
    record.verifiedat = "2026-01-01T00:00:00+00:00"
    record.settingsroute = f"/settings/{platform}"
    record.verificationroute = f"/verify/{platform}"
    record.manifestroute = f"/manifest/{platform}"
    record.adaptermodule = f"app.adapters.{platform}"
    record.tags = ["security", "ai"]
    record.metadata = {"version": "1.0"}
    return record


def _make_unverified_record(platform: str = "cursor") -> MagicMock:
    record = _make_record(platform)
    record.verifiedat = None
    return record


def _make_unconfigurable_record(platform: str = "goose") -> MagicMock:
    record = _make_record(platform)
    record.verifiedat = None
    record.settingsroute = None
    return record


# ---------------------------------------------------------------------------
# _resolve_install_command
# ---------------------------------------------------------------------------


class TestResolveInstallCommand:
    def test_unpaid_returns_placeholder_for_known_platform(self) -> None:
        result = _resolve_install_command(_KNOWN_PLATFORM, paid=False)
        assert result == _INSTALL_PLACEHOLDER

    def test_unpaid_returns_placeholder_for_unknown_platform(self) -> None:
        result = _resolve_install_command(_UNKNOWN_PLATFORM, paid=False)
        assert result == _INSTALL_PLACEHOLDER

    def test_paid_returns_real_command_for_known_platform(self) -> None:
        result = _resolve_install_command(_KNOWN_PLATFORM, paid=True)
        assert result == _PLATFORM_INSTALL_COMMANDS[_KNOWN_PLATFORM]
        assert _INSTALL_PLACEHOLDER not in result

    def test_paid_returns_generic_command_for_unknown_platform(self) -> None:
        result = _resolve_install_command(_UNKNOWN_PLATFORM, paid=True)
        assert _UNKNOWN_PLATFORM in result
        assert result != _INSTALL_PLACEHOLDER

    def test_all_known_platforms_have_real_commands(self) -> None:
        for platform, command in _PLATFORM_INSTALL_COMMANDS.items():
            result = _resolve_install_command(platform, paid=True)
            assert result == command
            assert _INSTALL_PLACEHOLDER not in result


# ---------------------------------------------------------------------------
# build_ui_integration_settings_page — structure
# ---------------------------------------------------------------------------


class TestBuildPageStructure:
    def _call(self, records: list, paid: bool = False) -> dict:
        registry = MagicMock()
        registry.list_integrations.return_value = records
        with patch(
            "app.ui.integrationsettings.get_integration_registry",
            return_value=registry,
        ):
            return build_ui_integration_settings_page(paid=paid)

    def test_top_level_keys_present(self) -> None:
        result = self._call([])
        for key in ("pageid", "title", "section", "status", "service", "generatedat", "summary", "actions", "settings"):
            assert key in result

    def test_pageid_unchanged(self) -> None:
        result = self._call([])
        assert result["pageid"] == "ui-integrations-settings"

    def test_empty_registry_returns_empty_settings(self) -> None:
        result = self._call([])
        assert result["settings"] == []
        assert result["summary"]["totalintegrations"] == 0

    def test_settings_list_length_matches_records(self) -> None:
        records = [_make_record("claude_code"), _make_record("cursor")]
        result = self._call(records)
        assert len(result["settings"]) == 2

    def test_install_command_key_present_on_every_card(self) -> None:
        records = [_make_record("claude_code"), _make_record("cursor"), _make_unconfigurable_record("goose")]
        result = self._call(records)
        for card in result["settings"]:
            assert "install_command" in card

    def test_all_existing_keys_still_present_on_card(self) -> None:
        result = self._call([_make_record("claude_code")])
        card = result["settings"][0]
        for key in (
            "integrationid",
            "displayname",
            "platform",
            "status",
            "verified",
            "verifiedat",
            "settingsroute",
            "verificationroute",
            "manifestroute",
            "adaptermodule",
            "configurable",
            "configurationstate",
            "tags",
            "metadata",
            "install_command",
        ):
            assert key in card, f"missing key: {key}"


# ---------------------------------------------------------------------------
# build_ui_integration_settings_page — paid=False (default)
# ---------------------------------------------------------------------------


class TestBuildPageUnpaid:
    def _call(self, records: list, paid: bool = False) -> dict:
        registry = MagicMock()
        registry.list_integrations.return_value = records
        with patch(
            "app.ui.integrationsettings.get_integration_registry",
            return_value=registry,
        ):
            return build_ui_integration_settings_page(paid=paid)

    def test_default_paid_is_false(self) -> None:
        registry = MagicMock()
        registry.list_integrations.return_value = [_make_record("claude_code")]
        with patch(
            "app.ui.integrationsettings.get_integration_registry",
            return_value=registry,
        ):
            result = build_ui_integration_settings_page()
        assert result["settings"][0]["install_command"] == _INSTALL_PLACEHOLDER

    def test_all_cards_show_placeholder_when_unpaid(self) -> None:
        records = [_make_record(p) for p in _PLATFORM_INSTALL_COMMANDS]
        result = self._call(records, paid=False)
        for card in result["settings"]:
            assert card["install_command"] == _INSTALL_PLACEHOLDER

    def test_cards_are_not_hidden_when_unpaid(self) -> None:
        records = [_make_record("claude_code"), _make_record("cursor")]
        result = self._call(records, paid=False)
        assert len(result["settings"]) == 2


# ---------------------------------------------------------------------------
# build_ui_integration_settings_page — paid=True
# ---------------------------------------------------------------------------


class TestBuildPagePaid:
    def _call(self, records: list, paid: bool = True) -> dict:
        registry = MagicMock()
        registry.list_integrations.return_value = records
        with patch(
            "app.ui.integrationsettings.get_integration_registry",
            return_value=registry,
        ):
            return build_ui_integration_settings_page(paid=paid)

    def test_known_platform_gets_real_command_when_paid(self) -> None:
        result = self._call([_make_record("claude_code")], paid=True)
        assert result["settings"][0]["install_command"] == _PLATFORM_INSTALL_COMMANDS["claude_code"]

    def test_no_card_shows_placeholder_when_paid(self) -> None:
        records = [_make_record(p) for p in _PLATFORM_INSTALL_COMMANDS]
        result = self._call(records, paid=True)
        for card in result["settings"]:
            assert card["install_command"] != _INSTALL_PLACEHOLDER

    def test_unknown_platform_gets_generic_command_when_paid(self) -> None:
        result = self._call([_make_record(_UNKNOWN_PLATFORM)], paid=True)
        cmd = result["settings"][0]["install_command"]
        assert _UNKNOWN_PLATFORM in cmd
        assert cmd != _INSTALL_PLACEHOLDER

    def test_cards_are_not_hidden_when_paid(self) -> None:
        records = [_make_record("claude_code"), _make_record("cursor")]
        result = self._call(records, paid=True)
        assert len(result["settings"]) == 2


# ---------------------------------------------------------------------------
# summary counts
# ---------------------------------------------------------------------------


class TestSummaryCounts:
    def _call(self, records: list) -> dict:
        registry = MagicMock()
        registry.list_integrations.return_value = records
        with patch(
            "app.ui.integrationsettings.get_integration_registry",
            return_value=registry,
        ):
            return build_ui_integration_settings_page()

    def test_configurable_count(self) -> None:
        records = [_make_record("claude_code"), _make_unconfigurable_record("goose")]
        result = self._call(records)
        assert result["summary"]["configurableintegrations"] == 1

    def test_verified_count(self) -> None:
        records = [_make_record("claude_code"), _make_unverified_record("cursor")]
        result = self._call(records)
        assert result["summary"]["verifiedintegrations"] == 1

    def test_pending_count(self) -> None:
        records = [_make_record("claude_code"), _make_unverified_record("cursor")]
        result = self._call(records)
        assert result["summary"]["pendingintegrations"] == 1


# ---------------------------------------------------------------------------
# configurationstate logic
# ---------------------------------------------------------------------------


class TestConfigurationState:
    def _get_card(self, record: MagicMock) -> dict:
        registry = MagicMock()
        registry.list_integrations.return_value = [record]
        with patch(
            "app.ui.integrationsettings.get_integration_registry",
            return_value=registry,
        ):
            return build_ui_integration_settings_page()["settings"][0]

    def test_verified_is_configured(self) -> None:
        assert self._get_card(_make_record("claude_code"))["configurationstate"] == "configured"

    def test_configurable_unverified_is_pending(self) -> None:
        assert self._get_card(_make_unverified_record("cursor"))["configurationstate"] == "pending"

    def test_unconfigurable_is_unavailable(self) -> None:
        assert self._get_card(_make_unconfigurable_record("goose"))["configurationstate"] == "unavailable"


# ---------------------------------------------------------------------------
# get_ui_integration_settings_page wrapper
# ---------------------------------------------------------------------------


class TestGetPageWrapper:
    def _call(self, paid: bool) -> dict:
        registry = MagicMock()
        registry.list_integrations.return_value = [_make_record("claude_code")]
        with patch(
            "app.ui.integrationsettings.get_integration_registry",
            return_value=registry,
        ):
            return get_ui_integration_settings_page(paid=paid)

    def test_wrapper_passes_paid_true(self) -> None:
        result = self._call(paid=True)
        assert result["settings"][0]["install_command"] != _INSTALL_PLACEHOLDER

    def test_wrapper_passes_paid_false(self) -> None:
        result = self._call(paid=False)
        assert result["settings"][0]["install_command"] == _INSTALL_PLACEHOLDER

    def test_wrapper_default_is_unpaid(self) -> None:
        registry = MagicMock()
        registry.list_integrations.return_value = [_make_record("claude_code")]
        with patch(
            "app.ui.integrationsettings.get_integration_registry",
            return_value=registry,
        ):
            result = get_ui_integration_settings_page()
        assert result["settings"][0]["install_command"] == _INSTALL_PLACEHOLDER
