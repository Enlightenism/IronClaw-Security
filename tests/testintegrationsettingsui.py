from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from app.ui.integrations.settings import buildintegrationssettingsview


def test_buildintegrationssettingsview_returns_html_response() -> None:
    response = buildintegrationssettingsview()
    assert isinstance(response, HTMLResponse)
    assert response.status_code == 200


def test_buildintegrationssettingsview_returns_html_document() -> None:
    response = buildintegrationssettingsview()

    content = response.body.decode("utf-8")
    assert "<!DOCTYPE html>" in content
    assert "<html" in content
    assert "</html>" in content
    assert "<body" in content
    assert "</body>" in content


def test_buildintegrationssettingsview_contains_page_title_and_heading() -> None:
    response = buildintegrationssettingsview()

    content = response.body.decode("utf-8")
    assert "Integration Settings" in content
    assert "<title>Integration Settings" in content or ">Integration Settings<" in content


def test_buildintegrationssettingsview_contains_expected_settings_sections() -> None:
    response = buildintegrationssettingsview()

    content = response.body.decode("utf-8")
    expected_markers = [
        "Default Guard Mode",
        "Bidirectional Sync",
        "Providers",
        "OpenClaw",
        "Claude Code",
        "Cursor",
        "Goose",
        "Gemini CLI",
        "GitHub Copilot",
        "Security Guardian",
    ]
    missing_markers = [marker for marker in expected_markers if marker not in content]
    assert not missing_markers, f"missing UI markers: {missing_markers}"

    expected_providers = {
        "OpenClaw",
        "Claude Code",
        "Cursor",
        "Goose",
        "Gemini CLI",
        "GitHub Copilot",
        "Security Guardian",
    }
    present_providers = {marker for marker in expected_providers if marker in content}
    assert present_providers == expected_providers

    stale_markers = ["OpenAI", "Standalone IronClaw"]
    assert all(not re.search(rf"(?i)\b{re.escape(marker)}\b", content) for marker in stale_markers), f"stale UI markers present: {stale_markers}"


def test_buildintegrationssettingsview_uses_canonical_provider_metadata() -> None:
    response = buildintegrationssettingsview()

    content = response.body.decode("utf-8")
    expected_providers = [
        "OpenClaw",
        "Claude Code",
        "Cursor",
        "Goose",
        "Gemini CLI",
        "GitHub Copilot",
        "Security Guardian",
    ]
    for provider in expected_providers:
        assert provider in content
    assert "Standalone IronClaw" not in content
    assert not re.search(r"(?i)\bstandalone\s+ironclaw\b", content)


def test_buildintegrationssettingsview_contains_stable_test_ids() -> None:
    response = buildintegrationssettingsview()

    content = response.body.decode("utf-8")
    expected_test_ids = [
        'data-testid="integrations-settings-page"',
        'data-testid="default-guard-mode"',
        'data-testid="bidirectional-sync"',
        'data-testid="providers-list"',
    ]

    missing_test_ids = [marker for marker in expected_test_ids if marker not in content]
    assert not missing_test_ids, f"missing test ids: {missing_test_ids}"
