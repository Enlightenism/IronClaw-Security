from __future__ import annotations

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
        "OpenAI",
        "Claude",
        "OpenClaw",
    ]

    missing_markers = [marker for marker in expected_markers if marker not in content]
    assert not missing_markers, f"missing UI markers: {missing_markers}"


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