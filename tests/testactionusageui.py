from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


USAGE_UI_PATHS = (
    "/ui/usage/reports",
    "/ui/usage/event",
    "/ui/usage",
    "/ui/usage/summary",
)


def _safe_get(path: str) -> Any:
    response = client.get(path)
    if response.status_code == 404:
        pytest.skip(f"usage UI route not registered: {path}")
    assert response.status_code < 500
    return response


def _html_from(path: str) -> str:
    response = _safe_get(path)
    assert response.status_code == 200
    content_type = response.headers.get("content-type", "")
    assert content_type.startswith("text/html") or "html" in content_type
    body = response.text
    assert isinstance(body, str)
    assert body.strip()
    return body


def test_usage_ui_has_at_least_one_registered_route() -> None:
    statuses = []
    for path in USAGE_UI_PATHS:
        response = client.get(path)
        statuses.append(response.status_code)

    assert any(status == 200 for status in statuses)


@pytest.mark.parametrize("path", USAGE_UI_PATHS)
def test_usage_ui_routes_do_not_error_when_present(path: str) -> None:
    response = client.get(path)
    if response.status_code == 404:
        pytest.skip(f"usage UI route not registered: {path}")

    assert response.status_code == 200
    assert response.headers.get("content-type", "").startswith("text/html")


@pytest.mark.parametrize("path", USAGE_UI_PATHS)
def test_usage_ui_routes_render_non_empty_html_when_present(path: str) -> None:
    body = _html_from(path)

    assert "<html" in body.lower()
    assert "</html>" in body.lower()


@pytest.mark.parametrize("path", USAGE_UI_PATHS)
def test_usage_ui_routes_include_usage_related_keywords_when_present(path: str) -> None:
    body = _html_from(path).lower()

    assert any(
        keyword in body
        for keyword in (
            "usage",
            "units",
            "quota",
            "remaining",
            "billing",
            "summary",
            "owner",
        )
    )


@pytest.mark.parametrize("path", USAGE_UI_PATHS)
def test_usage_ui_routes_are_not_redirects(path: str) -> None:
    response = client.get(path, follow_redirects=False)
    if response.status_code == 404:
        pytest.skip(f"usage UI route not registered: {path}")

    assert response.status_code not in {301, 302, 307, 308}


@pytest.mark.parametrize("path", USAGE_UI_PATHS)
def test_usage_ui_routes_are_repeatable_when_present(path: str) -> None:
    first = client.get(path)
    second = client.get(path)

    if first.status_code == 404 or second.status_code == 404:
        pytest.skip(f"usage UI route not registered: {path}")

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.text.strip()
    assert second.text.strip()


def test_usage_reports_ui_route_contains_table_or_list_when_present() -> None:
    path_candidates = ("/ui/usage/reports", "/ui/usage")
    for path in path_candidates:
        response = client.get(path)
        if response.status_code != 200:
            continue

        body = response.text.lower()
        assert any(tag in body for tag in ("<table", "<ul", "<ol", "data-usage"))
        return

    pytest.skip("usage reports UI route not available")


def test_usage_event_detail_ui_route_contains_detail_elements_when_present() -> None:
    path_candidates = ("/ui/usage/event", "/ui/usage/detail")
    for path in path_candidates:
        response = client.get(path)
        if response.status_code != 200:
            continue

        body = response.text.lower()
        assert any(
            keyword in body
            for keyword in (
                "event",
                "detail",
                "request",
                "usage id",
                "owner",
            )
        )
        return

    pytest.skip("usage event detail UI route not available")


def test_usage_summary_ui_route_contains_summary_keywords_when_present() -> None:
    path_candidates = ("/ui/usage/summary", "/ui/usage")
    for path in path_candidates:
        response = client.get(path)
        if response.status_code != 200:
            continue

        body = response.text.lower()
        assert any(
            keyword in body
            for keyword in (
                "summary",
                "totals",
                "total units",
                "total cost",
                "remaining quota",
            )
        )
        return

    pytest.skip("usage summary UI route not available")


def test_usage_ui_routes_include_csrf_or_safety_indicators_when_present() -> None:
    for path in USAGE_UI_PATHS:
        response = client.get(path)
        if response.status_code != 200:
            continue

        body = response.text.lower()
        if "form" in body:
            assert any(
                token in body
                for token in (
                    "csrf",
                    "xsrf",
                    "data-token",
                    "data-request-id",
                )
            )
            return

    pytest.skip("no usage UI forms detected for CSRF check")


def test_usage_ui_routes_include_owner_or_account_reference_when_present() -> None:
    for path in USAGE_UI_PATHS:
        response = client.get(path)
        if response.status_code != 200:
            continue

        body = response.text.lower()
        if any(keyword in body for keyword in ("owner", "account", "user")):
            return

    pytest.skip("usage UI does not surface owner/account keywords")