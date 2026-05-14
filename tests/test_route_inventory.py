from __future__ import annotations

from app.main import app


def _route_signatures() -> set[tuple[str, str]]:
    signatures: set[tuple[str, str]] = set()

    for route in app.routes:
        path = getattr(route, "path", None)
        methods = getattr(route, "methods", None)

        if not path or not methods:
            continue

        for method in methods:
            if method in {"HEAD", "OPTIONS"}:
                continue
            signatures.add((method, path))

    return signatures


def test_expected_core_routes_are_registered():
    routes = _route_signatures()

    expected = {
        ("GET", "/"),
        ("GET", "/health"),
        ("POST", "/scan/"),
        ("POST", "/scan/batch"),
        ("GET", "/history/"),
        ("GET", "/history/{scan_id}"),
        ("POST", "/history/{scan_id}/review"),
        ("GET", "/history/events"),
        ("GET", "/history/events/by-session/{session_id}"),
        ("GET", "/history/events/by-actor/{actor_id}"),
        ("GET", "/guard/reviews/summary"),
        ("GET", "/guard/reviews/pending"),
        ("GET", "/guard/reviews/{review_id}"),
        ("POST", "/guard/reviews/{review_id}/approve"),
        ("POST", "/guard/reviews/{review_id}/reject"),
        ("GET", "/guard/audit/events"),
        ("GET", "/guard/audit/events/by-session/{session_id}"),
        ("GET", "/guard/audit/events/by-actor/{actor_id}"),
        ("GET", "/guard/audit/events/by-request/{request_id}"),
        ("GET", "/guard/audit/events/by-trace/{trace_id}"),
        ("POST", "/guard/execute"),
        ("GET", "/policy/status"),
        ("POST", "/policy/guard-bundle"),
        ("GET", "/docs"),
        ("GET", "/openapi.json"),
    }

    missing = expected - routes
    assert not missing, f"Missing expected routes: {sorted(missing)}"
