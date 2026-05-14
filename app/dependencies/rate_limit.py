from __future__ import annotations

from fastapi import Request

from app.core.rate_limit import enforce_rate_limit


def limit_policy_routes(request: Request) -> None:
    enforce_rate_limit(
        request,
        bucket="policy_routes",
        limit=30,
        window_seconds=60,
    )


def limit_guard_routes(request: Request) -> None:
    enforce_rate_limit(
        request,
        bucket="guard_routes",
        limit=60,
        window_seconds=60,
    )


def limit_execute_routes(request: Request) -> None:
    enforce_rate_limit(
        request,
        bucket="execute_routes",
        limit=20,
        window_seconds=60,
    )


def limit_scan_routes(request: Request) -> None:
    enforce_rate_limit(
        request,
        bucket="scan_routes",
        limit=30,
        window_seconds=60,
    )
