from __future__ import annotations

import argparse
import json
import os
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Final

import httpx

REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[1]
RESULT_FILE: Final[Path] = REPO_ROOT / ".smoketest-results.json"

DEFAULT_BASE_URL: Final[str] = "http://127.0.0.1:8000"

HEALTH_ENDPOINT: Final[str] = "/api/health"
PROBES_LIVENESS_ENDPOINT: Final[str] = "/api/health/liveness"
PROBES_READINESS_ENDPOINT: Final[str] = "/api/health/readiness"
SYSTEM_STATUS_ENDPOINT: Final[str] = "/api/system/status"

UI_MANIFEST_ENDPOINT: Final[str] = "/api/ui/manifest"
UI_STATUS_ENDPOINT: Final[str] = "/api/ui/status/runtime"
UI_RUNTIME_STATUS_ENDPOINT: Final[str] = "/api/ui/runtime/status"

TIMEOUT_SECONDS: Final[float] = 5.0


@dataclass(frozen=True, slots=True)
class SmokeCheck:
    name: str
    ok: bool
    status_code: int | None
    detail: str
    duration_ms: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class SmokeTestReport:
    base_url: str
    overall_status: str
    checks: tuple[SmokeCheck, ...]
    total_duration_ms: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "base_url": self.base_url,
            "overall_status": self.overall_status,
            "total_duration_ms": self.total_duration_ms,
            "checks": [check.to_dict() for check in self.checks],
        }


def _env_base_url() -> str:
    value = os.environ.get("IRONCLAW_BASE_URL")
    if not value:
        return DEFAULT_BASE_URL
    return value.rstrip("/")


def _record(
    checks: list[SmokeCheck],
    name: str,
    ok: bool,
    status_code: int | None,
    detail: str,
    duration_ms: int,
) -> None:
    entry = SmokeCheck(
        name=name,
        ok=ok,
        status_code=status_code,
        detail=detail,
        duration_ms=duration_ms,
    )
    checks.append(entry)
    label = "OK" if ok else "FAIL"
    status_display = f" ({status_code})" if status_code is not None else ""
    print(f"[{label}] {name}{status_display} [{duration_ms}ms]: {detail}")


def _response_snippet(response: httpx.Response, limit: int = 400) -> str:
    text = response.text
    if len(text) <= limit:
        return text
    return text[:limit] + "...(truncated)"


def _validate_success_payload(name: str, payload: Any) -> tuple[bool, str]:
    if isinstance(payload, dict):
        if name in {"health", "health-liveness", "health-readiness", "system-status"}:
            status = str(payload.get("status", "")).lower()
            if status not in {"ok", "pass", "healthy"}:
                return False, f"unexpected payload status field: {payload!r}"
            return True, "healthy status"

        if name.startswith("ui-"):
            return True, "ui endpoint reachable"

        return True, "ok"

    return True, "non-dict JSON payload"


def _get(client: httpx.Client, name: str, path: str, checks: list[SmokeCheck]) -> None:
    started = time.perf_counter()

    try:
        response = client.get(path)
    except httpx.RequestError as exc:
        duration_ms = round((time.perf_counter() - started) * 1000)
        _record(
            checks,
            name,
            False,
            None,
            f"request error: {exc.__class__.__name__}: {exc}",
            duration_ms,
        )
        return

    duration_ms = round((time.perf_counter() - started) * 1000)
    ok = 200 <= response.status_code < 300
    if not ok:
        _record(
            checks,
            name,
            False,
            response.status_code,
            f"unexpected status {response.status_code}, body: {_response_snippet(response)!r}",
            duration_ms,
        )
        return

    try:
        payload = response.json()
    except ValueError:
        _record(checks, name, True, response.status_code, "non-JSON response body", duration_ms)
        return

    payload_ok, detail = _validate_success_payload(name, payload)
    _record(checks, name, payload_ok, response.status_code, detail, duration_ms)


def _run_smoketests(base_url: str) -> SmokeTestReport:
    checks: list[SmokeCheck] = []
    timeout = httpx.Timeout(TIMEOUT_SECONDS)
    started = time.perf_counter()

    with httpx.Client(base_url=base_url, timeout=timeout, follow_redirects=True) as client:
        _get(client, "health", HEALTH_ENDPOINT, checks)
        _get(client, "health-liveness", PROBES_LIVENESS_ENDPOINT, checks)
        _get(client, "health-readiness", PROBES_READINESS_ENDPOINT, checks)
        _get(client, "system-status", SYSTEM_STATUS_ENDPOINT, checks)

        _get(client, "ui-manifest", UI_MANIFEST_ENDPOINT, checks)
        _get(client, "ui-status", UI_STATUS_ENDPOINT, checks)
        _get(client, "ui-runtime-status", UI_RUNTIME_STATUS_ENDPOINT, checks)

    total_duration_ms = round((time.perf_counter() - started) * 1000)
    overall_status = "ok" if all(check.ok for check in checks) else "fail"
    return SmokeTestReport(
        base_url=base_url,
        overall_status=overall_status,
        checks=tuple(checks),
        total_duration_ms=total_duration_ms,
    )


def _write_report(report: SmokeTestReport) -> None:
    RESULT_FILE.write_text(
        json.dumps(report.to_dict(), indent=2) + "\n",
        encoding="utf-8",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run IronClaw smoke tests against a running instance."
    )
    parser.add_argument(
        "--base-url",
        help=f"Override base URL for the IronClaw API (default: {DEFAULT_BASE_URL!r} or $IRONCLAW_BASE_URL).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the smoke test report JSON to stdout in addition to writing it to disk.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    base_url = (args.base_url or _env_base_url()).rstrip("/")

    print(f"Running IronClaw smoketests against {base_url} ...")
    report = _run_smoketests(base_url)
    _write_report(report)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))

    print(f"SMOKETEST: {report.overall_status.upper()} ({report.total_duration_ms}ms)")
    return 0 if report.overall_status == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())