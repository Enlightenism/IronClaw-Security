from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final, Literal

import httpx

DEFAULT_BASE_URL: Final[str] = "http://127.0.0.1:8000"
DEFAULT_TIMEOUT_SECONDS: Final[float] = 5.0
DEFAULT_RESULT_FILE: Final[Path] = Path(__file__).resolve().with_name(".smoketestclient-results.json")

# FastAPI app exposes these routes without the /api prefix
HEALTH_ENDPOINT: Final[str] = "/health"
LIVENESS_ENDPOINT: Final[str] = "/health/liveness"
READINESS_ENDPOINT: Final[str] = "/health/readiness"
SYSTEM_STATUS_ENDPOINT: Final[str] = "/system/status"
UI_MANIFEST_ENDPOINT: Final[str] = "/ui/manifest"
UI_STATUS_ENDPOINT: Final[str] = "/ui/status"
UI_RUNTIME_STATUS_ENDPOINT: Final[str] = "/ui/runtime-status"

HEALTHY_STATUS_VALUES: Final[set[str]] = {"ok", "pass", "healthy", "ready", "live", "alive"}
CheckKind = Literal["health", "ui", "generic"]


@dataclass(frozen=True, slots=True)
class EndpointCheck:
    name: str
    path: str
    kind: CheckKind = "generic"
    required: bool = True


@dataclass(frozen=True, slots=True)
class SmokeCheckResult:
    name: str
    path: str
    ok: bool
    status_code: int | None
    duration_ms: int
    detail: str
    required: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class SmokeClientReport:
    base_url: str
    generated_at: str
    overall_status: str
    passed: int
    failed: int
    total_duration_ms: int
    checks: tuple[SmokeCheckResult, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "base_url": self.base_url,
            "generated_at": self.generated_at,
            "overall_status": self.overall_status,
            "passed": self.passed,
            "failed": self.failed,
            "total_duration_ms": self.total_duration_ms,
            "checks": [item.to_dict() for item in self.checks],
        }


DEFAULT_CHECKS: Final[tuple[EndpointCheck, ...]] = (
    EndpointCheck(name="health", path=HEALTH_ENDPOINT, kind="health"),
    EndpointCheck(name="health-liveness", path=LIVENESS_ENDPOINT, kind="health"),
    EndpointCheck(name="health-readiness", path=READINESS_ENDPOINT, kind="health"),
    EndpointCheck(name="system-status", path=SYSTEM_STATUS_ENDPOINT, kind="health"),
    EndpointCheck(name="ui-manifest", path=UI_MANIFEST_ENDPOINT, kind="ui"),
    EndpointCheck(name="ui-status", path=UI_STATUS_ENDPOINT, kind="ui"),
    EndpointCheck(name="ui-runtime-status", path=UI_RUNTIME_STATUS_ENDPOINT, kind="ui"),
)


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _env_base_url() -> str:
    value = os.environ.get("IRONCLAW_BASE_URL")
    return value.rstrip("/") if value else DEFAULT_BASE_URL


def _env_timeout() -> float:
    value = os.environ.get("IRONCLAW_SMOKETEST_TIMEOUT_SECONDS")
    if not value:
        return DEFAULT_TIMEOUT_SECONDS
    try:
        timeout = float(value.strip())
    except (TypeError, ValueError):
        return DEFAULT_TIMEOUT_SECONDS
    return timeout if timeout > 0 else DEFAULT_TIMEOUT_SECONDS


def _response_snippet(response: httpx.Response, limit: int = 400) -> str:
    text = response.text
    if len(text) <= limit:
        return text
    return f"{text[:limit]}...(truncated)"


def _validate_payload(check: EndpointCheck, payload: Any) -> tuple[bool, str]:
    if not isinstance(payload, dict):
        return True, "non-dict JSON payload"

    if check.kind == "health":
        status_value = str(payload.get("status", "")).strip().lower()
        if status_value not in HEALTHY_STATUS_VALUES:
            return False, f"unexpected status field: {payload!r}"
        return True, f"healthy status={status_value}"

    if check.kind == "ui":
        return True, "ui endpoint reachable"

    return True, "ok"


def _record_result(
    results: list[SmokeCheckResult],
    *,
    check: EndpointCheck,
    ok: bool,
    status_code: int | None,
    duration_ms: int,
    detail: str,
) -> None:
    item = SmokeCheckResult(
        name=check.name,
        path=check.path,
        ok=ok,
        status_code=status_code,
        duration_ms=duration_ms,
        detail=detail,
        required=check.required,
    )
    results.append(item)
    label = "OK" if ok else "FAIL"
    code = f" ({status_code})" if status_code is not None else ""
    print(f"[{label}] {check.name}{code} [{duration_ms}ms]: {detail}")


def _run_check(client: httpx.Client, check: EndpointCheck, results: list[SmokeCheckResult]) -> None:
    started = time.perf_counter()

    try:
        response = client.get(check.path)
    except httpx.RequestError as exc:
        duration_ms = round((time.perf_counter() - started) * 1000)
        _record_result(
            results,
            check=check,
            ok=False,
            status_code=None,
            duration_ms=duration_ms,
            detail=f"request error: {exc.__class__.__name__}: {exc}",
        )
        return

    duration_ms = round((time.perf_counter() - started) * 1000)

    if not (200 <= response.status_code < 300):
        _record_result(
            results,
            check=check,
            ok=False,
            status_code=response.status_code,
            duration_ms=duration_ms,
            detail=f"unexpected status {response.status_code}, body: {_response_snippet(response)!r}",
        )
        return

    try:
        payload = response.json()
    except ValueError:
        _record_result(
            results,
            check=check,
            ok=True,
            status_code=response.status_code,
            duration_ms=duration_ms,
            detail="non-JSON response body",
        )
        return

    payload_ok, detail = _validate_payload(check, payload)
    _record_result(
        results,
        check=check,
        ok=payload_ok,
        status_code=response.status_code,
        duration_ms=duration_ms,
        detail=detail,
    )


def run_smoketest_client(
    *,
    base_url: str,
    timeout_seconds: float,
    checks: tuple[EndpointCheck, ...] = DEFAULT_CHECKS,
) -> SmokeClientReport:
    results: list[SmokeCheckResult] = []
    started = time.perf_counter()

    timeout = httpx.Timeout(timeout_seconds)
    with httpx.Client(
        base_url=base_url.rstrip("/"),
        timeout=timeout,
        follow_redirects=True,
        headers={"Accept": "application/json"},
    ) as client:
        for check in checks:
            _run_check(client, check, results)

    total_duration_ms = round((time.perf_counter() - started) * 1000)
    failed = sum(1 for item in results if not item.ok and item.required)
    passed = sum(1 for item in results if item.ok)
    overall_status = "ok" if failed == 0 else "fail"

    return SmokeClientReport(
        base_url=base_url.rstrip("/"),
        generated_at=_utc_now_iso(),
        overall_status=overall_status,
        passed=passed,
        failed=failed,
        total_duration_ms=total_duration_ms,
        checks=tuple(results),
    )


def _write_report(report: SmokeClientReport, output_file: Path) -> None:
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(json.dumps(report.to_dict(), indent=2) + "\n", encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run IronClaw smoke-test probes against a live instance."
    )
    parser.add_argument(
        "--base-url",
        default=None,
        help=f"Base URL for the IronClaw API, defaulting to {DEFAULT_BASE_URL!r} or $IRONCLAW_BASE_URL.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=None,
        help=f"Per-request timeout in seconds, defaulting to {DEFAULT_TIMEOUT_SECONDS}.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_RESULT_FILE,
        help="Write the smoke-test JSON report to this path.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the JSON report to stdout.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    base_url = (args.base_url or _env_base_url()).rstrip("/")
    timeout_seconds = args.timeout if args.timeout and args.timeout > 0 else _env_timeout()
    output_file = args.output.expanduser().resolve()

    print(f"Running IronClaw smoke-test client against {base_url} ...")
    report = run_smoketest_client(base_url=base_url, timeout_seconds=timeout_seconds)
    _write_report(report, output_file)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))

    print(f"Smoke-test report written to {output_file}")
    print(f"SMOKETESTCLIENT: {report.overall_status.upper()} ({report.total_duration_ms}ms)")
    return 0 if report.overall_status == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))