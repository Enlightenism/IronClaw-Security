from __future__ import annotations

import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Final

from fastapi.testclient import TestClient

from app.main import app

RESULT_FILE: Final[Path] = Path(__file__).resolve().with_name(".testclient-results.json")


@dataclass(frozen=True, slots=True)
class ClientCheckResult:
    name: str
    ok: bool
    status_code: int | None
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _response_snippet(response_text: str, limit: int = 400) -> str:
    if len(response_text) <= limit:
        return response_text
    return f"{response_text[:limit]}...(truncated)"


def _validate_status_payload(name: str, payload: Any) -> tuple[bool, str]:
    if not isinstance(payload, dict):
        return True, "non-dict JSON payload"

    if name in {"health", "health-liveness", "health-readiness", "system-status"}:
        status_value = str(payload.get("status", "")).strip().lower()
        if status_value not in {"ok", "pass", "healthy", "ready", "live", "alive"}:
            return False, f"unexpected status field: {payload!r}"
        return True, f"healthy status={status_value}"

    if name.startswith("ui-"):
        return True, "ui endpoint reachable"

    return True, "ok"


def _record(results: list[ClientCheckResult], name: str, ok: bool, status_code: int | None, detail: str) -> None:
    entry = ClientCheckResult(name=name, ok=ok, status_code=status_code, detail=detail)
    results.append(entry)
    label = "OK" if ok else "FAIL"
    code = f" ({status_code})" if status_code is not None else ""
    print(f"[{label}] {name}{code}: {detail}")


def _run_get(
    client: TestClient,
    *,
    name: str,
    path: str,
    results: list[ClientCheckResult],
) -> None:
    try:
        response = client.get(path)
    except Exception as exc:
        _record(results, name, False, None, f"request error: {type(exc).__name__}: {exc}")
        return

    if not (200 <= response.status_code < 300):
        _record(
            results,
            name,
            False,
            response.status_code,
            f"unexpected status {response.status_code}, body: {_response_snippet(response.text)!r}",
        )
        return

    try:
        payload = response.json()
    except ValueError:
        _record(results, name, True, response.status_code, "non-JSON response body")
        return

    ok, detail = _validate_status_payload(name, payload)
    _record(results, name, ok, response.status_code, detail)


def run_testclient_checks() -> dict[str, Any]:
    results: list[ClientCheckResult] = []

    with TestClient(app) as client:
        _run_get(client, name="health", path="/api/health", results=results)
        _run_get(client, name="health-liveness", path="/api/health/liveness", results=results)
        _run_get(client, name="health-readiness", path="/api/health/readiness", results=results)
        _run_get(client, name="system-status", path="/api/system/status", results=results)
        _run_get(client, name="ui-manifest", path="/api/ui/manifest", results=results)
        _run_get(client, name="ui-status", path="/api/ui/status/runtime", results=results)
        _run_get(client, name="ui-runtime-status", path="/api/ui/runtime/status", results=results)

    passed = sum(1 for item in results if item.ok)
    failed = sum(1 for item in results if not item.ok)
    overall_status = "ok" if failed == 0 else "fail"

    report = {
        "overall_status": overall_status,
        "passed": passed,
        "failed": failed,
        "checks": [item.to_dict() for item in results],
    }
    RESULT_FILE.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main(argv: list[str] | None = None) -> int:  # noqa: ARG001
    report = run_testclient_checks()
    print(f"TestClient report written to {RESULT_FILE}")
    print(f"TESTCLIENT: {report['overall_status'].upper()}")
    return 0 if report["overall_status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
