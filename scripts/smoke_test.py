from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from app.main import app

ROOT = Path(__file__).resolve().parents[1]
RESULT_FILE = ROOT / ".smoke-test-results.json"
client = TestClient(app)


def _record(
    results: list[dict[str, Any]],
    *,
    name: str,
    ok: bool,
    detail: str,
    status_code: int | None = None,
) -> None:
    results.append(
        {
            "name": name,
            "ok": ok,
            "detail": detail,
            "status_code": status_code,
        },
    )
    label = "PASS" if ok else "FAIL"
    suffix = f" (status={status_code})" if status_code is not None else ""
    print(f"[{label}] {name}{suffix}: {detail}")


def _get_json(path: str) -> tuple[int, str, Any]:
    response = client.get(path)
    content_type = response.headers.get("content-type", "")
    body: Any
    if content_type.startswith("application/json"):
        body = response.json()
    else:
        body = response.text
    return response.status_code, content_type, body


def _smoke_health(results: list[dict[str, Any]]) -> None:
    candidates = ["/health", "/healthz", "/api/health", "/api/healthz"]
    for path in candidates:
        status_code, content_type, body = _get_json(path)
        if status_code == 200:
            if content_type.startswith("application/json") and isinstance(body, dict):
                _record(
                    results,
                    name="health-endpoint",
                    ok=True,
                    detail=f"{path} responded with JSON",
                    status_code=status_code,
                )
                return
            _record(
                results,
                name="health-endpoint",
                ok=True,
                detail=f"{path} responded successfully",
                status_code=status_code,
            )
            return
    _record(
        results,
        name="health-endpoint",
        ok=False,
        detail="no supported health endpoint returned 200",
    )


def _smoke_openapi(results: list[dict[str, Any]]) -> None:
    status_code, content_type, body = _get_json("/openapi.json")
    ok = status_code == 200 and content_type.startswith("application/json") and isinstance(body, dict) and "paths" in body
    _record(
        results,
        name="openapi",
        ok=ok,
        detail="OpenAPI document is available" if ok else "OpenAPI document missing or invalid",
        status_code=status_code,
    )


def _smoke_docs(results: list[dict[str, Any]]) -> None:
    response = client.get("/docs")
    ok = response.status_code == 200 and "text/html" in response.headers.get("content-type", "")
    _record(
        results,
        name="docs-ui",
        ok=ok,
        detail="Swagger UI responded" if ok else "Swagger UI unavailable",
        status_code=response.status_code,
    )


def _smoke_key_api(results: list[dict[str, Any]]) -> None:
    candidates = [
        "/system",
        "/api/system",
        "/telemetry/access",
        "/admin/organizations",
        "/ui/pages",
        "/status",
    ]
    for path in candidates:
        status_code, content_type, body = _get_json(path)
        if status_code == 200:
            if content_type.startswith("application/json") and isinstance(body, dict):
                _record(
                    results,
                    name="key-api",
                    ok=True,
                    detail=f"{path} returned JSON object",
                    status_code=status_code,
                )
                return
            if isinstance(body, list):
                _record(
                    results,
                    name="key-api",
                    ok=True,
                    detail=f"{path} returned JSON list",
                    status_code=status_code,
                )
                return
    _record(
        results,
        name="key-api",
        ok=False,
        detail="no candidate key API endpoint returned 200",
    )


def _smoke_basic_ui(results: list[dict[str, Any]]) -> None:
    candidates = ["/", "/ui", "/ui/pages", "/runtime-status", "/status"]
    for path in candidates:
        response = client.get(path)
        content_type = response.headers.get("content-type", "")
        if response.status_code == 200:
            if "text/html" in content_type:
                _record(
                    results,
                    name="basic-ui",
                    ok=True,
                    detail=f"{path} returned HTML",
                    status_code=response.status_code,
                )
                return
            if content_type.startswith("application/json"):
                payload = response.json()
                if isinstance(payload, dict):
                    _record(
                        results,
                        name="basic-ui",
                        ok=True,
                        detail=f"{path} returned JSON-backed UI surface",
                        status_code=response.status_code,
                    )
                    return
    _record(
        results,
        name="basic-ui",
        ok=False,
        detail="no candidate UI route returned a usable response",
    )


def _write_results(results: list[dict[str, Any]], ok: bool) -> None:
    RESULT_FILE.write_text(
        json.dumps(
            {
                "status": "ok" if ok else "fail",
                "checks": results,
            },
            indent=2,
        ),
        encoding="utf-8",
    )


def main() -> None:
    results: list[dict[str, Any]] = []

    _smoke_health(results)
    _smoke_openapi(results)
    _smoke_docs(results)
    _smoke_key_api(results)
    _smoke_basic_ui(results)

    ok = all(item["ok"] for item in results)
    _write_results(results, ok)

    print("SMOKE TEST STATUS: PASS" if ok else "SMOKE TEST STATUS: FAIL")
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    main()
