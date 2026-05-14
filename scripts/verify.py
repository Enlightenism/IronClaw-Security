from __future__ import annotations

import ast
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
APP_DIR = ROOT / "app"
TESTS_DIR = ROOT / "tests"
REQUIREMENTS_FILE = ROOT / "requirements.txt"
ENV_EXAMPLE_FILE = ROOT / ".env.example"
RESULT_FILE = ROOT / ".verify-results.json"


def _print(message: str) -> None:
    print(message)


def _run(cmd: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=str(cwd or ROOT),
        text=True,
        capture_output=True,
        check=False,
    )


def _record(results: list[dict[str, Any]], name: str, ok: bool, detail: str) -> None:
    results.append({"name": name, "ok": ok, "detail": detail})
    status = "PASS" if ok else "FAIL"
    _print(f"[{status}] {name}: {detail}")


def _check_required_paths(results: list[dict[str, Any]]) -> None:
    required = [
        APP_DIR,
        TESTS_DIR,
        REQUIREMENTS_FILE,
        ROOT / "app" / "main.py",
    ]
    missing = [str(path.relative_to(ROOT)) for path in required if not path.exists()]
    if missing:
        _record(results, "required-paths", False, f"missing: {', '.join(missing)}")
        return
    _record(results, "required-paths", True, "all required project paths are present")


def _check_python_version(results: list[dict[str, Any]]) -> None:
    version = sys.version.split()[0]
    if sys.version_info >= (3, 12):
        _record(results, "python-version", True, version)
        return
    _record(results, "python-version", False, f"{version} is below 3.12")


def _check_env_example_present(results: list[dict[str, Any]]) -> None:
    if ENV_EXAMPLE_FILE.exists():
        _record(results, "env-example-present", True, ".env.example is present")
        return
    _record(results, "env-example-present", False, ".env.example is missing")


def _check_core_imports(results: list[dict[str, Any]]) -> None:
    command = [
        sys.executable,
        "-c",
        "import fastapi, pytest; import app.main; print('ok')",
    ]
    completed = _run(command)
    if completed.returncode == 0:
        _record(results, "core-imports", True, "fastapi, pytest, and app.main imported successfully")
        return
    detail = (completed.stderr or completed.stdout).strip() or "import failure"
    _record(results, "core-imports", False, detail)


def _check_compile(results: list[dict[str, Any]]) -> None:
    completed = _run([sys.executable, "-m", "compileall", "-q", "app", "tests", "scripts"])
    if completed.returncode == 0:
        _record(results, "compileall", True, "python sources compiled successfully")
        return
    detail = (completed.stderr or completed.stdout).strip() or "compileall failed"
    _record(results, "compileall", False, detail)


def _check_health_route_declared(results: list[dict[str, Any]]) -> None:
    main_file = ROOT / "app" / "main.py"
    if not main_file.exists():
        _record(results, "health-route-declared", False, "app/main.py not found")
        return

    try:
        source = main_file.read_text(encoding="utf-8")
        tree = ast.parse(source)
    except SyntaxError as exc:
        _record(results, "health-route-declared", False, f"syntax error in app/main.py: {exc}")
        return

    route_markers = {
        "/health",
        "/healthz",
        "/api/health",
        "/api/healthz",
        "/api/health/liveness",
        "/api/health/readiness",
    }
    found = False

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not isinstance(func, ast.Attribute):
            continue
        if func.attr not in {"get", "post", "put", "delete", "patch", "api_route"}:
            continue
        if not node.args:
            continue
        first_arg = node.args[0]
        if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
            if first_arg.value in route_markers:
                found = True
                break

    if found:
        _record(results, "health-route-declared", True, "health-style route declaration found")
        return
    _record(
        results,
        "health-route-declared",
        False,
        "no health-style route declaration found in app/main.py",
    )


def _check_key_tests_present(results: list[dict[str, Any]]) -> None:
    candidates = [
        "testmain.py",
        "testapi.py",
        "testliveappsmoke.py",
        "testcliinstall.py",
        "testcliverify.py",
    ]
    present = [name for name in candidates if (TESTS_DIR / name).exists()]
    if present:
        _record(results, "key-tests-present", True, f"found: {', '.join(present)}")
        return
    _record(results, "key-tests-present", False, "no key smoke/api/install tests found")


def _check_pip_check(results: list[dict[str, Any]]) -> None:
    completed = _run([sys.executable, "-m", "pip", "check"])
    if completed.returncode == 0:
        _record(results, "pip-check", True, "dependency metadata is consistent")
        return
    detail = (completed.stderr or completed.stdout).strip() or "pip check failed"
    _record(results, "pip-check", False, detail)


def _write_results(results: list[dict[str, Any]], ok: bool) -> None:
    payload = {
        "status": "ok" if ok else "fail",
        "generated_at": datetime.now(UTC).isoformat(),
        "python_version": sys.version.split()[0],
        "checks": results,
    }
    RESULT_FILE.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def main() -> None:
    results: list[dict[str, Any]] = []

    _check_required_paths(results)
    _check_python_version(results)
    _check_env_example_present(results)
    _check_core_imports(results)
    _check_compile(results)
    _check_health_route_declared(results)
    _check_key_tests_present(results)
    _check_pip_check(results)

    ok = all(item["ok"] for item in results)
    _write_results(results, ok)

    if ok:
        _print("VERIFY STATUS: PASS")
        raise SystemExit(0)

    _print("VERIFY STATUS: FAIL")
    raise SystemExit(1)


if __name__ == "__main__":
    main()
