from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
APP_DIR = ROOT / "app"
MIGRATIONS_DIR = ROOT / "migrations"
RESULT_FILE = ROOT / ".deployment-readiness.json"
ENV_EXAMPLE_FILE = ROOT / ".env.example"
REQUIREMENTS_FILE = ROOT / "requirements.txt"
COMPOSE_FILE = ROOT / "compose.yaml"

URL_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://.+")


def _record(results: list[dict[str, Any]], name: str, ok: bool, detail: str) -> None:
    results.append({"name": name, "ok": ok, "detail": detail})
    label = "OK" if ok else "FAIL"
    print(f"[{label}] {name}: {detail}")


def _read_env_example_keys() -> list[str]:
    if not ENV_EXAMPLE_FILE.exists():
        return []
    keys: list[str] = []
    for raw_line in ENV_EXAMPLE_FILE.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key = line.split("=", 1)[0].strip()
        if key:
            keys.append(key)
    return keys


def _run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=str(ROOT),
        text=True,
        capture_output=True,
        check=False,
    )


def _check_required_files(results: list[dict[str, Any]]) -> None:
    required = [
        APP_DIR,
        ROOT / "app" / "main.py",
        REQUIREMENTS_FILE,
    ]
    missing = [str(path.relative_to(ROOT)) for path in required if not path.exists()]
    if missing:
        _record(results, "required-files", False, f"missing: {', '.join(missing)}")
        return
    _record(results, "required-files", True, "core application files are present")


def _check_env_contract(results: list[dict[str, Any]]) -> None:
    keys = _read_env_example_keys()
    if not keys:
        _record(results, "env-contract", False, ".env.example missing or contains no keys")
        return

    missing = [key for key in keys if not os.getenv(key)]
    if missing:
        _record(results, "env-contract", False, f"missing env vars: {', '.join(sorted(missing))}")
        return

    _record(results, "env-contract", True, f"all {len(keys)} required env vars are present")


def _check_database_config(results: list[dict[str, Any]]) -> None:
    candidates = ["DATABASE_URL", "SUPABASE_DB_URL", "POSTGRES_URL"]
    present = [(name, os.getenv(name, "").strip()) for name in candidates if os.getenv(name, "").strip()]
    if not present:
        _record(results, "database-config", False, "no database URL environment variable is configured")
        return

    name, value = present[0]
    if not URL_RE.match(value):
        _record(results, "database-config", False, f"{name} is set but not a valid URL-like value")
        return

    _record(results, "database-config", True, f"{name} is configured")


def _check_supabase_config(results: list[dict[str, Any]]) -> None:
    url = os.getenv("SUPABASE_URL", "").strip()
    key = os.getenv("SUPABASE_KEY", "").strip() or os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()

    if not url or not key:
        _record(results, "supabase-config", False, "SUPABASE_URL and key must both be configured")
        return
    if not URL_RE.match(url):
        _record(results, "supabase-config", False, "SUPABASE_URL is not valid")
        return

    _record(results, "supabase-config", True, "Supabase integration variables are configured")


def _check_external_integrations(results: list[dict[str, Any]]) -> None:
    groups = {
        "openai": ["OPENAI_API_KEY"],
        "groq": ["GROQ_API_KEY"],
    }

    configured: list[str] = []
    for name, keys in groups.items():
        if any(os.getenv(key, "").strip() for key in keys):
            configured.append(name)

    if not configured:
        _record(results, "external-integrations", False, "no external integration credentials are configured")
        return

    _record(results, "external-integrations", True, f"configured integrations: {', '.join(sorted(configured))}")


def _check_secrets_quality(results: list[dict[str, Any]]) -> None:
    secret_like_keys = [
        "SECRET_KEY",
        "JWT_SECRET",
        "API_SECRET",
        "SUPABASE_KEY",
        "SUPABASE_SERVICE_ROLE_KEY",
        "OPENAI_API_KEY",
        "GROQ_API_KEY",
    ]

    bad: list[str] = []
    for key in secret_like_keys:
        value = os.getenv(key, "").strip()
        if not value:
            continue
        lowered = value.lower()
        if lowered in {"changeme", "change-me", "default", "example", "test", "dummy"}:
            bad.append(key)
        if len(value) < 12:
            bad.append(key)

    if bad:
        _record(results, "secrets-quality", False, f"weak placeholder or short secrets: {', '.join(sorted(set(bad)))}")
        return

    _record(results, "secrets-quality", True, "configured secrets passed basic quality checks")


def _check_migrations(results: list[dict[str, Any]]) -> None:
    if not MIGRATIONS_DIR.exists():
        _record(results, "migrations", False, "migrations directory is missing")
        return

    files = sorted(
        path.name
        for path in MIGRATIONS_DIR.iterdir()
        if path.is_file() and path.suffix.lower() in {".sql", ".py"}
    )
    if not files:
        _record(results, "migrations", False, "no migration files found")
        return

    _record(results, "migrations", True, f"found {len(files)} migration file(s)")


def _check_compose_runtime(results: list[dict[str, Any]]) -> None:
    if not COMPOSE_FILE.exists():
        _record(results, "compose-runtime", False, "compose.yaml is missing")
        return

    text = COMPOSE_FILE.read_text(encoding="utf-8").lower()
    checks = {
        "healthcheck": "healthcheck:" in text,
        "restart": "restart:" in text,
        "environment": "environment:" in text or "env_file:" in text,
    }
    missing = [name for name, ok in checks.items() if not ok]
    if missing:
        _record(results, "compose-runtime", False, f"compose.yaml missing: {', '.join(missing)}")
        return

    _record(results, "compose-runtime", True, "compose runtime controls are present")


def _check_imports(results: list[dict[str, Any]]) -> None:
    completed = _run([sys.executable, "-c", "import app.main; print('ok')"])
    if completed.returncode == 0:
        _record(results, "app-import", True, "app.main imports successfully")
        return

    detail = (completed.stderr or completed.stdout).strip() or "import failed"
    _record(results, "app-import", False, detail)


def _check_dependency_health(results: list[dict[str, Any]]) -> None:
    completed = _run([sys.executable, "-m", "pip", "check"])
    if completed.returncode == 0:
        _record(results, "dependency-health", True, "pip dependency graph is consistent")
        return

    detail = (completed.stderr or completed.stdout).strip() or "pip check failed"
    _record(results, "dependency-health", False, detail)


def _write_result(results: list[dict[str, Any]], ok: bool) -> None:
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

    _check_required_files(results)
    _check_env_contract(results)
    _check_database_config(results)
    _check_supabase_config(results)
    _check_external_integrations(results)
    _check_secrets_quality(results)
    _check_migrations(results)
    _check_compose_runtime(results)
    _check_imports(results)
    _check_dependency_health(results)

    ok = all(item["ok"] for item in results)
    _write_result(results, ok)

    print("DEPLOYMENT READINESS: OK" if ok else "DEPLOYMENT READINESS: FAIL")
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    main()