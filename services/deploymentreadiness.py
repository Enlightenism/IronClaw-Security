from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import platform
import socket
import sys
from typing import Any

_ALLOWED_ENVIRONMENTS = {"local", "dev", "preview", "staging", "prod", "production"}
_ALLOWED_CHANNELS = {"stable", "preview", "dev"}
_REQUIRED_DIRECTORIES = ("data", "output", "samples", "rules")
_REQUIRED_FILES = ("requirements.txt",)
_RECOMMENDED_FILES = ("compose.yaml", "Dockerfile", ".env.example")


@dataclass(slots=True)
class DeploymentReadinessCheck:
    check_id: str
    title: str
    status: str
    detail: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class DeploymentReadinessView:
    release_id: str
    environment: str
    overall_status: str
    updated_at: str
    checks: list[DeploymentReadinessCheck]
    metadata: dict[str, Any] = field(default_factory=dict)


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _iso_now() -> str:
    return _utc_now().isoformat()


def _default_release_id() -> str:
    return "ironclaw-security-gen1"


def _detect_environment() -> str:
    value = os.getenv("IRONCLAW_ENV") or os.getenv("ENVIRONMENT") or os.getenv("APP_ENV") or "local"
    return str(value).strip().lower()


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _config_path(root: Path) -> Path:
    return root / ".env"


def _hostname() -> str:
    try:
        return socket.gethostname() or "unknown-host"
    except Exception:
        return "unknown-host"


def _python_version_text() -> str:
    version = sys.version_info
    return f"{version.major}.{version.minor}.{version.micro}"


def _status_priority(status: str) -> int:
    if status == "blocked":
        return 3
    if status == "warning":
        return 2
    return 1


def _overall_status(checks: list[DeploymentReadinessCheck]) -> str:
    highest = 1
    for check in checks:
        highest = max(highest, _status_priority(check.status))
    if highest >= 3:
        return "blocked"
    if highest == 2:
        return "warning"
    return "ready"


def _make_check(
    check_id: str,
    title: str,
    ok: bool,
    detail: str,
    *,
    warning: bool = False,
    metadata: dict[str, Any] | None = None,
) -> DeploymentReadinessCheck:
    status = "ready" if ok and not warning else "warning" if ok and warning else "blocked"
    return DeploymentReadinessCheck(
        check_id=check_id,
        title=title,
        status=status,
        detail=detail,
        metadata=metadata or {},
    )


def _python_check() -> DeploymentReadinessCheck:
    version = sys.version_info
    ok = (version.major, version.minor) >= (3, 11)
    return _make_check(
        "python-version",
        "Python runtime",
        ok,
        f"Detected Python {_python_version_text()}",
        metadata={"required_minimum": "3.11", "detected": _python_version_text()},
    )


def _environment_check(environment: str) -> DeploymentReadinessCheck:
    ok = environment in _ALLOWED_ENVIRONMENTS
    return _make_check(
        "environment",
        "Deployment environment",
        ok,
        f"Detected environment: {environment}",
        metadata={"allowed": sorted(_ALLOWED_ENVIRONMENTS), "detected": environment},
    )


def _root_layout_check(root: Path) -> DeploymentReadinessCheck:
    missing = [name for name in _REQUIRED_DIRECTORIES if not (root / name).is_dir()]
    ok = not missing
    detail = "Repository layout looks ready." if ok else f"Missing required directories: {', '.join(missing)}"
    return _make_check(
        "repository-layout",
        "Repository layout",
        ok,
        detail,
        metadata={"root": str(root), "missing_directories": missing},
    )


def _required_files_check(root: Path) -> DeploymentReadinessCheck:
    missing = [name for name in _REQUIRED_FILES if not (root / name).is_file()]
    ok = not missing
    detail = "Required deployment files are present." if ok else f"Missing required files: {', '.join(missing)}"
    return _make_check(
        "required-files",
        "Required files",
        ok,
        detail,
        metadata={"missing_files": missing},
    )


def _recommended_files_check(root: Path) -> DeploymentReadinessCheck:
    missing = [name for name in _RECOMMENDED_FILES if not (root / name).exists()]
    warning = bool(missing)
    detail = "Recommended deployment files are present." if not warning else f"Missing recommended files: {', '.join(missing)}"
    return _make_check(
        "recommended-files",
        "Recommended deployment files",
        True,
        detail,
        warning=warning,
        metadata={"missing_files": missing},
    )


def _env_file_check(root: Path) -> DeploymentReadinessCheck:
    env_path = _config_path(root)
    if not env_path.exists():
        return _make_check(
            "environment-file",
            "Environment file",
            True,
            "No .env file found; acceptable when runtime secrets are injected externally.",
            warning=True,
            metadata={"path": str(env_path), "mode": "external-secrets-or-missing"},
        )

    try:
        content = env_path.read_text(encoding="utf-8")
    except Exception as exc:
        return _make_check(
            "environment-file",
            "Environment file",
            False,
            f"Unable to read .env file: {exc}",
            metadata={"path": str(env_path)},
        )

    non_comment_lines = [line.strip() for line in content.splitlines() if line.strip() and not line.strip().startswith("#")]
    has_pairs = any("=" in line for line in non_comment_lines)
    return _make_check(
        "environment-file",
        "Environment file",
        has_pairs,
        "Environment file is readable and contains key/value settings." if has_pairs else "Environment file exists but does not contain usable key/value entries.",
        metadata={"path": str(env_path), "entry_count": len(non_comment_lines)},
    )


def _channel_check(root: Path) -> DeploymentReadinessCheck:
    config_json = root / "config.json"
    if not config_json.exists():
        return _make_check(
            "release-channel",
            "Release channel",
            True,
            "config.json not found; release channel defaults can be supplied by install/update tooling.",
            warning=True,
            metadata={"path": str(config_json), "detected_channel": None},
        )

    try:
        payload = json.loads(config_json.read_text(encoding="utf-8"))
    except Exception as exc:
        return _make_check(
            "release-channel",
            "Release channel",
            False,
            f"config.json is not valid JSON: {exc}",
            metadata={"path": str(config_json)},
        )

    channel = str(payload.get("channel", "stable")).strip().lower()
    ok = channel in _ALLOWED_CHANNELS
    return _make_check(
        "release-channel",
        "Release channel",
        ok,
        f"Configured channel: {channel}",
        metadata={
            "path": str(config_json),
            "detected_channel": channel,
            "allowed": sorted(_ALLOWED_CHANNELS),
        },
    )


def _api_key_check() -> DeploymentReadinessCheck:
    candidate_names = (
        "IRONCLAW_API_KEY",
        "IRONCLAW_INTERNAL_API_KEY",
        "IRONCLAW_PLATFORM_API_KEY",
    )
    detected = [name for name in candidate_names if os.getenv(name)]
    ok = bool(detected)
    return _make_check(
        "api-keys",
        "API key environment",
        ok,
        "Detected API key environment variables: " + (", ".join(detected) if detected else "none"),
        metadata={"detected": detected, "candidates": list(candidate_names)},
    )


def _supabase_env_check() -> DeploymentReadinessCheck:
    required = ("SUPABASE_URL", "SUPABASE_KEY")
    detected = [name for name in required if os.getenv(name)]
    ok = len(detected) == len(required)
    return _make_check(
        "supabase-environment",
        "Supabase environment",
        ok,
        "Detected Supabase environment variables: " + (", ".join(detected) if detected else "none"),
        metadata={"required": list(required), "detected": detected},
    )


def _tests_presence_check(root: Path) -> DeploymentReadinessCheck:
    tests_dir = root / "tests"
    if not tests_dir.is_dir():
        return _make_check(
            "test-suite",
            "Test suite presence",
            False,
            "tests/ directory is missing.",
            metadata={"path": str(tests_dir)},
        )

    test_files = sorted(p.name for p in tests_dir.glob("test*.py"))
    ok = bool(test_files)
    return _make_check(
        "test-suite",
        "Test suite presence",
        ok,
        f"Detected {len(test_files)} test files in tests/." if ok else "No pytest files detected in tests/.",
        metadata={"path": str(tests_dir), "count": len(test_files)},
    )


def _migrations_check(root: Path) -> DeploymentReadinessCheck:
    migrations_dir = root / "supabase" / "migrations"
    if not migrations_dir.is_dir():
        return _make_check(
            "supabase-migrations",
            "Supabase migrations",
            False,
            "Supabase migrations directory is missing.",
            metadata={"path": str(migrations_dir)},
        )

    migration_files = sorted(p.name for p in migrations_dir.glob("*.sql"))
    ok = bool(migration_files)
    return _make_check(
        "supabase-migrations",
        "Supabase migrations",
        ok,
        f"Detected {len(migration_files)} migration files." if ok else "No SQL migration files found.",
        metadata={"path": str(migrations_dir), "count": len(migration_files)},
    )


def _docker_artifacts_check(root: Path) -> DeploymentReadinessCheck:
    dockerfile_exists = (root / "Dockerfile").is_file()
    compose_exists = (root / "compose.yaml").is_file()
    ok = dockerfile_exists and compose_exists
    return _make_check(
        "container-artifacts",
        "Container artifacts",
        ok,
        f"Dockerfile={'present' if dockerfile_exists else 'missing'}, compose.yaml={'present' if compose_exists else 'missing'}",
        metadata={"dockerfile": dockerfile_exists, "compose": compose_exists},
    )


def build_deployment_readiness(
    root: Path | None = None,
    *,
    release_id: str | None = None,
    environment: str | None = None,
) -> DeploymentReadinessView:
    repo_root = (root or _repo_root()).resolve()
    resolved_environment = (environment or _detect_environment()).strip().lower()
    checks = [
        _python_check(),
        _environment_check(resolved_environment),
        _root_layout_check(repo_root),
        _required_files_check(repo_root),
        _recommended_files_check(repo_root),
        _env_file_check(repo_root),
        _channel_check(repo_root),
        _api_key_check(),
        _supabase_env_check(),
        _tests_presence_check(repo_root),
        _migrations_check(repo_root),
        _docker_artifacts_check(repo_root),
    ]
    overall_status = _overall_status(checks)
    return DeploymentReadinessView(
        release_id=release_id or _default_release_id(),
        environment=resolved_environment,
        overall_status=overall_status,
        updated_at=_iso_now(),
        checks=checks,
        metadata={
            "root": str(repo_root),
            "platform": platform.platform(),
            "python_executable": sys.executable,
            "python_version": _python_version_text(),
            "hostname": _hostname(),
            "check_count": len(checks),
        },
    )


def deployment_readiness_payload(
    root: Path | None = None,
    *,
    release_id: str | None = None,
    environment: str | None = None,
) -> dict[str, Any]:
    readiness = build_deployment_readiness(
        root=root,
        release_id=release_id,
        environment=environment,
    )
    return asdict(readiness)
