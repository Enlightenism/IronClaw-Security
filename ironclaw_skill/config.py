from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
from typing import Any, Final

from dotenv import load_dotenv

from app.core.install_key_formats import InstallKeyFormatRegistry, normalize_install_key_program

DEFAULT_BASE_URL: Final[str] = "http://127.0.0.1:8000"
DEFAULT_POLICY_MODE: Final[str] = "review"
DEFAULT_TIMEOUT_SECONDS: Final[float] = 10.0
DEFAULT_BACKUP_TARGET: Final[str] = "primary"
DEFAULT_RESTORE_TARGET: Final[str] = "primary"
DEFAULT_CONFIG_DIRNAME: Final[str] = ".ironclaw"
DEFAULT_CONFIG_FILENAME: Final[str] = "config.json"
DEFAULT_SKILL_FILENAME: Final[str] = "skill.json"
DEFAULT_ENV_FILENAME: Final[str] = ".env"
DEFAULT_PROVIDER_TARGETS: Final[tuple[str, ...]] = tuple(InstallKeyFormatRegistry.list_programs())


class IronClawSkillConfigError(RuntimeError):
    """Raised when IronClaw skill configuration is invalid or cannot be loaded."""


@dataclass(frozen=True, slots=True)
class IronClawSkillConfig:
    environment: str
    project_root: Path
    config_dir: Path
    config_file: Path
    skill_file: Path
    env_file: Path
    base_url: str
    policy_mode: str
    timeout_seconds: float
    backup_target: str
    restore_target: str
    openai_api_key: str | None
    guard_model_path: str | None
    api_secret: str | None
    jwt_secret: str | None
    skill_enabled: bool
    provider_targets: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["project_root"] = str(self.project_root)
        payload["config_dir"] = str(self.config_dir)
        payload["config_file"] = str(self.config_file)
        payload["skill_file"] = str(self.skill_file)
        payload["env_file"] = str(self.env_file)
        payload["provider_targets"] = list(self.provider_targets)
        return payload


def _project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _default_config_dir() -> Path:
    configured = os.getenv("IRONCLAW_CONFIG_DIR")
    if configured and configured.strip():
        return Path(configured).expanduser().resolve()
    return (Path.home() / DEFAULT_CONFIG_DIRNAME).resolve()


def _config_file(config_dir: Path) -> Path:
    return config_dir / DEFAULT_CONFIG_FILENAME


def _skill_file(config_dir: Path) -> Path:
    return config_dir / DEFAULT_SKILL_FILENAME


def _env_file(project_root: Path) -> Path:
    return project_root / DEFAULT_ENV_FILENAME


def _normalize_optional_text(value: Any) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip()
    return normalized or None


def _normalize_required_text(value: Any, *, field_name: str) -> str:
    normalized = _normalize_optional_text(value)
    if normalized is None:
        raise IronClawSkillConfigError(f"{field_name} must not be empty")
    return normalized


def _load_json_object(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise IronClawSkillConfigError(f"Invalid JSON in {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise IronClawSkillConfigError(f"Expected JSON object in {path}")
    return payload


def _coerce_bool(value: Any, *, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value

    normalized = str(value).strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    return default


def _coerce_timeout(value: Any, *, default: float) -> float:
    if value is None or value == "":
        return default
    try:
        timeout = float(value)
    except (TypeError, ValueError) as exc:
        raise IronClawSkillConfigError(f"Invalid timeout value: {value!r}") from exc
    if timeout <= 0:
        raise IronClawSkillConfigError("timeout_seconds must be greater than 0")
    return timeout


def _coerce_policy_mode(value: Any, *, default: str) -> str:
    normalized = _normalize_optional_text(value)
    if normalized is None:
        return default
    lowered = normalized.lower()
    if lowered not in {"allow", "review", "block"}:
        raise IronClawSkillConfigError(f"Invalid policy_mode: {value!r}")
    return lowered


def _normalize_provider_target_name(value: Any) -> str:
    if value is None:
        raise IronClawSkillConfigError("provider target must not be empty")

    candidate = str(value).strip()
    if not candidate:
        raise IronClawSkillConfigError("provider target must not be empty")

    normalized = candidate.lower().replace(" ", "_").replace("-", "_")
    normalized = normalized.replace("__", "_").strip("_")

    canonical = normalize_install_key_program(normalized)
    if canonical is None:
        raise IronClawSkillConfigError(f"Unsupported provider target: {value!r}")
    return canonical


def _coerce_provider_targets(value: Any) -> tuple[str, ...]:
    if value is None:
        return DEFAULT_PROVIDER_TARGETS

    if isinstance(value, str):
        items = [part.strip() for part in value.split(",") if part.strip()]
    elif isinstance(value, (list, tuple)):
        items = [str(item).strip() for item in value if str(item).strip()]
    else:
        raise IronClawSkillConfigError("provider_targets must be a list, tuple, or comma-separated string")

    normalized: list[str] = []
    seen: set[str] = set()

    for item in items:
        canonical = _normalize_provider_target_name(item)
        if canonical not in seen:
            seen.add(canonical)
            normalized.append(canonical)

    return tuple(normalized or DEFAULT_PROVIDER_TARGETS)


def _resolve_base_url(
    *,
    env: dict[str, str],
    config_payload: dict[str, Any],
    skill_payload: dict[str, Any],
) -> str:
    for candidate in (
        env.get("IRONCLAW_BASE_URL"),
        skill_payload.get("base_url"),
        config_payload.get("base_url"),
        DEFAULT_BASE_URL,
    ):
        normalized = _normalize_optional_text(candidate)
        if normalized is not None:
            return normalized.rstrip("/")
    return DEFAULT_BASE_URL


def load_skill_config(
    *,
    environment: str | None = None,
    project_root: Path | None = None,
    config_dir: Path | None = None,
    load_dotenv_file: bool = True,
) -> IronClawSkillConfig:
    resolved_project_root = (project_root or _project_root()).expanduser().resolve()
    resolved_config_dir = (config_dir or _default_config_dir()).expanduser().resolve()
    resolved_config_file = _config_file(resolved_config_dir)
    resolved_skill_file = _skill_file(resolved_config_dir)
    resolved_env_file = _env_file(resolved_project_root)

    if load_dotenv_file and resolved_env_file.exists():
        load_dotenv(dotenv_path=resolved_env_file, override=False)

    env = dict(os.environ)
    config_payload = _load_json_object(resolved_config_file)
    skill_payload = _load_json_object(resolved_skill_file)

    base_url = _resolve_base_url(
        env=env,
        config_payload=config_payload,
        skill_payload=skill_payload,
    )

    policy_mode = _coerce_policy_mode(
        env.get("IRONCLAW_POLICY_MODE") or skill_payload.get("default_policy_mode") or config_payload.get("policy_mode"),
        default=DEFAULT_POLICY_MODE,
    )

    timeout_seconds = _coerce_timeout(
        env.get("IRONCLAW_TIMEOUT_SECONDS") or skill_payload.get("default_timeout_seconds") or config_payload.get("timeout_seconds"),
        default=DEFAULT_TIMEOUT_SECONDS,
    )

    backup_target = _normalize_optional_text(env.get("IRONCLAW_BACKUP_TARGET_NAME")) or _normalize_optional_text(env.get("IRONCLAW_BACKUP_TARGET")) or _normalize_optional_text(config_payload.get("backup_target")) or DEFAULT_BACKUP_TARGET

    restore_target = _normalize_optional_text(env.get("IRONCLAW_RESTORE_TARGET_NAME")) or _normalize_optional_text(env.get("IRONCLAW_RESTORE_TARGET")) or _normalize_optional_text(config_payload.get("restore_target")) or DEFAULT_RESTORE_TARGET

    skill_enabled = _coerce_bool(
        env.get("IRONCLAW_SKILL_ENABLED", skill_payload.get("enabled")),
        default=True,
    )

    provider_targets = _coerce_provider_targets(
        env.get("IRONCLAW_PROVIDER_TARGETS") or skill_payload.get("provider_targets"),
    )

    resolved_environment = _normalize_optional_text(environment) or _normalize_optional_text(env.get("IRONCLAW_ENV")) or _normalize_optional_text(env.get("IRONCLAW_MODE")) or "development"

    return IronClawSkillConfig(
        environment=resolved_environment,
        project_root=resolved_project_root,
        config_dir=resolved_config_dir,
        config_file=resolved_config_file,
        skill_file=resolved_skill_file,
        env_file=resolved_env_file,
        base_url=base_url,
        policy_mode=policy_mode,
        timeout_seconds=timeout_seconds,
        backup_target=backup_target,
        restore_target=restore_target,
        openai_api_key=_normalize_optional_text(env.get("OPENAI_API_KEY")),
        guard_model_path=_normalize_optional_text(env.get("GUARD_MODEL_PATH")),
        api_secret=_normalize_optional_text(env.get("API_SECRET")),
        jwt_secret=_normalize_optional_text(env.get("JWT_SECRET")),
        skill_enabled=skill_enabled,
        provider_targets=provider_targets,
    )


def require_skill_config(
    *,
    environment: str | None = None,
    project_root: Path | None = None,
    config_dir: Path | None = None,
    require_enabled: bool = False,
    require_api_secret: bool = False,
) -> IronClawSkillConfig:
    config = load_skill_config(
        environment=environment,
        project_root=project_root,
        config_dir=config_dir,
    )

    if require_enabled and not config.skill_enabled:
        raise IronClawSkillConfigError("IronClaw skill integration is disabled.")

    if require_api_secret and not config.api_secret:
        raise IronClawSkillConfigError("API_SECRET is required but not configured.")

    if not config.base_url:
        raise IronClawSkillConfigError("IronClaw base_url is not configured.")

    return config


def save_skill_config(
    config: IronClawSkillConfig,
    *,
    include_secrets: bool = False,
) -> None:
    config.config_dir.mkdir(parents=True, exist_ok=True)

    base_payload = {
        "schema_version": 1,
        "product": "IronClaw-Security",
        "base_url": config.base_url,
        "backup_target": config.backup_target,
        "restore_target": config.restore_target,
        "timeout_seconds": config.timeout_seconds,
        "policy_mode": config.policy_mode,
    }

    skill_payload = {
        "enabled": config.skill_enabled,
        "provider_targets": list(config.provider_targets),
        "base_url": config.base_url,
        "default_policy_mode": config.policy_mode,
        "default_timeout_seconds": config.timeout_seconds,
    }

    config.config_file.write_text(json.dumps(base_payload, indent=2) + "\n", encoding="utf-8")
    config.skill_file.write_text(json.dumps(skill_payload, indent=2) + "\n", encoding="utf-8")

    if include_secrets:
        env_lines = [
            f"IRONCLAW_BASE_URL={config.base_url}",
            f"IRONCLAW_POLICY_MODE={config.policy_mode}",
            f"IRONCLAW_TIMEOUT_SECONDS={config.timeout_seconds}",
            f"IRONCLAW_BACKUP_TARGET_NAME={config.backup_target}",
            f"IRONCLAW_RESTORE_TARGET_NAME={config.restore_target}",
            f"IRONCLAW_PROVIDER_TARGETS={','.join(config.provider_targets)}",
        ]
        if config.openai_api_key:
            env_lines.append(f"OPENAI_API_KEY={config.openai_api_key}")
        if config.guard_model_path:
            env_lines.append(f"GUARD_MODEL_PATH={config.guard_model_path}")
        if config.api_secret:
            env_lines.append(f"API_SECRET={config.api_secret}")
        if config.jwt_secret:
            env_lines.append(f"JWT_SECRET={config.jwt_secret}")

        config.env_file.write_text("\n".join(env_lines) + "\n", encoding="utf-8")


def skill_config_env(config: IronClawSkillConfig) -> dict[str, str]:
    env: dict[str, str] = {
        "IRONCLAW_BASE_URL": config.base_url,
        "IRONCLAW_POLICY_MODE": config.policy_mode,
        "IRONCLAW_TIMEOUT_SECONDS": str(config.timeout_seconds),
        "IRONCLAW_BACKUP_TARGET_NAME": config.backup_target,
        "IRONCLAW_RESTORE_TARGET_NAME": config.restore_target,
        "IRONCLAW_SKILL_ENABLED": "true" if config.skill_enabled else "false",
        "IRONCLAW_PROVIDER_TARGETS": ",".join(config.provider_targets),
    }

    if config.openai_api_key:
        env["OPENAI_API_KEY"] = config.openai_api_key
    if config.guard_model_path:
        env["GUARD_MODEL_PATH"] = config.guard_model_path
    if config.api_secret:
        env["API_SECRET"] = config.api_secret
    if config.jwt_secret:
        env["JWT_SECRET"] = config.jwt_secret

    return env


__all__ = [
    "IronClawSkillConfig",
    "IronClawSkillConfigError",
    "load_skill_config",
    "require_skill_config",
    "save_skill_config",
    "skill_config_env",
]
