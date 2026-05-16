from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
from typing import Any, Final

from dotenv import load_dotenv

DEFAULT_BASE_URL: Final[str] = "http://127.0.0.1:8000"
DEFAULT_TIMEOUT_SECONDS: Final[float] = 10.0
DEFAULT_POLICY_MODE: Final[str] = "review"
DEFAULT_CONFIG_DIRNAME: Final[str] = ".ironclaw"
DEFAULT_CONFIG_FILENAME: Final[str] = "config.json"
DEFAULT_SKILL_FILENAME: Final[str] = "skill.json"


class IronClawSkillContextError(RuntimeError):
    """Raised when IronClaw skill context cannot be resolved."""


@dataclass(frozen=True, slots=True)
class IronClawSkillContext:
    environment: str
    project_root: Path
    config_dir: Path
    config_file: Path
    skill_file: Path
    env_file: Path
    base_url: str
    openai_api_key: str | None
    groq_api_key: str | None
    api_secret: str | None
    jwt_secret: str | None
    backup_target: str
    restore_target: str
    policy_mode: str
    timeout_seconds: float

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["project_root"] = str(self.project_root)
        payload["config_dir"] = str(self.config_dir)
        payload["config_file"] = str(self.config_file)
        payload["skill_file"] = str(self.skill_file)
        payload["env_file"] = str(self.env_file)
        return payload


def _project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _default_config_dir() -> Path:
    return Path(os.getenv("IRONCLAW_CONFIG_DIR", Path.home() / DEFAULT_CONFIG_DIRNAME)).expanduser().resolve()


def _config_file(config_dir: Path) -> Path:
    return config_dir / DEFAULT_CONFIG_FILENAME


def _skill_file(config_dir: Path) -> Path:
    return config_dir / DEFAULT_SKILL_FILENAME


def _env_file(project_root: Path) -> Path:
    return project_root / ".env"


def _normalize_optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None


def _load_json_object(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise IronClawSkillContextError(f"Expected JSON object in {path}")
    return payload


def _coerce_timeout(value: Any, *, default: float) -> float:
    if value is None or value == "":
        return default
    try:
        timeout = float(value)
    except (TypeError, ValueError) as exc:
        raise IronClawSkillContextError(f"Invalid timeout value: {value!r}") from exc
    if timeout <= 0:
        raise IronClawSkillContextError("Timeout must be greater than 0")
    return timeout


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
        if isinstance(candidate, str) and candidate.strip():
            return candidate.rstrip("/")
    return DEFAULT_BASE_URL


def _resolve_policy_mode(
    *,
    env: dict[str, str],
    skill_payload: dict[str, Any],
) -> str:
    for candidate in (
        env.get("IRONCLAW_POLICY_MODE"),
        skill_payload.get("default_policy_mode"),
        DEFAULT_POLICY_MODE,
    ):
        if isinstance(candidate, str) and candidate.strip():
            normalized = candidate.strip().lower()
            if normalized in {"allow", "review", "block"}:
                return normalized
    return DEFAULT_POLICY_MODE


def _resolve_target_name(
    *,
    env: dict[str, str],
    config_payload: dict[str, Any],
    key: str,
    default: str,
) -> str:
    candidate = env.get(key)
    if candidate and candidate.strip():
        return candidate.strip()

    config_candidate = config_payload.get(key.lower()) or config_payload.get(key)
    if isinstance(config_candidate, str) and config_candidate.strip():
        return config_candidate.strip()

    return default


def resolve_skill_context(
    *,
    environment: str | None = None,
    project_root: Path | None = None,
    config_dir: Path | None = None,
    load_dotenv_file: bool = True,
) -> IronClawSkillContext:
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

    timeout_seconds = _coerce_timeout(
        env.get("IRONCLAW_TIMEOUT_SECONDS") or skill_payload.get("default_timeout_seconds") or config_payload.get("timeout_seconds"),
        default=DEFAULT_TIMEOUT_SECONDS,
    )

    resolved_environment = _normalize_optional_text(environment) or _normalize_optional_text(env.get("IRONCLAW_ENV")) or _normalize_optional_text(env.get("IRONCLAW_MODE")) or "development"

    backup_target = _normalize_optional_text(env.get("IRONCLAW_BACKUP_TARGET_NAME")) or _normalize_optional_text(env.get("IRONCLAW_BACKUP_TARGET")) or _normalize_optional_text(config_payload.get("backup_target")) or "primary"

    restore_target = _normalize_optional_text(env.get("IRONCLAW_RESTORE_TARGET_NAME")) or _normalize_optional_text(env.get("IRONCLAW_RESTORE_TARGET")) or _normalize_optional_text(config_payload.get("restore_target")) or "primary"

    return IronClawSkillContext(
        environment=resolved_environment,
        project_root=resolved_project_root,
        config_dir=resolved_config_dir,
        config_file=resolved_config_file,
        skill_file=resolved_skill_file,
        env_file=resolved_env_file,
        base_url=base_url,
        openai_api_key=_normalize_optional_text(env.get("OPENAI_API_KEY")),
        groq_api_key=_normalize_optional_text(env.get("GROQ_API_KEY")),
        api_secret=_normalize_optional_text(env.get("API_SECRET")),
        jwt_secret=_normalize_optional_text(env.get("JWT_SECRET")),
        backup_target=backup_target,
        restore_target=restore_target,
        policy_mode=_resolve_policy_mode(env=env, skill_payload=skill_payload),
        timeout_seconds=timeout_seconds,
    )


def require_skill_context(
    *,
    environment: str | None = None,
    project_root: Path | None = None,
    config_dir: Path | None = None,
    require_api_secret: bool = False,
) -> IronClawSkillContext:
    context = resolve_skill_context(
        environment=environment,
        project_root=project_root,
        config_dir=config_dir,
    )

    if not context.base_url:
        raise IronClawSkillContextError("IronClaw base URL is not configured.")

    if require_api_secret and not context.api_secret:
        raise IronClawSkillContextError("API_SECRET is required but not configured.")

    return context


def skill_env_overrides(context: IronClawSkillContext) -> dict[str, str]:
    overrides = {
        "IRONCLAW_BASE_URL": context.base_url,
        "IRONCLAW_BACKUP_TARGET_NAME": context.backup_target,
        "IRONCLAW_RESTORE_TARGET_NAME": context.restore_target,
        "IRONCLAW_POLICY_MODE": context.policy_mode,
        "IRONCLAW_TIMEOUT_SECONDS": str(context.timeout_seconds),
    }

    if context.openai_api_key:
        overrides["OPENAI_API_KEY"] = context.openai_api_key
    if context.groq_api_key:
        overrides["GROQ_API_KEY"] = context.groq_api_key
    if context.api_secret:
        overrides["API_SECRET"] = context.api_secret
    if context.jwt_secret:
        overrides["JWT_SECRET"] = context.jwt_secret

    return overrides


__all__ = [
    "IronClawSkillContext",
    "IronClawSkillContextError",
    "require_skill_context",
    "resolve_skill_context",
    "skill_env_overrides",
]
