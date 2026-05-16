from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
import json
import os
from pathlib import Path
from typing import Any

from .errors import ProviderConfigurationError

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]

JsonValue = Any


def _env(name: str, default: str | None = None) -> str | None:
    value = os.getenv(name)
    if value is None:
        return default
    value = value.strip()
    return value or default


def _env_bool(name: str, default: bool = False) -> bool:
    value = _env(name)
    if value is None:
        return default
    return value.lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    value = _env(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _normalize_mapping(value: Mapping[str, Any] | None) -> dict[str, Any]:
    return dict(value or {})


def _first_present(*values: str | None, default: str | None = None) -> str | None:
    for value in values:
        if value is not None and str(value).strip():
            return str(value).strip()
    return default


def _resolve_path(value: str | None, *, base_dir: Path | None = None) -> Path | None:
    if not value:
        return None
    path = Path(value).expanduser()
    if not path.is_absolute() and base_dir is not None:
        path = base_dir / path
    return path.resolve()


def _load_structured_config(path: Path) -> dict[str, Any]:
    """Backwards-compatible loader for structured config files.

    Primary source of truth is TOML; if TOML parsing fails, fall back to JSON
    so tests can exercise legacy JSON configs without changing the core model.
    """
    text = path.read_text(encoding="utf-8")

    if tomllib is not None:
        try:
            return tomllib.loads(text)
        except Exception:
            # Fall through to JSON for legacy configs written as JSON.
            pass

    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:  # pragma: no cover - defensive
        raise ProviderConfigurationError(
            f"Failed to parse configuration file '{path}': {exc}",
        ) from exc


@dataclass(slots=True, frozen=True)
class ProviderConfig:
    name: str
    enabled: bool = True
    model: str | None = None
    endpoint: str | None = None
    api_key: str | None = None
    timeout_seconds: int = 30
    connect_timeout_seconds: int = 10
    max_retries: int = 2
    organization: str | None = None
    project: str | None = None
    headers: Mapping[str, str] = field(default_factory=dict)
    metadata: Mapping[str, JsonValue] = field(default_factory=dict)

    @property
    def configured(self) -> bool:
        return bool(self.endpoint or self.api_key or self.model)

    def require_ready(self) -> None:
        if not self.enabled:
            raise ProviderConfigurationError(f"Provider '{self.name}' is disabled")
        if not self.configured:
            raise ProviderConfigurationError(f"Provider '{self.name}' is not configured")


@dataclass(slots=True, frozen=True)
class SecurityConfig:
    review_on_high_risk: bool = True
    block_on_policy_violation: bool = True
    allow_network: bool = False
    allow_tool_invocation: bool = False
    allow_filesystem_write: bool = False
    enable_sandbox: bool = True
    enable_audit_logging: bool = True
    enable_prompt_redaction: bool = True
    max_payload_bytes: int = 262_144
    max_output_bytes: int = 262_144
    max_execution_seconds: int = 120


@dataclass(slots=True, frozen=True)
class PathsConfig:
    root_dir: Path
    config_file: Path | None = None
    audit_log_path: Path | None = None
    rules_dir: Path | None = None
    quarantine_dir: Path | None = None
    output_dir: Path | None = None

    @staticmethod
    def default(root_dir: Path | None = None) -> PathsConfig:
        root = (root_dir or Path.cwd()).resolve()
        return PathsConfig(
            root_dir=root,
            config_file=None,
            audit_log_path=root / "output" / "security-events.jsonl",
            rules_dir=root / "rules" / "openclaw",
            quarantine_dir=root / "quarantine",
            output_dir=root / "output",
        )


@dataclass(slots=True, frozen=True)
class IronClawSkillConfig:
    app_name: str = "ironclawskill"
    environment: str = "development"
    default_provider: str = "openclaw"
    fail_closed: bool = True
    telemetry_enabled: bool = True
    debug: bool = False
    paths: PathsConfig = field(default_factory=PathsConfig.default)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    providers: Mapping[str, ProviderConfig] = field(default_factory=dict)
    metadata: Mapping[str, JsonValue] = field(default_factory=dict)

    def get_provider(self, name: str | None = None) -> ProviderConfig:
        provider_name = (name or self.default_provider).strip().lower()
        provider = self.providers.get(provider_name)
        if provider is None:
            raise KeyError(f"Unknown provider '{provider_name}'")
        return provider

    def require_provider(self, name: str | None = None) -> ProviderConfig:
        provider = self.get_provider(name)
        provider.require_ready()
        return provider

    @property
    def enabled_providers(self) -> tuple[str, ...]:
        return tuple(name for name, provider in self.providers.items() if provider.enabled)

    # Backwards-compatible alias for older call sites / tests
    @property
    def enabledproviders(self) -> tuple[str, ...]:
        return self.enabled_providers

    # Backwards-compatible Pydantic-style export used in tests
    def model_dump(self) -> dict[str, Any]:
        """Provide a Pydantic-like export API so tests can compare configs
        using model_dump() even though this is a dataclass-based model.
        """

        def _provider_dict(p: ProviderConfig) -> dict[str, Any]:
            d = asdict(p)
            return d

        def _paths_dict(p: PathsConfig) -> dict[str, Any]:
            d = asdict(p)
            d["root_dir"] = str(d["root_dir"])
            if d["config_file"] is not None:
                d["config_file"] = str(d["config_file"])
            if d["audit_log_path"] is not None:
                d["audit_log_path"] = str(d["audit_log_path"])
            if d["rules_dir"] is not None:
                d["rules_dir"] = str(d["rules_dir"])
            if d["quarantine_dir"] is not None:
                d["quarantine_dir"] = str(d["quarantine_dir"])
            if d["output_dir"] is not None:
                d["output_dir"] = str(d["output_dir"])
            return d

        base = {
            "app_name": self.app_name,
            "environment": self.environment,
            "default_provider": self.default_provider,
            "fail_closed": self.fail_closed,
            "telemetry_enabled": self.telemetry_enabled,
            "debug": self.debug,
            "paths": _paths_dict(self.paths),
            "security": asdict(self.security),
            "providers": {name: _provider_dict(cfg) for name, cfg in self.providers.items()},
            "metadata": dict(self.metadata),
        }
        return base

    @classmethod
    def from_mapping(
        cls,
        data: Mapping[str, Any] | None = None,
        *,
        root_dir: Path | None = None,
        config_file: Path | None = None,
    ) -> IronClawSkillConfig:
        raw = dict(data or {})
        resolved_root = (root_dir or Path.cwd()).resolve()
        base_dir = (config_file.parent if config_file is not None else resolved_root).resolve()

        app_name = str(raw.get("app_name") or "ironclawskill")
        environment = str(raw.get("environment") or "development")
        default_provider = str(raw.get("default_provider") or "openclaw").lower()
        fail_closed = bool(raw.get("fail_closed", True))
        telemetry_enabled = bool(raw.get("telemetry_enabled", True))
        debug = bool(raw.get("debug", False))

        raw_paths = _normalize_mapping(raw.get("paths"))
        default_paths = PathsConfig.default(resolved_root)
        paths = PathsConfig(
            root_dir=resolved_root,
            config_file=config_file.resolve() if config_file else None,
            audit_log_path=_resolve_path(raw_paths.get("audit_log_path"), base_dir=base_dir) or default_paths.audit_log_path,
            rules_dir=_resolve_path(raw_paths.get("rules_dir"), base_dir=base_dir) or default_paths.rules_dir,
            quarantine_dir=_resolve_path(raw_paths.get("quarantine_dir"), base_dir=base_dir) or default_paths.quarantine_dir,
            output_dir=_resolve_path(raw_paths.get("output_dir"), base_dir=base_dir) or default_paths.output_dir,
        )

        raw_security = _normalize_mapping(raw.get("security"))
        security = SecurityConfig(
            review_on_high_risk=bool(raw_security.get("review_on_high_risk", True)),
            block_on_policy_violation=bool(raw_security.get("block_on_policy_violation", True)),
            allow_network=bool(raw_security.get("allow_network", False)),
            allow_tool_invocation=bool(raw_security.get("allow_tool_invocation", False)),
            allow_filesystem_write=bool(raw_security.get("allow_filesystem_write", False)),
            enable_sandbox=bool(raw_security.get("enable_sandbox", True)),
            enable_audit_logging=bool(raw_security.get("enable_audit_logging", True)),
            enable_prompt_redaction=bool(raw_security.get("enable_prompt_redaction", True)),
            max_payload_bytes=int(raw_security.get("max_payload_bytes", 262_144)),
            max_output_bytes=int(raw_security.get("max_output_bytes", 262_144)),
            max_execution_seconds=int(raw_security.get("max_execution_seconds", 120)),
        )

        raw_providers = _normalize_mapping(raw.get("providers"))
        providers: dict[str, ProviderConfig] = {}
        for name, item in raw_providers.items():
            item_map = _normalize_mapping(item)
            provider_name = str(name).lower()
            providers[provider_name] = ProviderConfig(
                name=provider_name,
                enabled=bool(item_map.get("enabled", True)),
                model=_first_present(item_map.get("model")),
                endpoint=_first_present(item_map.get("endpoint")),
                api_key=_first_present(item_map.get("api_key")),
                timeout_seconds=int(item_map.get("timeout_seconds", 30)),
                connect_timeout_seconds=int(item_map.get("connect_timeout_seconds", 10)),
                max_retries=int(item_map.get("max_retries", 2)),
                organization=_first_present(item_map.get("organization")),
                project=_first_present(item_map.get("project")),
                headers={str(k): str(v) for k, v in _normalize_mapping(item_map.get("headers")).items()},
                metadata=_normalize_mapping(item_map.get("metadata")),
            )

        config = cls(
            app_name=app_name,
            environment=environment,
            default_provider=default_provider,
            fail_closed=fail_closed,
            telemetry_enabled=telemetry_enabled,
            debug=debug,
            paths=paths,
            security=security,
            providers=providers,
            metadata=_normalize_mapping(raw.get("metadata")),
        )
        return config.with_env_overrides()

    @classmethod
    def from_toml_file(cls, path: str | Path, *, root_dir: Path | None = None) -> IronClawSkillConfig:
        file_path = Path(path).expanduser().resolve()
        data = _load_structured_config(file_path)
        return cls.from_mapping(data, root_dir=root_dir or file_path.parent, config_file=file_path)

    @classmethod
    def from_env(cls, *, root_dir: Path | None = None) -> IronClawSkillConfig:
        base = cls(
            app_name=_env("IRONCLAWSKILL_APP_NAME", "ironclawskill") or "ironclawskill",
            environment=_env("IRONCLAWSKILL_ENV", "development") or "development",
            default_provider=(_env("IRONCLAWSKILL_DEFAULT_PROVIDER", "openclaw") or "openclaw").lower(),
            fail_closed=_env_bool("IRONCLAWSKILL_FAIL_CLOSED", True),
            telemetry_enabled=_env_bool("IRONCLAWSKILL_TELEMETRY_ENABLED", True),
            debug=_env_bool("IRONCLAWSKILL_DEBUG", False),
            paths=PathsConfig.default(root_dir),
            security=SecurityConfig(),
            providers={},
            metadata={},
        )
        return base.with_env_overrides()

    @classmethod
    def load(
        cls,
        *,
        root_dir: Path | None = None,
        config_path: str | Path | None = None,
    ) -> IronClawSkillConfig:
        search_root = (root_dir or Path.cwd()).resolve()
        explicit = _resolve_path(str(config_path), base_dir=search_root) if config_path else None
        env_path = _resolve_path(_env("IRONCLAWSKILL_CONFIG"), base_dir=search_root)
        candidates = [path for path in (explicit, env_path) if path is not None]
        candidates.extend(
            [
                search_root / "config" / "ironclawskill.toml",
                search_root / "config" / "ironclawskill.example.toml",
            ],
        )

        for candidate in candidates:
            if candidate.exists():
                return cls.from_toml_file(candidate, root_dir=search_root)
        return cls.from_env(root_dir=search_root)

    def with_env_overrides(self) -> IronClawSkillConfig:
        providers = {name: provider for name, provider in self.providers.items()}

        for provider_name in ("openclaw", "claude"):
            prefix = f"IRONCLAWSKILL_{provider_name.upper()}_"
            existing = providers.get(provider_name, ProviderConfig(name=provider_name, enabled=False))
            providers[provider_name] = ProviderConfig(
                name=provider_name,
                enabled=_env_bool(f"{prefix}ENABLED", existing.enabled),
                model=_first_present(_env(f"{prefix}MODEL"), existing.model),
                endpoint=_first_present(_env(f"{prefix}ENDPOINT"), existing.endpoint),
                api_key=_first_present(
                    _env(f"{prefix}API_KEY"),
                    _env(f"{provider_name.upper()}_API_KEY"),
                    existing.api_key,
                ),
                timeout_seconds=_env_int(f"{prefix}TIMEOUT_SECONDS", existing.timeout_seconds),
                connect_timeout_seconds=_env_int(
                    f"{prefix}CONNECT_TIMEOUT_SECONDS",
                    existing.connect_timeout_seconds,
                ),
                max_retries=_env_int(f"{prefix}MAX_RETRIES", existing.max_retries),
                organization=_first_present(_env(f"{prefix}ORGANIZATION"), existing.organization),
                project=_first_present(_env(f"{prefix}PROJECT"), existing.project),
                headers=dict(existing.headers),
                metadata=dict(existing.metadata),
            )

        paths = PathsConfig(
            root_dir=self.paths.root_dir,
            config_file=self.paths.config_file,
            audit_log_path=_resolve_path(
                _env("IRONCLAWSKILL_AUDIT_LOG_PATH"),
                base_dir=self.paths.root_dir,
            )
            or self.paths.audit_log_path,
            rules_dir=_resolve_path(
                _env("IRONCLAWSKILL_RULES_DIR"),
                base_dir=self.paths.root_dir,
            )
            or self.paths.rules_dir,
            quarantine_dir=_resolve_path(
                _env("IRONCLAWSKILL_QUARANTINE_DIR"),
                base_dir=self.paths.root_dir,
            )
            or self.paths.quarantine_dir,
            output_dir=_resolve_path(
                _env("IRONCLAWSKILL_OUTPUT_DIR"),
                base_dir=self.paths.root_dir,
            )
            or self.paths.output_dir,
        )

        security = SecurityConfig(
            review_on_high_risk=_env_bool(
                "IRONCLAWSKILL_REVIEW_ON_HIGH_RISK",
                self.security.review_on_high_risk,
            ),
            block_on_policy_violation=_env_bool(
                "IRONCLAWSKILL_BLOCK_ON_POLICY_VIOLATION",
                self.security.block_on_policy_violation,
            ),
            allow_network=_env_bool("IRONCLAWSKILL_ALLOW_NETWORK", self.security.allow_network),
            allow_tool_invocation=_env_bool(
                "IRONCLAWSKILL_ALLOW_TOOL_INVOCATION",
                self.security.allow_tool_invocation,
            ),
            allow_filesystem_write=_env_bool(
                "IRONCLAWSKILL_ALLOW_FILESYSTEM_WRITE",
                self.security.allow_filesystem_write,
            ),
            enable_sandbox=_env_bool("IRONCLAWSKILL_ENABLE_SANDBOX", self.security.enable_sandbox),
            enable_audit_logging=_env_bool(
                "IRONCLAWSKILL_ENABLE_AUDIT_LOGGING",
                self.security.enable_audit_logging,
            ),
            enable_prompt_redaction=_env_bool(
                "IRONCLAWSKILL_ENABLE_PROMPT_REDACTION",
                self.security.enable_prompt_redaction,
            ),
            max_payload_bytes=_env_int(
                "IRONCLAWSKILL_MAX_PAYLOAD_BYTES",
                self.security.max_payload_bytes,
            ),
            max_output_bytes=_env_int(
                "IRONCLAWSKILL_MAX_OUTPUT_BYTES",
                self.security.max_output_bytes,
            ),
            max_execution_seconds=_env_int(
                "IRONCLAWSKILL_MAX_EXECUTION_SECONDS",
                self.security.max_execution_seconds,
            ),
        )

        return IronClawSkillConfig(
            app_name=_env("IRONCLAWSKILL_APP_NAME", self.app_name) or self.app_name,
            environment=_env("IRONCLAWSKILL_ENV", self.environment) or self.environment,
            default_provider=(_env("IRONCLAWSKILL_DEFAULT_PROVIDER", self.default_provider) or self.default_provider).lower(),
            fail_closed=_env_bool("IRONCLAWSKILL_FAIL_CLOSED", self.fail_closed),
            telemetry_enabled=_env_bool(
                "IRONCLAWSKILL_TELEMETRY_ENABLED",
                self.telemetry_enabled,
            ),
            debug=_env_bool("IRONCLAWSKILL_DEBUG", self.debug),
            paths=paths,
            security=security,
            providers=providers,
            metadata=dict(self.metadata),
        )


def load_config(
    *,
    root_dir: Path | None = None,
    config_path: str | Path | None = None,
) -> IronClawSkillConfig:
    return IronClawSkillConfig.load(root_dir=root_dir, config_path=config_path)


loadconfig = load_config


__all__ = [
    "IronClawSkillConfig",
    "JsonValue",
    "PathsConfig",
    "ProviderConfig",
    "SecurityConfig",
    "load_config",
    "loadconfig",
]
