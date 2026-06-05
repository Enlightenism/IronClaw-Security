from __future__ import annotations

from enum import StrEnum
from functools import lru_cache
import logging
import os

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

try:
    from pydantic_settings import BaseSettings, SettingsConfigDict

    _HAS_PYDANTIC_SETTINGS = True
except ModuleNotFoundError:  # pragma: no cover
    _HAS_PYDANTIC_SETTINGS = False

    from typing import get_args, get_origin

    from pydantic import ConfigDict as _CD

    def _coerce_env_str(value: str, annotation) -> object:
        import typing

        origin = get_origin(annotation)
        args = get_args(annotation)
        if origin is typing.Union:
            inner = [a for a in args if a is not type(None)]
            if len(inner) == 1:
                annotation = inner[0]
                origin = get_origin(annotation)
                args = get_args(annotation)
        if annotation is bool:
            return value.strip().lower() in {"1", "true", "yes", "on"}
        if annotation is int:
            return int(value)
        if annotation is float:
            return float(value)
        return value

    class BaseSettings(BaseModel):  # type: ignore[no-redef]
        model_config = _CD(extra="ignore")

        def __init__(self, **data):
            merged: dict = {}
            for field_name, model_field in self.__class__.model_fields.items():
                alias = model_field.alias or field_name
                env_value = os.getenv(alias) or os.getenv(alias.upper()) or os.getenv(alias.lower())
                if env_value is not None and field_name not in data:
                    merged[field_name] = _coerce_env_str(env_value, model_field.annotation)
            merged.update(data)
            super().__init__(**merged)

    def SettingsConfigDict(**kwargs):  # type: ignore[no-redef]
        from pydantic import ConfigDict

        return ConfigDict(**kwargs)


logger = logging.getLogger(__name__)


_DEFAULT_REGION = "us-east-1"
_IRONCLAW_REGION_ENV = "IRONCLAW_REGION"


def _region_env_key(region_code: str) -> str:
    return region_code.upper().replace("-", "_")


class RegionCode(StrEnum):
    US_EAST_1 = "us-east-1"
    US_WEST_2 = "us-west-2"
    EU_WEST_1 = "eu-west-1"
    AP_SOUTHEAST_1 = "ap-southeast-1"

    @classmethod
    def values(cls) -> list[str]:
        return [m.value for m in cls]

    @classmethod
    def from_string(cls, value: str) -> RegionCode:
        normalized = value.strip().lower()
        for member in cls:
            if member.value == normalized:
                return member
        raise ValueError(f"Unknown region code '{value}'. Supported regions: {cls.values()}")


class RegionConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    region_code: RegionCode
    supabase_url: str
    supabase_service_role_key: str
    supabase_anon_key: str
    is_primary: bool = False
    is_read_replica: bool = False
    weight: int = Field(default=100, ge=1, le=1000)

    @field_validator("supabase_url")
    @classmethod
    def validate_supabase_url(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("supabase_url must not be empty")
        if not (value.startswith("https://") or value.startswith("http://")):
            raise ValueError(f"supabase_url must begin with https:// or http://, got: {value!r}")
        return value.rstrip("/")

    @field_validator("supabase_service_role_key", "supabase_anon_key")
    @classmethod
    def validate_non_empty_key(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Supabase key fields must not be empty")
        return value

    @model_validator(mode="after")
    def validate_role_exclusivity(self) -> RegionConfig:
        if self.is_primary and self.is_read_replica:
            raise ValueError(f"Region '{self.region_code}' cannot be both is_primary=True " "and is_read_replica=True simultaneously.")
        return self

    def masked(self) -> dict:
        return {
            "region_code": self.region_code,
            "supabase_url": self.supabase_url,
            "supabase_service_role_key": "***",
            "supabase_anon_key": "***",
            "is_primary": self.is_primary,
            "is_read_replica": self.is_read_replica,
            "weight": self.weight,
        }


class MultiRegionSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    ironclaw_region: str = Field(default=_DEFAULT_REGION, alias="IRONCLAW_REGION")
    ha_enabled: bool = Field(default=False, alias="HA_ENABLED")
    region_failover_enabled: bool = Field(default=False, alias="REGION_FAILOVER_ENABLED")
    region_health_check_interval_seconds: int = Field(default=30, alias="REGION_HEALTH_CHECK_INTERVAL_SECONDS")
    primary_region: str = Field(default=_DEFAULT_REGION, alias="PRIMARY_REGION")
    replica_regions: str = Field(default="", alias="REPLICA_REGIONS")

    @field_validator("ironclaw_region", "primary_region")
    @classmethod
    def normalize_region_code(cls, value: str) -> str:
        return value.strip().lower()

    @field_validator("replica_regions")
    @classmethod
    def normalize_replica_regions(cls, value: str) -> str:
        return value.strip()

    @field_validator("region_health_check_interval_seconds")
    @classmethod
    def positive_interval(cls, value: int) -> int:
        if value < 1:
            raise ValueError("REGION_HEALTH_CHECK_INTERVAL_SECONDS must be >= 1")
        return value

    @model_validator(mode="after")
    def validate_ha_requires_replicas(self) -> MultiRegionSettings:
        if self.ha_enabled and not self.replica_regions.strip():
            raise ValueError("HA_ENABLED=true requires at least one entry in REPLICA_REGIONS")
        return self

    def parsed_replica_codes(self) -> list[str]:
        if not self.replica_regions.strip():
            return []
        return [c.strip().lower() for c in self.replica_regions.split(",") if c.strip()]


@lru_cache(maxsize=1)
def get_multi_region_settings() -> MultiRegionSettings:
    return MultiRegionSettings()


def get_active_region() -> RegionCode:
    raw = os.getenv(_IRONCLAW_REGION_ENV, "").strip().lower()
    if not raw:
        return RegionCode.US_EAST_1
    return RegionCode.from_string(raw)


def _build_region_config_from_env(
    region_code: str,
    *,
    is_primary: bool = False,
    is_read_replica: bool = False,
) -> RegionConfig | None:
    prefix = _region_env_key(region_code)

    supabase_url = os.getenv(f"REGION_{prefix}_SUPABASE_URL", "").strip().rstrip("/")
    if not supabase_url:
        return None

    service_role_key = os.getenv(f"REGION_{prefix}_SUPABASE_SERVICE_ROLE_KEY", "").strip()
    anon_key = os.getenv(f"REGION_{prefix}_SUPABASE_ANON_KEY", "").strip()

    _is_primary_raw = os.getenv(f"REGION_{prefix}_IS_PRIMARY", "").strip().lower()
    _is_replica_raw = os.getenv(f"REGION_{prefix}_IS_READ_REPLICA", "").strip().lower()

    resolved_primary = _is_primary_raw in {"1", "true", "yes", "on"} if _is_primary_raw else is_primary
    resolved_replica = _is_replica_raw in {"1", "true", "yes", "on"} if _is_replica_raw else is_read_replica

    _weight_raw = os.getenv(f"REGION_{prefix}_WEIGHT", "100").strip()
    try:
        weight = max(1, min(1000, int(_weight_raw)))
    except ValueError:
        weight = 100
        logger.warning("Invalid REGION_%s_WEIGHT value '%s'; defaulting to 100.", prefix, _weight_raw)

    if not service_role_key or not anon_key:
        logger.warning(
            "Region '%s' has SUPABASE_URL set but is missing SERVICE_ROLE_KEY or ANON_KEY — region will be skipped.",
            region_code,
        )
        return None

    try:
        return RegionConfig(
            region_code=RegionCode.from_string(region_code),
            supabase_url=supabase_url,
            supabase_service_role_key=service_role_key,
            supabase_anon_key=anon_key,
            is_primary=resolved_primary,
            is_read_replica=resolved_replica,
            weight=weight,
        )
    except (ValueError, Exception) as exc:  # pragma: no cover
        logger.error("Failed to build RegionConfig for region '%s': %s", region_code, exc)
        return None


def get_region_configs() -> list[RegionConfig]:
    mr_settings = get_multi_region_settings()
    configs: list[RegionConfig] = []
    seen: set[str] = set()

    primary_code = mr_settings.primary_region.strip().lower()
    if primary_code:
        cfg = _build_region_config_from_env(primary_code, is_primary=True, is_read_replica=False)
        if cfg is not None:
            configs.append(cfg)
            seen.add(primary_code)

    for replica_code in mr_settings.parsed_replica_codes():
        if replica_code in seen:
            logger.debug("Region '%s' already registered as primary; skipping replica entry.", replica_code)
            continue
        cfg = _build_region_config_from_env(replica_code, is_primary=False, is_read_replica=True)
        if cfg is not None:
            configs.append(cfg)
            seen.add(replica_code)

    return configs


def get_primary_region_config() -> RegionConfig:
    configs = get_region_configs()
    for cfg in configs:
        if cfg.is_primary:
            return cfg
    raise RuntimeError("No primary region is configured. " "Set PRIMARY_REGION and provide " "REGION_<CODE>_SUPABASE_URL / _SERVICE_ROLE_KEY / _ANON_KEY env vars.")


def get_read_replica_configs() -> list[RegionConfig]:
    return [cfg for cfg in get_region_configs() if cfg.is_read_replica]


__all__ = [
    "RegionCode",
    "RegionConfig",
    "MultiRegionSettings",
    "get_multi_region_settings",
    "get_active_region",
    "get_region_configs",
    "get_primary_region_config",
    "get_read_replica_configs",
]
