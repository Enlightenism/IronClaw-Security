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

    from pydantic import ConfigDict as _CD

    class BaseSettings(BaseModel):  # type: ignore[no-redef]
        model_config = _CD(extra="ignore")

        def __init__(self, **data):
            merged: dict = {}
            for field_name, model_field in self.__class__.model_fields.items():
                alias = model_field.alias or field_name
                env_value = os.getenv(alias) or os.getenv(alias.upper()) or os.getenv(alias.lower())
                if env_value is not None and field_name not in data:
                    merged[field_name] = env_value
            merged.update(data)
            super().__init__(**merged)

    def SettingsConfigDict(**kwargs):  # type: ignore[no-redef]
        from pydantic import ConfigDict

        return ConfigDict(**kwargs)


logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEFAULT_REGION = "us-east-1"
_IRONCLAW_REGION_ENV = "IRONCLAW_REGION"

# Per-region env var prefixes follow the pattern:
#   REGION_<UPPER_CODE_UNDERSCORED>_SUPABASE_URL
#   REGION_<UPPER_CODE_UNDERSCORED>_SUPABASE_SERVICE_ROLE_KEY
#   REGION_<UPPER_CODE_UNDERSCORED>_SUPABASE_ANON_KEY
#   REGION_<UPPER_CODE_UNDERSCORED>_IS_PRIMARY
#   REGION_<UPPER_CODE_UNDERSCORED>_IS_READ_REPLICA
#   REGION_<UPPER_CODE_UNDERSCORED>_WEIGHT
#
# Where UPPER_CODE_UNDERSCORED replaces hyphens with underscores and
# uppercases the region code, e.g.:  us-east-1 → US_EAST_1


def _region_env_key(region_code: str) -> str:
    """Convert region code to the env var prefix component."""
    return region_code.upper().replace("-", "_")


# ---------------------------------------------------------------------------
# RegionCode enum
# ---------------------------------------------------------------------------


class RegionCode(StrEnum):
    """Supported IronClaw deployment regions."""

    US_EAST_1 = "us-east-1"
    US_WEST_2 = "us-west-2"
    EU_WEST_1 = "eu-west-1"
    AP_SOUTHEAST_1 = "ap-southeast-1"

    @classmethod
    def values(cls) -> list[str]:
        return [m.value for m in cls]

    @classmethod
    def from_string(cls, value: str) -> RegionCode:
        """Case-insensitive lookup; raises ValueError on unknown region."""
        normalized = value.strip().lower()
        for member in cls:
            if member.value == normalized:
                return member
        raise ValueError(f"Unknown region code '{value}'. " f"Supported regions: {cls.values()}")


# ---------------------------------------------------------------------------
# RegionConfig — runtime model for a single region's connection data
# ---------------------------------------------------------------------------


class RegionConfig(BaseModel):
    """
    Immutable runtime descriptor for a single IronClaw deployment region.

    Instances are constructed by get_region_configs() from environment
    variables.  Credentials are kept in memory only — never serialised to
    disk or logged.
    """

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
        """
        Return a safe dict representation — credentials are masked.
        Used for API responses and logging.
        """
        return {
            "region_code": self.region_code,
            "supabase_url": self.supabase_url,
            "supabase_service_role_key": "***",
            "supabase_anon_key": "***",
            "is_primary": self.is_primary,
            "is_read_replica": self.is_read_replica,
            "weight": self.weight,
        }


# ---------------------------------------------------------------------------
# MultiRegionSettings — env-driven configuration for HA / multi-region mode
# ---------------------------------------------------------------------------


class MultiRegionSettings(BaseSettings):
    """
    Environment-driven settings for IronClaw multi-region / HA operation.

    These settings are additive to core Settings and are consumed exclusively
    by region.py functions.  They are validated at boot via
    get_multi_region_settings().
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
        env_file_override=True,
    )

    # The region this IronClaw instance is serving from.
    # Overrides IRONCLAW_REGION env var; falls back to us-east-1.
    ironclaw_region: str = Field(default=_DEFAULT_REGION, alias="IRONCLAW_REGION")

    # HA control flags
    ha_enabled: bool = Field(default=False, alias="HA_ENABLED")
    region_failover_enabled: bool = Field(default=False, alias="REGION_FAILOVER_ENABLED")
    region_health_check_interval_seconds: int = Field(default=30, alias="REGION_HEALTH_CHECK_INTERVAL_SECONDS")

    # Comma-separated list of region codes that are active replicas.
    # Example: "us-west-2,eu-west-1"
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
        """Return the REPLICA_REGIONS value as a stripped, non-empty list."""
        if not self.replica_regions.strip():
            return []
        return [c.strip().lower() for c in self.replica_regions.split(",") if c.strip()]


@lru_cache(maxsize=1)
def get_multi_region_settings() -> MultiRegionSettings:
    """Return a validated, cached MultiRegionSettings instance."""
    return MultiRegionSettings()


# ---------------------------------------------------------------------------
# get_active_region()
# ---------------------------------------------------------------------------


def get_active_region() -> RegionCode:
    """
    Return the RegionCode this IronClaw instance is currently serving from.

    Resolution order:
      1. IRONCLAW_REGION environment variable (direct os.getenv — always
         reflects the live process environment, not the cached settings object)
      2. Falls back to RegionCode.US_EAST_1

    Raises ValueError if the env var is set to an unrecognised region code.
    """
    raw = os.getenv(_IRONCLAW_REGION_ENV, "").strip().lower()
    if not raw:
        return RegionCode.US_EAST_1
    return RegionCode.from_string(raw)


# ---------------------------------------------------------------------------
# _build_region_config_from_env()
# ---------------------------------------------------------------------------


def _build_region_config_from_env(
    region_code: str,
    *,
    is_primary: bool = False,
    is_read_replica: bool = False,
) -> RegionConfig | None:
    """
    Attempt to build a RegionConfig for the given region code by reading
    per-region env vars.  Returns None if the required Supabase URL env var
    is absent (meaning the region is not configured in this deployment).
    """
    prefix = _region_env_key(region_code)

    supabase_url = os.getenv(f"REGION_{prefix}_SUPABASE_URL", "").strip().rstrip("/")
    if not supabase_url:
        return None

    service_role_key = os.getenv(f"REGION_{prefix}_SUPABASE_SERVICE_ROLE_KEY", "").strip()
    anon_key = os.getenv(f"REGION_{prefix}_SUPABASE_ANON_KEY", "").strip()

    # Per-region overrides for role flags (env wins over caller-supplied default)
    _is_primary_raw = os.getenv(f"REGION_{prefix}_IS_PRIMARY", "").strip().lower()
    _is_replica_raw = os.getenv(f"REGION_{prefix}_IS_READ_REPLICA", "").strip().lower()

    resolved_primary = _is_primary_raw in {"1", "true", "yes", "on"} if _is_primary_raw else is_primary
    resolved_replica = _is_replica_raw in {"1", "true", "yes", "on"} if _is_replica_raw else is_read_replica

    _weight_raw = os.getenv(f"REGION_{prefix}_WEIGHT", "100").strip()
    try:
        weight = max(1, min(1000, int(_weight_raw)))
    except ValueError:
        weight = 100
        logger.warning(
            "Invalid REGION_%s_WEIGHT value '%s'; defaulting to 100.",
            prefix,
            _weight_raw,
        )

    if not service_role_key or not anon_key:
        logger.warning(
            "Region '%s' has SUPABASE_URL set but is missing " "SERVICE_ROLE_KEY or ANON_KEY — region will be skipped.",
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
        logger.error(
            "Failed to build RegionConfig for region '%s': %s",
            region_code,
            exc,
        )
        return None


# ---------------------------------------------------------------------------
# get_region_configs()
# ---------------------------------------------------------------------------


def get_region_configs() -> list[RegionConfig]:
    """
    Parse all configured regions from environment variables and return a list
    of validated RegionConfig objects.

    A region is considered configured when its
    REGION_<CODE>_SUPABASE_URL env var is present and non-empty.

    Resolution:
      - PRIMARY_REGION → always attempted first, is_primary=True
      - REPLICA_REGIONS (comma-separated) → each attempted, is_read_replica=True
      - Regions with missing or incomplete credentials are silently skipped
        with a warning logged.
      - Duplicate region codes across primary + replicas are de-duplicated
        (primary wins on conflict).
    """
    mr_settings = get_multi_region_settings()
    configs: list[RegionConfig] = []
    seen: set[str] = set()

    # Primary region
    primary_code = mr_settings.primary_region.strip().lower()
    if primary_code:
        cfg = _build_region_config_from_env(primary_code, is_primary=True, is_read_replica=False)
        if cfg is not None:
            configs.append(cfg)
            seen.add(primary_code)

    # Replica regions
    for replica_code in mr_settings.parsed_replica_codes():
        if replica_code in seen:
            logger.debug(
                "Region '%s' already registered as primary; skipping replica entry.",
                replica_code,
            )
            continue
        cfg = _build_region_config_from_env(replica_code, is_primary=False, is_read_replica=True)
        if cfg is not None:
            configs.append(cfg)
            seen.add(replica_code)

    return configs


# ---------------------------------------------------------------------------
# get_primary_region_config()
# ---------------------------------------------------------------------------


def get_primary_region_config() -> RegionConfig:
    """
    Return the single RegionConfig marked is_primary=True.

    Raises:
        RuntimeError: if no primary region is configured in the current
                      environment (i.e. no region with is_primary=True
                      was constructed by get_region_configs()).
    """
    configs = get_region_configs()
    for cfg in configs:
        if cfg.is_primary:
            return cfg
    raise RuntimeError("No primary region is configured. " "Set PRIMARY_REGION and provide " "REGION_<CODE>_SUPABASE_URL / _SERVICE_ROLE_KEY / _ANON_KEY env vars.")


# ---------------------------------------------------------------------------
# get_read_replica_configs()
# ---------------------------------------------------------------------------


def get_read_replica_configs() -> list[RegionConfig]:
    """
    Return all RegionConfig objects where is_read_replica=True.

    Returns an empty list when no replicas are configured, which is the
    expected state for single-region deployments.
    """
    return [cfg for cfg in get_region_configs() if cfg.is_read_replica]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

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
