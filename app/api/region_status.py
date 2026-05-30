from __future__ import annotations

from datetime import datetime
import logging
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel

from app.core.auth import require_api_key
from app.core.region import (
    RegionConfig,
    get_active_region,
    get_multi_region_settings,
    get_region_configs,
)
from app.core.settings import get_settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/region", tags=["region"])

# ---------------------------------------------------------------------------
# Response schemas
# ---------------------------------------------------------------------------


class RegionHealthSummary(BaseModel):
    region_code: str
    is_primary: bool
    is_read_replica: bool
    weight: int
    configured: bool


class RegionStatusResponse(BaseModel):
    active_region: str
    ha_enabled: bool
    failover_enabled: bool
    health_check_interval_seconds: int
    primary_region: str
    replica_regions: list[str]
    regions: list[RegionHealthSummary]


class RegionConfigResponse(BaseModel):
    region_code: str
    supabase_url: str
    is_primary: bool
    is_read_replica: bool
    weight: int


class RegionHealthLogEntry(BaseModel):
    id: str | None = None
    region_code: str
    checked_at: datetime | None = None
    is_healthy: bool
    latency_ms: float | None = None
    error_message: str | None = None
    metadata: dict[str, Any] | None = None


class RegionHealthLogResponse(BaseModel):
    region_code: str
    entries: list[RegionHealthLogEntry]
    total: int


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mask_config(cfg: RegionConfig) -> RegionConfigResponse:
    return RegionConfigResponse(
        region_code=cfg.region_code,
        supabase_url=cfg.supabase_url,
        is_primary=cfg.is_primary,
        is_read_replica=cfg.is_read_replica,
        weight=cfg.weight,
    )


def _build_region_summary(configs: list[RegionConfig]) -> list[RegionHealthSummary]:
    return [
        RegionHealthSummary(
            region_code=cfg.region_code,
            is_primary=cfg.is_primary,
            is_read_replica=cfg.is_read_replica,
            weight=cfg.weight,
            configured=True,
        )
        for cfg in configs
    ]


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get(
    "/status",
    response_model=RegionStatusResponse,
    summary="Region Status",
    description=("Returns the current active region, HA enabled flag, failover state, " "and a list of all configured regions with configuration summary. " "No authentication required — safe for infrastructure health checks."),
    status_code=status.HTTP_200_OK,
)
async def get_region_status() -> RegionStatusResponse:
    try:
        mr_settings = get_multi_region_settings()
        active = get_active_region()
        configs = get_region_configs()
    except Exception as exc:
        logger.exception("region_status: failed to load region configuration")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Region configuration unavailable.",
        ) from exc

    return RegionStatusResponse(
        active_region=str(active),
        ha_enabled=mr_settings.ha_enabled,
        failover_enabled=mr_settings.region_failover_enabled,
        health_check_interval_seconds=mr_settings.region_health_check_interval_seconds,
        primary_region=mr_settings.primary_region,
        replica_regions=mr_settings.parsed_replica_codes(),
        regions=_build_region_summary(configs),
    )


@router.get(
    "/primary",
    response_model=RegionConfigResponse,
    summary="Primary Region Config",
    description=("Returns the primary region's configuration. " "Credentials are masked — URL is visible, keys are not returned. " "Requires a valid API key."),
    status_code=status.HTTP_200_OK,
)
async def get_primary_region(
    _: Annotated[None, Depends(require_api_key)],
) -> RegionConfigResponse:
    try:
        configs = get_region_configs()
    except Exception as exc:
        logger.exception("region_primary: failed to load region configs")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Region configuration unavailable.",
        ) from exc

    primary = next((c for c in configs if c.is_primary), None)
    if primary is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No primary region is configured.",
        )

    return _mask_config(primary)


@router.get(
    "/replicas",
    response_model=list[RegionConfigResponse],
    summary="Read Replica Region Configs",
    description=("Returns the list of configured read replica regions. " "Credentials are masked — URLs are visible, keys are not returned. " "Requires a valid API key."),
    status_code=status.HTTP_200_OK,
)
async def get_replica_regions(
    _: Annotated[None, Depends(require_api_key)],
) -> list[RegionConfigResponse]:
    try:
        configs = get_region_configs()
    except Exception as exc:
        logger.exception("region_replicas: failed to load region configs")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Region configuration unavailable.",
        ) from exc

    return [_mask_config(c) for c in configs if c.is_read_replica]


@router.get(
    "/health",
    response_model=list[RegionHealthLogResponse],
    summary="Region Health Log",
    description=("Queries the region_health_log table in Supabase and returns the last N " "health check entries per configured region, ordered by checked_at descending. " "Requires a valid API key."),
    status_code=status.HTTP_200_OK,
)
async def get_region_health_log(
    _: Annotated[None, Depends(require_api_key)],
    limit: Annotated[
        int,
        Query(ge=1, le=200, description="Max entries to return per region."),
    ] = 20,
) -> list[RegionHealthLogResponse]:
    settings = get_settings()

    try:
        from supabase import create_client

        client = create_client(settings.supabase_url, settings.supabase_service_role_key)
    except Exception as exc:
        logger.exception("region_health: failed to create Supabase client")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Supabase client unavailable.",
        ) from exc

    try:
        configs = get_region_configs()
    except Exception as exc:
        logger.exception("region_health: failed to load region configs")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Region configuration unavailable.",
        ) from exc

    results: list[RegionHealthLogResponse] = []

    for cfg in configs:
        region_code = str(cfg.region_code)
        try:
            response = client.table("region_health_log").select("*").eq("region_code", region_code).order("checked_at", desc=True).limit(limit).execute()
            raw_entries: list[dict[str, Any]] = response.data or []
        except Exception as exc:
            logger.warning(
                "region_health: Supabase query failed for region=%s error=%s",
                region_code,
                exc,
            )
            raw_entries = []

        entries: list[RegionHealthLogEntry] = []
        for row in raw_entries:
            try:
                entries.append(
                    RegionHealthLogEntry(
                        id=str(row.get("id")) if row.get("id") is not None else None,
                        region_code=row.get("region_code", region_code),
                        checked_at=row.get("checked_at"),
                        is_healthy=bool(row.get("is_healthy", False)),
                        latency_ms=row.get("latency_ms"),
                        error_message=row.get("error_message"),
                        metadata=row.get("metadata"),
                    )
                )
            except Exception as parse_exc:
                logger.debug(
                    "region_health: skipping malformed row region=%s error=%s",
                    region_code,
                    parse_exc,
                )

        results.append(
            RegionHealthLogResponse(
                region_code=region_code,
                entries=entries,
                total=len(entries),
            )
        )

    return results
