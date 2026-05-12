from __future__ import annotations

from datetime import UTC, datetime
from hashlib import sha256
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

router = APIRouter(
    prefix="/release-policy",
    tags=["release-policy"],
)


class ReleasePolicySummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policy_id: str = Field(min_length=3, max_length=64)
    version: str = Field(min_length=1, max_length=32)
    channel: Literal["dev", "staging", "production"]
    status: Literal["active", "draft", "deprecated"]
    minimum_upgrade_from: str = Field(min_length=1, max_length=32)
    backup_required: bool
    migration_required: bool
    rollout_strategy: Literal["manual", "canary", "blue-green", "in-place"]


class ReleasePolicyDetail(ReleasePolicySummary):
    generated_at: datetime
    checksum: str = Field(min_length=64, max_length=64)
    compatibility_notes: list[str]
    required_env: list[str]
    preflight_checks: list[str]
    upgrade_steps: list[str]
    rollback_steps: list[str]


class ReleasePolicyListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[ReleasePolicySummary]
    count: int


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _build_policy(
    *,
    version: str,
    channel: Literal["dev", "staging", "production"],
) -> ReleasePolicyDetail:
    generated_at = _utcnow()

    compatibility_notes = [
        "Use verified environment files before deployment.",
        "Run deployment readiness and smoke verification before cutover.",
        "Do not skip backup generation before restore-impacting upgrades.",
    ]
    required_env = [
        "IRONCLAW_ENV",
        "IRONCLAW_BASE_URL",
        "SUPABASE_URL",
        "SUPABASE_SERVICE_ROLE_KEY",
    ]
    preflight_checks = [
        "python -m scripts.verify",
        "python -m scripts.securityqualitygate",
        "python -m scripts.deploymentreadiness",
        "python -m scripts.smoketest --base-url http://127.0.0.1:8000",
    ]
    upgrade_steps = [
        "Create backup snapshot.",
        "Validate environment configuration.",
        "Build updated container image.",
        "Apply deployment compose changes.",
        "Run readiness and smoke verification.",
    ]
    rollback_steps = [
        "Stop failed rollout.",
        "Restore previous image and compose state.",
        "Run restore flow from latest verified backup if data regression is detected.",
        "Re-run smoke verification.",
    ]

    checksum_source = "|".join(
        [
            version,
            channel,
            "active",
            ",".join(required_env),
            ",".join(preflight_checks),
            ",".join(upgrade_steps),
            ",".join(rollback_steps),
        ]
    )

    return ReleasePolicyDetail(
        policy_id=f"ironclaw-{channel}",
        version=version,
        channel=channel,
        status="active",
        minimum_upgrade_from="1.0.0",
        backup_required=True,
        migration_required=channel in {"staging", "production"},
        rollout_strategy="blue-green" if channel == "production" else "canary",
        generated_at=generated_at,
        checksum=sha256(checksum_source.encode("utf-8")).hexdigest(),
        compatibility_notes=compatibility_notes,
        required_env=required_env,
        preflight_checks=preflight_checks,
        upgrade_steps=upgrade_steps,
        rollback_steps=rollback_steps,
    )


def _policy_catalog() -> dict[str, ReleasePolicyDetail]:
    return {
        "dev": _build_policy(version="1.0.0-dev", channel="dev"),
        "staging": _build_policy(version="1.0.0-rc1", channel="staging"),
        "production": _build_policy(version="1.0.0", channel="production"),
    }


@router.get(
    "",
    response_model=ReleasePolicyListResponse,
    summary="List release policies",
)
def list_release_policies(
    channel: Annotated[
        Literal["dev", "staging", "production"] | None,
        Query(
            description="Optionally filter release policies by channel.",
        ),
    ] = None,
) -> ReleasePolicyListResponse:
    catalog = _policy_catalog()
    items = list(catalog.values())

    if channel is not None:
        items = [policy for policy in items if policy.channel == channel]

    summaries = [
        ReleasePolicySummary.model_validate(policy.model_dump())
        for policy in items
    ]
    return ReleasePolicyListResponse(items=summaries, count=len(summaries))


@router.get(
    "/{channel}",
    response_model=ReleasePolicyDetail,
    summary="Get release policy by channel",
)
def get_release_policy(
    channel: Literal["dev", "staging", "production"],
) -> ReleasePolicyDetail:
    policy = _policy_catalog().get(channel)
    if policy is None:
        raise HTTPException(status_code=404, detail="release policy not found")
    return policy