from __future__ import annotations

from datetime import UTC, datetime
from hashlib import sha256

from schemas.release_policy import (
    ReleaseChannel,
    ReleasePolicyDetail,
    ReleasePolicyListResponse,
    ReleasePolicyResolveResponse,
    ReleasePolicySummary,
)


class ReleasePolicyNotFoundError(LookupError):
    """Raised when a requested release policy channel does not exist."""


class ReleasePolicyService:
    def _utcnow(self) -> datetime:
        return datetime.now(UTC)

    def _checksum_for(
        self,
        *,
        version: str,
        channel: ReleaseChannel,
        status: str,
        required_env: list[str],
        preflight_checks: list[str],
        upgrade_steps: list[str],
        rollback_steps: list[str],
    ) -> str:
        raw = "|".join(
            [
                version,
                channel,
                status,
                ",".join(required_env),
                ",".join(preflight_checks),
                ",".join(upgrade_steps),
                ",".join(rollback_steps),
            ]
        )
        return sha256(raw.encode("utf-8")).hexdigest()

    def _build_policy(
        self,
        *,
        version: str,
        channel: ReleaseChannel,
    ) -> ReleasePolicyDetail:
        compatibility_notes = [
            "Use verified environment values before rollout.",
            "Require deployment readiness and smoke verification before cutover.",
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

        status = "active"
        rollout_strategy = "blue-green" if channel == "production" else "canary"

        return ReleasePolicyDetail(
            policy_id=f"ironclaw-{channel}",
            version=version,
            channel=channel,
            status=status,
            minimum_upgrade_from="1.0.0",
            backup_required=True,
            migration_required=channel in {"staging", "production"},
            rollout_strategy=rollout_strategy,
            generated_at=self._utcnow(),
            checksum=self._checksum_for(
                version=version,
                channel=channel,
                status=status,
                required_env=required_env,
                preflight_checks=preflight_checks,
                upgrade_steps=upgrade_steps,
                rollback_steps=rollback_steps,
            ),
            compatibility_notes=compatibility_notes,
            required_env=required_env,
            preflight_checks=preflight_checks,
            upgrade_steps=upgrade_steps,
            rollback_steps=rollback_steps,
        )

    def _catalog(self) -> dict[ReleaseChannel, ReleasePolicyDetail]:
        return {
            "dev": self._build_policy(version="1.0.0-dev", channel="dev"),
            "staging": self._build_policy(version="1.0.0-rc1", channel="staging"),
            "production": self._build_policy(version="1.0.0", channel="production"),
        }

    def list_policies(
        self,
        *,
        channel: ReleaseChannel | None = None,
    ) -> ReleasePolicyListResponse:
        items = list(self._catalog().values())
        if channel is not None:
            items = [policy for policy in items if policy.channel == channel]

        summaries = [
            ReleasePolicySummary.model_validate(policy.model_dump())
            for policy in items
        ]
        return ReleasePolicyListResponse(items=summaries, count=len(summaries))

    def get_policy(self, channel: ReleaseChannel) -> ReleasePolicyDetail:
        policy = self._catalog().get(channel)
        if policy is None:
            raise ReleasePolicyNotFoundError(f"release policy not found for channel={channel}")
        return policy

    def resolve_policy(self, channel: ReleaseChannel) -> ReleasePolicyResolveResponse:
        policy = self.get_policy(channel)
        return ReleasePolicyResolveResponse(
            policy=policy,
            resolved_channel=channel,
        )


release_policy_service = ReleasePolicyService()