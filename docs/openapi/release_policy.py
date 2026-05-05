from __future__ import annotations

from typing import Any, Final


RELEASE_POLICY_LIST_RESPONSE_EXAMPLE: Final[dict[str, Any]] = {
    "items": [
        {
            "policy_id": "ironclaw-production",
            "version": "1.0.0",
            "channel": "production",
            "status": "active",
            "minimum_upgrade_from": "1.0.0",
            "backup_required": True,
            "migration_required": True,
            "rollout_strategy": "blue-green",
        },
        {
            "policy_id": "ironclaw-staging",
            "version": "1.0.0-rc1",
            "channel": "staging",
            "status": "active",
            "minimum_upgrade_from": "1.0.0",
            "backup_required": True,
            "migration_required": True,
            "rollout_strategy": "canary",
        },
    ],
    "count": 2,
}

RELEASE_POLICY_DETAIL_RESPONSE_EXAMPLE: Final[dict[str, Any]] = {
    "policy_id": "ironclaw-production",
    "version": "1.0.0",
    "channel": "production",
    "status": "active",
    "minimum_upgrade_from": "1.0.0",
    "backup_required": True,
    "migration_required": True,
    "rollout_strategy": "blue-green",
    "generated_at": "2026-04-27T22:00:00Z",
    "checksum": "0b5b2f6d3a0d2b7a4b6d0c8d0d7104b6c2f80f2f8d4b5d6d4b8f7e2a1c3d5e7f",
    "compatibility_notes": [
        "Use verified environment values before rollout.",
        "Require deployment readiness and smoke verification before cutover.",
        "Do not skip backup generation before restore-impacting upgrades.",
    ],
    "required_env": [
        "IRONCLAW_ENV",
        "IRONCLAW_BASE_URL",
        "SUPABASE_URL",
        "SUPABASE_SERVICE_ROLE_KEY",
    ],
    "preflight_checks": [
        "python -m scripts.verify",
        "python -m scripts.securityqualitygate",
        "python -m scripts.deploymentreadiness",
        "python -m scripts.smoketest --base-url http://127.0.0.1:8000",
    ],
    "upgrade_steps": [
        "Create backup snapshot.",
        "Validate environment configuration.",
        "Build updated container image.",
        "Apply deployment compose changes.",
        "Run readiness and smoke verification.",
    ],
    "rollback_steps": [
        "Stop failed rollout.",
        "Restore previous image and compose state.",
        "Run restore flow from latest verified backup if data regression is detected.",
        "Re-run smoke verification.",
    ],
}

RELEASE_POLICY_LATEST_DECISION_RESPONSE_EXAMPLE: Final[dict[str, Any]] = {
    "status": "ok",
    "decision": {
        "decision_id": "release-policy-production-20260427T220000Z",
        "channel": "production",
        "allowed": True,
        "requested_version": "1.0.0",
        "minimum_upgrade_from": "1.0.0",
        "decision_reason": "all release policy checks passed",
        "actor": "deployment-controller",
        "decided_at": "2026-04-27T22:00:00Z",
        "metadata": {
            "source": "release-policy-gate",
            "pipeline": "prod-rollout",
        },
    },
}

RELEASE_POLICY_LATEST_DECISION_EMPTY_RESPONSE_EXAMPLE: Final[dict[str, Any]] = {
    "status": "empty",
    "decision": None,
}

RELEASE_POLICY_OPENAPI_RESPONSES: Final[dict[int, dict[str, Any]]] = {
    200: {
        "description": "Release policy response returned successfully.",
        "content": {
            "application/json": {
                "examples": {
                    "list": {
                        "summary": "List release policies",
                        "value": RELEASE_POLICY_LIST_RESPONSE_EXAMPLE,
                    },
                    "detail": {
                        "summary": "Single release policy detail",
                        "value": RELEASE_POLICY_DETAIL_RESPONSE_EXAMPLE,
                    },
                    "latest-decision": {
                        "summary": "Latest release policy decision",
                        "value": RELEASE_POLICY_LATEST_DECISION_RESPONSE_EXAMPLE,
                    },
                    "latest-decision-empty": {
                        "summary": "No release policy decision recorded yet",
                        "value": RELEASE_POLICY_LATEST_DECISION_EMPTY_RESPONSE_EXAMPLE,
                    },
                }
            }
        },
    },
    404: {
        "description": "Requested release policy was not found.",
    },
}