from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.ui.groq.prompt_guard_metrics import build_prompt_guard_metrics_view
from app.ui.groq.prompt_guard_policy import build_prompt_guard_policy_view

router = APIRouter(
    prefix="/ui/groq",
    tags=["groq-prompt-guard-recommendations"],
)


RecommendationPriority = Literal["low", "medium", "high", "critical"]
RecommendationType = Literal[
    "policy_tuning",
    "review_queue",
    "allowlist_hygiene",
    "audit_visibility",
    "operator_workflow",
]


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(slots=True)
class PromptGuardRecommendation:
    id: str
    title: str
    description: str
    recommendation_type: RecommendationType
    priority: RecommendationPriority
    rationale: str
    suggested_action: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "recommendation_type": self.recommendation_type,
            "priority": self.priority,
            "rationale": self.rationale,
            "suggested_action": self.suggested_action,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class PromptGuardRecommendationsView:
    title: str
    generated_at: str
    items: list[PromptGuardRecommendation]
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "generated_at": self.generated_at,
            "items": [item.to_dict() for item in self.items],
            "metadata": dict(self.metadata),
        }


class PromptGuardRecommendationView(BaseModel):
    id: str
    title: str
    description: str
    recommendation_type: RecommendationType
    priority: RecommendationPriority
    rationale: str
    suggested_action: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class PromptGuardRecommendationsResponse(BaseModel):
    title: str
    generated_at: str
    items: list[PromptGuardRecommendationView]
    metadata: dict[str, Any] = Field(default_factory=dict)


def build_prompt_guard_recommendations_view() -> PromptGuardRecommendationsView:
    policy = build_prompt_guard_policy_view()
    metrics = build_prompt_guard_metrics_view()

    review_statuses = metrics.breakdowns.get("review_statuses", {})
    allowlist_statuses = metrics.breakdowns.get("allowlist_statuses", {})
    audit_event_types = metrics.breakdowns.get("audit_event_types", {})

    pending_reviews = int(review_statuses.get("pending", 0))
    active_allowlists = int(allowlist_statuses.get("active", 0))
    simulation_events = int(audit_event_types.get("simulation", 0))

    items: list[PromptGuardRecommendation] = []

    if policy.mode in ("disabled", "observe"):
        items.append(
            PromptGuardRecommendation(
                id="rec-1",
                title="Increase enforcement strength",
                description="Current prompt guard mode is not fully enforcing risky prompt decisions.",
                recommendation_type="policy_tuning",
                priority="critical" if policy.mode == "disabled" else "high",
                rationale=f"Policy mode is {policy.mode}, which lowers active protection for live prompts.",
                suggested_action="Move the prompt guard into assist or enforce mode after validation testing.",
                metadata={"policy_mode": policy.mode},
            )
        )

    if pending_reviews > 0:
        items.append(
            PromptGuardRecommendation(
                id="rec-2",
                title="Reduce pending review backlog",
                description="There are queued prompt guard cases waiting for operator review.",
                recommendation_type="review_queue",
                priority="high" if pending_reviews >= 5 else "medium",
                rationale=f"{pending_reviews} review item(s) are still pending, which can delay tuning decisions.",
                suggested_action="Triage pending review items and convert validated cases into policy updates or exceptions.",
                metadata={"pending_reviews": pending_reviews},
            )
        )

    if active_allowlists > 0:
        items.append(
            PromptGuardRecommendation(
                id="rec-3",
                title="Audit active allowlist scope",
                description="Active allowlist entries should stay narrow and time-bounded where possible.",
                recommendation_type="allowlist_hygiene",
                priority="medium",
                rationale=f"{active_allowlists} active allowlist entrie(s) are currently in effect.",
                suggested_action="Review each active allowlist entry for expiry, scope, and business justification.",
                metadata={"active_allowlists": active_allowlists},
            )
        )

    if simulation_events == 0:
        items.append(
            PromptGuardRecommendation(
                id="rec-4",
                title="Increase validation simulations",
                description="No simulation activity is visible in the audit trail.",
                recommendation_type="audit_visibility",
                priority="medium",
                rationale="Without simulation evidence, policy quality and operator confidence are harder to validate.",
                suggested_action="Run prompt guard simulation tests against expected safe and unsafe prompt patterns.",
                metadata={"simulation_events": simulation_events},
            )
        )

    if not items:
        items.append(
            PromptGuardRecommendation(
                id="rec-5",
                title="Maintain current guard posture",
                description="Prompt guard posture looks healthy based on current policy and operational signals.",
                recommendation_type="operator_workflow",
                priority="low",
                rationale="No immediate gaps were detected in policy mode, review queue, allowlist activity, or audit visibility.",
                suggested_action="Continue monitoring trends and keep policy reviews in the normal operating cadence.",
                metadata={},
            )
        )

    return PromptGuardRecommendationsView(
        title="Groq Prompt Guard Recommendations",
        generated_at=_utc_now(),
        items=items,
        metadata={
            "policy_mode": policy.mode,
            "policy_health": policy.health,
            "recommendation_count": len(items),
        },
    )


@router.get("/prompt-guard/recommendations", response_model=PromptGuardRecommendationsResponse)
def get_prompt_guard_recommendations() -> PromptGuardRecommendationsResponse:
    view = build_prompt_guard_recommendations_view()
    data = view.to_dict()

    return PromptGuardRecommendationsResponse(
        title=data["title"],
        generated_at=data["generated_at"],
        items=[PromptGuardRecommendationView(**item) for item in data["items"]],
        metadata=data["metadata"],
    )