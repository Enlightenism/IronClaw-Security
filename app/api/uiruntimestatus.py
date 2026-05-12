from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict, Field

from app.core.auth import require_api_key
from app.ui.runtimestatus import get_runtime_status_page

router = APIRouter(tags=["runtime-status-page"])


class RuntimeExecutorStatus(BaseModel):
    model_config = ConfigDict(extra="forbid")

    executorname: str = Field(default="")
    fallbackexecutorname: str = Field(default="")
    defaultmode: str = Field(default="")
    sandboxrequired: bool = Field(default=False)


class RuntimeMetricsStatus(BaseModel):
    model_config = ConfigDict(extra="forbid")

    totalrequests: int = Field(default=0, ge=0)
    allowcount: int = Field(default=0, ge=0)
    reviewcount: int = Field(default=0, ge=0)
    blockedcount: int = Field(default=0, ge=0)
    quarantinecount: int = Field(default=0, ge=0)
    latesteventat: str | None = Field(default=None)


class RuntimePolicyStatus(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policymode: Literal["dryrun", "enforce", "lockdown"] = Field(default="dryrun")
    defaultaction: Literal["allow", "review", "block"] = Field(default="review")


class RuntimeStatusPageResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pageid: str
    title: str
    path: str
    summary: str
    generatedat: str
    runtimeavailable: bool
    boundaryactive: bool
    reviewqueueenabled: bool
    executor: RuntimeExecutorStatus
    metrics: RuntimeMetricsStatus
    policy: RuntimePolicyStatus
    defaultfilepath: str
    metadata: dict[str, Any] = Field(default_factory=dict)


@router.get(
    "/ui/runtime/status",
    response_model=RuntimeStatusPageResponse,
    summary="Get Runtime Status",
    dependencies=[Depends(require_api_key)],
)
def runtime_status_page() -> RuntimeStatusPageResponse:
    payload: dict[str, Any] = get_runtime_status_page()

    metrics: dict[str, Any] = dict(payload.get("metrics", {}))
    if "totalrequests" not in metrics:
        metrics["totalrequests"] = int(metrics.get("totalevents", 0) or 0)
    metrics.pop("totalevents", None)

    if not metrics.get("latesteventat"):
        metrics["latesteventat"] = None

    payload["metrics"] = metrics

    if "policy" not in payload or not isinstance(payload["policy"], dict):
        payload["policy"] = {
            "policymode": "dryrun",
            "defaultaction": "review",
        }

    return RuntimeStatusPageResponse.model_validate(payload)