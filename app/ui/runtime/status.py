from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter
from pydantic import BaseModel

from app.config import (
    RISK_THRESHOLD_ALLOW_MAX,
    RISK_THRESHOLD_BLOCK_MIN,
    RISK_THRESHOLD_QUARANTINE_MIN,
)

router = APIRouter(
    prefix="/ui/runtime",
    tags=["runtime-status"],
)


class RuntimeHealthView(BaseModel):
    status: str
    pipelineavailable: bool
    boundaryavailable: bool
    reviewqueueenabled: bool
    realexecutionenabled: bool


class BoundaryThresholdView(BaseModel):
    allowmaxriskscore: int
    reviewminriskscore: int
    reviewmaxriskscore: int
    blockminriskscore: int


class ActiveExecutorView(BaseModel):
    executorname: str
    fallbackexecutorname: str | None = None
    defaultmode: str
    sandboxrequired: bool
    mode: str


class RuntimeMetricsView(BaseModel):
    totalevents: int
    totalrequests: int
    allowcount: int
    reviewcount: int
    blockedcount: int
    quarantinecount: int
    latesteventat: str | None = None


class RuntimePolicyView(BaseModel):
    policymode: str
    defaultaction: Literal["allow", "block"]


class RuntimeStatusResponse(BaseModel):
    generatedat: str
    runtime: RuntimeHealthView
    thresholds: BoundaryThresholdView
    runtimeavailable: bool
    boundaryactive: bool
    reviewqueueenabled: bool
    executor: ActiveExecutorView
    metrics: RuntimeMetricsView
    policy: RuntimePolicyView
    defaultfilepath: str
    notes: list[str]


@router.get("/status", response_model=RuntimeStatusResponse)
def get_runtime_status() -> RuntimeStatusResponse:
    runtime = RuntimeHealthView(
        status="healthy",
        pipelineavailable=True,
        boundaryavailable=True,
        reviewqueueenabled=True,
        realexecutionenabled=False,
    )

    return RuntimeStatusResponse(
        generatedat=datetime.now(UTC).isoformat(),
        runtime=runtime,
        thresholds=BoundaryThresholdView(
            allowmaxriskscore=RISK_THRESHOLD_ALLOW_MAX,
            reviewminriskscore=RISK_THRESHOLD_QUARANTINE_MIN,
            reviewmaxriskscore=max(RISK_THRESHOLD_ALLOW_MAX, RISK_THRESHOLD_BLOCK_MIN - 1),
            blockminriskscore=RISK_THRESHOLD_BLOCK_MIN,
        ),
        runtimeavailable=runtime.pipelineavailable,
        boundaryactive=runtime.boundaryavailable,
        reviewqueueenabled=runtime.reviewqueueenabled,
        executor=ActiveExecutorView(
            executorname="dryrunexecutor",
            fallbackexecutorname="dryrunexecutor",
            defaultmode="dryrun",
            sandboxrequired=True,
            mode="dryrun",
        ),
        metrics=RuntimeMetricsView(
            totalevents=0,
            totalrequests=0,
            allowcount=0,
            reviewcount=0,
            blockedcount=0,
            quarantinecount=0,
            latesteventat=None,
        ),
        policy=RuntimePolicyView(
            policymode="dryrun",
            defaultaction="block",
        ),
        defaultfilepath="app/api/actionexecute.py",
        notes=[
            "Guarded execution pipeline is available.",
            "Runtime boundary is enforcing dry-run execution for safe requests.",
            "High-risk actions remain halted before executor invocation.",
            "Runtime metrics block is present and ready for future live wiring.",
        ],
    )
