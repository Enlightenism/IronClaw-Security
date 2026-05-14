from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(
    prefix="/ui/settings",
    tags=["settings-configuration"],
)


class RuntimeConfigurationView(BaseModel):
    defaultfilepath: str
    defaultresponsestatus: str
    allowdryrun: bool
    allowreviewqueue: bool
    halt_high_risk: bool
    review_min_riskscore: int
    block_min_riskscore: int


class ExecutorConfigurationView(BaseModel):
    defaultexecutorname: str
    fallbackexecutorname: str
    realexecutionenabled: bool
    sandboxrequired: bool


class PolicyConfigurationView(BaseModel):
    policymode: str
    strictmodeenabled: bool
    quarantineenabled: bool
    maxriskscore: int


class SettingsConfigurationResponse(BaseModel):
    generatedat: str
    runtime: RuntimeConfigurationView
    executor: ExecutorConfigurationView
    policy: PolicyConfigurationView
    activeenvironment: str | None = None


@router.get("/configuration", response_model=SettingsConfigurationResponse)
def get_settings_configuration() -> SettingsConfigurationResponse:
    return SettingsConfigurationResponse(
        generatedat=datetime.now(UTC).isoformat(),
        runtime=RuntimeConfigurationView(
            defaultfilepath="app/api/actionexecute.py",
            defaultresponsestatus="completed",
            allowdryrun=True,
            allowreviewqueue=True,
            halt_high_risk=True,
            review_min_riskscore=50,
            block_min_riskscore=90,
        ),
        executor=ExecutorConfigurationView(
            defaultexecutorname="dryrunexecutor",
            fallbackexecutorname="dryrunexecutor",
            realexecutionenabled=False,
            sandboxrequired=True,
        ),
        policy=PolicyConfigurationView(
            policymode="strict",
            strictmodeenabled=True,
            quarantineenabled=True,
            maxriskscore=100,
        ),
        activeenvironment="local",
    )
