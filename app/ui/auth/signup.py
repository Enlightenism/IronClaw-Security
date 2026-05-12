from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter(
    prefix="/ui/auth",
    tags=["auth-signup"],
)


class SignupStepView(BaseModel):
    stepid: str
    title: str
    description: str
    status: str


class SignupPlanOptionView(BaseModel):
    planid: str
    name: str
    monthlypricecents: int
    highlighted: bool = False
    tagline: str
    executionlimit: int
    reviewlimit: int
    alertlimit: int


class SignupFieldView(BaseModel):
    fieldkey: str
    label: str
    inputtype: str
    required: bool = True
    placeholder: str | None = None
    helptext: str | None = None
    value: str | None = None


class SignupChecklistItemView(BaseModel):
    itemid: str
    label: str
    completed: bool = False


class SignupSummaryView(BaseModel):
    selectedplanid: str
    organizationname: str
    workspaceurl: str
    estimatedtrialdays: int
    recommendednextaction: str


class SignupPageResponse(BaseModel):
    generatedat: str
    environment: str
    pageheadline: str
    pagesubtitle: str
    steps: list[SignupStepView] = Field(default_factory=list)
    planoptions: list[SignupPlanOptionView] = Field(default_factory=list)
    accountfields: list[SignupFieldView] = Field(default_factory=list)
    organizationfields: list[SignupFieldView] = Field(default_factory=list)
    securityfields: list[SignupFieldView] = Field(default_factory=list)
    checklist: list[SignupChecklistItemView] = Field(default_factory=list)
    summary: SignupSummaryView
    notes: list[str] = Field(default_factory=list)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


@router.get("/signup", response_model=SignupPageResponse)
def get_signup_page() -> SignupPageResponse:
    steps = [
        SignupStepView(
            stepid="account",
            title="Create account",
            description="Register the initial owner account for your protected workspace.",
            status="current",
        ),
        SignupStepView(
            stepid="organization",
            title="Create organization",
            description="Name your workspace and choose the first protected environment.",
            status="upcoming",
        ),
        SignupStepView(
            stepid="security",
            title="Set guard defaults",
            description="Pick the starting runtime protection mode and review posture.",
            status="upcoming",
        ),
        SignupStepView(
            stepid="activate",
            title="Activate trial",
            description="Generate the first API key and begin guarded execution.",
            status="upcoming",
        ),
    ]

    planoptions = [
        SignupPlanOptionView(
            planid="starter",
            name="Starter",
            monthlypricecents=9900,
            highlighted=False,
            tagline="For solo builders and small product teams.",
            executionlimit=10000,
            reviewlimit=1000,
            alertlimit=2500,
        ),
        SignupPlanOptionView(
            planid="pro",
            name="Pro",
            monthlypricecents=29900,
            highlighted=True,
            tagline="Best for production teams protecting live AI systems.",
            executionlimit=50000,
            reviewlimit=5000,
            alertlimit=10000,
        ),
        SignupPlanOptionView(
            planid="enterprise",
            name="Enterprise",
            monthlypricecents=149900,
            highlighted=False,
            tagline="For large-scale protected operations with advanced control needs.",
            executionlimit=250000,
            reviewlimit=25000,
            alertlimit=50000,
        ),
    ]

    accountfields = [
        SignupFieldView(
            fieldkey="email",
            label="Work email",
            inputtype="email",
            placeholder="founder@company.com",
            helptext="This becomes the initial owner login.",
        ),
        SignupFieldView(
            fieldkey="password",
            label="Password",
            inputtype="password",
            placeholder="Create a strong password",
            helptext="Use a unique password for the organization owner account.",
        ),
        SignupFieldView(
            fieldkey="displayname",
            label="Full name",
            inputtype="text",
            placeholder="Jesse Example",
            helptext="Shown in review actions and audit history.",
        ),
    ]

    organizationfields = [
        SignupFieldView(
            fieldkey="organizationname",
            label="Organization name",
            inputtype="text",
            placeholder="IronClaw Protected Runtime",
            helptext="Displayed across billing, admin, and environment pages.",
            value="Alpha Security Lab",
        ),
        SignupFieldView(
            fieldkey="workspaceurl",
            label="Workspace slug",
            inputtype="text",
            placeholder="alpha-security-lab",
            helptext="Used as the base slug for your protected workspace.",
            value="alpha-security-lab",
        ),
        SignupFieldView(
            fieldkey="environmentname",
            label="First environment",
            inputtype="text",
            placeholder="production",
            helptext="Create the first guarded environment for onboarding.",
            value="production",
        ),
    ]

    securityfields = [
        SignupFieldView(
            fieldkey="policymode",
            label="Default policy mode",
            inputtype="select",
            placeholder="review",
            helptext="Review mode is the recommended safe starting point.",
            value="review",
        ),
        SignupFieldView(
            fieldkey="reviewemail",
            label="Review notification email",
            inputtype="email",
            placeholder="security@company.com",
            helptext="Receive alerts when new items enter manual review.",
        ),
        SignupFieldView(
            fieldkey="apikeylabel",
            label="Initial API key label",
            inputtype="text",
            placeholder="Production Guard Key",
            helptext="Name the first runtime key generated during onboarding.",
            value="Production Guard Key",
        ),
    ]

    checklist = [
        SignupChecklistItemView(
            itemid="choose-plan",
            label="Choose a plan aligned to expected execution volume",
            completed=True,
        ),
        SignupChecklistItemView(
            itemid="create-owner",
            label="Create the initial organization owner account",
            completed=False,
        ),
        SignupChecklistItemView(
            itemid="configure-policy",
            label="Set default policy mode and review routing",
            completed=False,
        ),
        SignupChecklistItemView(
            itemid="generate-key",
            label="Generate the first guarded runtime API key",
            completed=False,
        ),
    ]

    summary = SignupSummaryView(
        selectedplanid="pro",
        organizationname="Alpha Security Lab",
        workspaceurl="alpha-security-lab",
        estimatedtrialdays=14,
        recommendednextaction="Create the owner account and generate the first production guard key.",
    )

    return SignupPageResponse(
        generatedat=_utc_now(),
        environment="local",
        pageheadline="Start your protected IronClaw workspace.",
        pagesubtitle=(
            "Create the first organization, choose a plan, and generate the initial runtime guard "
            "configuration for safe AI execution."
        ),
        steps=steps,
        planoptions=planoptions,
        accountfields=accountfields,
        organizationfields=organizationfields,
        securityfields=securityfields,
        checklist=checklist,
        summary=summary,
        notes=[
            "Signup onboarding exposes the self-serve path from first account creation into protected runtime activation.",
            "All values are placeholder UI contract data for the current local-first Gen1 build.",
            "This page is ready to be wired to live auth, workspace provisioning, API key generation, and trial activation flows.",
        ],
    )