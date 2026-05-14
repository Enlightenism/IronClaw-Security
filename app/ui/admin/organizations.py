from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime

from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter(
    prefix="/ui/admin",
    tags=["admin-organizations"],
)


class OrganizationKpiView(BaseModel):
    label: str
    value: int
    trendlabel: str | None = None
    status: str = "neutral"


class OrganizationPlanCount(BaseModel):
    plan: str
    count: int


class OrganizationStatusCount(BaseModel):
    status: str
    count: int


class OrganizationMemberView(BaseModel):
    userid: str
    email: str
    displayname: str
    role: str
    status: str
    lastseenat: str | None = None


class OrganizationApiKeyView(BaseModel):
    keyid: str
    label: str
    prefix: str
    status: str
    createdat: str
    lastusedat: str | None = None
    scopelabels: list[str] = Field(default_factory=list)


class OrganizationEnvironmentView(BaseModel):
    environmentid: str
    name: str
    region: str
    status: str
    policyname: str
    activekeycount: int
    lastactivityat: str | None = None


class OrganizationView(BaseModel):
    organizationid: str
    name: str
    slug: str
    status: str
    plan: str
    seatcount: int
    monthlyexecutionlimit: int
    monthlyreviewlimit: int
    monthlyalertlimit: int
    createdat: str
    owneremail: str
    environments: list[OrganizationEnvironmentView] = Field(default_factory=list)
    members: list[OrganizationMemberView] = Field(default_factory=list)
    apikeys: list[OrganizationApiKeyView] = Field(default_factory=list)


class OrganizationRecentActivityView(BaseModel):
    activityid: str
    timestamp: str
    organizationid: str
    category: str
    actor: str
    summary: str


class OrganizationsOverviewResponse(BaseModel):
    generatedat: str
    environment: str
    overallstatus: str
    kpis: list[OrganizationKpiView] = Field(default_factory=list)
    plancounts: list[OrganizationPlanCount] = Field(default_factory=list)
    statuscounts: list[OrganizationStatusCount] = Field(default_factory=list)
    organizations: list[OrganizationView] = Field(default_factory=list)
    recentactivity: list[OrganizationRecentActivityView] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


def _utc_iso(year: int, month: int, day: int, hour: int, minute: int = 0) -> str:
    return datetime(year, month, day, hour, minute, 0, tzinfo=UTC).isoformat()


def _sample_organizations() -> list[OrganizationView]:
    return [
        OrganizationView(
            organizationid="org-001",
            name="Alpha Security Lab",
            slug="alpha-security-lab",
            status="active",
            plan="pro",
            seatcount=8,
            monthlyexecutionlimit=50000,
            monthlyreviewlimit=5000,
            monthlyalertlimit=10000,
            createdat=_utc_iso(2026, 4, 10, 9, 0),
            owneremail="owner@alpha.example",
            environments=[
                OrganizationEnvironmentView(
                    environmentid="env-001",
                    name="production",
                    region="us-central",
                    status="active",
                    policyname="IronClaw-Security Runtime Policy",
                    activekeycount=3,
                    lastactivityat=_utc_iso(2026, 4, 18, 13, 0),
                ),
                OrganizationEnvironmentView(
                    environmentid="env-002",
                    name="staging",
                    region="us-central",
                    status="active",
                    policyname="IronClaw-Security Runtime Policy",
                    activekeycount=1,
                    lastactivityat=_utc_iso(2026, 4, 18, 11, 15),
                ),
            ],
            members=[
                OrganizationMemberView(
                    userid="user-001",
                    email="owner@alpha.example",
                    displayname="Alpha Owner",
                    role="owner",
                    status="active",
                    lastseenat=_utc_iso(2026, 4, 18, 13, 5),
                ),
                OrganizationMemberView(
                    userid="user-002",
                    email="analyst@alpha.example",
                    displayname="Alpha Analyst",
                    role="analyst",
                    status="active",
                    lastseenat=_utc_iso(2026, 4, 18, 12, 40),
                ),
            ],
            apikeys=[
                OrganizationApiKeyView(
                    keyid="key-001",
                    label="Production Guard Key",
                    prefix="ic_prod_",
                    status="active",
                    createdat=_utc_iso(2026, 4, 10, 9, 15),
                    lastusedat=_utc_iso(2026, 4, 18, 13, 0),
                    scopelabels=["scan", "guard", "review-read"],
                ),
                OrganizationApiKeyView(
                    keyid="key-002",
                    label="Staging Guard Key",
                    prefix="ic_stage_",
                    status="active",
                    createdat=_utc_iso(2026, 4, 10, 9, 25),
                    lastusedat=_utc_iso(2026, 4, 18, 11, 15),
                    scopelabels=["scan", "guard"],
                ),
            ],
        ),
        OrganizationView(
            organizationid="org-002",
            name="Beta Runtime Defense",
            slug="beta-runtime-defense",
            status="trial",
            plan="starter",
            seatcount=3,
            monthlyexecutionlimit=10000,
            monthlyreviewlimit=1000,
            monthlyalertlimit=2500,
            createdat=_utc_iso(2026, 4, 12, 14, 20),
            owneremail="founder@beta.example",
            environments=[
                OrganizationEnvironmentView(
                    environmentid="env-003",
                    name="production",
                    region="us-east",
                    status="active",
                    policyname="IronClaw-Security Runtime Policy",
                    activekeycount=1,
                    lastactivityat=_utc_iso(2026, 4, 18, 10, 25),
                ),
            ],
            members=[
                OrganizationMemberView(
                    userid="user-003",
                    email="founder@beta.example",
                    displayname="Beta Founder",
                    role="owner",
                    status="active",
                    lastseenat=_utc_iso(2026, 4, 18, 10, 30),
                ),
            ],
            apikeys=[
                OrganizationApiKeyView(
                    keyid="key-003",
                    label="Beta Production Key",
                    prefix="ic_beta_",
                    status="active",
                    createdat=_utc_iso(2026, 4, 12, 14, 30),
                    lastusedat=_utc_iso(2026, 4, 18, 10, 25),
                    scopelabels=["scan", "guard"],
                ),
            ],
        ),
        OrganizationView(
            organizationid="org-003",
            name="Gamma Internal QA",
            slug="gamma-internal-qa",
            status="suspended",
            plan="enterprise",
            seatcount=12,
            monthlyexecutionlimit=250000,
            monthlyreviewlimit=25000,
            monthlyalertlimit=50000,
            createdat=_utc_iso(2026, 4, 8, 8, 45),
            owneremail="admin@gamma.example",
            environments=[
                OrganizationEnvironmentView(
                    environmentid="env-004",
                    name="sandbox",
                    region="local",
                    status="paused",
                    policyname="IronClaw-Security Runtime Policy",
                    activekeycount=0,
                    lastactivityat=_utc_iso(2026, 4, 17, 18, 0),
                ),
            ],
            members=[
                OrganizationMemberView(
                    userid="user-004",
                    email="admin@gamma.example",
                    displayname="Gamma Admin",
                    role="admin",
                    status="active",
                    lastseenat=_utc_iso(2026, 4, 17, 18, 10),
                ),
                OrganizationMemberView(
                    userid="user-005",
                    email="viewer@gamma.example",
                    displayname="Gamma Viewer",
                    role="viewer",
                    status="invited",
                    lastseenat=None,
                ),
            ],
            apikeys=[
                OrganizationApiKeyView(
                    keyid="key-004",
                    label="Legacy Sandbox Key",
                    prefix="ic_legacy_",
                    status="revoked",
                    createdat=_utc_iso(2026, 4, 8, 9, 0),
                    lastusedat=_utc_iso(2026, 4, 16, 16, 20),
                    scopelabels=["scan"],
                ),
            ],
        ),
    ]


def _sample_recent_activity() -> list[OrganizationRecentActivityView]:
    return [
        OrganizationRecentActivityView(
            activityid="org-activity-001",
            timestamp=_utc_iso(2026, 4, 18, 13, 5),
            organizationid="org-001",
            category="apikey",
            actor="Alpha Owner",
            summary="Rotated production guard key after high-risk execution review.",
        ),
        OrganizationRecentActivityView(
            activityid="org-activity-002",
            timestamp=_utc_iso(2026, 4, 18, 12, 15),
            organizationid="org-002",
            category="member",
            actor="Beta Founder",
            summary="Invited first analyst seat during trial onboarding.",
        ),
        OrganizationRecentActivityView(
            activityid="org-activity-003",
            timestamp=_utc_iso(2026, 4, 17, 18, 5),
            organizationid="org-003",
            category="environment",
            actor="Gamma Admin",
            summary="Paused sandbox environment pending policy updates.",
        ),
    ]


def _build_plan_counts(organizations: list[OrganizationView]) -> list[OrganizationPlanCount]:
    counts = Counter(organization.plan for organization in organizations)
    return [OrganizationPlanCount(plan=plan, count=count) for plan, count in sorted(counts.items())]


def _build_status_counts(organizations: list[OrganizationView]) -> list[OrganizationStatusCount]:
    counts = Counter(organization.status for organization in organizations)
    return [OrganizationStatusCount(status=status, count=count) for status, count in sorted(counts.items())]


@router.get("/organizations", response_model=OrganizationsOverviewResponse)
def get_organizations_overview() -> OrganizationsOverviewResponse:
    organizations = _sample_organizations()
    recentactivity = _sample_recent_activity()

    totalorganizations = len(organizations)
    activeorganizations = sum(1 for organization in organizations if organization.status == "active")
    trialorganizations = sum(1 for organization in organizations if organization.status == "trial")
    suspendedorganizations = sum(1 for organization in organizations if organization.status == "suspended")
    totalapikeys = sum(len(organization.apikeys) for organization in organizations)

    kpis = [
        OrganizationKpiView(
            label="totalorganizations",
            value=totalorganizations,
            trendlabel="Organizations currently provisioned",
            status="healthy" if totalorganizations > 0 else "warning",
        ),
        OrganizationKpiView(
            label="activeorganizations",
            value=activeorganizations,
            trendlabel="Organizations actively using IronClaw",
            status="healthy" if activeorganizations > 0 else "warning",
        ),
        OrganizationKpiView(
            label="trialorganizations",
            value=trialorganizations,
            trendlabel="Trials available for conversion into paid plans",
            status="warning" if trialorganizations > 0 else "healthy",
        ),
        OrganizationKpiView(
            label="activeapikeys",
            value=totalapikeys,
            trendlabel="Provisioned organization keys across environments",
            status="healthy" if totalapikeys > 0 else "warning",
        ),
    ]

    overallstatus = "healthy"
    if suspendedorganizations > 0:
        overallstatus = "attention"

    return OrganizationsOverviewResponse(
        generatedat=datetime.now(UTC).isoformat(),
        environment="local",
        overallstatus=overallstatus,
        kpis=kpis,
        plancounts=_build_plan_counts(organizations),
        statuscounts=_build_status_counts(organizations),
        organizations=organizations,
        recentactivity=recentactivity,
        notes=[
            "Organization admin overview exposes tenants, members, API keys, and environment-level runtime ownership.",
            "All values are placeholder UI contract data for the current local-first Gen1 build.",
            "This page is ready to be wired to live auth, tenant management, API key rotation, and plan enforcement services.",
        ],
    )
