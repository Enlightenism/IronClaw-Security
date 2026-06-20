from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter(
    prefix="/ui/auth",
    tags=["auth-login"],
)


class LoginFieldView(BaseModel):
    fieldkey: str
    label: str
    inputtype: str
    required: bool = True
    placeholder: str | None = None
    helptext: str | None = None


class LoginSecurityNoticeView(BaseModel):
    noticeid: str
    message: str
    severity: str


class LoginPageResponse(BaseModel):
    generatedat: str
    environment: str
    pageheadline: str
    pagesubtitle: str
    fields: list[LoginFieldView] = Field(default_factory=list)
    securitynotices: list[LoginSecurityNoticeView] = Field(default_factory=list)
    allowselfserve: bool
    signupurl: str
    forgotpasswordurl: str
    notes: list[str] = Field(default_factory=list)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


@router.get("/login", response_model=LoginPageResponse)
def get_login_page() -> LoginPageResponse:
    fields = [
        LoginFieldView(
            fieldkey="email",
            label="Work email",
            inputtype="email",
            placeholder="owner@company.com",
            helptext="Enter the email address for your IronClaw account.",
        ),
        LoginFieldView(
            fieldkey="password",
            label="Password",
            inputtype="password",
            placeholder="Your account password",
            helptext=None,
        ),
    ]

    securitynotices = [
        LoginSecurityNoticeView(
            noticeid="session-bound",
            message="Sessions are bound to this device. Shared sessions are not permitted.",
            severity="info",
        ),
        LoginSecurityNoticeView(
            noticeid="audit-logged",
            message="All login attempts are audit-logged regardless of outcome.",
            severity="info",
        ),
    ]

    return LoginPageResponse(
        generatedat=_utc_now(),
        environment="local",
        pageheadline="Sign in to IronClaw.",
        pagesubtitle=("Access your protected workspace. All agent actions, policy decisions, and runtime events are guarded and auditable."),
        fields=fields,
        securitynotices=securitynotices,
        allowselfserve=True,
        signupurl="/ui/auth/signup",
        forgotpasswordurl="/ui/auth/forgot-password",
        notes=[
            "Login page exposes the UI contract for the IronClaw authentication entry point.",
            "All values are placeholder UI contract data for the current local-first Gen1 build.",
            "This page is ready to be wired to live Supabase auth, session management, and MFA flows.",
        ],
    )
