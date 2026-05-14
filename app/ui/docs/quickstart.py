from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter(
    prefix="/ui/docs",
    tags=["docs-quickstart"],
)


class QuickstartStepView(BaseModel):
    stepid: str
    title: str
    description: str
    codeblock: str | None = None


class QuickstartSdkOptionView(BaseModel):
    sdkid: str
    name: str
    language: str
    installcommand: str
    samplecall: str


class QuickstartEndpointView(BaseModel):
    label: str
    method: str
    path: str
    description: str


class QuickstartChecklistItemView(BaseModel):
    itemid: str
    label: str
    completed: bool = False


class QuickstartPageResponse(BaseModel):
    generatedat: str
    environment: str
    headline: str
    intro: str
    baseurl: str
    apikeyheadername: str
    steps: list[QuickstartStepView] = Field(default_factory=list)
    sdkoptions: list[QuickstartSdkOptionView] = Field(default_factory=list)
    keyendpoints: list[QuickstartEndpointView] = Field(default_factory=list)
    checklist: list[QuickstartChecklistItemView] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


@router.get("/quickstart", response_model=QuickstartPageResponse)
def get_docs_quickstart() -> QuickstartPageResponse:
    steps = [
        QuickstartStepView(
            stepid="create-key",
            title="Create an API key",
            description="Generate a guarded runtime key from the organization admin surface before sending protected requests.",
            codeblock=("X-API-Key: ic_prod_your_generated_key\nUse a scoped key tied to the correct protected environment."),
        ),
        QuickstartStepView(
            stepid="first-guard-call",
            title="Send your first guarded execution request",
            description="Submit a protected action to IronClaw so policy, review, and boundary controls can evaluate it before runtime execution.",
            codeblock=('curl -X POST http://127.0.0.1:8000/guard/execute \\\n  -H "Content-Type: application/json" \\\n  -H "X-API-Key: ic_prod_your_generated_key" \\\n  -d \'{\n    "actiontype": "toolcall",\n    "target": "shell",\n    "riskscore": 82\n  }\''),
        ),
        QuickstartStepView(
            stepid="inspect-review",
            title="Check review and audit surfaces",
            description="Use the review queue and audit explorer endpoints to understand queued actions, denials, and policy outcomes.",
            codeblock=("GET /guard/reviews/pending\nGET /guard/audit/events\nGET /ui/audit/explorer"),
        ),
        QuickstartStepView(
            stepid="wire-policy",
            title="Tune your policy defaults",
            description="Inspect current policy status and align thresholds for review, quarantine, and hard block decisions.",
            codeblock=("GET /policy/status\nGET /ui/policy/settings"),
        ),
    ]

    sdkoptions = [
        QuickstartSdkOptionView(
            sdkid="curl",
            name="cURL",
            language="shell",
            installcommand="curl is preinstalled on most systems",
            samplecall=('curl -X POST http://127.0.0.1:8000/guard/action -H "Content-Type: application/json" -H "X-API-Key: ic_prod_your_generated_key" -d \'{"actiontype":"httpfetch","target":"https://example.com","riskscore":12}\''),
        ),
        QuickstartSdkOptionView(
            sdkid="python",
            name="Python",
            language="python",
            installcommand="pip install requests",
            samplecall=('import requests\n\nresponse = requests.post(\n    "http://127.0.0.1:8000/guard/action",\n    headers={"X-API-Key": "ic_prod_your_generated_key"},\n    json={"actiontype": "toolcall", "target": "filesystem", "riskscore": 67},\n)\nprint(response.json())'),
        ),
        QuickstartSdkOptionView(
            sdkid="javascript",
            name="JavaScript",
            language="javascript",
            installcommand="npm install undici",
            samplecall=(
                'import { request } from "undici";\n\n'
                'const response = await request("http://127.0.0.1:8000/guard/action", {\n'
                '  method: "POST",\n'
                "  headers: {\n"
                '    "content-type": "application/json",\n'
                '    "x-api-key": "ic_prod_your_generated_key"\n'
                "  },\n"
                '  body: JSON.stringify({ actiontype: "toolcall", target: "shell", riskscore: 91 })\n'
                "});"
            ),
        ),
    ]

    keyendpoints = [
        QuickstartEndpointView(
            label="Guard action",
            method="POST",
            path="/guard/action",
            description="Evaluate a proposed action against runtime policy before execution.",
        ),
        QuickstartEndpointView(
            label="Guard decision",
            method="POST",
            path="/guard/action-decision",
            description="Return a decision-focused guard response for orchestration logic.",
        ),
        QuickstartEndpointView(
            label="Guard execute",
            method="POST",
            path="/guard/execute",
            description="Submit a guarded runtime execution request with policy-aware outcome handling.",
        ),
        QuickstartEndpointView(
            label="Pending reviews",
            method="GET",
            path="/guard/reviews/pending",
            description="List items waiting for manual analyst review.",
        ),
        QuickstartEndpointView(
            label="Audit events",
            method="GET",
            path="/guard/audit/events",
            description="Inspect recent policy, review, and runtime audit events.",
        ),
        QuickstartEndpointView(
            label="Policy status",
            method="GET",
            path="/policy/status",
            description="Read the currently active runtime policy settings.",
        ),
    ]

    checklist = [
        QuickstartChecklistItemView(
            itemid="provision-org",
            label="Provision an organization and protected environment",
            completed=True,
        ),
        QuickstartChecklistItemView(
            itemid="generate-key",
            label="Generate a scoped API key for the target environment",
            completed=False,
        ),
        QuickstartChecklistItemView(
            itemid="send-guard-call",
            label="Send the first guarded action or execution request",
            completed=False,
        ),
        QuickstartChecklistItemView(
            itemid="verify-review-audit",
            label="Verify review queue and audit visibility after the first protected request",
            completed=False,
        ),
    ]

    return QuickstartPageResponse(
        generatedat=_utc_now(),
        environment="local",
        headline="Get IronClaw protection running in minutes.",
        intro=("This quickstart shows how to create a runtime key, send the first protected request, and inspect the review, audit, and policy surfaces that make IronClaw usable in production."),
        baseurl="http://127.0.0.1:8000",
        apikeyheadername="X-API-Key",
        steps=steps,
        sdkoptions=sdkoptions,
        keyendpoints=keyendpoints,
        checklist=checklist,
        notes=[
            "Docs quickstart exposes the minimum path from API key creation into first guarded execution and operational visibility.",
            "All values are placeholder UI contract data for the current local-first Gen1 build.",
            "This page is ready to be wired to live docs content, SDK snippets, and environment-aware endpoint discovery.",
        ],
    )
