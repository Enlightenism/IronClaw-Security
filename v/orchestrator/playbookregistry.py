from __future__ import annotations

from pydantic import BaseModel, Field


class PlaybookStep(BaseModel):
    order: int = Field(..., description="Execution order within the playbook")
    title: str = Field(..., description="Short operator-facing step title")
    description: str = Field(..., description="Detailed explanation of the step")
    automated: bool = Field(
        default=False,
        description="Whether the step is expected to be automated by orchestration",
    )
    owner: str = Field(
        ...,
        description="Owning role or subsystem (soc, runtime, remediationgate, analyst, etc.)",
    )


class PlaybookDefinition(BaseModel):
    slug: str = Field(..., description="Stable playbook identifier")
    name: str = Field(..., description="Human-readable playbook name")
    summary: str = Field(..., description="Short summary for UI and review workflows")
    severity: str = Field(..., description="Suggested severity bucket")
    tags: list[str] = Field(
        default_factory=list,
        description="Index tags for capability matching and filtering",
    )
    triggers: list[str] = Field(
        default_factory=list,
        description="Signal / cluster conditions that should suggest this playbook",
    )
    steps: list[PlaybookStep] = Field(
        default_factory=list,
        description="Ordered response steps",
    )


class PlaybookRegistry:
    """
    In-memory registry of default threat-response playbooks.

    Design goals:
    - Stable local-first defaults with no external dependency.
    - Simple lookup by slug for response coordinator / UI / review queue.
    - Clear, explainable steps that map to IronClaw enforcement and analyst workflows.
    """

    def __init__(self) -> None:
        self._playbooks: dict[str, PlaybookDefinition] = {}
        self._register_defaults()

    def list_playbooks(self) -> list[PlaybookDefinition]:
        return list(self._playbooks.values())

    def get(self, slug: str) -> PlaybookDefinition | None:
        return self._playbooks.get(slug)

    def has(self, slug: str) -> bool:
        return slug in self._playbooks

    def register(self, playbook: PlaybookDefinition) -> PlaybookDefinition:
        self._playbooks[playbook.slug] = playbook
        return playbook

    def _register_defaults(self) -> None:
        self.register(
            PlaybookDefinition(
                slug="security-signal-triage",
                name="Security Signal Triage",
                summary="Baseline analyst review workflow for medium-risk clustered signals.",
                severity="medium",
                tags=["triage", "review", "signals"],
                triggers=[
                    "cluster priority medium",
                    "queue_for_review recommendation",
                    "session risk medium",
                ],
                steps=[
                    PlaybookStep(
                        order=1,
                        title="Review signal summary",
                        description="Inspect the clustered signals, confidence, severity, and source systems.",
                        automated=False,
                        owner="analyst",
                    ),
                    PlaybookStep(
                        order=2,
                        title="Validate session and actor scope",
                        description="Confirm which session, actor, and integration boundaries are affected.",
                        automated=False,
                        owner="soc",
                    ),
                    PlaybookStep(
                        order=3,
                        title="Apply temporary monitoring controls",
                        description="Increase telemetry capture and preserve evidence while investigation continues.",
                        automated=True,
                        owner="runtime",
                    ),
                ],
            )
        )

        self.register(
            PlaybookDefinition(
                slug="prompt-injection-incident-response",
                name="Prompt Injection Incident Response",
                summary="Contain prompt-injection attempts and route impacted sessions for investigation.",
                severity="high",
                tags=["prompt-injection", "containment", "review"],
                triggers=[
                    "prompt injection present in cluster",
                    "hostile context correlation",
                    "quarantine_and_review recommendation",
                ],
                steps=[
                    PlaybookStep(
                        order=1,
                        title="Freeze affected request context",
                        description="Preserve prompts, tool plans, execution traces, and relevant telemetry for audit.",
                        automated=True,
                        owner="runtime",
                    ),
                    PlaybookStep(
                        order=2,
                        title="Quarantine suspicious session",
                        description="Restrict high-risk session activity to prevent further prompt-driven escalation.",
                        automated=True,
                        owner="remediationgate",
                    ),
                    PlaybookStep(
                        order=3,
                        title="Analyst validation",
                        description="Determine whether the behavior is malicious, accidental, or policy-tunable.",
                        automated=False,
                        owner="analyst",
                    ),
                ],
            )
        )

        self.register(
            PlaybookDefinition(
                slug="prompt-guard-hot-incident",
                name="Prompt Guard Hot Incident",
                summary="Fast response for high-confidence prompt-guard detections requiring immediate review.",
                severity="high",
                tags=["promptguard", "hot-incident", "review"],
                triggers=[
                    "review_and_rate_limit recommendation",
                    "high session risk",
                    "prompt injection dominant kind",
                ],
                steps=[
                    PlaybookStep(
                        order=1,
                        title="Apply step-up controls",
                        description="Tighten runtime controls, rate limits, and tool permissions for the session.",
                        automated=True,
                        owner="runtime",
                    ),
                    PlaybookStep(
                        order=2,
                        title="Queue priority review",
                        description="Send the case to the review queue with incident context and supporting telemetry.",
                        automated=True,
                        owner="reviewqueue",
                    ),
                    PlaybookStep(
                        order=3,
                        title="Evaluate spread",
                        description="Check whether the same actor, session family, or integration shows similar behavior.",
                        automated=False,
                        owner="soc",
                    ),
                ],
            )
        )

        self.register(
            PlaybookDefinition(
                slug="malware-sandbox-review",
                name="Malware Sandbox Review",
                summary="Review detonation output, linked artifacts, and campaign indicators before escalation.",
                severity="high",
                tags=["malware", "sandbox", "detonation"],
                triggers=[
                    "malware detonation present in cluster",
                    "review_and_quarantine recommendation",
                ],
                steps=[
                    PlaybookStep(
                        order=1,
                        title="Collect detonation evidence",
                        description="Gather sandbox logs, extracted indicators, file metadata, and linked artifacts.",
                        automated=True,
                        owner="runtime",
                    ),
                    PlaybookStep(
                        order=2,
                        title="Restrict artifact reuse",
                        description="Prevent further execution, download, or propagation of the suspicious artifact set.",
                        automated=True,
                        owner="remediationgate",
                    ),
                    PlaybookStep(
                        order=3,
                        title="Analyst malware review",
                        description="Review detonation indicators, outbound behavior, and campaign overlap.",
                        automated=False,
                        owner="analyst",
                    ),
                ],
            )
        )

        self.register(
            PlaybookDefinition(
                slug="malware-data-exfiltration-response",
                name="Malware and Data Exfiltration Response",
                summary="Critical incident workflow for malware or exfiltration signals requiring immediate restriction.",
                severity="critical",
                tags=["malware", "exfiltration", "critical", "quarantine"],
                triggers=[
                    "critical cluster with malware",
                    "critical cluster with data exfiltration",
                    "quarantine_and_restrict recommendation",
                ],
                steps=[
                    PlaybookStep(
                        order=1,
                        title="Immediate containment",
                        description="Block or quarantine the affected session, artifact, or execution path immediately.",
                        automated=True,
                        owner="remediationgate",
                    ),
                    PlaybookStep(
                        order=2,
                        title="Escalate incident",
                        description="Create or update the incident and mark it for urgent analyst response.",
                        automated=True,
                        owner="incidentservice",
                    ),
                    PlaybookStep(
                        order=3,
                        title="Investigate blast radius",
                        description="Trace linked sessions, actors, integrations, and artifacts for spread or exposure.",
                        automated=False,
                        owner="soc",
                    ),
                    PlaybookStep(
                        order=4,
                        title="Remediation follow-up",
                        description="Apply cleanup, credential rotation, and policy hardening as indicated by findings.",
                        automated=False,
                        owner="security-engineering",
                    ),
                ],
            )
        )

        self.register(
            PlaybookDefinition(
                slug="generic-critical-incident",
                name="Generic Critical Incident",
                summary="Fallback critical workflow when a cluster is severe but does not match a narrower playbook.",
                severity="critical",
                tags=["critical", "fallback", "incident"],
                triggers=[
                    "critical cluster",
                    "quarantine_and_review recommendation",
                ],
                steps=[
                    PlaybookStep(
                        order=1,
                        title="Contain affected execution scope",
                        description="Quarantine the risky scope while preserving evidence and minimizing spread.",
                        automated=True,
                        owner="remediationgate",
                    ),
                    PlaybookStep(
                        order=2,
                        title="Open urgent incident",
                        description="Create or update an incident record and route it for urgent review.",
                        automated=True,
                        owner="incidentservice",
                    ),
                    PlaybookStep(
                        order=3,
                        title="Operator investigation",
                        description="Review telemetry, correlation edges, and system context to determine next controls.",
                        automated=False,
                        owner="analyst",
                    ),
                ],
            )
        )

        self.register(
            PlaybookDefinition(
                slug="security-hot-incident",
                name="Security Hot Incident",
                summary="High-priority workflow for non-critical correlated security events needing rapid review.",
                severity="high",
                tags=["high", "incident", "review"],
                triggers=[
                    "review_and_rate_limit recommendation",
                    "cluster priority high",
                ],
                steps=[
                    PlaybookStep(
                        order=1,
                        title="Apply protective controls",
                        description="Reduce tool permissions, enforce stricter policy, or limit execution velocity.",
                        automated=True,
                        owner="runtime",
                    ),
                    PlaybookStep(
                        order=2,
                        title="Route for review",
                        description="Open or enrich the review item with cluster evidence and suggested playbook.",
                        automated=True,
                        owner="reviewqueue",
                    ),
                    PlaybookStep(
                        order=3,
                        title="Determine escalation need",
                        description="Decide whether the case should be upgraded to incident or quarantine status.",
                        automated=False,
                        owner="analyst",
                    ),
                ],
            )
        )