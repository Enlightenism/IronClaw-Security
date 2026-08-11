from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

# ---------------------------------------------------------------------------
# Enumerations — single source of truth for all threat detection contracts
# ---------------------------------------------------------------------------


class DetectionVerdict(StrEnum):
    ALLOW = "allow"
    MONITOR = "monitor"
    REVIEW = "review"
    BLOCK = "block"


class ThreatSeverityLevel(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IOCTypeEnum(StrEnum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    SHA256 = "sha256"
    SHA1 = "sha1"
    MD5 = "md5"
    CVE = "cve"
    MITRE_TECHNIQUE = "mitre_technique"
    MITRE_TACTIC = "mitre_tactic"
    EMAIL = "email"
    UNKNOWN = "unknown"


class ThreatFeedSourceEnum(StrEnum):
    MITRE_ATTACK = "mitre_attack"
    CISA_KEV = "cisa_kev"
    CUSTOM_IOC = "custom_ioc"
    STIX_TAXII = "stix_taxii"
    INTERNAL = "internal"


class IngestStatusEnum(StrEnum):
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    SKIPPED = "skipped"


class AlertSeverityEnum(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class HuntStatusEnum(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


# ---------------------------------------------------------------------------
# DetectionRequest — POST /threat/detect
# ---------------------------------------------------------------------------


class DetectionRequest(BaseModel):
    """Unified detection request accepted by the threat detection engine."""

    model_config = {"extra": "forbid"}

    event_id: str | None = Field(
        default=None,
        description="Caller-supplied event identifier for correlation. Generated if omitted.",
    )
    org_id: str | None = Field(
        default=None,
        description="Organization scope for IOC and policy resolution.",
    )
    agent_id: str | None = Field(
        default=None,
        description="Originating agentic system identifier.",
    )
    session_id: str | None = Field(
        default=None,
        description="Session context for multi-event correlation.",
    )
    text: str | None = Field(
        default=None,
        description="Raw text payload to scan for IOC matches and keyword patterns.",
    )
    url: str | None = Field(
        default=None,
        description="URL artifact to assess.",
    )
    domain: str | None = Field(
        default=None,
        description="Domain artifact to assess.",
    )
    hashes: list[str] | None = Field(
        default=None,
        description="File hash artifacts to assess (MD5, SHA1, SHA256).",
    )
    ioc_values: list[str] | None = Field(
        default=None,
        description="Explicit IOC values to match directly against the store.",
    )
    context: str | None = Field(
        default=None,
        description="Human-readable label for the detection context (e.g. 'tool_call', 'prompt_input').",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Caller-supplied key/value metadata attached to the detection event.",
    )
    minimum_confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Minimum IOC confidence threshold. Matches below this floor are ignored.",
    )

    @model_validator(mode="after")
    def require_at_least_one_observable(self) -> DetectionRequest:
        has_payload = any(
            [
                self.text,
                self.url,
                self.domain,
                self.hashes,
                self.ioc_values,
            ]
        )
        if not has_payload:
            raise ValueError("DetectionRequest requires at least one of: text, url, domain, hashes, ioc_values.")
        return self


# ---------------------------------------------------------------------------
# IOCMatch — embedded in DetectionResult
# ---------------------------------------------------------------------------


class IOCMatch(BaseModel):
    """A single IOC that matched during detection."""

    model_config = {"extra": "ignore"}

    ioc_id: str | None = Field(default=None, description="Store-assigned IOC identifier.")
    value: str
    ioc_type: str
    confidence: float = Field(ge=0.0, le=1.0)
    severity: str
    source: str
    tags: list[str] = Field(default_factory=list)
    matched_on: str | None = Field(
        default=None,
        description="Field or context in which this IOC was matched.",
    )
    mitre_technique_id: str | None = None
    mitre_tactic: str | None = None
    # Explicit list fields so downstream aggregation can read collections directly
    mitre_technique_ids: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    cve_id: str | None = None
    reference: str | None = None
    first_seen: str | None = None
    last_seen: str | None = None


# ---------------------------------------------------------------------------
# CorrelationSignal — embedded in DetectionResult
# ---------------------------------------------------------------------------


class CorrelationSignal(BaseModel):
    """Represents a pattern or event chain surfaced by the correlation engine."""

    model_config = {"extra": "ignore"}

    signal_id: str
    pattern_type: str = Field(
        description="e.g. 'multi_ioc_cooccurrence', 'attack_chain', 'temporal_cluster'",
    )
    # signal_type is an alias-style field maintained for backward compatibility with consumers/tests
    signal_type: str | None = Field(default=None)
    matched_event_ids: list[str] = Field(default_factory=list)
    contributing_ioc_ids: list[str] = Field(default_factory=list)
    mitre_technique_ids: list[str] = Field(default_factory=list)
    # Added explicit list for mitre_techniques to match engine expectations
    mitre_techniques: list[str] = Field(default_factory=list)
    # Added singular field to accept mitre_technique_id directly from tests/builders
    mitre_technique_id: str | None = None
    confidence: float = Field(ge=0.0, le=1.0)
    score_contribution: float = Field(ge=0.0, le=1.0)
    description: str = ""

    @model_validator(mode="after")
    def ensure_signal_and_pattern_aliases(self) -> CorrelationSignal:
        """
        Keep pattern_type and signal_type aligned:

        - If signal_type is missing/None/empty, set it to the value of pattern_type.
        - If pattern_type is missing/empty, but signal_type provided, set pattern_type to signal_type.
        This maintains the legacy alias behavior expected by tests and other consumers.
        """
        pt = (self.pattern_type or "").strip()
        st = (self.signal_type or "").strip()

        if not pt and st:
            # pattern_type empty but signal_type provided -> adopt signal_type
            self.pattern_type = st
        elif not st and pt:
            # signal_type missing -> adopt pattern_type
            self.signal_type = pt
        # ensure both attributes are consistent (lowercase normalization expected by engine)
        if isinstance(self.pattern_type, str):
            self.pattern_type = self.pattern_type.lower()
        if isinstance(self.signal_type, str):
            self.signal_type = self.signal_type.lower()
        return self


# ---------------------------------------------------------------------------
# DetectionResult — response from POST /threat/detect
# ---------------------------------------------------------------------------


class DetectionResult(BaseModel):
    """
    Structured result returned by the threat detection engine.
    Consumed by: threat_alerts, action_guard, actionguard, incidents.
    """

    model_config = {"extra": "ignore"}

    event_id: str
    org_id: str | None = None
    agent_id: str | None = None
    session_id: str | None = None
    verdict: DetectionVerdict
    score: float = Field(ge=0.0, le=1.0, description="Normalized 0.0–1.0 composite threat score.")
    severity: ThreatSeverityLevel
    scanned_text: str | None = Field(
        default=None,
        description="The raw text payload that was scanned. Echoed back for traceability.",
    )
    ioc_matches: list[IOCMatch] = Field(default_factory=list)
    correlation_signals: list[CorrelationSignal] = Field(default_factory=list)
    risk_families: list[str] = Field(default_factory=list)
    extracted_indicators: list[str] = Field(default_factory=list)
    rationale: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    context: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    assessed_at: str = Field(description="ISO 8601 UTC timestamp of detection.")
    detection_engine_version: str = Field(default="1.0.0")

    @property
    def is_threat(self) -> bool:
        return self.verdict in (DetectionVerdict.REVIEW, DetectionVerdict.BLOCK)

    @property
    def requires_block(self) -> bool:
        return self.verdict == DetectionVerdict.BLOCK

    @property
    def top_ioc(self) -> IOCMatch | None:
        """Returns the highest-confidence IOC match, or None if no matches."""
        if not self.ioc_matches:
            return None
        return max(self.ioc_matches, key=lambda m: m.confidence)

    @property
    def ioc_match_count(self) -> int:
        return len(self.ioc_matches)

    @property
    def correlation_signal_count(self) -> int:
        return len(self.correlation_signals)


# ---------------------------------------------------------------------------
# ThreatAlert — emitted by threat_alerts router / escalation bridge
# ---------------------------------------------------------------------------


class ThreatAlert(BaseModel):
    """
    Structured alert emitted when a DetectionResult verdict is REVIEW or BLOCK.
    Bridges into incidents.py and notifications.py.
    """

    model_config = {"extra": "ignore"}

    alert_id: str
    event_id: str
    org_id: str | None = None
    agent_id: str | None = None
    session_id: str | None = None
    verdict: DetectionVerdict
    severity: AlertSeverityEnum
    score: float = Field(ge=0.0, le=1.0)
    title: str
    description: str = ""
    ioc_matches: list[IOCMatch] = Field(default_factory=list)
    correlation_signals: list[CorrelationSignal] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    risk_families: list[str] = Field(default_factory=list)
    suppressed: bool = Field(
        default=False,
        description="True if this alert was deduplicated within the suppression window.",
    )
    suppression_reason: str | None = None
    incident_id: str | None = Field(
        default=None,
        description="Set after escalation to incidents.py.",
    )
    created_at: str
    metadata: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# HuntQuery — POST /threat/hunt
# ---------------------------------------------------------------------------


class HuntQuery(BaseModel):
    """
    Retrospective threat hunt query submitted to threat_hunt_service.
    Supports IOC sweep, MITRE technique sweep, and temporal cluster queries.
    """

    model_config = {"extra": "forbid"}

    hunt_id: str | None = Field(
        default=None,
        description="Caller-supplied hunt identifier. Generated if omitted.",
    )
    org_id: str | None = None
    ioc_value: str | None = Field(
        default=None,
        description="Exact IOC value to sweep across stored detection history.",
    )
    ioc_type: IOCTypeEnum | None = None
    mitre_technique_id: str | None = Field(
        default=None,
        description="MITRE ATT&CK technique ID (e.g. T1059) to hunt for.",
    )
    cve_id: str | None = Field(
        default=None,
        description="CVE identifier to hunt for across detection and IOC records.",
    )
    risk_family: str | None = Field(
        default=None,
        description="Risk family tag to sweep (e.g. 'command_and_control').",
    )
    start_time: datetime | None = Field(
        default=None,
        description="Inclusive start of the hunt time window (UTC).",
    )
    end_time: datetime | None = Field(
        default=None,
        description="Inclusive end of the hunt time window (UTC).",
    )
    minimum_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Minimum DetectionResult score to include in hunt results.",
    )
    limit: int = Field(default=100, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def require_at_least_one_hunt_dimension(self) -> HuntQuery:
        has_dimension = any(
            [
                self.ioc_value,
                self.mitre_technique_id,
                self.cve_id,
                self.risk_family,
            ]
        )
        if not has_dimension:
            raise ValueError("HuntQuery requires at least one of: ioc_value, mitre_technique_id, cve_id, risk_family.")
        return self


# ---------------------------------------------------------------------------
# HuntMatch — individual match inside HuntResult
# ---------------------------------------------------------------------------


class HuntMatch(BaseModel):
    model_config = {"extra": "ignore"}

    event_id: str
    org_id: str | None = None
    agent_id: str | None = None
    session_id: str | None = None
    verdict: DetectionVerdict
    score: float = Field(ge=0.0, le=1.0)
    severity: ThreatSeverityLevel
    matched_ioc_value: str | None = None
    matched_ioc_type: str | None = None
    matched_mitre_technique: str | None = None
    risk_families: list[str] = Field(default_factory=list)
    context: str | None = None
    assessed_at: str
    confidence: float = Field(ge=0.0, le=1.0)


# ---------------------------------------------------------------------------
# HuntResult — response from POST /threat/hunt
# ---------------------------------------------------------------------------


class HuntResult(BaseModel):
    model_config = {"extra": "ignore"}

    hunt_id: str
    org_id: str | None = None
    status: HuntStatusEnum
    total_matches: int = Field(ge=0)
    matches: list[HuntMatch] = Field(default_factory=list)
    query_summary: dict[str, Any] = Field(default_factory=dict)
    executed_at: str
    duration_ms: int | None = None
    errors: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# IOCImportRequest — POST /threat/iocs (bulk import)
# ---------------------------------------------------------------------------


class IOCImportEntry(BaseModel):
    """Single IOC entry in a bulk import request."""

    model_config = {"extra": "forbid"}

    value: str = Field(min_length=1)
    ioc_type: IOCTypeEnum | None = None
    severity: ThreatSeverityLevel = ThreatSeverityLevel.MEDIUM
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    tags: list[str] = Field(default_factory=list)
    description: str = ""
    mitre_technique_id: str | None = None
    mitre_tactic: str | None = None
    cve_id: str | None = None
    expiry: str | None = None
    reference: str | None = None
    extra: dict[str, Any] = Field(default_factory=dict)

    @field_validator("tags", mode="before")
    @classmethod
    def coerce_tags(cls, v: Any) -> list[str]:
        if isinstance(v, str):
            return [t.strip() for t in v.split(",") if t.strip()]
        return v


class IOCImportRequest(BaseModel):
    """Bulk IOC import payload for POST /threat/iocs."""

    model_config = {"extra": "forbid"}

    org_id: str | None = None
    entries: list[IOCImportEntry] = Field(min_length=1)
    source_label: str | None = Field(
        default=None,
        description="Optional human label for this import batch (e.g. 'pentest-2026-05').",
    )
    overwrite_existing: bool = Field(
        default=False,
        description="If True, existing IOCs with the same fingerprint are updated. If False, they are skipped.",
    )


class IOCImportResult(BaseModel):
    model_config = {"extra": "ignore"}

    ingest_id: str
    org_id: str | None = None
    iocs_submitted: int
    iocs_inserted: int
    iocs_updated: int
    iocs_skipped: int
    errors: list[str] = Field(default_factory=list)
    status: IngestStatusEnum
    completed_at: str


# ---------------------------------------------------------------------------
# TAXIIIngestRequest — POST /threat/feeds/taxii/ingest
# ---------------------------------------------------------------------------


class TAXIIIngestRequest(BaseModel):
    """
    API-layer schema for triggering a STIX/TAXII 2.1 ingest via the STIXAdapter.
    Maps directly to TAXIIConfig in stix_adapter.py — callers supply connection
    parameters here; the router constructs the TAXIIConfig dataclass from this model.
    """

    model_config = {"extra": "forbid"}

    discovery_url: str = Field(
        description="TAXII 2.1 discovery endpoint URL.",
    )
    collection_id: str | None = Field(
        default=None,
        description="Target collection ID. If omitted, the first readable collection is used.",
    )
    api_root: str | None = Field(
        default=None,
        description="Override the TAXII API root URL. If omitted, discovered from the server.",
    )
    username: str | None = Field(
        default=None,
        description="Basic-auth username for the TAXII server.",
    )
    password: str | None = Field(
        default=None,
        description="Basic-auth password for the TAXII server.",
    )
    verify_ssl: bool = Field(
        default=True,
        description="Whether to verify the TAXII server's TLS certificate.",
    )
    timeout: int = Field(
        default=30,
        ge=5,
        le=300,
        description="HTTP request timeout in seconds.",
    )
    page_size: int = Field(
        default=500,
        ge=1,
        le=5000,
        description="Number of objects to fetch per TAXII page.",
    )
    extra_headers: dict[str, str] = Field(
        default_factory=dict,
        description="Additional HTTP headers to include in TAXII requests.",
    )
    org_id: str | None = Field(
        default=None,
        description="Organization scope for ingested IOCs.",
    )
    added_after: str | None = Field(
        default=None,
        description="ISO 8601 UTC timestamp — only fetch objects added after this time.",
    )
    source_label: str | None = Field(
        default=None,
        description="Human-readable label embedded in IOC tags for this ingest batch.",
    )


# ---------------------------------------------------------------------------
# FeedRefreshRequest — POST /threat/feeds/refresh
# ---------------------------------------------------------------------------


class FeedRefreshRequest(BaseModel):
    """Manually trigger a feed refresh for one or more sources."""

    model_config = {"extra": "forbid"}

    sources: list[ThreatFeedSourceEnum] = Field(
        min_length=1,
        description="List of feed sources to refresh.",
    )
    org_id: str | None = None
    force: bool = Field(
        default=False,
        description="If True, bypasses the minimum refresh interval guard.",
    )
    custom_url: str | None = Field(
        default=None,
        description="Override the default source URL (single-source requests only).",
    )
    taxii_ingest: TAXIIIngestRequest | None = Field(
        default=None,
        description=("STIX/TAXII connection parameters. Required when sources contains STIX_TAXII and the caller needs to specify a non-default server."),
    )

    @model_validator(mode="after")
    def custom_url_requires_single_source(self) -> FeedRefreshRequest:
        if self.custom_url and len(self.sources) > 1:
            raise ValueError("custom_url may only be set when refreshing a single source.")
        return self

    @model_validator(mode="after")
    def taxii_ingest_requires_stix_taxii_source(self) -> FeedRefreshRequest:
        if self.taxii_ingest and ThreatFeedSourceEnum.STIX_TAXII not in self.sources:
            raise ValueError("taxii_ingest may only be set when STIX_TAXII is included in sources.")
        return self


class FeedRefreshResult(BaseModel):
    """Aggregated result of a feed refresh operation."""

    model_config = {"extra": "ignore"}

    request_id: str
    org_id: str | None = None
    results: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Per-source FeedIngestResult dicts.",
    )
    total_iocs_inserted: int = 0
    total_iocs_updated: int = 0
    total_errors: int = 0
    started_at: str
    completed_at: str | None = None


# ---------------------------------------------------------------------------
# IOCFilterParams — query params for GET /threat/iocs
# ---------------------------------------------------------------------------


class IOCFilterParams(BaseModel):
    model_config = {"extra": "ignore"}

    source: ThreatFeedSourceEnum | None = None
    ioc_type: IOCTypeEnum | None = None
    severity: ThreatSeverityLevel | None = None
    org_id: str | None = None
    active: bool | None = None
    tag: str | None = None
    mitre_technique_id: str | None = None
    cve_id: str | None = None
    value_contains: str | None = None
    limit: int = Field(default=100, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)


# ---------------------------------------------------------------------------
# IOCResponse — GET /threat/iocs response shape
# ---------------------------------------------------------------------------


class IOCResponse(BaseModel):
    model_config = {"extra": "ignore"}

    ioc_id: str
    ioc_type: str
    value: str
    source: str
    severity: str
    confidence: float
    tags: list[str]
    description: str
    org_id: str | None
    mitre_technique_id: str | None
    mitre_tactic: str | None
    cve_id: str | None
    first_seen: str
    last_seen: str
    expiry: str | None
    active: bool
    feed_ingest_id: str
    extra: dict[str, Any]


# ---------------------------------------------------------------------------
# DetectionSummary — lightweight shape for listing stored detections
# ---------------------------------------------------------------------------


class DetectionSummary(BaseModel):
    model_config = {"extra": "ignore"}

    event_id: str
    org_id: str | None = None
    agent_id: str | None = None
    session_id: str | None = None
    verdict: DetectionVerdict
    score: float
    severity: ThreatSeverityLevel
    ioc_match_count: int
    correlation_signal_count: int
    assessed_at: str


# ---------------------------------------------------------------------------
# __all__
# ---------------------------------------------------------------------------


__all__ = [
    "AlertSeverityEnum",
    "CorrelationSignal",
    "DetectionRequest",
    "DetectionResult",
    "DetectionSummary",
    "DetectionVerdict",
    "FeedRefreshRequest",
    "FeedRefreshResult",
    "HuntMatch",
    "HuntQuery",
    "HuntResult",
    "HuntStatusEnum",
    "IOCFilterParams",
    "IOCImportEntry",
    "IOCImportRequest",
    "IOCImportResult",
    "IOCMatch",
    "IOCResponse",
    "IOCTypeEnum",
    "IngestStatusEnum",
    "TAXIIIngestRequest",
    "ThreatAlert",
    "ThreatFeedSourceEnum",
    "ThreatSeverityLevel",
]
