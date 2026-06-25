from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class IOCType(StrEnum):
    """
    Indicator of Compromise type.
    Maps to the ioc_type column in ioc_records.
    Distinct from IOCTypeEnum in threat_detection.py which carries extended
    hash sub-types and MITRE-specific values for the detection engine.
    """

    DOMAIN = "domain"
    IP = "ip"
    HASH = "hash"
    URL = "url"
    EMAIL = "email"
    PATTERN = "pattern"


class IOCSeverity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IOCSource(StrEnum):
    INTERNAL = "internal"
    MITRE_ATTACK = "mitre_attack"
    CISA_KEV = "cisa_kev"
    CUSTOM_IOC = "custom_ioc"
    STIX_TAXII = "stix_taxii"


# ---------------------------------------------------------------------------
# Core record models
# ---------------------------------------------------------------------------


class IOCRecord(BaseModel):
    """
    Read model — maps 1:1 to the ioc_records table row returned from Supabase.
    Consumed by: threat_detection router, ioc service, audit events (ioc.matched).
    """

    model_config = ConfigDict(from_attributes=True)

    ioc_id: str = Field(..., description="UUID primary key from ioc_records.ioc_id")
    ioc_type: IOCType
    value: str = Field(..., description="Raw IOC value — domain, IP, hash, URL, email, or pattern string")
    source: IOCSource = IOCSource.INTERNAL
    severity: IOCSeverity = IOCSeverity.MEDIUM
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    active: bool = Field(default=True)
    org_id: str | None = None
    tags: list[str] = Field(default_factory=list)
    description: str = Field(default="")
    mitre_technique_id: str | None = None
    mitre_tactic: str | None = None
    cve_id: str | None = None
    reference: str | None = None
    expiry: datetime | None = None
    feed_ingest_id: str | None = None
    extra: dict[str, Any] = Field(default_factory=dict)
    first_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime | None = None


class IOCCreate(BaseModel):
    """
    Write model — submitted when creating a new IOC record.
    ioc_id, created_at, updated_at are assigned by the persistence layer.
    """

    model_config = ConfigDict(from_attributes=True)

    ioc_type: IOCType
    value: str = Field(
        ...,
        min_length=1,
        max_length=2048,
        description="Raw IOC value",
    )
    source: IOCSource = IOCSource.INTERNAL
    severity: IOCSeverity = IOCSeverity.MEDIUM
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    active: bool = Field(default=True)
    org_id: str | None = None
    tags: list[str] = Field(default_factory=list)
    description: str = Field(default="", max_length=4096)
    mitre_technique_id: str | None = Field(default=None, max_length=32)
    mitre_tactic: str | None = Field(default=None, max_length=128)
    cve_id: str | None = Field(default=None, max_length=32)
    reference: str | None = Field(default=None, max_length=2048)
    expiry: datetime | None = None
    feed_ingest_id: str | None = None
    extra: dict[str, Any] = Field(default_factory=dict)
    first_seen: datetime | None = None
    last_seen: datetime | None = None

    @field_validator("tags", mode="before")
    @classmethod
    def _coerce_tags(cls, v: Any) -> list[str]:
        if isinstance(v, str):
            return [t.strip() for t in v.split(",") if t.strip()]
        return v

    @field_validator("value", mode="after")
    @classmethod
    def _strip_value(cls, v: str) -> str:
        return v.strip()


class IOCUpdate(BaseModel):
    """
    Partial update model — all fields optional.
    Only supplied fields are written; unset fields are left unchanged in ioc_records.
    """

    model_config = ConfigDict(from_attributes=True)

    ioc_type: IOCType | None = None
    value: str | None = Field(default=None, min_length=1, max_length=2048)
    source: IOCSource | None = None
    severity: IOCSeverity | None = None
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    active: bool | None = None
    org_id: str | None = None
    tags: list[str] | None = None
    description: str | None = Field(default=None, max_length=4096)
    mitre_technique_id: str | None = Field(default=None, max_length=32)
    mitre_tactic: str | None = Field(default=None, max_length=128)
    cve_id: str | None = Field(default=None, max_length=32)
    reference: str | None = Field(default=None, max_length=2048)
    expiry: datetime | None = None
    extra: dict[str, Any] | None = None
    last_seen: datetime | None = None

    @model_validator(mode="after")
    def _require_at_least_one_field(self) -> IOCUpdate:
        set_fields = {k for k, v in self.model_dump(exclude_unset=True).items() if v is not None}
        if not set_fields:
            raise ValueError("IOCUpdate requires at least one field to be set.")
        return self

    @field_validator("tags", mode="before")
    @classmethod
    def _coerce_tags(cls, v: Any) -> list[str] | None:
        if isinstance(v, str):
            return [t.strip() for t in v.split(",") if t.strip()]
        return v


# ---------------------------------------------------------------------------
# Match result
# ---------------------------------------------------------------------------


class IOCMatchResult(BaseModel):
    """
    Returned when an observable (text, URL, domain, hash, email) is matched
    against the ioc_records store.
    Consumed by: threat_detection engine, action_guard, scan layer.
    """

    model_config = ConfigDict(from_attributes=True)

    matched: bool = Field(..., description="True if at least one IOC matched")
    ioc_id: str | None = Field(default=None, description="Matching ioc_records.ioc_id")
    ioc_type: IOCType | None = None
    value: str | None = Field(default=None, description="The matched IOC value")
    source: IOCSource | None = None
    severity: IOCSeverity | None = None
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    tags: list[str] = Field(default_factory=list)
    mitre_technique_id: str | None = None
    mitre_tactic: str | None = None
    cve_id: str | None = None
    reference: str | None = None
    matched_on: str | None = Field(
        default=None,
        description="Field or context in which this IOC matched (e.g. 'url', 'domain', 'text')",
    )
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    extra: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Query / filter model
# ---------------------------------------------------------------------------


class IOCQueryParams(BaseModel):
    """Filter parameters for GET /ioc or service-layer queries against ioc_records."""

    ioc_type: IOCType | None = None
    source: IOCSource | None = None
    severity: IOCSeverity | None = None
    org_id: str | None = None
    active: bool | None = None
    tag: str | None = None
    mitre_technique_id: str | None = None
    cve_id: str | None = None
    value_contains: str | None = None
    confidence_min: float | None = Field(default=None, ge=0.0, le=1.0)
    confidence_max: float | None = Field(default=None, ge=0.0, le=1.0)
    since: datetime | None = None
    until: datetime | None = None
    limit: int = Field(default=100, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class IOCListResponse(BaseModel):
    """Paginated response for IOC record queries."""

    model_config = ConfigDict(from_attributes=True)

    count: int = Field(ge=0)
    total: int | None = None
    items: list[IOCRecord] = Field(default_factory=list)


class IOCRecordResponse(BaseModel):
    """Single-record response wrapper for create / update / delete operations."""

    model_config = ConfigDict(from_attributes=True)

    ok: bool
    ioc_id: str | None = None
    error: str | None = None


# ---------------------------------------------------------------------------
# Access summary models (IOC layer observability)
# ---------------------------------------------------------------------------


class IOCAccessCountsSchema(BaseModel):
    total_records: int = 0
    active_records: int = 0
    inactive_records: int = 0
    critical_iocs: int = 0
    high_iocs: int = 0
    matches_last_24h: int = 0
    latest_record_at: str = "Not yet recorded"


class IOCAccessControlsSchema(BaseModel):
    org_scoping_enabled: bool = False
    expiry_enforcement_enabled: bool = False
    confidence_threshold_enforced: bool = False
    feed_ingest_tracked: bool = False
    audit_on_match: bool = False


class IOCAccessSummaryResponse(BaseModel):
    pageid: str
    title: str
    path: str
    summary: str
    generatedat: str
    accessavailable: bool = False
    ioc_store_ready: bool = False
    match_engine_connected: bool = False
    counts: IOCAccessCountsSchema = Field(default_factory=IOCAccessCountsSchema)
    controls: IOCAccessControlsSchema = Field(default_factory=IOCAccessControlsSchema)
    recent_matches: list[dict[str, Any]] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# __all__
# ---------------------------------------------------------------------------


__all__ = [
    "IOCAccessControlsSchema",
    "IOCAccessCountsSchema",
    "IOCAccessSummaryResponse",
    "IOCCreate",
    "IOCListResponse",
    "IOCMatchResult",
    "IOCQueryParams",
    "IOCRecord",
    "IOCRecordResponse",
    "IOCSeverity",
    "IOCSource",
    "IOCType",
    "IOCUpdate",
]
