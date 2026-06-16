from __future__ import annotations

from datetime import UTC, datetime

from pydantic import ValidationError
import pytest

from app.schemas.telemetry import (
    TelemetryAccessControlsSchema,
    TelemetryAccessCountsSchema,
    TelemetryAccessSummaryResponse,
    TelemetryBatch,
    TelemetryEvent,
    TelemetryEventCreate,
    TelemetryEventType,
    TelemetryIngestResponse,
    TelemetryQueryParams,
    TelemetryResponse,
    TelemetrySeverity,
    TelemetryVerdict,
)

# ---------------------------------------------------------------------------
# TelemetryEventType — complete value coverage
# ---------------------------------------------------------------------------


def test_telemetry_event_type_prompt_group():
    expected = {
        TelemetryEventType.PROMPT_RECEIVED,
        TelemetryEventType.PROMPT_SCANNED,
        TelemetryEventType.PROMPT_INJECTION_DETECTED,
        TelemetryEventType.PROMPT_BLOCKED,
        TelemetryEventType.PROMPT_ALLOWED,
        TelemetryEventType.PROMPT_QUARANTINED,
        TelemetryEventType.PROMPT_FLAGGED,
        TelemetryEventType.PROMPT_REDACTED,
    }
    actual = {e for e in TelemetryEventType if e.value.startswith("prompt.")}
    assert actual == expected


def test_telemetry_event_type_tool_call_group():
    expected = {
        TelemetryEventType.TOOL_CALL_RECEIVED,
        TelemetryEventType.TOOL_CALL_EVALUATED,
        TelemetryEventType.TOOL_CALL_ALLOWED,
        TelemetryEventType.TOOL_CALL_BLOCKED,
        TelemetryEventType.TOOL_CALL_QUARANTINED,
        TelemetryEventType.TOOL_CALL_SANDBOXED,
        TelemetryEventType.TOOL_CALL_FAILED,
    }
    actual = {e for e in TelemetryEventType if e.value.startswith("tool_call.")}
    assert actual == expected


def test_telemetry_event_type_action_group():
    expected = {
        TelemetryEventType.ACTION_SUBMITTED,
        TelemetryEventType.ACTION_DECISION_MADE,
        TelemetryEventType.ACTION_EXECUTED,
        TelemetryEventType.ACTION_BLOCKED,
        TelemetryEventType.ACTION_QUARANTINED,
        TelemetryEventType.ACTION_FAILED,
        TelemetryEventType.ACTION_SANDBOXED,
        TelemetryEventType.ACTION_REVIEWED,
        TelemetryEventType.ACTION_REVIEW_APPROVED,
        TelemetryEventType.ACTION_REVIEW_REJECTED,
    }
    actual = {e for e in TelemetryEventType if e.value.startswith("action.")}
    assert actual == expected


def test_telemetry_event_type_policy_group():
    expected = {
        TelemetryEventType.POLICY_EVALUATED,
        TelemetryEventType.POLICY_VIOLATION,
        TelemetryEventType.POLICY_UPDATED,
        TelemetryEventType.POLICY_CREATED,
        TelemetryEventType.POLICY_DELETED,
    }
    actual = {e for e in TelemetryEventType if e.value.startswith("policy.")}
    assert actual == expected


def test_telemetry_event_type_agent_group():
    expected = {
        TelemetryEventType.AGENT_SESSION_STARTED,
        TelemetryEventType.AGENT_SESSION_ENDED,
        TelemetryEventType.AGENT_TRUST_DEGRADED,
        TelemetryEventType.AGENT_TRUST_RESTORED,
        TelemetryEventType.AGENT_PROFILE_CREATED,
        TelemetryEventType.AGENT_PROFILE_UPDATED,
    }
    actual = {e for e in TelemetryEventType if e.value.startswith("agent.")}
    assert actual == expected


def test_telemetry_event_type_auth_group():
    expected = {
        TelemetryEventType.AUTH_SUCCESS,
        TelemetryEventType.AUTH_FAILURE,
        TelemetryEventType.AUTH_TOKEN_REVOKED,
        TelemetryEventType.AUTH_RATE_LIMITED,
    }
    actual = {e for e in TelemetryEventType if e.value.startswith("auth.")}
    assert actual == expected


def test_telemetry_event_type_data_group():
    expected = {
        TelemetryEventType.DATA_ACCESS,
        TelemetryEventType.DATA_EXPORT_ATTEMPTED,
        TelemetryEventType.DATA_EXPORT_BLOCKED,
        TelemetryEventType.DATA_REDACTED,
        TelemetryEventType.DATA_LEAKAGE_DETECTED,
    }
    actual = {e for e in TelemetryEventType if e.value.startswith("data.")}
    assert actual == expected


def test_telemetry_event_type_threat_group():
    expected = {
        TelemetryEventType.THREAT_DETECTED,
        TelemetryEventType.THREAT_CORRELATED,
        TelemetryEventType.ATTACK_SEQUENCE_IDENTIFIED,
        TelemetryEventType.IOC_MATCHED,
    }
    actual = {e for e in TelemetryEventType if e.value.startswith("threat.") or e.value.startswith("attack.") or e.value.startswith("ioc.")}
    assert actual == expected


def test_telemetry_event_type_audit_group():
    expected = {
        TelemetryEventType.AUDIT_LOG_WRITTEN,
        TelemetryEventType.AUDIT_EXPORT_REQUESTED,
    }
    actual = {e for e in TelemetryEventType if e.value.startswith("audit.")}
    assert actual == expected


def test_telemetry_event_type_system_group():
    expected = {
        TelemetryEventType.SYSTEM_STARTUP,
        TelemetryEventType.SYSTEM_SHUTDOWN,
        TelemetryEventType.SYSTEM_ERROR,
        TelemetryEventType.SYSTEM_HEALTH_CHECK,
        TelemetryEventType.TELEMETRY_BATCH_INGESTED,
        TelemetryEventType.TELEMETRY_BATCH_FAILED,
    }
    actual = {e for e in TelemetryEventType if e.value.startswith("system.") or e.value.startswith("telemetry.")}
    assert actual == expected


def test_telemetry_event_type_alert_group():
    expected = {
        TelemetryEventType.ALERT_CREATED,
        TelemetryEventType.ALERT_ESCALATED,
        TelemetryEventType.ALERT_RESOLVED,
    }
    actual = {e for e in TelemetryEventType if e.value.startswith("alert.")}
    assert actual == expected


def test_telemetry_event_type_webhook_group():
    expected = {
        TelemetryEventType.WEBHOOK_DELIVERED,
        TelemetryEventType.WEBHOOK_FAILED,
    }
    actual = {e for e in TelemetryEventType if e.value.startswith("webhook.")}
    assert actual == expected


def test_telemetry_event_type_unknown_member():
    assert TelemetryEventType.UNKNOWN == TelemetryEventType("unknown")


@pytest.mark.parametrize("member", list(TelemetryEventType))
def test_telemetry_event_type_all_round_trip(member):
    assert TelemetryEventType(member.value) == member


def test_telemetry_event_type_invalid():
    with pytest.raises(ValueError):
        TelemetryEventType("not.a.real.event")


# ---------------------------------------------------------------------------
# TelemetryVerdict — complete coverage
# ---------------------------------------------------------------------------


def test_telemetry_verdict_values():
    assert set(TelemetryVerdict) == {
        TelemetryVerdict.ALLOW,
        TelemetryVerdict.WARN,
        TelemetryVerdict.QUARANTINE,
        TelemetryVerdict.BLOCK,
        TelemetryVerdict.UNKNOWN,
    }


@pytest.mark.parametrize("value", ["allow", "warn", "quarantine", "block", "unknown"])
def test_telemetry_verdict_from_string(value):
    assert TelemetryVerdict(value).value == value


def test_telemetry_verdict_invalid():
    with pytest.raises(ValueError):
        TelemetryVerdict("pass")


# ---------------------------------------------------------------------------
# TelemetrySeverity — complete coverage
# ---------------------------------------------------------------------------


def test_telemetry_severity_values():
    assert set(TelemetrySeverity) == {
        TelemetrySeverity.INFO,
        TelemetrySeverity.LOW,
        TelemetrySeverity.MEDIUM,
        TelemetrySeverity.HIGH,
        TelemetrySeverity.CRITICAL,
    }


@pytest.mark.parametrize("value", ["info", "low", "medium", "high", "critical"])
def test_telemetry_severity_from_string(value):
    assert TelemetrySeverity(value).value == value


def test_telemetry_severity_invalid():
    with pytest.raises(ValueError):
        TelemetrySeverity("fatal")


# ---------------------------------------------------------------------------
# TelemetryEventCreate — field validation
# ---------------------------------------------------------------------------

_BASE_CREATE = dict(
    event_type=TelemetryEventType.PROMPT_SCANNED,
    source="ironclaw-api",
)


def test_telemetry_event_create_minimal():
    ev = TelemetryEventCreate(**_BASE_CREATE)
    assert ev.event_type == TelemetryEventType.PROMPT_SCANNED
    assert ev.source == "ironclaw-api"


def test_telemetry_event_create_tags_default_empty():
    ev = TelemetryEventCreate(**_BASE_CREATE)
    assert ev.tags == []


def test_telemetry_event_create_payload_default_empty():
    ev = TelemetryEventCreate(**_BASE_CREATE)
    assert ev.payload == {}


def test_telemetry_event_create_dimensions_default_empty():
    ev = TelemetryEventCreate(**_BASE_CREATE)
    assert ev.dimensions == {}


def test_telemetry_event_create_optional_fields_default_none():
    ev = TelemetryEventCreate(**_BASE_CREATE)
    assert ev.org_id is None
    assert ev.agent_id is None
    assert ev.session_id is None
    assert ev.verdict is None
    assert ev.severity is None
    assert ev.timestamp is None


def test_telemetry_event_create_missing_source_rejected():
    with pytest.raises(ValidationError):
        TelemetryEventCreate(event_type=TelemetryEventType.PROMPT_SCANNED)


def test_telemetry_event_create_empty_source_rejected():
    with pytest.raises(ValidationError):
        TelemetryEventCreate(event_type=TelemetryEventType.PROMPT_SCANNED, source="")


def test_telemetry_event_create_source_too_long_rejected():
    with pytest.raises(ValidationError):
        TelemetryEventCreate(
            event_type=TelemetryEventType.PROMPT_SCANNED,
            source="x" * 257,
        )


def test_telemetry_event_create_missing_event_type_rejected():
    with pytest.raises(ValidationError):
        TelemetryEventCreate(source="ironclaw-api")


def test_telemetry_event_create_invalid_event_type_rejected():
    with pytest.raises(ValidationError):
        TelemetryEventCreate(source="ironclaw-api", event_type="not.valid")


def test_telemetry_event_create_full_construction():
    ev = TelemetryEventCreate(
        event_type=TelemetryEventType.PROMPT_INJECTION_DETECTED,
        source="guard-layer",
        org_id="org-abc",
        agent_id="agent-001",
        session_id="sess-xyz",
        verdict=TelemetryVerdict.BLOCK,
        severity=TelemetrySeverity.CRITICAL,
        tags=["injection", "high-risk"],
        payload={"pattern": "ignore previous", "score": 0.98},
        dimensions={"model": "claude-3", "runtime": "mcp"},
        timestamp="2026-06-16T10:00:00Z",
    )
    assert ev.org_id == "org-abc"
    assert ev.verdict == TelemetryVerdict.BLOCK
    assert ev.severity == TelemetrySeverity.CRITICAL
    assert "injection" in ev.tags
    assert ev.payload["score"] == 0.98
    assert ev.dimensions["model"] == "claude-3"


@pytest.mark.parametrize("event_type", list(TelemetryEventType))
def test_telemetry_event_create_all_event_types_accepted(event_type):
    ev = TelemetryEventCreate(event_type=event_type, source="test")
    assert ev.event_type == event_type


# ---------------------------------------------------------------------------
# TelemetryBatch — min-length enforcement
# ---------------------------------------------------------------------------

_VALID_EVENT = TelemetryEventCreate(
    event_type=TelemetryEventType.PROMPT_SCANNED,
    source="batch-source",
)


def test_telemetry_batch_single_event():
    batch = TelemetryBatch(events=[_VALID_EVENT])
    assert len(batch.events) == 1


def test_telemetry_batch_multiple_events():
    batch = TelemetryBatch(events=[_VALID_EVENT, _VALID_EVENT])
    assert len(batch.events) == 2


def test_telemetry_batch_empty_events_rejected():
    with pytest.raises(ValidationError):
        TelemetryBatch(events=[])


def test_telemetry_batch_optional_fields_default_none():
    batch = TelemetryBatch(events=[_VALID_EVENT])
    assert batch.org_id is None
    assert batch.source is None


def test_telemetry_batch_with_org_and_source():
    batch = TelemetryBatch(
        events=[_VALID_EVENT],
        org_id="org-001",
        source="pipeline-ingester",
    )
    assert batch.org_id == "org-001"
    assert batch.source == "pipeline-ingester"


def test_telemetry_batch_missing_events_rejected():
    with pytest.raises(ValidationError):
        TelemetryBatch()


def test_telemetry_batch_preserves_event_integrity():
    ev1 = TelemetryEventCreate(
        event_type=TelemetryEventType.ACTION_BLOCKED,
        source="executor",
        verdict=TelemetryVerdict.BLOCK,
    )
    ev2 = TelemetryEventCreate(
        event_type=TelemetryEventType.POLICY_VIOLATION,
        source="policy-engine",
        severity=TelemetrySeverity.HIGH,
    )
    batch = TelemetryBatch(events=[ev1, ev2])
    assert batch.events[0].event_type == TelemetryEventType.ACTION_BLOCKED
    assert batch.events[1].severity == TelemetrySeverity.HIGH


# ---------------------------------------------------------------------------
# TelemetryQueryParams — limit/offset bounds
# ---------------------------------------------------------------------------


def test_telemetry_query_params_defaults():
    q = TelemetryQueryParams()
    assert q.limit == 100
    assert q.offset == 0
    assert q.event_type is None
    assert q.source is None
    assert q.org_id is None
    assert q.agent_id is None
    assert q.session_id is None
    assert q.verdict is None
    assert q.severity is None
    assert q.since is None
    assert q.until is None


def test_telemetry_query_params_limit_min():
    q = TelemetryQueryParams(limit=1)
    assert q.limit == 1


def test_telemetry_query_params_limit_max():
    q = TelemetryQueryParams(limit=1000)
    assert q.limit == 1000


def test_telemetry_query_params_limit_below_min_rejected():
    with pytest.raises(ValidationError):
        TelemetryQueryParams(limit=0)


def test_telemetry_query_params_limit_above_max_rejected():
    with pytest.raises(ValidationError):
        TelemetryQueryParams(limit=1001)


def test_telemetry_query_params_offset_zero():
    q = TelemetryQueryParams(offset=0)
    assert q.offset == 0


def test_telemetry_query_params_offset_positive():
    q = TelemetryQueryParams(offset=50)
    assert q.offset == 50


def test_telemetry_query_params_offset_negative_rejected():
    with pytest.raises(ValidationError):
        TelemetryQueryParams(offset=-1)


def test_telemetry_query_params_full_filter():
    since = datetime(2026, 1, 1, tzinfo=UTC)
    until = datetime(2026, 6, 16, tzinfo=UTC)
    q = TelemetryQueryParams(
        event_type=TelemetryEventType.PROMPT_INJECTION_DETECTED,
        source="guard-layer",
        org_id="org-abc",
        agent_id="agent-001",
        session_id="sess-xyz",
        verdict=TelemetryVerdict.BLOCK,
        severity=TelemetrySeverity.CRITICAL,
        since=since,
        until=until,
        limit=25,
        offset=10,
    )
    assert q.event_type == TelemetryEventType.PROMPT_INJECTION_DETECTED
    assert q.verdict == TelemetryVerdict.BLOCK
    assert q.severity == TelemetrySeverity.CRITICAL
    assert q.since == since
    assert q.until == until
    assert q.limit == 25
    assert q.offset == 10


@pytest.mark.parametrize("verdict", list(TelemetryVerdict))
def test_telemetry_query_params_all_verdicts(verdict):
    q = TelemetryQueryParams(verdict=verdict)
    assert q.verdict == verdict


@pytest.mark.parametrize("severity", list(TelemetrySeverity))
def test_telemetry_query_params_all_severities(severity):
    q = TelemetryQueryParams(severity=severity)
    assert q.severity == severity


# ---------------------------------------------------------------------------
# TelemetryEvent — read model round-trip
# ---------------------------------------------------------------------------

_BASE_EVENT = dict(
    timestamp="2026-06-16T10:00:00Z",
    event_type="prompt.scanned",
)


def test_telemetry_event_minimal():
    ev = TelemetryEvent(**_BASE_EVENT)
    assert ev.timestamp == "2026-06-16T10:00:00Z"
    assert ev.event_type == "prompt.scanned"


def test_telemetry_event_defaults():
    ev = TelemetryEvent(**_BASE_EVENT)
    assert ev.id is None
    assert ev.source is None
    assert ev.org_id is None
    assert ev.agent_id is None
    assert ev.session_id is None
    assert ev.verdict is None
    assert ev.severity is None
    assert ev.tags == []
    assert ev.payload == {}
    assert ev.dimensions == {}
    assert ev.created_at is None


def test_telemetry_event_missing_timestamp_rejected():
    with pytest.raises(ValidationError):
        TelemetryEvent(event_type="prompt.scanned")


def test_telemetry_event_missing_event_type_rejected():
    with pytest.raises(ValidationError):
        TelemetryEvent(timestamp="2026-06-16T10:00:00Z")


def test_telemetry_event_full_round_trip():
    ev = TelemetryEvent(
        id="evt-001",
        timestamp="2026-06-16T10:00:00Z",
        event_type="prompt.injection_detected",
        source="guard-layer",
        org_id="org-abc",
        agent_id="agent-001",
        session_id="sess-xyz",
        verdict=TelemetryVerdict.BLOCK,
        severity=TelemetrySeverity.CRITICAL,
        tags=["injection"],
        payload={"score": 0.99},
        dimensions={"model": "claude-3"},
        created_at="2026-06-16T10:00:01Z",
    )
    dumped = ev.model_dump()
    restored = TelemetryEvent(**dumped)
    assert restored.id == "evt-001"
    assert restored.verdict == TelemetryVerdict.BLOCK
    assert restored.severity == TelemetrySeverity.CRITICAL
    assert restored.tags == ["injection"]
    assert restored.payload["score"] == 0.99


def test_telemetry_event_serializes_to_dict():
    ev = TelemetryEvent(**_BASE_EVENT)
    d = ev.model_dump()
    assert "timestamp" in d
    assert "event_type" in d
    assert d["tags"] == []
    assert d["payload"] == {}


# ---------------------------------------------------------------------------
# TelemetryResponse — paginated response shape
# ---------------------------------------------------------------------------


def test_telemetry_response_minimal():
    r = TelemetryResponse(count=0)
    assert r.count == 0
    assert r.total is None
    assert r.items == []


def test_telemetry_response_with_items():
    ev = TelemetryEvent(**_BASE_EVENT)
    r = TelemetryResponse(count=1, total=1, items=[ev])
    assert r.count == 1
    assert r.total == 1
    assert len(r.items) == 1
    assert r.items[0].event_type == "prompt.scanned"


def test_telemetry_response_missing_count_rejected():
    with pytest.raises(ValidationError):
        TelemetryResponse()


# ---------------------------------------------------------------------------
# TelemetryIngestResponse — shape and defaults
# ---------------------------------------------------------------------------


def test_telemetry_ingest_response_success():
    r = TelemetryIngestResponse(ok=True, received=5, inserted=5)
    assert r.ok is True
    assert r.received == 5
    assert r.inserted == 5
    assert r.duplicates == 0
    assert r.validation_errors == []
    assert r.error is None


def test_telemetry_ingest_response_partial_failure():
    r = TelemetryIngestResponse(
        ok=False,
        received=5,
        inserted=3,
        duplicates=1,
        validation_errors=[{"index": 4, "detail": "invalid event_type"}],
        error="partial ingest failure",
    )
    assert r.ok is False
    assert r.inserted == 3
    assert r.duplicates == 1
    assert len(r.validation_errors) == 1
    assert r.error == "partial ingest failure"


def test_telemetry_ingest_response_defaults():
    r = TelemetryIngestResponse(ok=True)
    assert r.received == 0
    assert r.inserted == 0
    assert r.duplicates == 0
    assert r.validation_errors == []
    assert r.error is None


def test_telemetry_ingest_response_missing_ok_rejected():
    with pytest.raises(ValidationError):
        TelemetryIngestResponse()


# ---------------------------------------------------------------------------
# TelemetryAccessCountsSchema — defaults
# ---------------------------------------------------------------------------


def test_telemetry_access_counts_defaults():
    c = TelemetryAccessCountsSchema()
    assert c.totalevents == 0
    assert c.allowedreads == 0
    assert c.flaggedreads == 0
    assert c.deniedreads == 0
    assert c.sensitiveexports == 0
    assert c.latesteventat == "Not yet recorded"


def test_telemetry_access_counts_full():
    c = TelemetryAccessCountsSchema(
        totalevents=100,
        allowedreads=80,
        flaggedreads=15,
        deniedreads=5,
        sensitiveexports=2,
        latesteventat="2026-06-16T10:00:00Z",
    )
    assert c.totalevents == 100
    assert c.latesteventat == "2026-06-16T10:00:00Z"


# ---------------------------------------------------------------------------
# TelemetryAccessControlsSchema — defaults
# ---------------------------------------------------------------------------


def test_telemetry_access_controls_defaults():
    c = TelemetryAccessControlsSchema()
    assert c.retentiontracked is False
    assert c.actorattributionrequired is False
    assert c.sessioncorrelationenabled is False
    assert c.requestcorrelationenabled is False
    assert c.redactionguardavailable is False


def test_telemetry_access_controls_all_enabled():
    c = TelemetryAccessControlsSchema(
        retentiontracked=True,
        actorattributionrequired=True,
        sessioncorrelationenabled=True,
        requestcorrelationenabled=True,
        redactionguardavailable=True,
    )
    assert all(
        [
            c.retentiontracked,
            c.actorattributionrequired,
            c.sessioncorrelationenabled,
            c.requestcorrelationenabled,
            c.redactionguardavailable,
        ]
    )


# ---------------------------------------------------------------------------
# TelemetryAccessSummaryResponse — contract
# ---------------------------------------------------------------------------

_BASE_SUMMARY = dict(
    pageid="telemetry-001",
    title="Telemetry Access Summary",
    path="/telemetry",
    summary="Access summary for telemetry layer",
    generatedat="2026-06-16T10:00:00Z",
)


def test_telemetry_access_summary_response_minimal():
    r = TelemetryAccessSummaryResponse(**_BASE_SUMMARY)
    assert r.pageid == "telemetry-001"
    assert r.title == "Telemetry Access Summary"
    assert r.accessavailable is False
    assert r.auditvisibilityenabled is False
    assert r.recenteventsready is False
    assert r.exportcontrolled is False
    assert r.recentevents == []
    assert r.metadata == {}
    assert isinstance(r.counts, TelemetryAccessCountsSchema)
    assert isinstance(r.controls, TelemetryAccessControlsSchema)


def test_telemetry_access_summary_response_required_fields_enforced():
    for missing_field in ["pageid", "title", "path", "summary", "generatedat"]:
        payload = {k: v for k, v in _BASE_SUMMARY.items() if k != missing_field}
        with pytest.raises(ValidationError):
            TelemetryAccessSummaryResponse(**payload)


def test_telemetry_access_summary_response_full():
    counts = TelemetryAccessCountsSchema(totalevents=50, allowedreads=40)
    controls = TelemetryAccessControlsSchema(retentiontracked=True)
    r = TelemetryAccessSummaryResponse(
        **_BASE_SUMMARY,
        accessavailable=True,
        auditvisibilityenabled=True,
        recenteventsready=True,
        exportcontrolled=True,
        counts=counts,
        controls=controls,
        recentevents=[{"id": "evt-001", "event_type": "prompt.scanned"}],
        metadata={"env": "production"},
    )
    assert r.accessavailable is True
    assert r.counts.totalevents == 50
    assert r.controls.retentiontracked is True
    assert len(r.recentevents) == 1
    assert r.metadata["env"] == "production"
