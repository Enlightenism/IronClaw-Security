from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import ValidationError
import pytest

from app.schemas.ioc import (
    IOCAccessControlsSchema,
    IOCAccessCountsSchema,
    IOCAccessSummaryResponse,
    IOCCreate,
    IOCListResponse,
    IOCMatchResult,
    IOCQueryParams,
    IOCRecord,
    IOCRecordResponse,
    IOCSeverity,
    IOCSource,
    IOCType,
    IOCUpdate,
)

# ---------------------------------------------------------------------------
# IOCType — complete member coverage and round-trip
# ---------------------------------------------------------------------------


def test_ioc_type_complete_membership():
    assert set(IOCType) == {
        IOCType.DOMAIN,
        IOCType.IP,
        IOCType.HASH,
        IOCType.URL,
        IOCType.EMAIL,
        IOCType.PATTERN,
    }


@pytest.mark.parametrize("member", list(IOCType))
def test_ioc_type_round_trip(member):
    assert IOCType(member.value) == member


@pytest.mark.parametrize(
    "value",
    ["domain", "ip", "hash", "url", "email", "pattern"],
)
def test_ioc_type_from_string(value):
    assert IOCType(value).value == value


def test_ioc_type_invalid():
    with pytest.raises(ValueError):
        IOCType("asn")


# ---------------------------------------------------------------------------
# IOCSeverity — complete membership
# ---------------------------------------------------------------------------


def test_ioc_severity_complete_membership():
    assert set(IOCSeverity) == {
        IOCSeverity.LOW,
        IOCSeverity.MEDIUM,
        IOCSeverity.HIGH,
        IOCSeverity.CRITICAL,
    }


@pytest.mark.parametrize("value", ["low", "medium", "high", "critical"])
def test_ioc_severity_from_string(value):
    assert IOCSeverity(value).value == value


def test_ioc_severity_invalid():
    with pytest.raises(ValueError):
        IOCSeverity("info")


@pytest.mark.parametrize("member", list(IOCSeverity))
def test_ioc_severity_round_trip(member):
    assert IOCSeverity(member.value) == member


# ---------------------------------------------------------------------------
# IOCSource — complete membership
# ---------------------------------------------------------------------------


def test_ioc_source_complete_membership():
    assert set(IOCSource) == {
        IOCSource.INTERNAL,
        IOCSource.MITRE_ATTACK,
        IOCSource.CISA_KEV,
        IOCSource.CUSTOM_IOC,
        IOCSource.STIX_TAXII,
    }


@pytest.mark.parametrize(
    "value",
    ["internal", "mitre_attack", "cisa_kev", "custom_ioc", "stix_taxii"],
)
def test_ioc_source_from_string(value):
    assert IOCSource(value).value == value


def test_ioc_source_invalid():
    with pytest.raises(ValueError):
        IOCSource("open_source")


@pytest.mark.parametrize("member", list(IOCSource))
def test_ioc_source_round_trip(member):
    assert IOCSource(member.value) == member


# ---------------------------------------------------------------------------
# IOCRecord — required-field enforcement and from_attributes round-trip
# ---------------------------------------------------------------------------

_BASE_RECORD: dict[str, Any] = dict(
    ioc_id="ioc-001",
    ioc_type=IOCType.DOMAIN,
    value="malicious.example.com",
)


def test_ioc_record_minimal():
    r = IOCRecord(**_BASE_RECORD)
    assert r.ioc_id == "ioc-001"
    assert r.ioc_type == IOCType.DOMAIN
    assert r.value == "malicious.example.com"


def test_ioc_record_defaults():
    r = IOCRecord(**_BASE_RECORD)
    assert r.source == IOCSource.INTERNAL
    assert r.severity == IOCSeverity.MEDIUM
    assert r.confidence == 0.8
    assert r.active is True
    assert r.org_id is None
    assert r.tags == []
    assert r.description == ""
    assert r.mitre_technique_id is None
    assert r.mitre_tactic is None
    assert r.cve_id is None
    assert r.reference is None
    assert r.expiry is None
    assert r.feed_ingest_id is None
    assert r.extra == {}
    assert r.updated_at is None


def test_ioc_record_created_at_defaults_to_utc_now():
    r = IOCRecord(**_BASE_RECORD)
    assert r.created_at is not None
    assert r.created_at.tzinfo is not None


def test_ioc_record_missing_ioc_id_rejected():
    payload = {k: v for k, v in _BASE_RECORD.items() if k != "ioc_id"}
    with pytest.raises(ValidationError):
        IOCRecord(**payload)


def test_ioc_record_missing_ioc_type_rejected():
    payload = {k: v for k, v in _BASE_RECORD.items() if k != "ioc_type"}
    with pytest.raises(ValidationError):
        IOCRecord(**payload)


def test_ioc_record_missing_value_rejected():
    payload = {k: v for k, v in _BASE_RECORD.items() if k != "value"}
    with pytest.raises(ValidationError):
        IOCRecord(**payload)


def test_ioc_record_full_construction():
    ts = datetime(2026, 6, 16, 10, 0, 0, tzinfo=UTC)
    r = IOCRecord(
        ioc_id="ioc-999",
        ioc_type=IOCType.IP,
        value="192.168.1.1",
        source=IOCSource.CISA_KEV,
        severity=IOCSeverity.CRITICAL,
        confidence=0.95,
        active=False,
        org_id="org-001",
        tags=["apt29", "c2"],
        description="Known C2 IP from APT29 campaign",
        mitre_technique_id="T1071",
        mitre_tactic="command-and-control",
        cve_id="CVE-2024-1234",
        reference="https://example.com/ref",
        expiry=ts,
        feed_ingest_id="feed-abc",
        extra={"tlp": "red"},
        first_seen=ts,
        last_seen=ts,
        created_at=ts,
        updated_at=ts,
    )
    assert r.ioc_id == "ioc-999"
    assert r.ioc_type == IOCType.IP
    assert r.source == IOCSource.CISA_KEV
    assert r.severity == IOCSeverity.CRITICAL
    assert r.confidence == 0.95
    assert r.active is False
    assert r.tags == ["apt29", "c2"]
    assert r.mitre_technique_id == "T1071"
    assert r.extra == {"tlp": "red"}


def test_ioc_record_from_attributes_round_trip():
    ts = datetime(2026, 6, 16, 10, 0, 0, tzinfo=UTC)
    r = IOCRecord(
        ioc_id="ioc-rt-001",
        ioc_type=IOCType.HASH,
        value="d41d8cd98f00b204e9800998ecf8427e",
        source=IOCSource.MITRE_ATTACK,
        severity=IOCSeverity.HIGH,
        confidence=0.9,
        active=True,
        tags=["malware"],
        description="Known malware hash",
        first_seen=ts,
        last_seen=ts,
        created_at=ts,
    )
    dumped = r.model_dump()
    restored = IOCRecord(**dumped)
    assert restored.ioc_id == r.ioc_id
    assert restored.ioc_type == r.ioc_type
    assert restored.value == r.value
    assert restored.source == r.source
    assert restored.severity == r.severity
    assert restored.confidence == r.confidence
    assert restored.tags == r.tags
    assert restored.created_at == r.created_at


def test_ioc_record_confidence_below_min_rejected():
    with pytest.raises(ValidationError):
        IOCRecord(**{**_BASE_RECORD, "confidence": -0.1})


def test_ioc_record_confidence_above_max_rejected():
    with pytest.raises(ValidationError):
        IOCRecord(**{**_BASE_RECORD, "confidence": 1.1})


def test_ioc_record_confidence_boundaries_accepted():
    r_min = IOCRecord(**{**_BASE_RECORD, "confidence": 0.0})
    r_max = IOCRecord(**{**_BASE_RECORD, "confidence": 1.0})
    assert r_min.confidence == 0.0
    assert r_max.confidence == 1.0


@pytest.mark.parametrize("ioc_type", list(IOCType))
def test_ioc_record_all_ioc_types_accepted(ioc_type):
    r = IOCRecord(**{**_BASE_RECORD, "ioc_type": ioc_type})
    assert r.ioc_type == ioc_type


@pytest.mark.parametrize("severity", list(IOCSeverity))
def test_ioc_record_all_severities_accepted(severity):
    r = IOCRecord(**{**_BASE_RECORD, "severity": severity})
    assert r.severity == severity


@pytest.mark.parametrize("source", list(IOCSource))
def test_ioc_record_all_sources_accepted(source):
    r = IOCRecord(**{**_BASE_RECORD, "source": source})
    assert r.source == source


# ---------------------------------------------------------------------------
# IOCCreate — required-field enforcement, bounds, validators
# ---------------------------------------------------------------------------

_BASE_CREATE: dict[str, Any] = dict(
    ioc_type=IOCType.URL,
    value="https://malicious.example.com/payload",
)


def test_ioc_create_minimal():
    c = IOCCreate(**_BASE_CREATE)
    assert c.ioc_type == IOCType.URL
    assert c.value == "https://malicious.example.com/payload"


def test_ioc_create_defaults():
    c = IOCCreate(**_BASE_CREATE)
    assert c.source == IOCSource.INTERNAL
    assert c.severity == IOCSeverity.MEDIUM
    assert c.confidence == 0.8
    assert c.active is True
    assert c.org_id is None
    assert c.tags == []
    assert c.description == ""
    assert c.mitre_technique_id is None
    assert c.mitre_tactic is None
    assert c.cve_id is None
    assert c.reference is None
    assert c.expiry is None
    assert c.feed_ingest_id is None
    assert c.extra == {}
    assert c.first_seen is None
    assert c.last_seen is None


def test_ioc_create_missing_ioc_type_rejected():
    with pytest.raises(ValidationError):
        IOCCreate(value="192.168.1.1")


def test_ioc_create_missing_value_rejected():
    with pytest.raises(ValidationError):
        IOCCreate(ioc_type=IOCType.IP)


def test_ioc_create_value_min_length_enforced():
    with pytest.raises(ValidationError):
        IOCCreate(ioc_type=IOCType.DOMAIN, value="")


def test_ioc_create_value_max_length_enforced():
    with pytest.raises(ValidationError):
        IOCCreate(ioc_type=IOCType.URL, value="x" * 2049)


def test_ioc_create_value_min_boundary_accepted():
    c = IOCCreate(ioc_type=IOCType.DOMAIN, value="a")
    assert c.value == "a"


def test_ioc_create_value_max_boundary_accepted():
    c = IOCCreate(ioc_type=IOCType.URL, value="x" * 2048)
    assert len(c.value) == 2048


def test_ioc_create_value_strip_validator():
    c = IOCCreate(ioc_type=IOCType.DOMAIN, value="  malicious.example.com  ")
    assert c.value == "malicious.example.com"


def test_ioc_create_value_strip_validator_leading_only():
    c = IOCCreate(ioc_type=IOCType.IP, value="  10.0.0.1")
    assert c.value == "10.0.0.1"


def test_ioc_create_value_strip_validator_trailing_only():
    c = IOCCreate(ioc_type=IOCType.IP, value="10.0.0.1  ")
    assert c.value == "10.0.0.1"


def test_ioc_create_tags_string_coercion_comma_separated():
    c = IOCCreate(**{**_BASE_CREATE, "tags": "apt29,c2,malware"})
    assert c.tags == ["apt29", "c2", "malware"]


def test_ioc_create_tags_string_coercion_with_spaces():
    c = IOCCreate(**{**_BASE_CREATE, "tags": "  apt29 , c2 , malware  "})
    assert c.tags == ["apt29", "c2", "malware"]


def test_ioc_create_tags_string_coercion_single():
    c = IOCCreate(**{**_BASE_CREATE, "tags": "c2"})
    assert c.tags == ["c2"]


def test_ioc_create_tags_string_coercion_empty_string():
    c = IOCCreate(**{**_BASE_CREATE, "tags": ""})
    assert c.tags == []


def test_ioc_create_tags_list_passthrough():
    c = IOCCreate(**{**_BASE_CREATE, "tags": ["apt29", "c2"]})
    assert c.tags == ["apt29", "c2"]


def test_ioc_create_description_max_length_enforced():
    with pytest.raises(ValidationError):
        IOCCreate(**{**_BASE_CREATE, "description": "x" * 4097})


def test_ioc_create_description_max_boundary_accepted():
    c = IOCCreate(**{**_BASE_CREATE, "description": "x" * 4096})
    assert len(c.description) == 4096


def test_ioc_create_mitre_technique_id_max_length_enforced():
    with pytest.raises(ValidationError):
        IOCCreate(**{**_BASE_CREATE, "mitre_technique_id": "x" * 33})


def test_ioc_create_mitre_tactic_max_length_enforced():
    with pytest.raises(ValidationError):
        IOCCreate(**{**_BASE_CREATE, "mitre_tactic": "x" * 129})


def test_ioc_create_cve_id_max_length_enforced():
    with pytest.raises(ValidationError):
        IOCCreate(**{**_BASE_CREATE, "cve_id": "x" * 33})


def test_ioc_create_reference_max_length_enforced():
    with pytest.raises(ValidationError):
        IOCCreate(**{**_BASE_CREATE, "reference": "x" * 2049})


def test_ioc_create_confidence_below_min_rejected():
    with pytest.raises(ValidationError):
        IOCCreate(**{**_BASE_CREATE, "confidence": -0.1})


def test_ioc_create_confidence_above_max_rejected():
    with pytest.raises(ValidationError):
        IOCCreate(**{**_BASE_CREATE, "confidence": 1.1})


def test_ioc_create_confidence_boundaries_accepted():
    c_min = IOCCreate(**{**_BASE_CREATE, "confidence": 0.0})
    c_max = IOCCreate(**{**_BASE_CREATE, "confidence": 1.0})
    assert c_min.confidence == 0.0
    assert c_max.confidence == 1.0


def test_ioc_create_full_construction():
    ts = datetime(2026, 6, 16, 10, 0, 0, tzinfo=UTC)
    c = IOCCreate(
        ioc_type=IOCType.EMAIL,
        value="attacker@evil.example.com",
        source=IOCSource.CUSTOM_IOC,
        severity=IOCSeverity.HIGH,
        confidence=0.95,
        active=True,
        org_id="org-001",
        tags=["phishing", "spear"],
        description="Spear phishing sender address",
        mitre_technique_id="T1566",
        mitre_tactic="initial-access",
        cve_id=None,
        reference="https://example.com/intel",
        expiry=ts,
        feed_ingest_id="feed-001",
        extra={"campaign": "op-alpha"},
        first_seen=ts,
        last_seen=ts,
    )
    assert c.ioc_type == IOCType.EMAIL
    assert c.source == IOCSource.CUSTOM_IOC
    assert c.severity == IOCSeverity.HIGH
    assert c.tags == ["phishing", "spear"]
    assert c.mitre_technique_id == "T1566"
    assert c.extra == {"campaign": "op-alpha"}


@pytest.mark.parametrize("ioc_type", list(IOCType))
def test_ioc_create_all_ioc_types_accepted(ioc_type):
    c = IOCCreate(ioc_type=ioc_type, value="test-value")
    assert c.ioc_type == ioc_type


# ---------------------------------------------------------------------------
# IOCUpdate — at-least-one-field validator and partial field acceptance
# ---------------------------------------------------------------------------


def test_ioc_update_empty_payload_rejected():
    with pytest.raises(ValidationError):
        IOCUpdate()


def test_ioc_update_all_none_rejected():
    with pytest.raises(ValidationError):
        IOCUpdate(
            ioc_type=None,
            value=None,
            source=None,
            severity=None,
            confidence=None,
            active=None,
            org_id=None,
            tags=None,
            description=None,
            mitre_technique_id=None,
            mitre_tactic=None,
            cve_id=None,
            reference=None,
            expiry=None,
            extra=None,
            last_seen=None,
        )


def test_ioc_update_single_field_accepted():
    u = IOCUpdate(severity=IOCSeverity.CRITICAL)
    assert u.severity == IOCSeverity.CRITICAL


def test_ioc_update_active_field_accepted():
    u = IOCUpdate(active=False)
    assert u.active is False


def test_ioc_update_value_field_accepted():
    u = IOCUpdate(value="updated.malicious.com")
    assert u.value == "updated.malicious.com"


def test_ioc_update_confidence_field_accepted():
    u = IOCUpdate(confidence=0.5)
    assert u.confidence == 0.5


def test_ioc_update_value_min_length_enforced():
    with pytest.raises(ValidationError):
        IOCUpdate(value="")


def test_ioc_update_value_max_length_enforced():
    with pytest.raises(ValidationError):
        IOCUpdate(value="x" * 2049)


def test_ioc_update_description_max_length_enforced():
    with pytest.raises(ValidationError):
        IOCUpdate(description="x" * 4097)


def test_ioc_update_confidence_below_min_rejected():
    with pytest.raises(ValidationError):
        IOCUpdate(confidence=-0.1)


def test_ioc_update_confidence_above_max_rejected():
    with pytest.raises(ValidationError):
        IOCUpdate(confidence=1.1)


def test_ioc_update_tags_string_coercion():
    u = IOCUpdate(tags="apt29,c2")
    assert u.tags == ["apt29", "c2"]


def test_ioc_update_tags_list_passthrough():
    u = IOCUpdate(tags=["apt29", "c2"])
    assert u.tags == ["apt29", "c2"]


def test_ioc_update_partial_multiple_fields():
    ts = datetime(2026, 6, 16, 10, 0, 0, tzinfo=UTC)
    u = IOCUpdate(
        severity=IOCSeverity.HIGH,
        active=False,
        last_seen=ts,
        description="Updated description",
    )
    assert u.severity == IOCSeverity.HIGH
    assert u.active is False
    assert u.last_seen == ts
    assert u.description == "Updated description"
    assert u.ioc_type is None
    assert u.value is None
    assert u.confidence is None


def test_ioc_update_unset_fields_not_in_model_dump_exclude_unset():
    u = IOCUpdate(active=True)
    dumped = u.model_dump(exclude_unset=True)
    assert "active" in dumped
    assert "severity" not in dumped
    assert "value" not in dumped


# ---------------------------------------------------------------------------
# IOCMatchResult — matched=True/False shapes with optional field defaults
# ---------------------------------------------------------------------------


def test_ioc_match_result_matched_true_minimal():
    r = IOCMatchResult(
        matched=True,
        ioc_id="ioc-001",
        ioc_type=IOCType.DOMAIN,
        value="malicious.example.com",
        severity=IOCSeverity.HIGH,
        confidence=0.95,
    )
    assert r.matched is True
    assert r.ioc_id == "ioc-001"
    assert r.ioc_type == IOCType.DOMAIN
    assert r.value == "malicious.example.com"
    assert r.severity == IOCSeverity.HIGH
    assert r.confidence == 0.95


def test_ioc_match_result_matched_false_minimal():
    r = IOCMatchResult(matched=False)
    assert r.matched is False
    assert r.ioc_id is None
    assert r.ioc_type is None
    assert r.value is None
    assert r.source is None
    assert r.severity is None
    assert r.confidence is None
    assert r.tags == []
    assert r.mitre_technique_id is None
    assert r.mitre_tactic is None
    assert r.cve_id is None
    assert r.reference is None
    assert r.matched_on is None
    assert r.first_seen is None
    assert r.last_seen is None
    assert r.extra == {}


def test_ioc_match_result_missing_matched_rejected():
    with pytest.raises(ValidationError):
        IOCMatchResult()


def test_ioc_match_result_tags_default_empty_list():
    r = IOCMatchResult(matched=True)
    assert r.tags == []


def test_ioc_match_result_extra_default_empty_dict():
    r = IOCMatchResult(matched=True)
    assert r.extra == {}


def test_ioc_match_result_confidence_below_min_rejected():
    with pytest.raises(ValidationError):
        IOCMatchResult(matched=True, confidence=-0.1)


def test_ioc_match_result_confidence_above_max_rejected():
    with pytest.raises(ValidationError):
        IOCMatchResult(matched=True, confidence=1.1)


def test_ioc_match_result_confidence_boundaries_accepted():
    r_min = IOCMatchResult(matched=True, confidence=0.0)
    r_max = IOCMatchResult(matched=True, confidence=1.0)
    assert r_min.confidence == 0.0
    assert r_max.confidence == 1.0


def test_ioc_match_result_full_matched_shape():
    ts = datetime(2026, 6, 16, 10, 0, 0, tzinfo=UTC)
    r = IOCMatchResult(
        matched=True,
        ioc_id="ioc-007",
        ioc_type=IOCType.IP,
        value="10.0.0.99",
        source=IOCSource.STIX_TAXII,
        severity=IOCSeverity.CRITICAL,
        confidence=1.0,
        tags=["c2", "botnet"],
        mitre_technique_id="T1071",
        mitre_tactic="command-and-control",
        cve_id="CVE-2024-9999",
        reference="https://example.com/intel",
        matched_on="ip",
        first_seen=ts,
        last_seen=ts,
        extra={"tlp": "red", "actor": "apt29"},
    )
    assert r.matched is True
    assert r.ioc_id == "ioc-007"
    assert r.source == IOCSource.STIX_TAXII
    assert r.tags == ["c2", "botnet"]
    assert r.matched_on == "ip"
    assert r.extra["actor"] == "apt29"


# ---------------------------------------------------------------------------
# IOCQueryParams — limit/offset/confidence bounds
# ---------------------------------------------------------------------------


def test_ioc_query_params_defaults():
    q = IOCQueryParams()
    assert q.limit == 100
    assert q.offset == 0
    assert q.ioc_type is None
    assert q.source is None
    assert q.severity is None
    assert q.org_id is None
    assert q.active is None
    assert q.tag is None
    assert q.mitre_technique_id is None
    assert q.cve_id is None
    assert q.value_contains is None
    assert q.confidence_min is None
    assert q.confidence_max is None
    assert q.since is None
    assert q.until is None


def test_ioc_query_params_limit_min_boundary():
    q = IOCQueryParams(limit=1)
    assert q.limit == 1


def test_ioc_query_params_limit_max_boundary():
    q = IOCQueryParams(limit=1000)
    assert q.limit == 1000


def test_ioc_query_params_limit_below_min_rejected():
    with pytest.raises(ValidationError):
        IOCQueryParams(limit=0)


def test_ioc_query_params_limit_above_max_rejected():
    with pytest.raises(ValidationError):
        IOCQueryParams(limit=1001)


def test_ioc_query_params_offset_zero():
    q = IOCQueryParams(offset=0)
    assert q.offset == 0


def test_ioc_query_params_offset_positive():
    q = IOCQueryParams(offset=250)
    assert q.offset == 250


def test_ioc_query_params_offset_negative_rejected():
    with pytest.raises(ValidationError):
        IOCQueryParams(offset=-1)


def test_ioc_query_params_confidence_min_boundary():
    q = IOCQueryParams(confidence_min=0.0)
    assert q.confidence_min == 0.0


def test_ioc_query_params_confidence_max_boundary():
    q = IOCQueryParams(confidence_max=1.0)
    assert q.confidence_max == 1.0


def test_ioc_query_params_confidence_min_below_zero_rejected():
    with pytest.raises(ValidationError):
        IOCQueryParams(confidence_min=-0.1)


def test_ioc_query_params_confidence_min_above_one_rejected():
    with pytest.raises(ValidationError):
        IOCQueryParams(confidence_min=1.1)


def test_ioc_query_params_confidence_max_below_zero_rejected():
    with pytest.raises(ValidationError):
        IOCQueryParams(confidence_max=-0.1)


def test_ioc_query_params_confidence_max_above_one_rejected():
    with pytest.raises(ValidationError):
        IOCQueryParams(confidence_max=1.1)


def test_ioc_query_params_full_filter():
    since = datetime(2026, 1, 1, tzinfo=UTC)
    until = datetime(2026, 6, 16, tzinfo=UTC)
    q = IOCQueryParams(
        ioc_type=IOCType.IP,
        source=IOCSource.CISA_KEV,
        severity=IOCSeverity.CRITICAL,
        org_id="org-001",
        active=True,
        tag="c2",
        mitre_technique_id="T1071",
        cve_id="CVE-2024-1234",
        value_contains="192.168",
        confidence_min=0.7,
        confidence_max=1.0,
        since=since,
        until=until,
        limit=50,
        offset=10,
    )
    assert q.ioc_type == IOCType.IP
    assert q.source == IOCSource.CISA_KEV
    assert q.severity == IOCSeverity.CRITICAL
    assert q.confidence_min == 0.7
    assert q.confidence_max == 1.0
    assert q.since == since
    assert q.until == until
    assert q.limit == 50
    assert q.offset == 10


@pytest.mark.parametrize("ioc_type", list(IOCType))
def test_ioc_query_params_all_ioc_types(ioc_type):
    q = IOCQueryParams(ioc_type=ioc_type)
    assert q.ioc_type == ioc_type


@pytest.mark.parametrize("severity", list(IOCSeverity))
def test_ioc_query_params_all_severities(severity):
    q = IOCQueryParams(severity=severity)
    assert q.severity == severity


@pytest.mark.parametrize("source", list(IOCSource))
def test_ioc_query_params_all_sources(source):
    q = IOCQueryParams(source=source)
    assert q.source == source


# ---------------------------------------------------------------------------
# IOCListResponse — pagination shape
# ---------------------------------------------------------------------------


def test_ioc_list_response_empty():
    r = IOCListResponse(count=0)
    assert r.count == 0
    assert r.total is None
    assert r.items == []


def test_ioc_list_response_with_items():
    item = IOCRecord(**_BASE_RECORD)
    r = IOCListResponse(count=1, total=1, items=[item])
    assert r.count == 1
    assert r.total == 1
    assert len(r.items) == 1
    assert r.items[0].ioc_id == "ioc-001"


def test_ioc_list_response_count_below_zero_rejected():
    with pytest.raises(ValidationError):
        IOCListResponse(count=-1)


def test_ioc_list_response_missing_count_rejected():
    with pytest.raises(ValidationError):
        IOCListResponse()


def test_ioc_list_response_total_is_optional():
    r = IOCListResponse(count=5)
    assert r.total is None


def test_ioc_list_response_multiple_items():
    item1 = IOCRecord(**{**_BASE_RECORD, "ioc_id": "ioc-001"})
    item2 = IOCRecord(**{**_BASE_RECORD, "ioc_id": "ioc-002", "ioc_type": IOCType.IP, "value": "10.0.0.1"})
    r = IOCListResponse(count=2, total=2, items=[item1, item2])
    assert r.count == 2
    assert r.items[1].ioc_type == IOCType.IP


def test_ioc_list_response_items_default_empty():
    r = IOCListResponse(count=0, total=0)
    assert r.items == []


# ---------------------------------------------------------------------------
# IOCRecordResponse — ok/error shape
# ---------------------------------------------------------------------------


def test_ioc_record_response_success():
    r = IOCRecordResponse(ok=True, ioc_id="ioc-001")
    assert r.ok is True
    assert r.ioc_id == "ioc-001"
    assert r.error is None


def test_ioc_record_response_failure():
    r = IOCRecordResponse(ok=False, error="IOC record not found")
    assert r.ok is False
    assert r.ioc_id is None
    assert r.error == "IOC record not found"


def test_ioc_record_response_missing_ok_rejected():
    with pytest.raises(ValidationError):
        IOCRecordResponse()


def test_ioc_record_response_defaults():
    r = IOCRecordResponse(ok=True)
    assert r.ioc_id is None
    assert r.error is None


def test_ioc_record_response_ok_false_no_error():
    r = IOCRecordResponse(ok=False)
    assert r.ok is False
    assert r.error is None


# ---------------------------------------------------------------------------
# IOCAccessCountsSchema — defaults and full construction
# ---------------------------------------------------------------------------


def test_ioc_access_counts_defaults():
    c = IOCAccessCountsSchema()
    assert c.total_records == 0
    assert c.active_records == 0
    assert c.inactive_records == 0
    assert c.critical_iocs == 0
    assert c.high_iocs == 0
    assert c.matches_last_24h == 0
    assert c.latest_record_at == "Not yet recorded"


def test_ioc_access_counts_full():
    c = IOCAccessCountsSchema(
        total_records=500,
        active_records=450,
        inactive_records=50,
        critical_iocs=30,
        high_iocs=80,
        matches_last_24h=12,
        latest_record_at="2026-06-16T10:00:00Z",
    )
    assert c.total_records == 500
    assert c.active_records == 450
    assert c.inactive_records == 50
    assert c.critical_iocs == 30
    assert c.high_iocs == 80
    assert c.matches_last_24h == 12
    assert c.latest_record_at == "2026-06-16T10:00:00Z"


# ---------------------------------------------------------------------------
# IOCAccessControlsSchema — defaults and full construction
# ---------------------------------------------------------------------------


def test_ioc_access_controls_defaults():
    c = IOCAccessControlsSchema()
    assert c.org_scoping_enabled is False
    assert c.expiry_enforcement_enabled is False
    assert c.confidence_threshold_enforced is False
    assert c.feed_ingest_tracked is False
    assert c.audit_on_match is False


def test_ioc_access_controls_all_enabled():
    c = IOCAccessControlsSchema(
        org_scoping_enabled=True,
        expiry_enforcement_enabled=True,
        confidence_threshold_enforced=True,
        feed_ingest_tracked=True,
        audit_on_match=True,
    )
    assert all(
        [
            c.org_scoping_enabled,
            c.expiry_enforcement_enabled,
            c.confidence_threshold_enforced,
            c.feed_ingest_tracked,
            c.audit_on_match,
        ]
    )


# ---------------------------------------------------------------------------
# IOCAccessSummaryResponse — required-field enforcement and defaults
# ---------------------------------------------------------------------------

_BASE_SUMMARY: dict[str, Any] = dict(
    pageid="ioc-access-001",
    title="IOC Access Summary",
    path="/ioc",
    summary="Access summary for IOC store layer",
    generatedat="2026-06-16T10:00:00Z",
)


def test_ioc_access_summary_response_minimal():
    r = IOCAccessSummaryResponse(**_BASE_SUMMARY)
    assert r.pageid == "ioc-access-001"
    assert r.title == "IOC Access Summary"
    assert r.path == "/ioc"
    assert r.summary == "Access summary for IOC store layer"
    assert r.generatedat == "2026-06-16T10:00:00Z"
    assert r.accessavailable is False
    assert r.ioc_store_ready is False
    assert r.match_engine_connected is False
    assert r.recent_matches == []
    assert r.metadata == {}
    assert isinstance(r.counts, IOCAccessCountsSchema)
    assert isinstance(r.controls, IOCAccessControlsSchema)


def test_ioc_access_summary_response_required_fields_enforced():
    for missing_field in ["pageid", "title", "path", "summary", "generatedat"]:
        payload = {k: v for k, v in _BASE_SUMMARY.items() if k != missing_field}
        with pytest.raises(ValidationError):
            IOCAccessSummaryResponse(**payload)


def test_ioc_access_summary_response_nested_defaults():
    r = IOCAccessSummaryResponse(**_BASE_SUMMARY)
    assert r.counts.total_records == 0
    assert r.counts.latest_record_at == "Not yet recorded"
    assert r.controls.org_scoping_enabled is False
    assert r.controls.audit_on_match is False


def test_ioc_access_summary_response_full():
    counts = IOCAccessCountsSchema(
        total_records=300,
        active_records=280,
        critical_iocs=15,
        matches_last_24h=7,
    )
    controls = IOCAccessControlsSchema(
        org_scoping_enabled=True,
        audit_on_match=True,
        confidence_threshold_enforced=True,
    )
    r = IOCAccessSummaryResponse(
        **_BASE_SUMMARY,
        accessavailable=True,
        ioc_store_ready=True,
        match_engine_connected=True,
        counts=counts,
        controls=controls,
        recent_matches=[{"ioc_id": "ioc-001", "matched_on": "domain", "severity": "high"}],
        metadata={"env": "production", "version": "2.0"},
    )
    assert r.accessavailable is True
    assert r.ioc_store_ready is True
    assert r.match_engine_connected is True
    assert r.counts.total_records == 300
    assert r.counts.critical_iocs == 15
    assert r.controls.audit_on_match is True
    assert len(r.recent_matches) == 1
    assert r.recent_matches[0]["matched_on"] == "domain"
    assert r.metadata["env"] == "production"


def test_ioc_access_summary_response_recent_matches_default_empty():
    r = IOCAccessSummaryResponse(**_BASE_SUMMARY)
    assert r.recent_matches == []


def test_ioc_access_summary_response_metadata_default_empty():
    r = IOCAccessSummaryResponse(**_BASE_SUMMARY)
    assert r.metadata == {}
