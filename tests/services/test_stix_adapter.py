"""
Tests for app.services.stix_adapter

Covers:
- _extract_mitre_from_labels normalization & tactic extraction
- _parse_stix_indicator producing IOCRecord with mitre fields and extras
- _parse_stix_sco producing IOCRecord with mitre fields and extras
- parse_stix_bundle integration for a small bundle

These tests are self-contained and do not call network endpoints.
"""

from __future__ import annotations

from datetime import datetime

from app.schemas.threat_detection import IOCTypeEnum, ThreatFeedSourceEnum
from app.services.stix_adapter import (
    _extract_mitre_from_labels,
    _parse_stix_indicator,
    _parse_stix_sco,
    parse_stix_bundle,
)
from app.services.threat_feed_ingestion import IOCRecord


def test_extract_mitre_from_labels_technique_only():
    labels = ["some label", "this contains t1059 somewhere"]
    tech, tactic = _extract_mitre_from_labels(labels)
    assert tech == "T1059"
    assert tactic is None


def test_extract_mitre_from_labels_with_exact_tactic_label():
    labels = ["Initial Access", "other"]
    tech, tactic = _extract_mitre_from_labels(labels)
    assert tech is None
    assert tactic == "initial-access"


def test_extract_mitre_from_labels_with_mitre_prefixed_tactic():
    labels = ["mitre:privilege escalation", "T1078"]
    tech, tactic = _extract_mitre_from_labels(labels)
    assert tech == "T1078"
    # normalized to lowercase + hyphen
    assert tactic == "privilege-escalation"


def test_parse_stix_indicator_produces_mitre_fields_and_extras():
    now = datetime.utcnow().isoformat() + "Z"
    indicator = {
        "type": "indicator",
        "id": "indicator--1",
        "name": "Test Indicator",
        "labels": ["some-label", "t1078", "Initial Access"],
        "pattern": "[ipv4-addr:value = '1.2.3.4']",
        "pattern_type": "stix",
        "confidence": 90,
        "valid_from": now,
        "valid_until": None,
    }

    records = _parse_stix_indicator(
        indicator,
        stix_id=indicator["id"],
        ingest_id="ingest-test",
        org_id=None,
        now=now,
        source=ThreatFeedSourceEnum.STIX_TAXII,
        feed_source_label="unit-test",
    )

    assert isinstance(records, list)
    assert len(records) == 1
    rec: IOCRecord = records[0]

    # Value should be the IPv4 string
    assert rec.value == "1.2.3.4"
    # MITRE technique normalized to uppercase
    assert rec.mitre_technique_id == "T1078"
    # Tactic normalized lower-hyphen
    assert rec.mitre_tactic == "initial-access"
    # Extras should include mitre fields
    assert rec.extra.get("mitre_technique_id") == "T1078"
    assert rec.extra.get("mitre_tactic") == "initial-access"
    # Tag mitre-attack present
    assert "mitre-attack" in rec.tags


def test_parse_stix_sco_file_hash_with_mitre_labels():
    # file SCO with SHA256 and labels including a technique and a tactic variant
    file_hash = "a" * 64
    obj = {
        "type": "file",
        "id": "file--1",
        "hashes": {"SHA-256": file_hash},
        "labels": ["T1059", "Privilege Escalation"],
        "confidence": 80,
        "name": "malicious binary",
    }

    rec = _parse_stix_sco(
        obj=obj,
        stix_id=obj["id"],
        ioc_type=IOCTypeEnum.SHA256,
        raw_value=file_hash,
        ingest_id="ingest-test",
        org_id=None,
        now="2023-01-01T00:00:00Z",
        source=ThreatFeedSourceEnum.STIX_TAXII,
        feed_source_label="unit-test",
    )

    assert isinstance(rec, IOCRecord)
    # hash value preserved (normalization in threat_feed_ingestion may lowercase)
    assert rec.value.lower() == file_hash.lower()
    # MITRE technique normalized
    assert rec.mitre_technique_id == "T1059"
    # Tactic normalized to hyphenated lowercase
    assert rec.mitre_tactic == "privilege-escalation"
    # Extra contains mitre entries
    assert rec.extra.get("mitre_technique_id") == "T1059"
    assert rec.extra.get("mitre_tactic") == "privilege-escalation"
    assert "mitre-attack" in rec.tags


def test_parse_stix_bundle_integration_multiple_objects():
    bundle = {
        "type": "bundle",
        "id": "bundle--1",
        "objects": [
            # indicator -> should yield one record
            {
                "type": "indicator",
                "id": "indicator--1",
                "labels": ["t1078", "initial-access"],
                "pattern": "[ipv4-addr:value = '2.2.2.2']",
                "pattern_type": "stix",
                "confidence": 50,
                "name": "Indicator 1",
            },
            # ipv4 SCO -> should yield one record
            {"type": "ipv4-addr", "id": "ipv4--1", "value": "3.3.3.3", "labels": [], "confidence": 50},
            # irrelevant type should be skipped
            {"type": "relationship", "id": "rel--1"},
        ],
    }

    result = parse_stix_bundle(bundle, ingest_id="ingest-x", org_id=None, source_label="unit-test")
    assert hasattr(result, "records")
    # two records expected (indicator produced 1, ipv4-addr produced 1)
    assert len(result.records) == 2
    # ensure bundle_id propagated
    assert result.bundle_id == "bundle--1"
    # confirm one of the records contains the mitre technique from the indicator
    mitre_present = any(getattr(r, "mitre_technique_id", None) == "T1078" for r in result.records)
    assert mitre_present
