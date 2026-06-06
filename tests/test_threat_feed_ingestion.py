from __future__ import annotations

from collections.abc import Generator
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch
import uuid

import pytest

from app.services.threat_feed_ingestion import (
    FeedIngestResult,
    IngestStatusEnum,
    IOCFilterRequest,
    IOCRecord,
    IOCTypeEnum,
    ThreatFeedIngestionService,
    ThreatFeedSourceEnum,
    ThreatSeverityLevel,
    _detect_ioc_type,
    _normalize_value,
    _parse_cisa_kev,
    _parse_custom_ioc_csv,
    _parse_custom_ioc_json,
    _parse_mitre_attack,
    _sha256_hex,
    get_threat_feed_service,
    reset_threat_feed_service,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _make_ioc_record(
    *,
    value: str = "198.51.100.1",
    ioc_type: str = IOCTypeEnum.IPV4,
    severity: str = ThreatSeverityLevel.HIGH,
    source: str = ThreatFeedSourceEnum.CUSTOM_IOC,
    confidence: float = 0.9,
    tags: list[str] | None = None,
    org_id: str | None = None,
    ingest_id: str = "ingest-test",
) -> IOCRecord:
    now = _utc_now()
    fingerprint = _sha256_hex(f"{source}:{org_id or 'global'}:{value}")
    ioc_id = f"ioc-{fingerprint[:16]}"
    return IOCRecord(
        ioc_id=ioc_id,
        ioc_type=ioc_type,
        value=value,
        source=source,
        severity=severity,
        confidence=confidence,
        tags=tags or ["custom-ioc"],
        description="test ioc",
        org_id=org_id,
        mitre_technique_id=None,
        mitre_tactic=None,
        cve_id=None,
        first_seen=now,
        last_seen=now,
        expiry=None,
        active=True,
        feed_ingest_id=ingest_id,
        extra={},
    )


def _make_mock_store(
    *,
    bulk_upsert_return: tuple[int, int, int] = (1, 0, 0),
    persist_ingest_return: bool = True,
    get_ioc_return: IOCRecord | None = None,
    lookup_by_value_return: list[IOCRecord] | None = None,
    count_iocs_return: int = 0,
) -> MagicMock:
    store = MagicMock()
    store.bulk_upsert.return_value = bulk_upsert_return
    store.persist_ingest_result.return_value = persist_ingest_return
    store.get_ioc.return_value = get_ioc_return
    store.lookup_by_value.return_value = lookup_by_value_return or []
    store.lookup_by_cve.return_value = []
    store.lookup_by_mitre_technique.return_value = []
    store.filter_iocs.return_value = []
    store.deactivate_ioc.return_value = True
    store.delete_ioc.return_value = True
    store.count_iocs.return_value = count_iocs_return
    store.list_ingest_history.return_value = []
    return store


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def mock_store() -> MagicMock:
    return _make_mock_store()


@pytest.fixture()
def svc(mock_store: MagicMock) -> Generator[ThreatFeedIngestionService, None, None]:
    """Fresh service with IOCStore fully mocked — no Supabase calls."""
    reset_threat_feed_service()
    service = get_threat_feed_service()
    service.reset()
    with patch("app.services.ioc_store.get_ioc_store", return_value=mock_store):
        yield service
    service.reset()


# ---------------------------------------------------------------------------
# Tests — IOC type detection
# ---------------------------------------------------------------------------


class TestDetectIOCType:
    def test_ipv4(self):
        assert _detect_ioc_type("192.168.1.1") == IOCTypeEnum.IPV4

    def test_ipv6(self):
        assert _detect_ioc_type("2001:db8::1") == IOCTypeEnum.IPV6

    def test_domain(self):
        assert _detect_ioc_type("evil.example.com") == IOCTypeEnum.DOMAIN

    def test_url_http(self):
        assert _detect_ioc_type("http://malicious.io/path") == IOCTypeEnum.URL

    def test_url_https(self):
        assert _detect_ioc_type("https://phishing.example.org") == IOCTypeEnum.URL

    def test_sha256(self):
        assert _detect_ioc_type("a" * 64) == IOCTypeEnum.SHA256

    def test_sha1(self):
        assert _detect_ioc_type("b" * 40) == IOCTypeEnum.SHA1

    def test_md5(self):
        assert _detect_ioc_type("c" * 32) == IOCTypeEnum.MD5

    def test_cve(self):
        assert _detect_ioc_type("CVE-2021-44228") == IOCTypeEnum.CVE

    def test_cve_lowercase(self):
        assert _detect_ioc_type("cve-2021-44228") == IOCTypeEnum.CVE

    def test_mitre_technique(self):
        assert _detect_ioc_type("T1059") == IOCTypeEnum.MITRE_TECHNIQUE

    def test_mitre_subtechnique(self):
        assert _detect_ioc_type("T1059.001") == IOCTypeEnum.MITRE_TECHNIQUE

    def test_email(self):
        assert _detect_ioc_type("attacker@evil.com") == IOCTypeEnum.EMAIL

    def test_unknown(self):
        assert _detect_ioc_type("not_an_ioc_$$") == IOCTypeEnum.UNKNOWN


# ---------------------------------------------------------------------------
# Tests — Value normalization
# ---------------------------------------------------------------------------


class TestNormalizeValue:
    def test_domain_lowercased(self):
        assert _normalize_value("EVIL.EXAMPLE.COM", IOCTypeEnum.DOMAIN) == "evil.example.com"

    def test_sha256_lowercased(self):
        assert _normalize_value("ABCD" * 16, IOCTypeEnum.SHA256) == ("abcd" * 16)

    def test_cve_uppercased(self):
        assert _normalize_value("cve-2021-44228", IOCTypeEnum.CVE) == "CVE-2021-44228"

    def test_mitre_uppercased(self):
        assert _normalize_value("t1059", IOCTypeEnum.MITRE_TECHNIQUE) == "T1059"

    def test_ip_unchanged(self):
        assert _normalize_value("198.51.100.1", IOCTypeEnum.IPV4) == "198.51.100.1"


# ---------------------------------------------------------------------------
# Tests — MITRE ATT&CK parser
# ---------------------------------------------------------------------------


class TestParseMitreAttack:
    def _bundle(self, objects: list[dict]) -> dict:
        return {"type": "bundle", "id": "bundle--1", "objects": objects}

    def _technique(
        self,
        mitre_id: str = "T1059",
        name: str = "Command Execution",
        *,
        revoked: bool = False,
        deprecated: bool = False,
    ) -> dict:
        return {
            "type": "attack-pattern",
            "id": f"attack-pattern--{uuid.uuid4()}",
            "name": name,
            "description": "Executes commands.",
            "revoked": revoked,
            "x_mitre_deprecated": deprecated,
            "external_references": [{"source_name": "mitre-attack", "external_id": mitre_id}],
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
            "x_mitre_platforms": ["Windows"],
            "x_mitre_data_sources": [],
            "x_mitre_detection": "",
            "x_mitre_permissions_required": [],
        }

    def test_parses_attack_pattern(self):
        records, errors = _parse_mitre_attack(self._bundle([self._technique("T1059")]), "ingest-test", None)
        assert len(records) == 1
        assert errors == []
        rec = records[0]
        assert rec.value == "T1059"
        assert rec.ioc_type == IOCTypeEnum.MITRE_TECHNIQUE
        assert rec.source == ThreatFeedSourceEnum.MITRE_ATTACK
        assert rec.mitre_technique_id == "T1059"
        assert rec.active is True
        assert rec.feed_ingest_id == "ingest-test"
        assert "mitre-attack" in rec.tags

    def test_skips_revoked(self):
        records, _ = _parse_mitre_attack(self._bundle([self._technique("T0001", revoked=True)]), "ingest-test", None)
        assert records == []

    def test_skips_deprecated(self):
        records, _ = _parse_mitre_attack(self._bundle([self._technique("T0002", deprecated=True)]), "ingest-test", None)
        assert records == []

    def test_skips_object_without_mitre_external_ref(self):
        obj = self._technique("T1059")
        obj["external_references"] = []
        records, _ = _parse_mitre_attack(self._bundle([obj]), "ingest-test", None)
        assert records == []

    def test_org_id_propagated(self):
        records, _ = _parse_mitre_attack(self._bundle([self._technique("T1059")]), "ingest-test", "org-abc")
        assert records[0].org_id == "org-abc"

    def test_empty_bundle(self):
        records, errors = _parse_mitre_attack({"objects": []}, "ingest-test", None)
        assert records == []
        assert errors == []

    def test_tactic_tag_present(self):
        records, _ = _parse_mitre_attack(self._bundle([self._technique("T1059")]), "ingest-test", None)
        assert "execution" in records[0].tags


# ---------------------------------------------------------------------------
# Tests — CISA KEV parser
# ---------------------------------------------------------------------------


class TestParseCisaKev:
    def _kev(self, vulns: list[dict]) -> dict:
        return {
            "catalogVersion": "2024.01",
            "dateReleased": "2024-01-01",
            "count": len(vulns),
            "vulnerabilities": vulns,
        }

    def _vuln(
        self,
        cve_id: str = "CVE-2021-44228",
        ransomware: str = "Known",
    ) -> dict:
        return {
            "cveID": cve_id,
            "vendorProject": "Apache",
            "product": "Log4j",
            "vulnerabilityName": "Log4Shell",
            "dateAdded": "2021-12-10",
            "shortDescription": "Remote code execution.",
            "requiredAction": "Apply update.",
            "dueDate": "2021-12-24",
            "knownRansomwareCampaignUse": ransomware,
        }

    def test_parses_cve(self):
        records, errors = _parse_cisa_kev(self._kev([self._vuln()]), "ingest-test", None)
        assert len(records) == 1
        assert errors == []
        rec = records[0]
        assert rec.value == "CVE-2021-44228"
        assert rec.ioc_type == IOCTypeEnum.CVE
        assert rec.source == ThreatFeedSourceEnum.CISA_KEV
        assert rec.cve_id == "CVE-2021-44228"
        assert "ransomware" in rec.tags
        assert rec.severity == ThreatSeverityLevel.CRITICAL

    def test_non_ransomware_is_high(self):
        records, _ = _parse_cisa_kev(
            self._kev([self._vuln("CVE-2022-0001", ransomware="Unknown")]),
            "ingest-test",
            None,
        )
        assert records[0].severity == ThreatSeverityLevel.HIGH
        assert "ransomware" not in records[0].tags

    def test_skips_invalid_cve_format(self):
        vuln = {
            "cveID": "NOTACVE",
            "vendorProject": "X",
            "product": "Y",
            "vulnerabilityName": "Z",
            "shortDescription": "",
            "requiredAction": "",
            "dueDate": "",
            "dateAdded": "",
            "knownRansomwareCampaignUse": "Unknown",
        }
        records, _ = _parse_cisa_kev(self._kev([vuln]), "ingest-test", None)
        assert records == []

    def test_org_id_propagated(self):
        records, _ = _parse_cisa_kev(self._kev([self._vuln()]), "ingest-test", "org-xyz")
        assert records[0].org_id == "org-xyz"

    def test_empty_vulnerabilities(self):
        records, errors = _parse_cisa_kev(self._kev([]), "ingest-test", None)
        assert records == []
        assert errors == []

    def test_cve_tag_present(self):
        records, _ = _parse_cisa_kev(self._kev([self._vuln()]), "ingest-test", None)
        assert "cisa-kev" in records[0].tags


# ---------------------------------------------------------------------------
# Tests — Custom IOC JSON parser
# ---------------------------------------------------------------------------


class TestParseCustomIocJson:
    def _entries(self, entries: list[dict]) -> list[dict]:
        return entries

    def _entry(
        self,
        value: str = "198.51.100.99",
        ioc_type: str = "ipv4",
        severity: str = "high",
    ) -> dict:
        return {
            "value": value,
            "ioc_type": ioc_type,
            "severity": severity,
            "confidence": 0.85,
            "tags": ["custom"],
            "description": "test entry",
        }

    def test_parses_entry(self):
        records, errors = _parse_custom_ioc_json(self._entries([self._entry()]), "ingest-test", None)
        assert len(records) == 1
        assert errors == []
        rec = records[0]
        assert rec.value == "198.51.100.99"
        assert rec.ioc_type == IOCTypeEnum.IPV4
        assert rec.source == ThreatFeedSourceEnum.CUSTOM_IOC
        assert rec.severity == ThreatSeverityLevel.HIGH
        assert rec.feed_ingest_id == "ingest-test"

    def test_skips_missing_value(self):
        entry = self._entry()
        del entry["value"]
        records, errors = _parse_custom_ioc_json(self._entries([entry]), "ingest-test", None)
        assert records == []
        assert len(errors) >= 1

    def test_org_id_propagated(self):
        records, _ = _parse_custom_ioc_json(self._entries([self._entry()]), "ingest-test", "org-abc")
        assert records[0].org_id == "org-abc"

    def test_empty_iocs_list(self):
        records, errors = _parse_custom_ioc_json([], "ingest-test", None)
        assert records == []
        assert errors == []

    def test_auto_detects_ioc_type_when_missing(self):
        entry = self._entry(value="CVE-2021-44228")
        entry.pop("ioc_type", None)
        records, _ = _parse_custom_ioc_json(self._entries([entry]), "ingest-test", None)
        assert len(records) == 1
        assert records[0].ioc_type == IOCTypeEnum.CVE


# ---------------------------------------------------------------------------
# Tests — Custom IOC CSV parser
# ---------------------------------------------------------------------------


class TestParseCustomIocCsv:
    def _csv(self, rows: list[str]) -> str:
        header = "value,ioc_type,severity,confidence,tags,description"
        return "\n".join([header] + rows)

    def test_parses_csv_row(self):
        csv_text = self._csv(["198.51.100.1,ipv4,high,0.9,custom,test ip"])
        records, errors = _parse_custom_ioc_csv(csv_text, "ingest-test", None)
        assert len(records) == 1
        assert errors == []
        rec = records[0]
        assert rec.value == "198.51.100.1"
        assert rec.ioc_type == IOCTypeEnum.IPV4
        assert rec.severity == ThreatSeverityLevel.HIGH
        assert "custom" in rec.tags

    def test_skips_empty_value_row(self):
        csv_text = self._csv([",ipv4,high,0.9,,empty value"])
        records, _ = _parse_custom_ioc_csv(csv_text, "ingest-test", None)
        assert records == []

    def test_empty_csv_body(self):
        csv_text = "value,ioc_type,severity,confidence,tags,description"
        records, errors = _parse_custom_ioc_csv(csv_text, "ingest-test", None)
        assert records == []
        assert errors == []

    def test_org_id_propagated(self):
        csv_text = self._csv(["evil.example.com,domain,medium,0.7,,test"])
        records, _ = _parse_custom_ioc_csv(csv_text, "ingest-test", "org-csv")
        assert records[0].org_id == "org-csv"

    def test_multiple_rows(self):
        csv_text = self._csv(
            [
                "198.51.100.1,ipv4,high,0.9,,ip one",
                "evil.example.com,domain,critical,0.99,,domain one",
            ]
        )
        records, errors = _parse_custom_ioc_csv(csv_text, "ingest-test", None)
        assert len(records) == 2
        assert errors == []


# ---------------------------------------------------------------------------
# Tests — ThreatFeedIngestionService.ingest_mitre_attack (store mock)
# ---------------------------------------------------------------------------


class TestIngestMitreAttackStoreIntegration:
    def _bundle(self, mitre_id: str = "T1059") -> dict:
        return {
            "type": "bundle",
            "objects": [
                {
                    "type": "attack-pattern",
                    "id": f"attack-pattern--{uuid.uuid4()}",
                    "name": "Command Execution",
                    "description": "desc",
                    "revoked": False,
                    "x_mitre_deprecated": False,
                    "external_references": [{"source_name": "mitre-attack", "external_id": mitre_id}],
                    "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
                    "x_mitre_platforms": [],
                    "x_mitre_data_sources": [],
                    "x_mitre_detection": "",
                    "x_mitre_permissions_required": [],
                }
            ],
        }

    def test_bulk_upsert_called_with_parsed_records(self, svc, mock_store):
        mock_store.bulk_upsert.return_value = (1, 0, 0)
        with patch(
            "app.services.threat_feed_ingestion._fetch_json",
            return_value=self._bundle("T1059"),
        ):
            svc.ingest_mitre_attack(org_id=None)
        mock_store.bulk_upsert.assert_called_once()
        records_arg = mock_store.bulk_upsert.call_args[0][0]
        assert len(records_arg) == 1
        assert records_arg[0].value == "T1059"
        assert records_arg[0].source == ThreatFeedSourceEnum.MITRE_ATTACK

    def test_persist_ingest_result_called_after_upsert(self, svc, mock_store):
        mock_store.bulk_upsert.return_value = (1, 0, 0)
        with patch(
            "app.services.threat_feed_ingestion._fetch_json",
            return_value=self._bundle("T1059"),
        ):
            svc.ingest_mitre_attack(org_id=None)
        mock_store.persist_ingest_result.assert_called_once()
        ingest_arg = mock_store.persist_ingest_result.call_args[0][0]
        assert isinstance(ingest_arg, FeedIngestResult)
        assert ingest_arg.source == ThreatFeedSourceEnum.MITRE_ATTACK
        assert ingest_arg.iocs_inserted == 1

    def test_result_reflects_upsert_counts(self, svc, mock_store):
        mock_store.bulk_upsert.return_value = (1, 2, 0)
        with patch(
            "app.services.threat_feed_ingestion._fetch_json",
            return_value=self._bundle("T1059"),
        ):
            result = svc.ingest_mitre_attack(org_id=None)
        assert result.iocs_inserted == 1
        assert result.iocs_updated == 2
        assert result.iocs_skipped == 0

    def test_store_not_called_on_empty_bundle(self, svc, mock_store):
        with patch(
            "app.services.threat_feed_ingestion._fetch_json",
            return_value={"type": "bundle", "objects": []},
        ):
            result = svc.ingest_mitre_attack(org_id=None)
        mock_store.bulk_upsert.assert_not_called()
        assert result.iocs_inserted == 0

    def test_parse_errors_recorded_in_result(self, svc, mock_store):
        bad_bundle = {
            "type": "bundle",
            "objects": [{"type": "attack-pattern", "id": "attack-pattern--bad"}],
        }
        with patch(
            "app.services.threat_feed_ingestion._fetch_json",
            return_value=bad_bundle,
        ):
            result = svc.ingest_mitre_attack(org_id=None)
        mock_store.bulk_upsert.assert_not_called()
        assert result.iocs_inserted == 0

    def test_org_id_forwarded_to_store_records(self, svc, mock_store):
        mock_store.bulk_upsert.return_value = (1, 0, 0)
        with patch(
            "app.services.threat_feed_ingestion._fetch_json",
            return_value=self._bundle("T1059"),
        ):
            svc.ingest_mitre_attack(org_id="org-mitre")
        records_arg = mock_store.bulk_upsert.call_args[0][0]
        assert records_arg[0].org_id == "org-mitre"

    def test_unused_result_not_assigned(self, svc, mock_store):
        mock_store.bulk_upsert.return_value = (1, 0, 0)
        with patch(
            "app.services.threat_feed_ingestion._fetch_json",
            return_value=self._bundle("T1059"),
        ):
            svc.ingest_mitre_attack(org_id=None)
        mock_store.bulk_upsert.assert_called_once()
        records_arg = mock_store.bulk_upsert.call_args[0][0]
        assert len(records_arg) == 1


# ---------------------------------------------------------------------------
# Tests — ThreatFeedIngestionService.ingest_cisa_kev (store mock)
# ---------------------------------------------------------------------------


class TestIngestCisaKevStoreIntegration:
    def _kev(self, cve_id: str = "CVE-2021-44228", ransomware: str = "Known") -> dict:
        return {
            "vulnerabilities": [
                {
                    "cveID": cve_id,
                    "vendorProject": "Apache",
                    "product": "Log4j",
                    "vulnerabilityName": "Log4Shell",
                    "dateAdded": "2021-12-10",
                    "shortDescription": "RCE.",
                    "requiredAction": "Patch.",
                    "dueDate": "2021-12-24",
                    "knownRansomwareCampaignUse": ransomware,
                }
            ]
        }

    def test_bulk_upsert_called_with_cve_record(self, svc, mock_store):
        mock_store.bulk_upsert.return_value = (1, 0, 0)
        with patch(
            "app.services.threat_feed_ingestion._fetch_json",
            return_value=self._kev(),
        ):
            svc.ingest_cisa_kev(org_id=None)
        mock_store.bulk_upsert.assert_called_once()
        records_arg = mock_store.bulk_upsert.call_args[0][0]
        assert records_arg[0].cve_id == "CVE-2021-44228"
        assert records_arg[0].source == ThreatFeedSourceEnum.CISA_KEV

    def test_persist_ingest_result_called(self, svc, mock_store):
        mock_store.bulk_upsert.return_value = (1, 0, 0)
        with patch(
            "app.services.threat_feed_ingestion._fetch_json",
            return_value=self._kev(),
        ):
            svc.ingest_cisa_kev(org_id=None)
        mock_store.persist_ingest_result.assert_called_once()
        arg = mock_store.persist_ingest_result.call_args[0][0]
        assert arg.source == ThreatFeedSourceEnum.CISA_KEV

    def test_result_reflects_upsert_counts(self, svc, mock_store):
        mock_store.bulk_upsert.return_value = (0, 1, 0)
        with patch(
            "app.services.threat_feed_ingestion._fetch_json",
            return_value=self._kev(),
        ):
            result = svc.ingest_cisa_kev(org_id=None)
        assert result.iocs_updated == 1

    def test_empty_kev_does_not_call_store(self, svc, mock_store):
        with patch(
            "app.services.threat_feed_ingestion._fetch_json",
            return_value={"vulnerabilities": []},
        ):
            result = svc.ingest_cisa_kev(org_id=None)
        mock_store.bulk_upsert.assert_not_called()
        assert result.iocs_inserted == 0

    def test_org_id_forwarded(self, svc, mock_store):
        mock_store.bulk_upsert.return_value = (1, 0, 0)
        with patch(
            "app.services.threat_feed_ingestion._fetch_json",
            return_value=self._kev(),
        ):
            svc.ingest_cisa_kev(org_id="org-kev")
        records_arg = mock_store.bulk_upsert.call_args[0][0]
        assert records_arg[0].org_id == "org-kev"


# ---------------------------------------------------------------------------
# Tests — ThreatFeedIngestionService.ingest_custom_ioc_json (store mock)
# ---------------------------------------------------------------------------


class TestIngestCustomJsonStoreIntegration:
    def _entries(self, value: str = "198.51.100.99") -> list[dict]:
        return [
            {
                "value": value,
                "ioc_type": "ipv4",
                "severity": "high",
                "confidence": 0.9,
                "tags": ["custom"],
                "description": "test",
            }
        ]

    def test_bulk_upsert_called(self, svc, mock_store):
        mock_store.bulk_upsert.return_value = (1, 0, 0)
        svc.ingest_custom_ioc_json(self._entries(), org_id=None)
        mock_store.bulk_upsert.assert_called_once()

    def test_persist_ingest_result_called(self, svc, mock_store):
        mock_store.bulk_upsert.return_value = (1, 0, 0)
        svc.ingest_custom_ioc_json(self._entries(), org_id=None)
        mock_store.persist_ingest_result.assert_called_once()

    def test_empty_iocs_does_not_call_store(self, svc, mock_store):
        svc.ingest_custom_ioc_json([], org_id=None)
        mock_store.bulk_upsert.assert_not_called()

    def test_org_id_forwarded(self, svc, mock_store):
        mock_store.bulk_upsert.return_value = (1, 0, 0)
        svc.ingest_custom_ioc_json(self._entries(), org_id="org-json")
        records_arg = mock_store.bulk_upsert.call_args[0][0]
        assert records_arg[0].org_id == "org-json"


# ---------------------------------------------------------------------------
# Tests — ThreatFeedIngestionService.ingest_custom_ioc_csv (store mock)
# ---------------------------------------------------------------------------


class TestIngestCustomCsvStoreIntegration:
    def _csv(self) -> str:
        return "value,ioc_type,severity,confidence,tags,description\n" "198.51.100.1,ipv4,high,0.9,custom,test ip\n"

    def test_bulk_upsert_called(self, svc, mock_store):
        mock_store.bulk_upsert.return_value = (1, 0, 0)
        svc.ingest_custom_ioc_csv(self._csv(), org_id=None)
        mock_store.bulk_upsert.assert_called_once()

    def test_persist_ingest_result_called(self, svc, mock_store):
        mock_store.bulk_upsert.return_value = (1, 0, 0)
        svc.ingest_custom_ioc_csv(self._csv(), org_id=None)
        mock_store.persist_ingest_result.assert_called_once()

    def test_empty_csv_does_not_call_store(self, svc, mock_store):
        svc.ingest_custom_ioc_csv("value,ioc_type,severity,confidence,tags,description", org_id=None)
        mock_store.bulk_upsert.assert_not_called()

    def test_org_id_forwarded(self, svc, mock_store):
        mock_store.bulk_upsert.return_value = (1, 0, 0)
        svc.ingest_custom_ioc_csv(self._csv(), org_id="org-csv")
        records_arg = mock_store.bulk_upsert.call_args[0][0]
        assert records_arg[0].org_id == "org-csv"


# ---------------------------------------------------------------------------
# Tests — FeedIngestResult dataclass
# ---------------------------------------------------------------------------


class TestFeedIngestResultDataclass:
    def _make(self, **kwargs) -> FeedIngestResult:
        defaults: dict = dict(
            ingest_id="ingest-001",
            source=ThreatFeedSourceEnum.MITRE_ATTACK,
            status=IngestStatusEnum.SUCCESS,
            iocs_parsed=10,
            iocs_inserted=8,
            iocs_updated=2,
            iocs_skipped=0,
            errors=[],
            started_at=_utc_now(),
            completed_at=_utc_now(),
            org_id=None,
            metadata={},
        )
        defaults.update(kwargs)
        return FeedIngestResult(**defaults)

    def test_success_status(self):
        r = self._make(errors=[], iocs_inserted=8)
        assert r.status == IngestStatusEnum.SUCCESS

    def test_partial_status(self):
        r = self._make(status=IngestStatusEnum.PARTIAL, errors=["parse error 1"])
        assert r.status == IngestStatusEnum.PARTIAL

    def test_failed_status(self):
        r = self._make(status=IngestStatusEnum.FAILED, iocs_inserted=0, errors=["bad row"])
        assert r.status == IngestStatusEnum.FAILED

    def test_to_dict_contains_required_keys(self):
        r = self._make(org_id="org-x")
        d = r.to_dict()
        for key in (
            "ingest_id",
            "source",
            "org_id",
            "iocs_parsed",
            "iocs_inserted",
            "iocs_updated",
            "iocs_skipped",
            "errors",
            "status",
            "started_at",
        ):
            assert key in d


# ---------------------------------------------------------------------------
# Tests — IOCRecord dataclass
# ---------------------------------------------------------------------------


class TestIOCRecordDataclass:
    def test_to_dict_contains_required_keys(self):
        rec = _make_ioc_record()
        d = rec.to_dict()
        for key in (
            "ioc_id",
            "ioc_type",
            "value",
            "source",
            "severity",
            "confidence",
            "tags",
            "org_id",
            "mitre_technique_id",
            "cve_id",
            "first_seen",
            "last_seen",
            "active",
            "feed_ingest_id",
        ):
            assert key in d

    def test_tags_are_copy(self):
        rec = _make_ioc_record(tags=["apt"])
        d = rec.to_dict()
        d["tags"].append("injected")
        assert "injected" not in rec.tags

    def test_extra_is_copy(self):
        rec = _make_ioc_record()
        d = rec.to_dict()
        if "extra" in d:
            d["extra"]["injected"] = True
            assert "injected" not in rec.extra


# ---------------------------------------------------------------------------
# Tests — IOCFilterRequest
# ---------------------------------------------------------------------------


class TestIOCFilterRequest:
    def test_default_construction(self):
        f = IOCFilterRequest()
        assert f.source is None
        assert f.ioc_type is None
        assert f.severity is None
        assert f.org_id is None
        assert f.active is None
        assert f.tag is None

    def test_partial_filter(self):
        f = IOCFilterRequest(source=ThreatFeedSourceEnum.CISA_KEV, active=True)
        assert f.source == ThreatFeedSourceEnum.CISA_KEV
        assert f.active is True
        assert f.ioc_type is None


# ---------------------------------------------------------------------------
# Tests — Singleton lifecycle
# ---------------------------------------------------------------------------


class TestSingletonLifecycle:
    def test_get_threat_feed_service_returns_same_instance(self):
        reset_threat_feed_service()
        s1 = get_threat_feed_service()
        s2 = get_threat_feed_service()
        assert s1 is s2

    def test_reset_clears_state_not_instance(self):
        reset_threat_feed_service()
        s1 = get_threat_feed_service()
        reset_threat_feed_service()
        s2 = get_threat_feed_service()
        assert s1 is s2
