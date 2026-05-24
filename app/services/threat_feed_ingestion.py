from __future__ import annotations

from collections import deque
import csv
from dataclasses import dataclass, field
from datetime import UTC, datetime
import hashlib
import io
import ipaddress
import json
import logging
import re
import threading
from typing import TYPE_CHECKING, Any
import urllib.error
import urllib.request
from uuid import uuid4

from app.schemas.threat_detection import (
    IngestStatusEnum,
    IOCTypeEnum,
    ThreatFeedSourceEnum,
    ThreatSeverityLevel,
)

if TYPE_CHECKING:
    from app.services.stix_adapter import TAXIIConfig

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MITRE_ATTACK_ENTERPRISE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
_CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_DEFAULT_FETCH_TIMEOUT_SECONDS = 30
_MAX_IOC_STORE_SIZE = 50_000
_MAX_FEED_HISTORY_SIZE = 200
_IOC_ID_PREFIX = "ioc-"
_INGEST_ID_PREFIX = "ingest-"


# ---------------------------------------------------------------------------
# Backwards-compatible aliases — keep existing callers working
# ---------------------------------------------------------------------------

ThreatFeedSource = ThreatFeedSourceEnum
IOCType = IOCTypeEnum
ThreatSeverity = ThreatSeverityLevel
IngestStatus = IngestStatusEnum


# ---------------------------------------------------------------------------
# IOC record
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class IOCRecord:
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

    def to_dict(self) -> dict[str, Any]:
        return {
            "ioc_id": self.ioc_id,
            "ioc_type": self.ioc_type,
            "value": self.value,
            "source": self.source,
            "severity": self.severity,
            "confidence": self.confidence,
            "tags": list(self.tags),
            "description": self.description,
            "org_id": self.org_id,
            "mitre_technique_id": self.mitre_technique_id,
            "mitre_tactic": self.mitre_tactic,
            "cve_id": self.cve_id,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "expiry": self.expiry,
            "active": self.active,
            "feed_ingest_id": self.feed_ingest_id,
            "extra": dict(self.extra),
        }


# ---------------------------------------------------------------------------
# Ingest result
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class FeedIngestResult:
    ingest_id: str
    source: str
    status: str
    iocs_parsed: int
    iocs_inserted: int
    iocs_updated: int
    iocs_skipped: int
    errors: list[str]
    started_at: str
    completed_at: str | None
    org_id: str | None
    metadata: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "ingest_id": self.ingest_id,
            "source": self.source,
            "status": self.status,
            "iocs_parsed": self.iocs_parsed,
            "iocs_inserted": self.iocs_inserted,
            "iocs_updated": self.iocs_updated,
            "iocs_skipped": self.iocs_skipped,
            "errors": list(self.errors),
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "org_id": self.org_id,
            "metadata": dict(self.metadata),
        }


# ---------------------------------------------------------------------------
# IOC filter
# ---------------------------------------------------------------------------


@dataclass
class IOCFilterRequest:
    source: str | None = None
    ioc_type: str | None = None
    severity: str | None = None
    org_id: str | None = None
    active: bool | None = None
    tag: str | None = None
    mitre_technique_id: str | None = None
    cve_id: str | None = None
    value_contains: str | None = None
    limit: int = 100
    offset: int = 0


# ---------------------------------------------------------------------------
# Custom IOC upload input
# ---------------------------------------------------------------------------


@dataclass
class CustomIOCEntry:
    value: str
    ioc_type: str | None = None
    severity: str = ThreatSeverityLevel.MEDIUM
    confidence: float = 0.8
    tags: list[str] = field(default_factory=list)
    description: str = ""
    mitre_technique_id: str | None = None
    mitre_tactic: str | None = None
    cve_id: str | None = None
    expiry: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------


def _utcnow_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


_RE_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
_RE_SHA1 = re.compile(r"^[a-fA-F0-9]{40}$")
_RE_MD5 = re.compile(r"^[a-fA-F0-9]{32}$")
_RE_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_RE_MITRE_TECHNIQUE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)
_RE_MITRE_TACTIC = re.compile(
    r"^(initial-access|execution|persistence|privilege-escalation|defense-evasion|" r"credential-access|discovery|lateral-movement|collection|command-and-control|" r"exfiltration|impact|reconnaissance|resource-development)$",
    re.IGNORECASE,
)
_RE_DOMAIN = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
_RE_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_RE_URL = re.compile(r"^https?://", re.IGNORECASE)


def _detect_ioc_type(value: str) -> str:
    v = value.strip()
    if _RE_CVE.match(v):
        return IOCTypeEnum.CVE
    if _RE_MITRE_TECHNIQUE.match(v):
        return IOCTypeEnum.MITRE_TECHNIQUE
    if _RE_SHA256.match(v):
        return IOCTypeEnum.SHA256
    if _RE_SHA1.match(v):
        return IOCTypeEnum.SHA1
    if _RE_MD5.match(v):
        return IOCTypeEnum.MD5
    if _RE_URL.match(v):
        return IOCTypeEnum.URL
    if _RE_EMAIL.match(v):
        return IOCTypeEnum.EMAIL
    try:
        addr = ipaddress.ip_address(v)
        return IOCTypeEnum.IPV4 if addr.version == 4 else IOCTypeEnum.IPV6
    except ValueError:
        pass
    if _RE_DOMAIN.match(v):
        return IOCTypeEnum.DOMAIN
    return IOCTypeEnum.UNKNOWN


def _normalize_value(value: str, ioc_type: str) -> str:
    v = value.strip()
    if ioc_type in (IOCTypeEnum.DOMAIN,):
        return v.lower()
    if ioc_type in (IOCTypeEnum.SHA256, IOCTypeEnum.SHA1, IOCTypeEnum.MD5):
        return v.lower()
    if ioc_type in (IOCTypeEnum.CVE, IOCTypeEnum.MITRE_TECHNIQUE):
        return v.upper()
    return v


def _fetch_json(url: str, timeout: int = _DEFAULT_FETCH_TIMEOUT_SECONDS) -> dict[str, Any] | list[Any]:
    req = urllib.request.Request(url, headers={"User-Agent": "IronClaw-ThreatFeed/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read()
    return json.loads(raw.decode("utf-8", errors="replace"))


# ---------------------------------------------------------------------------
# MITRE ATT&CK parser
# ---------------------------------------------------------------------------


def _parse_mitre_attack(
    stix_bundle: dict[str, Any],
    ingest_id: str,
    org_id: str | None,
) -> tuple[list[IOCRecord], list[str]]:
    records: list[IOCRecord] = []
    errors: list[str] = []
    now = _utcnow_iso()
    objects = stix_bundle.get("objects", [])

    for obj in objects:
        try:
            obj_type = obj.get("type", "")
            if obj_type not in ("attack-pattern", "x-mitre-tactic"):
                continue

            stix_id: str = obj.get("id", "")
            name: str = obj.get("name", "")
            description_raw: str = obj.get("description", "")
            is_revoked: bool = obj.get("revoked", False)
            is_deprecated: bool = obj.get("x_mitre_deprecated", False)
            if is_revoked or is_deprecated:
                continue

            ext_refs: list[dict[str, Any]] = obj.get("external_references", [])
            mitre_id: str = ""
            for ref in ext_refs:
                if ref.get("source_name", "") in ("mitre-attack", "mitre-mobile-attack", "mitre-ics-attack"):
                    mitre_id = ref.get("external_id", "")
                    break

            if not mitre_id:
                continue

            if obj_type == "attack-pattern":
                ioc_type = IOCTypeEnum.MITRE_TECHNIQUE
                tactics: list[str] = [phase.get("phase_name", "") for phase in obj.get("kill_chain_phases", []) if phase.get("kill_chain_name", "").startswith("mitre")]
                tactic_str = tactics[0] if tactics else None
                platforms: list[str] = obj.get("x_mitre_platforms", [])
                extra: dict[str, Any] = {
                    "stix_id": stix_id,
                    "platforms": platforms,
                    "data_sources": obj.get("x_mitre_data_sources", []),
                    "detection": obj.get("x_mitre_detection", ""),
                    "permissions_required": obj.get("x_mitre_permissions_required", []),
                }
                severity = ThreatSeverityLevel.HIGH
                tags = ["mitre-attack", "technique"] + [t for t in tactics if t]
            else:
                ioc_type = IOCTypeEnum.MITRE_TACTIC
                tactic_str = obj.get("x_mitre_shortname", name.lower().replace(" ", "-"))
                extra = {"stix_id": stix_id}
                severity = ThreatSeverityLevel.MEDIUM
                tags = ["mitre-attack", "tactic"]

            ioc_id = f"{_IOC_ID_PREFIX}{_sha256_hex('mitre:' + mitre_id)[:16]}"
            value = _normalize_value(mitre_id, ioc_type)

            records.append(
                IOCRecord(
                    ioc_id=ioc_id,
                    ioc_type=ioc_type,
                    value=value,
                    source=ThreatFeedSourceEnum.MITRE_ATTACK,
                    severity=severity,
                    confidence=1.0,
                    tags=tags,
                    description=description_raw[:1024],
                    org_id=org_id,
                    mitre_technique_id=mitre_id if ioc_type == IOCTypeEnum.MITRE_TECHNIQUE else None,
                    mitre_tactic=tactic_str,
                    cve_id=None,
                    first_seen=now,
                    last_seen=now,
                    expiry=None,
                    active=True,
                    feed_ingest_id=ingest_id,
                    extra=extra,
                )
            )
        except Exception as exc:  # noqa: BLE001
            errors.append(f"mitre_parse_error stix_id={obj.get('id', '?')}: {exc}")

    return records, errors


# ---------------------------------------------------------------------------
# CISA KEV parser
# ---------------------------------------------------------------------------


def _parse_cisa_kev(
    kev_data: dict[str, Any],
    ingest_id: str,
    org_id: str | None,
) -> tuple[list[IOCRecord], list[str]]:
    records: list[IOCRecord] = []
    errors: list[str] = []
    now = _utcnow_iso()
    vulnerabilities: list[dict[str, Any]] = kev_data.get("vulnerabilities", [])

    for vuln in vulnerabilities:
        try:
            cve_id: str = vuln.get("cveID", "").strip()
            if not cve_id or not _RE_CVE.match(cve_id):
                continue

            vendor: str = vuln.get("vendorProject", "")
            product: str = vuln.get("product", "")
            vuln_name: str = vuln.get("vulnerabilityName", "")
            date_added: str = vuln.get("dateAdded", "")
            short_desc: str = vuln.get("shortDescription", "")
            required_action: str = vuln.get("requiredAction", "")
            due_date: str = vuln.get("dueDate", "")
            known_ransomware: str = vuln.get("knownRansomwareCampaignUse", "Unknown")

            severity = ThreatSeverityLevel.CRITICAL if known_ransomware.lower() == "known" else ThreatSeverityLevel.HIGH

            tags = ["cisa-kev", "cve", "exploited-in-wild"]
            if known_ransomware.lower() == "known":
                tags.append("ransomware")

            ioc_id = f"{_IOC_ID_PREFIX}{_sha256_hex('kev:' + cve_id)[:16]}"
            value = _normalize_value(cve_id, IOCTypeEnum.CVE)

            records.append(
                IOCRecord(
                    ioc_id=ioc_id,
                    ioc_type=IOCTypeEnum.CVE,
                    value=value,
                    source=ThreatFeedSourceEnum.CISA_KEV,
                    severity=severity,
                    confidence=1.0,
                    tags=tags,
                    description=f"{vuln_name}: {short_desc}"[:1024],
                    org_id=org_id,
                    mitre_technique_id=None,
                    mitre_tactic=None,
                    cve_id=value,
                    first_seen=now,
                    last_seen=now,
                    expiry=due_date or None,
                    active=True,
                    feed_ingest_id=ingest_id,
                    extra={
                        "vendor": vendor,
                        "product": product,
                        "date_added": date_added,
                        "required_action": required_action,
                        "due_date": due_date,
                        "known_ransomware_campaign_use": known_ransomware,
                    },
                )
            )
        except Exception as exc:  # noqa: BLE001
            errors.append(f"kev_parse_error cve={vuln.get('cveID', '?')}: {exc}")

    return records, errors


# ---------------------------------------------------------------------------
# Custom IOC parser (CSV + JSON)
# ---------------------------------------------------------------------------


def _parse_custom_ioc_json(
    raw: list[dict[str, Any]] | list[Any],
    ingest_id: str,
    org_id: str | None,
) -> tuple[list[IOCRecord], list[str]]:
    records: list[IOCRecord] = []
    errors: list[str] = []
    now = _utcnow_iso()

    for i, item in enumerate(raw):
        if not isinstance(item, dict):
            errors.append(f"row {i}: expected dict, got {type(item).__name__}")
            continue
        try:
            entry = _dict_to_custom_ioc_entry(item)
            record = _custom_ioc_entry_to_record(entry, ingest_id, org_id, now)
            if record is not None:
                records.append(record)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"row {i}: {exc}")

    return records, errors


def _parse_custom_ioc_csv(
    csv_text: str,
    ingest_id: str,
    org_id: str | None,
) -> tuple[list[IOCRecord], list[str]]:
    records: list[IOCRecord] = []
    errors: list[str] = []
    now = _utcnow_iso()

    try:
        reader = csv.DictReader(io.StringIO(csv_text.strip()))
    except Exception as exc:  # noqa: BLE001
        return [], [f"csv_parse_init_error: {exc}"]

    for i, row in enumerate(reader):
        try:
            entry = _dict_to_custom_ioc_entry(dict(row))
            record = _custom_ioc_entry_to_record(entry, ingest_id, org_id, now)
            if record is not None:
                records.append(record)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"csv_row {i}: {exc}")

    return records, errors


def _dict_to_custom_ioc_entry(item: dict[str, Any]) -> CustomIOCEntry:
    value = str(item.get("value", item.get("ioc", item.get("indicator", "")))).strip()
    if not value:
        raise ValueError("missing required field: value / ioc / indicator")

    raw_type = item.get("ioc_type", item.get("type", ""))
    ioc_type = str(raw_type).strip() if raw_type else None

    severity_raw = str(item.get("severity", ThreatSeverityLevel.MEDIUM)).strip().lower()
    try:
        severity = ThreatSeverityLevel(severity_raw)
    except ValueError:
        severity = ThreatSeverityLevel.MEDIUM

    confidence_raw = item.get("confidence", 0.8)
    try:
        confidence = float(confidence_raw)
        confidence = max(0.0, min(1.0, confidence))
    except (TypeError, ValueError):
        confidence = 0.8

    tags_raw = item.get("tags", "")
    if isinstance(tags_raw, list):
        tags = [str(t).strip() for t in tags_raw if str(t).strip()]
    else:
        tags = [t.strip() for t in str(tags_raw).split(",") if t.strip()]

    extra_raw = item.get("extra", item.get("metadata", {}))
    if isinstance(extra_raw, str):
        try:
            extra = json.loads(extra_raw)
        except json.JSONDecodeError:
            extra = {}
    elif isinstance(extra_raw, dict):
        extra = extra_raw
    else:
        extra = {}

    return CustomIOCEntry(
        value=value,
        ioc_type=ioc_type if ioc_type else None,
        severity=severity,
        confidence=confidence,
        tags=tags,
        description=str(item.get("description", ""))[:1024],
        mitre_technique_id=item.get("mitre_technique_id") or None,
        mitre_tactic=item.get("mitre_tactic") or None,
        cve_id=item.get("cve_id") or None,
        expiry=item.get("expiry") or None,
        extra=extra,
    )


def _custom_ioc_entry_to_record(
    entry: CustomIOCEntry,
    ingest_id: str,
    org_id: str | None,
    now: str,
) -> IOCRecord | None:
    if not entry.value:
        return None

    ioc_type = entry.ioc_type or _detect_ioc_type(entry.value)
    try:
        ioc_type = IOCTypeEnum(ioc_type)
    except ValueError:
        ioc_type = IOCTypeEnum.UNKNOWN

    value = _normalize_value(entry.value, ioc_type)
    scope = org_id if org_id is not None else "global"
    ioc_id = f"{_IOC_ID_PREFIX}{_sha256_hex('custom:' + scope + ':' + value)[:16]}"

    tags = list(entry.tags) + ["custom-ioc"]
    if entry.cve_id:
        tags.append("cve")
    if entry.mitre_technique_id:
        tags.append("mitre-attack")

    return IOCRecord(
        ioc_id=ioc_id,
        ioc_type=ioc_type,
        value=value,
        source=ThreatFeedSourceEnum.CUSTOM_IOC,
        severity=entry.severity,
        confidence=entry.confidence,
        tags=tags,
        description=entry.description,
        org_id=org_id,
        mitre_technique_id=entry.mitre_technique_id,
        mitre_tactic=entry.mitre_tactic,
        cve_id=entry.cve_id or (value if ioc_type == IOCTypeEnum.CVE else None),
        first_seen=now,
        last_seen=now,
        expiry=entry.expiry,
        active=True,
        feed_ingest_id=ingest_id,
        extra=dict(entry.extra),
    )


# ---------------------------------------------------------------------------
# ThreatFeedIngestionService
# ---------------------------------------------------------------------------


class ThreatFeedIngestionService:
    """
    Ingestion engine for IronClaw Threat Intelligence.

    Responsibilities:
    - Fetch and parse MITRE ATT&CK STIX bundle (enterprise attack patterns + tactics).
    - Fetch and parse CISA Known Exploited Vulnerabilities (KEV) catalog.
    - Ingest custom IOC lists via JSON array or CSV upload.
    - Deduplicate IOCs by deterministic ioc_id (sha256 of source:value).
    - Persist IOCs to Supabase via IOCStore (source of truth).
    - Maintain an optional bounded in-memory hot-cache for sub-millisecond lookups.
    - Maintain per-ingest result history in-memory and persist to Supabase.
    - Provide lookup, filtering, enrichment query, and deactivation APIs
      delegated to IOCStore as the authoritative backing store.

    Enum contracts are owned by app.schemas.threat_detection.
    """

    def __init__(
        self,
        *,
        max_ioc_store: int = _MAX_IOC_STORE_SIZE,
        max_feed_history: int = _MAX_FEED_HISTORY_SIZE,
        fetch_timeout: int = _DEFAULT_FETCH_TIMEOUT_SECONDS,
        mitre_url: str = _MITRE_ATTACK_ENTERPRISE_URL,
        cisa_kev_url: str = _CISA_KEV_URL,
    ) -> None:
        self._lock = threading.Lock()
        self._iocs: dict[str, IOCRecord] = {}
        self._ioc_order: deque[str] = deque()
        self._max_ioc_store = max_ioc_store
        self._ingest_history: deque[FeedIngestResult] = deque(maxlen=max_feed_history)
        self._fetch_timeout = fetch_timeout
        self._mitre_url = mitre_url
        self._cisa_kev_url = cisa_kev_url

    @staticmethod
    def _store():
        from app.services.ioc_store import get_ioc_store  # noqa: PLC0415

        return get_ioc_store()

    def ingest_mitre_attack(
        self,
        *,
        org_id: str | None = None,
        url: str | None = None,
    ) -> FeedIngestResult:
        ingest_id = f"{_INGEST_ID_PREFIX}{uuid4().hex[:20]}"
        started_at = _utcnow_iso()
        target_url = url or self._mitre_url

        logger.info("threat_feed.mitre_attack.start ingest_id=%s", ingest_id)

        try:
            raw = _fetch_json(target_url, timeout=self._fetch_timeout)
        except urllib.error.URLError as exc:
            return self._fail_result(ingest_id, ThreatFeedSourceEnum.MITRE_ATTACK, org_id, started_at, f"fetch_error: {exc}")
        except Exception as exc:  # noqa: BLE001
            return self._fail_result(ingest_id, ThreatFeedSourceEnum.MITRE_ATTACK, org_id, started_at, f"unexpected: {exc}")

        if not isinstance(raw, dict):
            return self._fail_result(ingest_id, ThreatFeedSourceEnum.MITRE_ATTACK, org_id, started_at, "unexpected_response_type: not a JSON object")

        records, errors = _parse_mitre_attack(raw, ingest_id, org_id)
        inserted, updated, skipped = self._upsert_iocs(records)

        result = FeedIngestResult(
            ingest_id=ingest_id,
            source=ThreatFeedSourceEnum.MITRE_ATTACK,
            status=IngestStatusEnum.SUCCESS if not errors else IngestStatusEnum.PARTIAL,
            iocs_parsed=len(records) + len(errors),
            iocs_inserted=inserted,
            iocs_updated=updated,
            iocs_skipped=skipped,
            errors=errors[:50],
            started_at=started_at,
            completed_at=_utcnow_iso(),
            org_id=org_id,
            metadata={"source_url": target_url, "bundle_type": raw.get("type", "")},
        )
        self._record_ingest(result)
        logger.info(
            "threat_feed.mitre_attack.done ingest_id=%s inserted=%d updated=%d errors=%d",
            ingest_id,
            inserted,
            updated,
            len(errors),
        )
        return result

    def ingest_cisa_kev(
        self,
        *,
        org_id: str | None = None,
        url: str | None = None,
    ) -> FeedIngestResult:
        ingest_id = f"{_INGEST_ID_PREFIX}{uuid4().hex[:20]}"
        started_at = _utcnow_iso()
        target_url = url or self._cisa_kev_url

        logger.info("threat_feed.cisa_kev.start ingest_id=%s", ingest_id)

        try:
            raw = _fetch_json(target_url, timeout=self._fetch_timeout)
        except urllib.error.URLError as exc:
            return self._fail_result(ingest_id, ThreatFeedSourceEnum.CISA_KEV, org_id, started_at, f"fetch_error: {exc}")
        except Exception as exc:  # noqa: BLE001
            return self._fail_result(ingest_id, ThreatFeedSourceEnum.CISA_KEV, org_id, started_at, f"unexpected: {exc}")

        if not isinstance(raw, dict):
            return self._fail_result(ingest_id, ThreatFeedSourceEnum.CISA_KEV, org_id, started_at, "unexpected_response_type: not a JSON object")

        records, errors = _parse_cisa_kev(raw, ingest_id, org_id)
        inserted, updated, skipped = self._upsert_iocs(records)

        catalog_version: str = raw.get("catalogVersion", "")
        date_released: str = raw.get("dateReleased", "")
        count: int = raw.get("count", 0)

        result = FeedIngestResult(
            ingest_id=ingest_id,
            source=ThreatFeedSourceEnum.CISA_KEV,
            status=IngestStatusEnum.SUCCESS if not errors else IngestStatusEnum.PARTIAL,
            iocs_parsed=len(records) + len(errors),
            iocs_inserted=inserted,
            iocs_updated=updated,
            iocs_skipped=skipped,
            errors=errors[:50],
            started_at=started_at,
            completed_at=_utcnow_iso(),
            org_id=org_id,
            metadata={
                "source_url": target_url,
                "catalog_version": catalog_version,
                "date_released": date_released,
                "published_count": count,
            },
        )
        self._record_ingest(result)
        logger.info(
            "threat_feed.cisa_kev.done ingest_id=%s inserted=%d updated=%d errors=%d",
            ingest_id,
            inserted,
            updated,
            len(errors),
        )
        return result

    def ingest_custom_ioc_json(
        self,
        entries: list[dict[str, Any]],
        *,
        org_id: str | None = None,
    ) -> FeedIngestResult:
        ingest_id = f"{_INGEST_ID_PREFIX}{uuid4().hex[:20]}"
        started_at = _utcnow_iso()

        if not isinstance(entries, list):
            return self._fail_result(ingest_id, ThreatFeedSourceEnum.CUSTOM_IOC, org_id, started_at, "input must be a JSON array")

        records, errors = _parse_custom_ioc_json(entries, ingest_id, org_id)
        inserted, updated, skipped = self._upsert_iocs(records)

        result = FeedIngestResult(
            ingest_id=ingest_id,
            source=ThreatFeedSourceEnum.CUSTOM_IOC,
            status=IngestStatusEnum.SUCCESS if not errors else IngestStatusEnum.PARTIAL,
            iocs_parsed=len(entries),
            iocs_inserted=inserted,
            iocs_updated=updated,
            iocs_skipped=skipped,
            errors=errors[:50],
            started_at=started_at,
            completed_at=_utcnow_iso(),
            org_id=org_id,
            metadata={"format": "json"},
        )
        self._record_ingest(result)
        logger.info(
            "threat_feed.custom_ioc_json.done ingest_id=%s inserted=%d updated=%d",
            ingest_id,
            inserted,
            updated,
        )
        return result

    def ingest_custom_ioc_csv(
        self,
        csv_text: str,
        *,
        org_id: str | None = None,
    ) -> FeedIngestResult:
        ingest_id = f"{_INGEST_ID_PREFIX}{uuid4().hex[:20]}"
        started_at = _utcnow_iso()

        records, errors = _parse_custom_ioc_csv(csv_text, ingest_id, org_id)
        inserted, updated, skipped = self._upsert_iocs(records)

        result = FeedIngestResult(
            ingest_id=ingest_id,
            source=ThreatFeedSourceEnum.CUSTOM_IOC,
            status=IngestStatusEnum.SUCCESS if not errors else IngestStatusEnum.PARTIAL,
            iocs_parsed=len(records) + len(errors),
            iocs_inserted=inserted,
            iocs_updated=updated,
            iocs_skipped=skipped,
            errors=errors[:50],
            started_at=started_at,
            completed_at=_utcnow_iso(),
            org_id=org_id,
            metadata={"format": "csv"},
        )
        self._record_ingest(result)
        logger.info(
            "threat_feed.custom_ioc_csv.done ingest_id=%s inserted=%d updated=%d",
            ingest_id,
            inserted,
            updated,
        )
        return result

    def _upsert_iocs(self, records: list[IOCRecord]) -> tuple[int, int, int]:
        if not records:
            return 0, 0, 0

        inserted, updated, skipped = self._store().bulk_upsert(records)

        with self._lock:
            for record in records:
                ioc_id = record.ioc_id
                if ioc_id in self._iocs:
                    existing = self._iocs[ioc_id]
                    self._iocs[ioc_id] = IOCRecord(
                        ioc_id=existing.ioc_id,
                        ioc_type=existing.ioc_type,
                        value=existing.value,
                        source=existing.source,
                        severity=record.severity,
                        confidence=max(existing.confidence, record.confidence),
                        tags=list(set(existing.tags) | set(record.tags)),
                        description=record.description if record.description else existing.description,
                        org_id=existing.org_id,
                        mitre_technique_id=existing.mitre_technique_id or record.mitre_technique_id,
                        mitre_tactic=existing.mitre_tactic or record.mitre_tactic,
                        cve_id=existing.cve_id or record.cve_id,
                        first_seen=existing.first_seen,
                        last_seen=record.last_seen,
                        expiry=record.expiry or existing.expiry,
                        active=True,
                        feed_ingest_id=record.feed_ingest_id,
                        extra={**existing.extra, **record.extra},
                    )
                else:
                    if len(self._iocs) >= self._max_ioc_store:
                        oldest_id = self._ioc_order.popleft()
                        self._iocs.pop(oldest_id, None)
                    self._iocs[record.ioc_id] = record
                    self._ioc_order.append(record.ioc_id)

        return inserted, updated, skipped

    def get_ioc(self, ioc_id: str) -> IOCRecord | None:
        with self._lock:
            cached = self._iocs.get(ioc_id)
        if cached is not None:
            return cached
        return self._store().get_ioc(ioc_id)

    def lookup_by_value(self, value: str, *, org_id: str | None = None) -> list[IOCRecord]:
        return self._store().lookup_by_value(value, org_id=org_id, active_only=True)

    def lookup_by_cve(self, cve_id: str, *, org_id: str | None = None) -> list[IOCRecord]:
        return self._store().lookup_by_cve(cve_id, org_id=org_id, active_only=True)

    def lookup_by_mitre_technique(self, technique_id: str, *, org_id: str | None = None) -> list[IOCRecord]:
        return self._store().lookup_by_mitre_technique(technique_id, org_id=org_id, active_only=True)

    def filter_iocs(self, req: IOCFilterRequest) -> list[IOCRecord]:
        return self._store().filter_iocs(req)

    def deactivate_ioc(self, ioc_id: str) -> bool:
        with self._lock:
            if ioc_id in self._iocs:
                try:
                    self._ioc_order.remove(ioc_id)
                except ValueError:
                    pass
                del self._iocs[ioc_id]
        result = self._store().deactivate_ioc(ioc_id)
        if result:
            logger.info("threat_feed.ioc.deactivated ioc_id=%s", ioc_id)
        return result

    def delete_ioc(self, ioc_id: str) -> bool:
        with self._lock:
            if ioc_id in self._iocs:
                try:
                    self._ioc_order.remove(ioc_id)
                except ValueError:
                    pass
                del self._iocs[ioc_id]
        result = self._store().delete_ioc(ioc_id)
        if result:
            logger.info("threat_feed.ioc.deleted ioc_id=%s", ioc_id)
        return result

    def count_iocs(
        self,
        *,
        source: str | None = None,
        active: bool | None = None,
        org_id: str | None = None,
    ) -> int:
        return self._store().count_iocs(source=source, active=active, org_id=org_id)

    def _record_ingest(self, result: FeedIngestResult) -> None:
        with self._lock:
            self._ingest_history.append(result)
        try:
            self._store().persist_ingest_result(result)
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "threat_feed._record_ingest.persist_error ingest_id=%s: %s",
                result.ingest_id,
                exc,
            )

    def list_ingest_history(
        self,
        *,
        source: str | None = None,
        limit: int = 50,
    ) -> list[FeedIngestResult]:
        with self._lock:
            items = list(self._ingest_history)
        if source is not None:
            items = [r for r in items if r.source == source]
        return items[-limit:]

    def get_ingest_result(self, ingest_id: str) -> FeedIngestResult | None:
        with self._lock:
            for item in self._ingest_history:
                if item.ingest_id == ingest_id:
                    return item
        return None

    def _fail_result(
        self,
        ingest_id: str,
        source: str,
        org_id: str | None,
        started_at: str,
        error: str,
    ) -> FeedIngestResult:
        result = FeedIngestResult(
            ingest_id=ingest_id,
            source=source,
            status=IngestStatusEnum.FAILED,
            iocs_parsed=0,
            iocs_inserted=0,
            iocs_updated=0,
            iocs_skipped=0,
            errors=[error],
            started_at=started_at,
            completed_at=_utcnow_iso(),
            org_id=org_id,
            metadata={},
        )
        self._record_ingest(result)
        logger.error(
            "threat_feed.ingest.failed source=%s ingest_id=%s error=%s",
            source,
            ingest_id,
            error,
        )
        return result

    def reset(self) -> None:
        with self._lock:
            self._iocs.clear()
            self._ioc_order.clear()
            self._ingest_history.clear()


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_THREAT_FEED_SERVICE = ThreatFeedIngestionService()


def get_threat_feed_service() -> ThreatFeedIngestionService:
    """Return the module-level ThreatFeedIngestionService singleton."""
    return _THREAT_FEED_SERVICE


def reset_threat_feed_service() -> None:
    """Clear all threat feed state. Intended for use in tests."""
    _THREAT_FEED_SERVICE.reset()


# ---------------------------------------------------------------------------
# run_feed_ingestion — dispatch adapter called by POST /threat/feeds/refresh
# Signature: (source, org_id, force, custom_url) -> FeedIngestResult
# ---------------------------------------------------------------------------

_SUPPORTED_SOURCES = {
    ThreatFeedSourceEnum.MITRE_ATTACK,
    ThreatFeedSourceEnum.CISA_KEV,
    ThreatFeedSourceEnum.STIX_TAXII,
}


def run_feed_ingestion(
    source: ThreatFeedSourceEnum,
    org_id: str | None,
    force: bool,
    custom_url: str | None,
    taxii_config: TAXIIConfig | None = None,
) -> FeedIngestResult:
    """
    Dispatch a single feed ingestion run for the given source.

    Called exclusively by POST /threat/feeds/refresh.
    Delegates to the singleton ThreatFeedIngestionService methods — no
    duplicate ingestion logic lives here.

    For STIX_TAXII: delegates to get_stix_adapter().ingest_bundle() if a
    pre-fetched bundle dict is supplied via taxii_config context, or to
    get_stix_adapter().ingest_from_taxii() if a TAXIIConfig is provided.
    If neither is available, returns a typed FAILED result explaining that
    TAXII ingestion requires a TAXIIConfig.

    Args:
        source:       Feed source enum value to ingest.
        org_id:       Scoping org ID; None for global ingest.
        force:        Reserved for future cache-bypass logic; accepted and
                      logged but does not alter current ingestion behaviour
                      (all runs are unconditional at this layer).
        custom_url:   Optional override URL for the feed endpoint.
        taxii_config: Optional TAXIIConfig for STIX_TAXII source. When
                      provided, delegates to STIXAdapter.ingest_from_taxii().
                      When None and source is STIX_TAXII, returns FAILED with
                      a clear explanation.

    Returns:
        FeedIngestResult dataclass with counts and status.
    """
    from app.services.stix_adapter import TAXIIConfig as _TAXIIConfig  # noqa: PLC0415
    from app.services.stix_adapter import get_stix_adapter

    svc = get_threat_feed_service()

    logger.info(
        "run_feed_ingestion source=%s org_id=%s force=%s custom_url=%s",
        source,
        org_id,
        force,
        custom_url,
    )

    if source == ThreatFeedSourceEnum.MITRE_ATTACK:
        return svc.ingest_mitre_attack(org_id=org_id, url=custom_url or None)

    if source == ThreatFeedSourceEnum.CISA_KEV:
        return svc.ingest_cisa_kev(org_id=org_id, url=custom_url or None)

    if source == ThreatFeedSourceEnum.STIX_TAXII:
        if taxii_config is None:
            ingest_id = f"{_INGEST_ID_PREFIX}{uuid4().hex[:20]}"
            now = _utcnow_iso()
            logger.warning(
                "run_feed_ingestion: STIX_TAXII requires a TAXIIConfig; none provided org_id=%s",
                org_id,
            )
            result = FeedIngestResult(
                ingest_id=ingest_id,
                source=ThreatFeedSourceEnum.STIX_TAXII,
                status=IngestStatusEnum.FAILED,
                iocs_parsed=0,
                iocs_inserted=0,
                iocs_updated=0,
                iocs_skipped=0,
                errors=["STIX_TAXII ingestion requires a TAXIIConfig (discovery_url, collection_id, " "credentials). Pass taxii_config= to run_feed_ingestion() or supply connection " "parameters via the feed refresh request body."],
                started_at=now,
                completed_at=now,
                org_id=org_id,
                metadata={"force": force, "custom_url": custom_url},
            )
            try:
                from app.services.ioc_store import get_ioc_store  # noqa: PLC0415

                get_ioc_store().persist_ingest_result(result)
            except Exception as exc:  # noqa: BLE001
                logger.error("run_feed_ingestion.persist_failed_result error: %s", exc)
            return result

        if not isinstance(taxii_config, _TAXIIConfig):
            ingest_id = f"{_INGEST_ID_PREFIX}{uuid4().hex[:20]}"
            now = _utcnow_iso()
            return FeedIngestResult(
                ingest_id=ingest_id,
                source=ThreatFeedSourceEnum.STIX_TAXII,
                status=IngestStatusEnum.FAILED,
                iocs_parsed=0,
                iocs_inserted=0,
                iocs_updated=0,
                iocs_skipped=0,
                errors=[f"taxii_config must be a TAXIIConfig instance, got {type(taxii_config).__name__}"],
                started_at=now,
                completed_at=now,
                org_id=org_id,
                metadata={"force": force, "custom_url": custom_url},
            )

        logger.info(
            "run_feed_ingestion.stix_taxii discovery_url=%s collection_id=%s org_id=%s",
            taxii_config.discovery_url,
            taxii_config.collection_id,
            org_id,
        )
        return get_stix_adapter().ingest_from_taxii(
            taxii_config,
            org_id=org_id,
        )

    # Unsupported source
    ingest_id = f"{_INGEST_ID_PREFIX}{uuid4().hex[:20]}"
    now = _utcnow_iso()
    source_val = source.value if hasattr(source, "value") else str(source)
    logger.warning("run_feed_ingestion: unsupported source=%s", source_val)
    return FeedIngestResult(
        ingest_id=ingest_id,
        source=source_val,
        status=IngestStatusEnum.FAILED,
        iocs_parsed=0,
        iocs_inserted=0,
        iocs_updated=0,
        iocs_skipped=0,
        errors=[f"Unsupported feed source: {source_val}"],
        started_at=now,
        completed_at=now,
        org_id=org_id,
        metadata={"force": force, "custom_url": custom_url},
    )


__all__ = [
    "CustomIOCEntry",
    "FeedIngestResult",
    "IOCFilterRequest",
    "IOCRecord",
    "IngestStatus",
    "IngestStatusEnum",
    "IOCType",
    "IOCTypeEnum",
    "ThreatFeedIngestionService",
    "ThreatFeedSource",
    "ThreatFeedSourceEnum",
    "ThreatSeverity",
    "ThreatSeverityLevel",
    "get_threat_feed_service",
    "reset_threat_feed_service",
    "run_feed_ingestion",
]
