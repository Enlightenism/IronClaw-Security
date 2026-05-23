from __future__ import annotations

from dataclasses import dataclass, field
import logging
import re
from typing import Any
import urllib.error
import urllib.request
from uuid import uuid4

from app.schemas.threat_detection import (
    IngestStatusEnum,
    IOCTypeEnum,
    ThreatFeedSourceEnum,
    ThreatSeverityLevel,
)
from app.services.ioc_store import IOCStore, get_ioc_store
from app.services.threat_feed_ingestion import (
    FeedIngestResult,
    IOCRecord,
    _normalize_value,
    _sha256_hex,
    _utcnow_iso,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_IOC_ID_PREFIX = "ioc-"
_INGEST_ID_PREFIX = "ingest-"
_DEFAULT_FETCH_TIMEOUT = 30
_MAX_BUNDLE_OBJECTS = 100_000
_MAX_ERRORS_RETURNED = 100
_TAXII_COLLECTION_PAGE_SIZE = 500

_STIX_TYPE_TO_IOC_TYPE: dict[str, str] = {
    "ipv4-addr": IOCTypeEnum.IPV4,
    "ipv6-addr": IOCTypeEnum.IPV6,
    "domain-name": IOCTypeEnum.DOMAIN,
    "url": IOCTypeEnum.URL,
    "file": IOCTypeEnum.SHA256,
    "email-addr": IOCTypeEnum.EMAIL,
}

_SEVERITY_FROM_CONFIDENCE: list[tuple[float, str]] = [
    (0.9, ThreatSeverityLevel.CRITICAL),
    (0.75, ThreatSeverityLevel.HIGH),
    (0.5, ThreatSeverityLevel.MEDIUM),
    (0.25, ThreatSeverityLevel.LOW),
    (0.0, ThreatSeverityLevel.INFO),
]

_RE_CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_RE_MITRE_TECH = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)

# ---------------------------------------------------------------------------
# TAXII Connection Config
# ---------------------------------------------------------------------------


@dataclass
class TAXIIConfig:
    """Connection parameters for a TAXII 2.1 server."""

    discovery_url: str
    collection_id: str | None = None
    username: str | None = None
    password: str | None = None
    api_root: str | None = None
    verify_ssl: bool = True
    timeout: int = _DEFAULT_FETCH_TIMEOUT
    page_size: int = _TAXII_COLLECTION_PAGE_SIZE
    extra_headers: dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Bundle parse result
# ---------------------------------------------------------------------------


@dataclass
class STIXParseResult:
    records: list[IOCRecord]
    errors: list[str]
    objects_seen: int
    objects_skipped: int
    bundle_id: str | None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _confidence_from_stix(obj: dict[str, Any]) -> float:
    """Extract confidence from STIX object. STIX confidence is 0-100; normalise to 0.0-1.0."""
    raw = obj.get("confidence")
    if raw is None:
        return 0.7
    try:
        val = float(raw)
        if val > 1.0:
            val = val / 100.0
        return max(0.0, min(1.0, val))
    except (TypeError, ValueError):
        return 0.7


def _severity_from_confidence(confidence: float) -> str:
    for threshold, level in _SEVERITY_FROM_CONFIDENCE:
        if confidence >= threshold:
            return level
    return ThreatSeverityLevel.INFO


def _extract_labels(obj: dict[str, Any]) -> list[str]:
    labels = obj.get("labels", [])
    if isinstance(labels, list):
        return [str(lb).strip() for lb in labels if lb]
    return []


def _extract_tlp_marking(obj: dict[str, Any]) -> str | None:
    for ref in obj.get("object_marking_refs", []):
        ref_str = str(ref).lower()
        if "tlp" in ref_str:
            for level in ("red", "amber", "green", "white", "clear"):
                if level in ref_str:
                    return f"tlp:{level}"
    return None


def _extract_mitre_from_labels(labels: list[str]) -> tuple[str | None, str | None]:
    """Extract MITRE technique_id and tactic from STIX labels."""
    technique_id: str | None = None
    tactic: str | None = None
    for lb in labels:
        m = _RE_MITRE_TECH.search(lb)
        if m and technique_id is None:
            technique_id = m.group(0).upper()
    return technique_id, tactic


def _extract_cve_from_labels_and_refs(
    obj: dict[str, Any],
    labels: list[str],
) -> str | None:
    for lb in labels:
        m = _RE_CVE.search(lb)
        if m:
            return m.group(0).upper()
    for ref in obj.get("external_references", []):
        ext_id = str(ref.get("external_id", ""))
        if _RE_CVE.match(ext_id):
            return ext_id.upper()
    return None


def _ioc_id_for_stix(
    stix_id: str,
    value: str,
    ioc_type: str,
    org_id: str | None,
) -> str:
    scope = org_id if org_id else "global"
    fingerprint = f"stix:{stix_id}:{ioc_type}:{scope}:{value}"
    return f"{_IOC_ID_PREFIX}{_sha256_hex(fingerprint)[:16]}"


def _description_from_obj(obj: dict[str, Any]) -> str:
    desc = obj.get("description", "")
    name = obj.get("name", "")
    if desc:
        return desc[:1024]
    if name:
        return name[:1024]
    return ""


# ---------------------------------------------------------------------------
# STIX object extractors
# ---------------------------------------------------------------------------


def _extract_ipv4(obj: dict[str, Any]) -> str | None:
    return obj.get("value")


def _extract_ipv6(obj: dict[str, Any]) -> str | None:
    return obj.get("value")


def _extract_domain(obj: dict[str, Any]) -> str | None:
    return obj.get("value")


def _extract_url(obj: dict[str, Any]) -> str | None:
    return obj.get("value")


def _extract_email(obj: dict[str, Any]) -> str | None:
    return obj.get("value")


def _extract_file_hash(obj: dict[str, Any]) -> tuple[str | None, str]:
    """
    STIX file objects carry hashes dict. Prefer SHA256 > SHA1 > MD5.
    Returns (value, ioc_type).
    """
    hashes: dict[str, str] = obj.get("hashes", {})
    for algo, ioc_type in (
        ("SHA-256", IOCTypeEnum.SHA256),
        ("SHA256", IOCTypeEnum.SHA256),
        ("SHA-1", IOCTypeEnum.SHA1),
        ("SHA1", IOCTypeEnum.SHA1),
        ("MD5", IOCTypeEnum.MD5),
    ):
        val = hashes.get(algo)
        if val:
            return str(val).strip(), ioc_type
    return None, IOCTypeEnum.UNKNOWN


def _extract_indicator_pattern(obj: dict[str, Any]) -> list[tuple[str, str]]:
    """
    Parse STIX indicator pattern string to extract (value, ioc_type) pairs.
    Handles common patterns:
        [ipv4-addr:value = '1.2.3.4']
        [domain-name:value = 'evil.com']
        [url:value = 'http://...']
        [file:hashes.'SHA-256' = 'abc...']
        [email-addr:value = 'foo@bar.com']
    """
    pattern: str = obj.get("pattern", "")
    results: list[tuple[str, str]] = []

    _PATTERN_EXTRACTORS: list[tuple[re.Pattern[str], str]] = [
        (re.compile(r"ipv4-addr:value\s*=\s*'([^']+)'"), IOCTypeEnum.IPV4),
        (re.compile(r"ipv4-addr:value\s*=\s*\"([^\"]+)\""), IOCTypeEnum.IPV4),
        (re.compile(r"ipv6-addr:value\s*=\s*'([^']+)'"), IOCTypeEnum.IPV6),
        (re.compile(r"ipv6-addr:value\s*=\s*\"([^\"]+)\""), IOCTypeEnum.IPV6),
        (re.compile(r"domain-name:value\s*=\s*'([^']+)'"), IOCTypeEnum.DOMAIN),
        (re.compile(r"domain-name:value\s*=\s*\"([^\"]+)\""), IOCTypeEnum.DOMAIN),
        (re.compile(r"url:value\s*=\s*'([^']+)'"), IOCTypeEnum.URL),
        (re.compile(r"url:value\s*=\s*\"([^\"]+)\""), IOCTypeEnum.URL),
        (re.compile(r"email-addr:value\s*=\s*'([^']+)'"), IOCTypeEnum.EMAIL),
        (re.compile(r"email-addr:value\s*=\s*\"([^\"]+)\""), IOCTypeEnum.EMAIL),
        (re.compile(r"file:hashes\.'SHA-256'\s*=\s*'([^']+)'"), IOCTypeEnum.SHA256),
        (re.compile(r"file:hashes\.'SHA-256'\s*=\s*\"([^\"]+)\""), IOCTypeEnum.SHA256),
        (re.compile(r"file:hashes\.'SHA256'\s*=\s*'([^']+)'"), IOCTypeEnum.SHA256),
        (re.compile(r"file:hashes\.'SHA-1'\s*=\s*'([^']+)'"), IOCTypeEnum.SHA1),
        (re.compile(r"file:hashes\.'MD5'\s*=\s*'([^']+)'"), IOCTypeEnum.MD5),
    ]

    for rgx, ioc_type in _PATTERN_EXTRACTORS:
        for match in rgx.finditer(pattern):
            val = match.group(1).strip()
            if val:
                results.append((val, ioc_type))

    return results


# ---------------------------------------------------------------------------
# Core STIX 2.1 bundle parser
# ---------------------------------------------------------------------------


def parse_stix_bundle(
    bundle: dict[str, Any],
    *,
    ingest_id: str,
    org_id: str | None,
    source_label: str | None = None,
) -> STIXParseResult:
    """
    Translate a STIX 2.1 bundle dict into a list of IOCRecords.

    Handles STIX object types:
    - indicator         (pattern-based; most common in threat intel feeds)
    - ipv4-addr
    - ipv6-addr
    - domain-name
    - url
    - file              (hash-based)
    - email-addr
    - observed-data     (references to SCOs)

    Intentionally skips: relationship, identity, marking-definition, course-of-action,
    attack-pattern, malware, tool, threat-actor, campaign, report, sighting.
    The MITRE ATT&CK ingestor in threat_feed_ingestion.py owns attack-pattern processing.
    """
    records: list[IOCRecord] = []
    errors: list[str] = []
    objects_seen = 0
    objects_skipped = 0
    now = _utcnow_iso()
    bundle_id: str | None = bundle.get("id")
    source = ThreatFeedSourceEnum.STIX_TAXII
    feed_source_label = source_label or "stix_taxii"

    objects: list[dict[str, Any]] = bundle.get("objects", [])
    if len(objects) > _MAX_BUNDLE_OBJECTS:
        logger.warning(
            "stix_adapter.parse_bundle bundle_id=%s object_count=%d exceeds max=%d; truncating",
            bundle_id,
            len(objects),
            _MAX_BUNDLE_OBJECTS,
        )
        objects = objects[:_MAX_BUNDLE_OBJECTS]

    for obj in objects:
        if not isinstance(obj, dict):
            objects_skipped += 1
            continue

        obj_type: str = obj.get("type", "")
        stix_id: str = obj.get("id", "")
        objects_seen += 1

        try:
            if obj_type == "indicator":
                new_records = _parse_stix_indicator(obj, stix_id, ingest_id, org_id, now, source, feed_source_label)
                records.extend(new_records)

            elif obj_type == "ipv4-addr":
                r = _parse_stix_sco(obj, stix_id, IOCTypeEnum.IPV4, _extract_ipv4(obj), ingest_id, org_id, now, source, feed_source_label)
                if r:
                    records.append(r)

            elif obj_type == "ipv6-addr":
                r = _parse_stix_sco(obj, stix_id, IOCTypeEnum.IPV6, _extract_ipv6(obj), ingest_id, org_id, now, source, feed_source_label)
                if r:
                    records.append(r)

            elif obj_type == "domain-name":
                r = _parse_stix_sco(obj, stix_id, IOCTypeEnum.DOMAIN, _extract_domain(obj), ingest_id, org_id, now, source, feed_source_label)
                if r:
                    records.append(r)

            elif obj_type == "url":
                r = _parse_stix_sco(obj, stix_id, IOCTypeEnum.URL, _extract_url(obj), ingest_id, org_id, now, source, feed_source_label)
                if r:
                    records.append(r)

            elif obj_type == "email-addr":
                r = _parse_stix_sco(obj, stix_id, IOCTypeEnum.EMAIL, _extract_email(obj), ingest_id, org_id, now, source, feed_source_label)
                if r:
                    records.append(r)

            elif obj_type == "file":
                val, hash_ioc_type = _extract_file_hash(obj)
                if val:
                    r = _parse_stix_sco(obj, stix_id, hash_ioc_type, val, ingest_id, org_id, now, source, feed_source_label)
                    if r:
                        records.append(r)
                else:
                    objects_skipped += 1

            else:
                objects_skipped += 1

        except Exception as exc:  # noqa: BLE001
            errors.append(f"stix_object_parse_error stix_id={stix_id} type={obj_type}: {exc}")

    logger.info(
        "stix_adapter.parse_bundle bundle_id=%s records=%d errors=%d skipped=%d",
        bundle_id,
        len(records),
        len(errors),
        objects_skipped,
    )

    return STIXParseResult(
        records=records,
        errors=errors,
        objects_seen=objects_seen,
        objects_skipped=objects_skipped,
        bundle_id=bundle_id,
    )


def _parse_stix_indicator(
    obj: dict[str, Any],
    stix_id: str,
    ingest_id: str,
    org_id: str | None,
    now: str,
    source: str,
    feed_source_label: str,
) -> list[IOCRecord]:
    """
    Parse a STIX 2.1 indicator object.
    One indicator can yield multiple IOCRecords if the pattern contains multiple observables.
    """
    confidence = _confidence_from_stix(obj)
    severity = _severity_from_confidence(confidence)
    labels = _extract_labels(obj)
    tlp = _extract_tlp_marking(obj)
    technique_id, tactic = _extract_mitre_from_labels(labels)
    cve_id = _extract_cve_from_labels_and_refs(obj, labels)
    description = _description_from_obj(obj)
    valid_from: str = obj.get("valid_from", now)
    valid_until: str | None = obj.get("valid_until")

    base_tags = ["stix-indicator", feed_source_label] + [lb for lb in labels if lb]
    if tlp:
        base_tags.append(tlp)
    if technique_id:
        base_tags.append("mitre-attack")

    pattern_pairs = _extract_indicator_pattern(obj)

    records: list[IOCRecord] = []

    for raw_value, ioc_type in pattern_pairs:
        value = _normalize_value(raw_value, ioc_type)
        ioc_id = _ioc_id_for_stix(stix_id, value, ioc_type, org_id)

        extra: dict[str, Any] = {
            "stix_id": stix_id,
            "stix_type": "indicator",
            "feed_source_label": feed_source_label,
            "pattern_type": obj.get("pattern_type", "stix"),
        }
        if obj.get("name"):
            extra["name"] = obj["name"]
        if tlp:
            extra["tlp"] = tlp
        if cve_id:
            extra["cve_id_extracted"] = cve_id

        records.append(
            IOCRecord(
                ioc_id=ioc_id,
                ioc_type=ioc_type,
                value=value,
                source=source,
                severity=severity,
                confidence=confidence,
                tags=list(base_tags),
                description=description,
                org_id=org_id,
                mitre_technique_id=technique_id,
                mitre_tactic=tactic,
                cve_id=cve_id,
                first_seen=valid_from,
                last_seen=now,
                expiry=valid_until,
                active=True,
                feed_ingest_id=ingest_id,
                extra=extra,
            )
        )

    return records


def _parse_stix_sco(
    obj: dict[str, Any],
    stix_id: str,
    ioc_type: str,
    raw_value: str | None,
    ingest_id: str,
    org_id: str | None,
    now: str,
    source: str,
    feed_source_label: str,
) -> IOCRecord | None:
    """Parse a STIX Cyber Observable (SCO) object into an IOCRecord."""
    if not raw_value:
        return None

    value = _normalize_value(raw_value.strip(), ioc_type)
    if not value:
        return None

    confidence = _confidence_from_stix(obj)
    severity = _severity_from_confidence(confidence)
    labels = _extract_labels(obj)
    tlp = _extract_tlp_marking(obj)
    technique_id, tactic = _extract_mitre_from_labels(labels)
    cve_id = _extract_cve_from_labels_and_refs(obj, labels)
    description = _description_from_obj(obj)

    tags = ["stix-observable", feed_source_label] + [lb for lb in labels if lb]
    if tlp:
        tags.append(tlp)

    ioc_id = _ioc_id_for_stix(stix_id, value, ioc_type, org_id)

    extra: dict[str, Any] = {
        "stix_id": stix_id,
        "stix_type": obj.get("type", ""),
        "feed_source_label": feed_source_label,
    }
    if tlp:
        extra["tlp"] = tlp

    return IOCRecord(
        ioc_id=ioc_id,
        ioc_type=ioc_type,
        value=value,
        source=source,
        severity=severity,
        confidence=confidence,
        tags=tags,
        description=description,
        org_id=org_id,
        mitre_technique_id=technique_id,
        mitre_tactic=tactic,
        cve_id=cve_id,
        first_seen=now,
        last_seen=now,
        expiry=None,
        active=True,
        feed_ingest_id=ingest_id,
        extra=extra,
    )


# ---------------------------------------------------------------------------
# HTTP fetch helpers for TAXII 2.1
# ---------------------------------------------------------------------------


def _build_taxii_request(
    url: str,
    config: TAXIIConfig,
    *,
    accept: str = "application/taxii+json;version=2.1",
    added_after: str | None = None,
    next_cursor: str | None = None,
) -> urllib.request.Request:
    full_url = url
    params: list[str] = []
    if added_after:
        params.append(f"added_after={urllib.request.quote(added_after)}")
    if next_cursor:
        params.append(f"next={urllib.request.quote(next_cursor)}")
    if params:
        full_url = f"{url}?{'&'.join(params)}"

    headers: dict[str, str] = {
        "Accept": accept,
        "User-Agent": "IronClaw-STIXAdapter/1.0",
        **config.extra_headers,
    }

    req = urllib.request.Request(full_url, headers=headers)

    if config.username and config.password:
        import base64

        creds = base64.b64encode(f"{config.username}:{config.password}".encode()).decode()
        req.add_header("Authorization", f"Basic {creds}")

    return req


def _fetch_taxii_json(
    url: str,
    config: TAXIIConfig,
    *,
    added_after: str | None = None,
    next_cursor: str | None = None,
) -> dict[str, Any] | list[Any]:
    req = _build_taxii_request(
        url,
        config,
        accept="application/taxii+json;version=2.1",
        added_after=added_after,
        next_cursor=next_cursor,
    )
    import json

    with urllib.request.urlopen(req, timeout=config.timeout) as resp:
        raw = resp.read()
    return json.loads(raw.decode("utf-8", errors="replace"))


def _fetch_stix_bundle(
    url: str,
    config: TAXIIConfig,
    *,
    added_after: str | None = None,
    next_cursor: str | None = None,
) -> dict[str, Any]:
    """Fetch a STIX bundle from a TAXII object endpoint."""
    req = _build_taxii_request(
        url,
        config,
        accept="application/stix+json;version=2.1",
        added_after=added_after,
        next_cursor=next_cursor,
    )
    import json

    with urllib.request.urlopen(req, timeout=config.timeout) as resp:
        raw = resp.read()
    return json.loads(raw.decode("utf-8", errors="replace"))


# ---------------------------------------------------------------------------
# TAXII 2.1 discovery
# ---------------------------------------------------------------------------


def _resolve_collection_url(config: TAXIIConfig) -> str | None:
    """
    Walk the TAXII 2.1 discovery → api-root → collections endpoint
    to produce a usable objects URL.
    """
    try:
        discovery = _fetch_taxii_json(config.discovery_url, config)
        if not isinstance(discovery, dict):
            return None

        api_roots: list[str] = discovery.get("api_roots", [])
        if config.api_root:
            target_root = config.api_root.rstrip("/")
        elif api_roots:
            target_root = api_roots[0].rstrip("/")
        else:
            return None

        if config.collection_id:
            return f"{target_root}/collections/{config.collection_id}/objects/"

        collections_resp = _fetch_taxii_json(f"{target_root}/collections/", config)
        if not isinstance(collections_resp, dict):
            return None

        collections: list[dict[str, Any]] = collections_resp.get("collections", [])
        if not collections:
            return None

        chosen = None
        for col in collections:
            if col.get("can_read", True):
                chosen = col
                break

        if not chosen:
            return None

        col_id = chosen["id"]
        return f"{target_root}/collections/{col_id}/objects/"

    except Exception as exc:  # noqa: BLE001
        logger.warning("stix_adapter._resolve_collection_url error: %s", exc)
        return None


# ---------------------------------------------------------------------------
# STIXAdapter — main entry point
# ---------------------------------------------------------------------------


class STIXAdapter:
    """
    STIX 2.1 / TAXII 2.1 adapter for IronClaw.

    Responsibilities:
    - Accept a pre-fetched STIX bundle dict and translate it into IOCRecords
      via parse_stix_bundle(), then persist via IOCStore.
    - Fetch bundles from a TAXII 2.1 server (with pagination) and ingest them.
    - Return FeedIngestResult in the same shape used by ThreatFeedIngestionService,
      so callers (routers, schedulers) see a uniform result contract.

    This adapter does NOT duplicate IOCStore, IOCRecord, or FeedIngestResult.
    It re-uses _detect_ioc_type, _normalize_value, _sha256_hex, _utcnow_iso,
    and IOCStore.bulk_upsert() from their canonical owners.
    """

    def __init__(
        self,
        *,
        store: IOCStore | None = None,
        fetch_timeout: int = _DEFAULT_FETCH_TIMEOUT,
    ) -> None:
        self._store = store or get_ioc_store()
        self._fetch_timeout = fetch_timeout

    # ------------------------------------------------------------------
    # Ingest from pre-fetched bundle dict
    # ------------------------------------------------------------------

    def ingest_bundle(
        self,
        bundle: dict[str, Any],
        *,
        org_id: str | None = None,
        source_label: str | None = None,
    ) -> FeedIngestResult:
        """
        Translate a STIX 2.1 bundle dict into IOCRecords and persist via IOCStore.

        Args:
            bundle:       STIX 2.1 bundle as a Python dict.
            org_id:       Scoping org ID; None for global.
            source_label: Human-readable label embedded in IOC tags/extra.

        Returns:
            FeedIngestResult with insert/update/skip/error counts.
        """
        ingest_id = f"{_INGEST_ID_PREFIX}{uuid4().hex[:20]}"
        started_at = _utcnow_iso()

        if not isinstance(bundle, dict):
            return self._fail(ingest_id, org_id, started_at, "bundle must be a dict")

        bundle_type = bundle.get("type", "")
        if bundle_type != "bundle":
            logger.warning(
                "stix_adapter.ingest_bundle: unexpected bundle type=%s; proceeding",
                bundle_type,
            )

        parse_result = parse_stix_bundle(
            bundle,
            ingest_id=ingest_id,
            org_id=org_id,
            source_label=source_label,
        )

        inserted, updated, skipped = self._store.bulk_upsert(parse_result.records)

        status = IngestStatusEnum.FAILED if not parse_result.records and parse_result.errors else IngestStatusEnum.PARTIAL if parse_result.errors else IngestStatusEnum.SUCCESS

        result = FeedIngestResult(
            ingest_id=ingest_id,
            source=ThreatFeedSourceEnum.STIX_TAXII,
            status=status,
            iocs_parsed=parse_result.objects_seen,
            iocs_inserted=inserted,
            iocs_updated=updated,
            iocs_skipped=skipped + parse_result.objects_skipped,
            errors=parse_result.errors[:_MAX_ERRORS_RETURNED],
            started_at=started_at,
            completed_at=_utcnow_iso(),
            org_id=org_id,
            metadata={
                "bundle_id": parse_result.bundle_id,
                "bundle_type": bundle_type,
                "objects_skipped": parse_result.objects_skipped,
                "source_label": source_label,
            },
        )

        self._persist_ingest_result(result)
        logger.info(
            "stix_adapter.ingest_bundle done ingest_id=%s inserted=%d updated=%d skipped=%d errors=%d",
            ingest_id,
            inserted,
            updated,
            skipped,
            len(parse_result.errors),
        )
        return result

    # ------------------------------------------------------------------
    # Ingest from raw bytes / string
    # ------------------------------------------------------------------

    def ingest_bundle_bytes(
        self,
        raw: bytes | str,
        *,
        org_id: str | None = None,
        source_label: str | None = None,
    ) -> FeedIngestResult:
        """Parse raw JSON bytes/str as a STIX bundle and ingest."""
        import json

        ingest_id = f"{_INGEST_ID_PREFIX}{uuid4().hex[:20]}"
        started_at = _utcnow_iso()

        try:
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8", errors="replace")
            bundle = json.loads(raw)
        except Exception as exc:  # noqa: BLE001
            return self._fail(ingest_id, org_id, started_at, f"json_parse_error: {exc}")

        if not isinstance(bundle, dict):
            return self._fail(ingest_id, org_id, started_at, "parsed JSON is not a dict")

        return self.ingest_bundle(bundle, org_id=org_id, source_label=source_label)

    # ------------------------------------------------------------------
    # Ingest from TAXII 2.1 server
    # ------------------------------------------------------------------

    def ingest_from_taxii(
        self,
        config: TAXIIConfig,
        *,
        org_id: str | None = None,
        added_after: str | None = None,
    ) -> FeedIngestResult:
        """
        Connect to a TAXII 2.1 server, discover or use the configured collection,
        page through all objects, and ingest the resulting STIX bundle.

        Args:
            config:      TAXIIConfig with server connection parameters.
            org_id:      Scoping org ID.
            added_after: Optional ISO timestamp to fetch only newer objects.

        Returns:
            FeedIngestResult aggregated across all pages.
        """
        ingest_id = f"{_INGEST_ID_PREFIX}{uuid4().hex[:20]}"
        started_at = _utcnow_iso()
        all_records: list[IOCRecord] = []
        all_errors: list[str] = []
        total_seen = 0
        total_skipped = 0
        page_count = 0

        try:
            if config.collection_id and config.api_root:
                objects_url = f"{config.api_root.rstrip('/')}/collections/{config.collection_id}/objects/"
            else:
                objects_url = _resolve_collection_url(config)
                if not objects_url:
                    return self._fail(
                        ingest_id,
                        org_id,
                        started_at,
                        "taxii_discovery_failed: could not resolve a readable collection URL",
                        metadata={"discovery_url": config.discovery_url},
                    )

            next_cursor: str | None = None

            while True:
                page_count += 1
                try:
                    envelope = _fetch_stix_bundle(
                        objects_url,
                        config,
                        added_after=added_after,
                        next_cursor=next_cursor,
                    )
                except urllib.error.HTTPError as exc:
                    all_errors.append(f"taxii_fetch_http_error page={page_count} status={exc.code}: {exc.reason}")
                    break
                except urllib.error.URLError as exc:
                    all_errors.append(f"taxii_fetch_url_error page={page_count}: {exc}")
                    break
                except Exception as exc:  # noqa: BLE001
                    all_errors.append(f"taxii_fetch_error page={page_count}: {exc}")
                    break

                if not isinstance(envelope, dict):
                    all_errors.append(f"taxii_unexpected_response page={page_count}: not a dict")
                    break

                bundle_id = envelope.get("id")
                objects: list[dict[str, Any]] = envelope.get("objects", [])

                page_bundle: dict[str, Any] = {
                    "type": "bundle",
                    "id": bundle_id or f"bundle--{uuid4()}",
                    "objects": objects,
                }

                parse_result = parse_stix_bundle(
                    page_bundle,
                    ingest_id=ingest_id,
                    org_id=org_id,
                    source_label=config.discovery_url,
                )

                all_records.extend(parse_result.records)
                all_errors.extend(parse_result.errors)
                total_seen += parse_result.objects_seen
                total_skipped += parse_result.objects_skipped

                next_cursor = envelope.get("next")
                if not next_cursor or not objects:
                    break

        except Exception as exc:  # noqa: BLE001
            all_errors.append(f"taxii_ingest_fatal: {exc}")

        inserted, updated, skipped = self._store.bulk_upsert(all_records)
        total_skipped += skipped

        status = IngestStatusEnum.FAILED if not all_records and all_errors else IngestStatusEnum.PARTIAL if all_errors else IngestStatusEnum.SUCCESS

        result = FeedIngestResult(
            ingest_id=ingest_id,
            source=ThreatFeedSourceEnum.STIX_TAXII,
            status=status,
            iocs_parsed=total_seen,
            iocs_inserted=inserted,
            iocs_updated=updated,
            iocs_skipped=total_skipped,
            errors=all_errors[:_MAX_ERRORS_RETURNED],
            started_at=started_at,
            completed_at=_utcnow_iso(),
            org_id=org_id,
            metadata={
                "taxii_server": config.discovery_url,
                "collection_id": config.collection_id,
                "pages_fetched": page_count,
                "added_after": added_after,
            },
        )

        self._persist_ingest_result(result)
        logger.info(
            "stix_adapter.ingest_from_taxii done ingest_id=%s pages=%d inserted=%d updated=%d errors=%d",
            ingest_id,
            page_count,
            inserted,
            updated,
            len(all_errors),
        )
        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _fail(
        self,
        ingest_id: str,
        org_id: str | None,
        started_at: str,
        error: str,
        *,
        metadata: dict[str, Any] | None = None,
    ) -> FeedIngestResult:
        result = FeedIngestResult(
            ingest_id=ingest_id,
            source=ThreatFeedSourceEnum.STIX_TAXII,
            status=IngestStatusEnum.FAILED,
            iocs_parsed=0,
            iocs_inserted=0,
            iocs_updated=0,
            iocs_skipped=0,
            errors=[error],
            started_at=started_at,
            completed_at=_utcnow_iso(),
            org_id=org_id,
            metadata=metadata or {},
        )
        self._persist_ingest_result(result)
        logger.error("stix_adapter.fail ingest_id=%s error=%s", ingest_id, error)
        return result

    def _persist_ingest_result(self, result: FeedIngestResult) -> None:
        try:
            self._store.persist_ingest_result(result)
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "stix_adapter._persist_ingest_result error ingest_id=%s: %s",
                result.ingest_id,
                exc,
            )


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_STIX_ADAPTER: STIXAdapter | None = None


def get_stix_adapter() -> STIXAdapter:
    global _STIX_ADAPTER  # noqa: PLW0603
    if _STIX_ADAPTER is None:
        _STIX_ADAPTER = STIXAdapter()
    return _STIX_ADAPTER


# ---------------------------------------------------------------------------
# Convenience top-level functions (called by routers / schedulers)
# ---------------------------------------------------------------------------


def ingest_stix_bundle(
    bundle: dict[str, Any],
    *,
    org_id: str | None = None,
    source_label: str | None = None,
) -> FeedIngestResult:
    """Top-level entry point: ingest a pre-fetched STIX 2.1 bundle dict."""
    return get_stix_adapter().ingest_bundle(bundle, org_id=org_id, source_label=source_label)


def ingest_stix_bundle_bytes(
    raw: bytes | str,
    *,
    org_id: str | None = None,
    source_label: str | None = None,
) -> FeedIngestResult:
    """Top-level entry point: ingest raw JSON bytes/str as a STIX 2.1 bundle."""
    return get_stix_adapter().ingest_bundle_bytes(raw, org_id=org_id, source_label=source_label)


def ingest_from_taxii(
    config: TAXIIConfig,
    *,
    org_id: str | None = None,
    added_after: str | None = None,
) -> FeedIngestResult:
    """Top-level entry point: fetch and ingest from a TAXII 2.1 server."""
    return get_stix_adapter().ingest_from_taxii(config, org_id=org_id, added_after=added_after)


__all__ = [
    "STIXAdapter",
    "STIXParseResult",
    "TAXIIConfig",
    "get_stix_adapter",
    "ingest_from_taxii",
    "ingest_stix_bundle",
    "ingest_stix_bundle_bytes",
    "parse_stix_bundle",
]
