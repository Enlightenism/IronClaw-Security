from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal
import uuid

import pytest

# ---------------------------------------------------------------------------
# Inline stub for app.services.threat_feed_service
# (the service module exists as a placeholder; these tests drive and validate
#  the interface contract so the real implementation can be wired in.)
# ---------------------------------------------------------------------------

ThreatIndicatorType = Literal[
    "ip",
    "domain",
    "url",
    "hash_md5",
    "hash_sha256",
    "hash_sha1",
    "email",
    "cve",
    "yara_rule",
    "sigma_rule",
]

ThreatSeverity = Literal["critical", "high", "medium", "low", "info"]

ThreatFeedStatus = Literal["active", "inactive", "error", "pending"]

ThreatMatchVerdict = Literal["block", "quarantine", "warn", "allow"]

_SEVERITY_SCORE: dict[str, int] = {
    "critical": 95,
    "high": 75,
    "medium": 50,
    "low": 25,
    "info": 5,
}

_VERDICT_FROM_SEVERITY: dict[str, ThreatMatchVerdict] = {
    "critical": "block",
    "high": "quarantine",
    "medium": "warn",
    "low": "allow",
    "info": "allow",
}


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _new_id() -> str:
    return str(uuid.uuid4())


@dataclass(slots=True)
class ThreatIndicator:
    indicator_id: str
    indicator_type: ThreatIndicatorType
    value: str
    severity: ThreatSeverity
    feed_id: str
    tags: list[str] = field(default_factory=list)
    confidence: int = 80
    first_seen: str = field(default_factory=_utc_now)
    last_seen: str = field(default_factory=_utc_now)
    expires_at: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "indicator_id": self.indicator_id,
            "indicator_type": self.indicator_type,
            "value": self.value,
            "severity": self.severity,
            "feed_id": self.feed_id,
            "tags": list(self.tags),
            "confidence": self.confidence,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "expires_at": self.expires_at,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class ThreatFeedSource:
    feed_id: str
    name: str
    feed_url: str | None
    status: ThreatFeedStatus
    indicator_count: int = 0
    last_ingested_at: str | None = None
    error_message: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "feed_id": self.feed_id,
            "name": self.name,
            "feed_url": self.feed_url,
            "status": self.status,
            "indicator_count": self.indicator_count,
            "last_ingested_at": self.last_ingested_at,
            "error_message": self.error_message,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class ThreatMatchResult:
    checked_at: str
    input_value: str
    input_type: ThreatIndicatorType
    matched: bool
    verdict: ThreatMatchVerdict
    matched_indicators: list[ThreatIndicator] = field(default_factory=list)
    highest_severity: ThreatSeverity | None = None
    confidence: int = 0
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "checked_at": self.checked_at,
            "input_value": self.input_value,
            "input_type": self.input_type,
            "matched": self.matched,
            "verdict": self.verdict,
            "matched_indicators": [i.to_dict() for i in self.matched_indicators],
            "highest_severity": self.highest_severity,
            "confidence": self.confidence,
            "reasons": list(self.reasons),
        }


@dataclass(slots=True)
class IngestionResult:
    feed_id: str
    ingested_at: str
    indicators_added: int
    indicators_updated: int
    indicators_skipped: int
    errors: list[str] = field(default_factory=list)
    success: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "feed_id": self.feed_id,
            "ingested_at": self.ingested_at,
            "indicators_added": self.indicators_added,
            "indicators_updated": self.indicators_updated,
            "indicators_skipped": self.indicators_skipped,
            "errors": list(self.errors),
            "success": self.success,
        }


# ---------------------------------------------------------------------------
# Threat Feed Ingestion Engine (in-memory implementation under test)
# ---------------------------------------------------------------------------


class ThreatFeedIngestionError(Exception):
    pass


class ThreatFeedEngine:
    """
    In-memory threat feed ingestion and lookup engine.
    Mirrors the production app.services.threat_feed_service contract.
    """

    def __init__(self) -> None:
        self._feeds: dict[str, ThreatFeedSource] = {}
        self._indicators: dict[str, ThreatIndicator] = {}  # indicator_id -> indicator
        self._index: dict[str, list[str]] = {}  # normalized_value -> [indicator_ids]

    # ---- Feed Registration ------------------------------------------------

    def register_feed(
        self,
        *,
        name: str,
        feed_url: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ThreatFeedSource:
        if not name or not name.strip():
            raise ThreatFeedIngestionError("Feed name is required.")
        feed_id = _new_id()
        source = ThreatFeedSource(
            feed_id=feed_id,
            name=name.strip(),
            feed_url=feed_url,
            status="pending",
            metadata=dict(metadata or {}),
        )
        self._feeds[feed_id] = source
        return source

    def get_feed(self, feed_id: str) -> ThreatFeedSource | None:
        return self._feeds.get(feed_id)

    def list_feeds(self) -> list[ThreatFeedSource]:
        return list(self._feeds.values())

    def deactivate_feed(self, feed_id: str) -> bool:
        feed = self._feeds.get(feed_id)
        if feed is None:
            return False
        feed.status = "inactive"
        return True

    # ---- Indicator Ingestion ----------------------------------------------

    def ingest_indicators(
        self,
        feed_id: str,
        raw_indicators: list[dict[str, Any]],
    ) -> IngestionResult:
        feed = self._feeds.get(feed_id)
        if feed is None:
            raise ThreatFeedIngestionError(f"Feed not found: {feed_id}")

        added = 0
        updated = 0
        skipped = 0
        errors: list[str] = []

        for raw in raw_indicators:
            try:
                indicator_type: ThreatIndicatorType = raw["indicator_type"]
                value: str = (raw.get("value") or "").strip()
                severity: ThreatSeverity = raw.get("severity", "medium")
                confidence: int = max(0, min(int(raw.get("confidence", 80)), 100))
                tags: list[str] = list(raw.get("tags") or [])
                expires_at: str | None = raw.get("expires_at")
                meta: dict[str, Any] = dict(raw.get("metadata") or {})

                if not value:
                    skipped += 1
                    continue

                normalized = value.lower()
                existing_ids = self._index.get(normalized, [])
                matched_existing = next(
                    (self._indicators[eid] for eid in existing_ids if self._indicators[eid].feed_id == feed_id),
                    None,
                )

                if matched_existing is not None:
                    matched_existing.severity = severity
                    matched_existing.confidence = confidence
                    matched_existing.tags = tags
                    matched_existing.last_seen = _utc_now()
                    matched_existing.expires_at = expires_at
                    matched_existing.metadata = meta
                    updated += 1
                else:
                    indicator = ThreatIndicator(
                        indicator_id=_new_id(),
                        indicator_type=indicator_type,
                        value=value,
                        severity=severity,
                        feed_id=feed_id,
                        tags=tags,
                        confidence=confidence,
                        expires_at=expires_at,
                        metadata=meta,
                    )
                    self._indicators[indicator.indicator_id] = indicator
                    self._index.setdefault(normalized, []).append(indicator.indicator_id)
                    added += 1

            except (KeyError, ValueError, TypeError) as exc:
                errors.append(f"Skipped malformed indicator: {exc}")

        feed.indicator_count += added
        if errors:
            feed.status = "error"
            feed.error_message = errors[-1]
        else:
            feed.status = "active"
        feed.last_ingested_at = _utc_now()

        return IngestionResult(
            feed_id=feed_id,
            ingested_at=_utc_now(),
            indicators_added=added,
            indicators_updated=updated,
            indicators_skipped=skipped,
            errors=errors,
            success=len(errors) == 0 or (added + updated) > 0,
        )

    # ---- Threat Lookup ----------------------------------------------------

    def lookup(
        self,
        value: str,
        indicator_type: ThreatIndicatorType,
    ) -> ThreatMatchResult:
        checked_at = _utc_now()
        normalized = value.strip().lower()

        if not normalized:
            return ThreatMatchResult(
                checked_at=checked_at,
                input_value=value,
                input_type=indicator_type,
                matched=False,
                verdict="allow",
                reasons=["Empty value submitted for lookup."],
            )

        candidate_ids = self._index.get(normalized, [])
        matched: list[ThreatIndicator] = [
            self._indicators[iid] for iid in candidate_ids if iid in self._indicators and self._indicators[iid].indicator_type == indicator_type and self._feeds.get(self._indicators[iid].feed_id, ThreatFeedSource(feed_id="", name="", feed_url=None, status="inactive")).status == "active"
        ]

        if not matched:
            return ThreatMatchResult(
                checked_at=checked_at,
                input_value=value,
                input_type=indicator_type,
                matched=False,
                verdict="allow",
                reasons=["No active threat indicators matched."],
            )

        severities_ranked = ["critical", "high", "medium", "low", "info"]
        highest_sev = min(
            matched,
            key=lambda i: severities_ranked.index(i.severity),
        ).severity
        avg_confidence = sum(i.confidence for i in matched) // len(matched)
        verdict: ThreatMatchVerdict = _VERDICT_FROM_SEVERITY[highest_sev]
        reasons = [f"Matched {len(matched)} active threat indicator(s) with highest severity '{highest_sev}'."]

        return ThreatMatchResult(
            checked_at=checked_at,
            input_value=value,
            input_type=indicator_type,
            matched=True,
            verdict=verdict,
            matched_indicators=matched,
            highest_severity=highest_sev,
            confidence=avg_confidence,
            reasons=reasons,
        )

    # ---- Feed-level stats -------------------------------------------------

    def feed_stats(self, feed_id: str) -> dict[str, Any]:
        feed = self._feeds.get(feed_id)
        if feed is None:
            raise ThreatFeedIngestionError(f"Feed not found: {feed_id}")
        indicators = [i for i in self._indicators.values() if i.feed_id == feed_id]
        severity_counts: dict[str, int] = {}
        type_counts: dict[str, int] = {}
        for ind in indicators:
            severity_counts[ind.severity] = severity_counts.get(ind.severity, 0) + 1
            type_counts[ind.indicator_type] = type_counts.get(ind.indicator_type, 0) + 1
        return {
            "feed_id": feed_id,
            "status": feed.status,
            "total_indicators": len(indicators),
            "severity_distribution": severity_counts,
            "type_distribution": type_counts,
            "last_ingested_at": feed.last_ingested_at,
        }

    def flush(self) -> None:
        self._feeds.clear()
        self._indicators.clear()
        self._index.clear()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def engine() -> ThreatFeedEngine:
    e = ThreatFeedEngine()
    yield e
    e.flush()


@pytest.fixture()
def registered_feed(engine: ThreatFeedEngine) -> ThreatFeedSource:
    return engine.register_feed(name="Test IOC Feed", feed_url="https://feeds.example.com/ioc.csv")


@pytest.fixture()
def populated_feed(engine: ThreatFeedEngine, registered_feed: ThreatFeedSource) -> tuple[ThreatFeedSource, IngestionResult]:
    raw = [
        {"indicator_type": "ip", "value": "198.51.100.1", "severity": "high", "confidence": 90},
        {"indicator_type": "ip", "value": "203.0.113.5", "severity": "critical", "confidence": 95},
        {"indicator_type": "domain", "value": "evil.example.com", "severity": "high", "confidence": 85},
        {"indicator_type": "hash_sha256", "value": "abc123def456", "severity": "medium", "confidence": 70},
        {"indicator_type": "url", "value": "http://malicious.example.org/payload", "severity": "critical", "confidence": 98},
    ]
    result = engine.ingest_indicators(registered_feed.feed_id, raw)
    return registered_feed, result


# ---------------------------------------------------------------------------
# Tests — Feed Registration
# ---------------------------------------------------------------------------


class TestFeedRegistration:

    def test_register_feed_returns_source(self, engine: ThreatFeedEngine) -> None:
        feed = engine.register_feed(name="Alpha Feed", feed_url="https://alpha.example.com/feed")
        assert isinstance(feed, ThreatFeedSource)
        assert feed.name == "Alpha Feed"
        assert feed.feed_url == "https://alpha.example.com/feed"
        assert feed.status == "pending"
        assert feed.feed_id

    def test_register_feed_without_url(self, engine: ThreatFeedEngine) -> None:
        feed = engine.register_feed(name="Offline Feed")
        assert feed.feed_url is None
        assert feed.status == "pending"

    def test_register_feed_empty_name_raises(self, engine: ThreatFeedEngine) -> None:
        with pytest.raises(ThreatFeedIngestionError):
            engine.register_feed(name="")

    def test_register_feed_whitespace_name_raises(self, engine: ThreatFeedEngine) -> None:
        with pytest.raises(ThreatFeedIngestionError):
            engine.register_feed(name="   ")

    def test_register_multiple_feeds_distinct_ids(self, engine: ThreatFeedEngine) -> None:
        f1 = engine.register_feed(name="Feed One")
        f2 = engine.register_feed(name="Feed Two")
        assert f1.feed_id != f2.feed_id

    def test_list_feeds_returns_all(self, engine: ThreatFeedEngine) -> None:
        engine.register_feed(name="Alpha")
        engine.register_feed(name="Beta")
        engine.register_feed(name="Gamma")
        feeds = engine.list_feeds()
        assert len(feeds) == 3

    def test_get_feed_by_id(self, engine: ThreatFeedEngine) -> None:
        feed = engine.register_feed(name="Lookup Test")
        fetched = engine.get_feed(feed.feed_id)
        assert fetched is not None
        assert fetched.feed_id == feed.feed_id
        assert fetched.name == "Lookup Test"

    def test_get_feed_missing_id_returns_none(self, engine: ThreatFeedEngine) -> None:
        result = engine.get_feed("nonexistent-id")
        assert result is None

    def test_register_feed_stores_metadata(self, engine: ThreatFeedEngine) -> None:
        feed = engine.register_feed(name="Meta Feed", metadata={"source": "misp", "tlp": "white"})
        assert feed.metadata["source"] == "misp"
        assert feed.metadata["tlp"] == "white"

    def test_deactivate_feed_sets_inactive(self, engine: ThreatFeedEngine) -> None:
        feed = engine.register_feed(name="Deactivate Me")
        result = engine.deactivate_feed(feed.feed_id)
        assert result is True
        assert engine.get_feed(feed.feed_id).status == "inactive"

    def test_deactivate_missing_feed_returns_false(self, engine: ThreatFeedEngine) -> None:
        assert engine.deactivate_feed("ghost-id") is False


# ---------------------------------------------------------------------------
# Tests — Indicator Ingestion
# ---------------------------------------------------------------------------


class TestIndicatorIngestion:

    def test_ingest_basic_ip_indicators(self, engine: ThreatFeedEngine, registered_feed: ThreatFeedSource) -> None:
        raw = [
            {"indicator_type": "ip", "value": "192.0.2.1", "severity": "high", "confidence": 88},
            {"indicator_type": "ip", "value": "192.0.2.2", "severity": "medium", "confidence": 60},
        ]
        result = engine.ingest_indicators(registered_feed.feed_id, raw)
        assert result.indicators_added == 2
        assert result.indicators_updated == 0
        assert result.indicators_skipped == 0
        assert result.success is True
        assert result.feed_id == registered_feed.feed_id

    def test_ingest_domain_indicator(self, engine: ThreatFeedEngine, registered_feed: ThreatFeedSource) -> None:
        raw = [{"indicator_type": "domain", "value": "malicious.test", "severity": "critical"}]
        result = engine.ingest_indicators(registered_feed.feed_id, raw)
        assert result.indicators_added == 1
        assert result.success is True

    def test_ingest_hash_indicators(self, engine: ThreatFeedEngine, registered_feed: ThreatFeedSource) -> None:
        raw = [
            {"indicator_type": "hash_md5", "value": "d41d8cd98f00b204e9800998ecf8427e", "severity": "medium"},
            {"indicator_type": "hash_sha256", "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "severity": "high"},
        ]
        result = engine.ingest_indicators(registered_feed.feed_id, raw)
        assert result.indicators_added == 2

    def test_ingest_url_indicator(self, engine: ThreatFeedEngine, registered_feed: ThreatFeedSource) -> None:
        raw = [{"indicator_type": "url", "value": "http://evil.example.net/cmd", "severity": "critical", "confidence": 99}]
        result = engine.ingest_indicators(registered_feed.feed_id, raw)
        assert result.indicators_added == 1

    def test_ingest_cve_indicator(self, engine: ThreatFeedEngine, registered_feed: ThreatFeedSource) -> None:
        raw = [{"indicator_type": "cve", "value": "CVE-2024-1234", "severity": "high", "confidence": 95}]
        result = engine.ingest_indicators(registered_feed.feed_id, raw)
        assert result.indicators_added == 1

    def test_ingest_updates_feed_status_to_active(self, engine: ThreatFeedEngine, registered_feed: ThreatFeedSource) -> None:
        raw = [{"indicator_type": "ip", "value": "10.0.0.1", "severity": "low"}]
        engine.ingest_indicators(registered_feed.feed_id, raw)
        feed = engine.get_feed(registered_feed.feed_id)
        assert feed.status == "active"
        assert feed.last_ingested_at is not None

    def test_ingest_updates_feed_indicator_count(self, engine: ThreatFeedEngine, registered_feed: ThreatFeedSource) -> None:
        raw = [
            {"indicator_type": "ip", "value": "10.10.10.1", "severity": "high"},
            {"indicator_type": "ip", "value": "10.10.10.2", "severity": "high"},
            {"indicator_type": "ip", "value": "10.10.10.3", "severity": "medium"},
        ]
        engine.ingest_indicators(registered_feed.feed_id, raw)
        feed = engine.get_feed(registered_feed.feed_id)
        assert feed.indicator_count == 3

    def test_ingest_deduplicates_same_value_same_feed(self, engine: ThreatFeedEngine, registered_feed: ThreatFeedSource) -> None:
        raw1 = [{"indicator_type": "ip", "value": "1.2.3.4", "severity": "low", "confidence": 50}]
        raw2 = [{"indicator_type": "ip", "value": "1.2.3.4", "severity": "critical", "confidence": 99}]
        r1 = engine.ingest_indicators(registered_feed.feed_id, raw1)
        r2 = engine.ingest_indicators(registered_feed.feed_id, raw2)
        assert r1.indicators_added == 1
        assert r2.indicators_updated == 1
        assert r2.indicators_added == 0

    def test_ingest_case_insensitive_deduplication(self, engine: ThreatFeedEngine, registered_feed: ThreatFeedSource) -> None:
        r1 = engine.ingest_indicators(
            registered_feed.feed_id,
            [{"indicator_type": "domain", "value": "EVIL.EXAMPLE.COM", "severity": "high"}],
        )
        r2 = engine.ingest_indicators(
            registered_feed.feed_id,
            [{"indicator_type": "domain", "value": "evil.example.com", "severity": "high"}],
        )
        assert r1.indicators_added == 1
        assert r2.indicators_updated == 1

    def test_ingest_skips_empty_value(self, engine: ThreatFeedEngine, registered_feed: ThreatFeedSource) -> None:
        raw = [{"indicator_type": "ip", "value": "", "severity": "high"}]
        result = engine.ingest_indicators(registered_feed.feed_id, raw)
        assert result.indicators_skipped == 1
        assert result.indicators_added == 0

    def test_ingest_skips_whitespace_value(self, engine: ThreatFeedEngine, registered_feed: ThreatFeedSource) -> None:
        raw = [{"indicator_type": "ip", "value": "   ", "severity": "high"}]
        result = engine.ingest_indicators(registered_feed.feed_id, raw)
        assert result.indicators_skipped == 1

    def test_ingest_mixed_valid_invalid_records(self, engine: ThreatFeedEngine, registered_feed: ThreatFeedSource) -> None:
        raw = [
            {"indicator_type": "ip", "value": "5.5.5.5", "severity": "high"},
            {"indicator_type": "ip", "value": "", "severity": "high"},
            {"indicator_type": "domain", "value": "ok.example.com", "severity": "medium"},
        ]
        result = engine.ingest_indicators(registered_feed.feed_id, raw)
        assert result.indicators_added == 2
        assert result.indicators_skipped == 1

    def test_ingest_missing_indicator_type_records_error(self, engine: ThreatFeedEngine, registered_feed: ThreatFeedSource) -> None:
        raw = [{"value": "9.9.9.9", "severity": "high"}]
        result = engine.ingest_indicators(registered_feed.feed_id, raw)
        assert len(result.errors) >= 1

    def test_ingest_to_unknown_feed_raises(self, engine: ThreatFeedEngine) -> None:
        with pytest.raises(ThreatFeedIngestionError):
            engine.ingest_indicators("bad-feed-id", [{"indicator_type": "ip", "value": "1.1.1.1", "severity": "high"}])

    def test_ingest_preserves_tags(self, engine: ThreatFeedEngine, registered_feed: ThreatFeedSource) -> None:
        raw = [{"indicator_type": "ip", "value": "7.7.7.7", "severity": "medium", "tags": ["botnet", "c2"]}]
        engine.ingest_indicators(registered_feed.feed_id, raw)
        result = engine.lookup("7.7.7.7", "ip")
        assert result.matched is True
        assert "botnet" in result.matched_indicators[0].tags
        assert "c2" in result.matched_indicators[0].tags

    def test_ingest_confidence_bounded_at_100(self, engine: ThreatFeedEngine, registered_feed: ThreatFeedSource) -> None:
        raw = [{"indicator_type": "ip", "value": "8.8.4.4", "severity": "high", "confidence": 999}]
        engine.ingest_indicators(registered_feed.feed_id, raw)
        result = engine.lookup("8.8.4.4", "ip")
        assert result.matched_indicators[0].confidence == 100

    def test_ingest_confidence_bounded_at_zero(self, engine: ThreatFeedEngine, registered_feed: ThreatFeedSource) -> None:
        raw = [{"indicator_type": "ip", "value": "8.8.8.8", "severity": "info", "confidence": -50}]
        engine.ingest_indicators(registered_feed.feed_id, raw)
        result = engine.lookup("8.8.8.8", "ip")
        assert result.matched_indicators[0].confidence == 0

    def test_ingest_large_batch(self, engine: ThreatFeedEngine, registered_feed: ThreatFeedSource) -> None:
        raw = [{"indicator_type": "ip", "value": f"10.0.{i // 256}.{i % 256}", "severity": "low"} for i in range(500)]
        result = engine.ingest_indicators(registered_feed.feed_id, raw)
        assert result.indicators_added == 500
        assert result.success is True

    def test_ingestion_result_to_dict_shape(self, engine: ThreatFeedEngine, registered_feed: ThreatFeedSource) -> None:
        raw = [{"indicator_type": "ip", "value": "99.99.99.99", "severity": "high"}]
        result = engine.ingest_indicators(registered_feed.feed_id, raw)
        d = result.to_dict()
        assert "feed_id" in d
        assert "ingested_at" in d
        assert "indicators_added" in d
        assert "indicators_updated" in d
        assert "indicators_skipped" in d
        assert "errors" in d
        assert "success" in d


# ---------------------------------------------------------------------------
# Tests — Threat Lookup
# ---------------------------------------------------------------------------


class TestThreatLookup:

    def test_lookup_matching_ip(self, engine: ThreatFeedEngine, populated_feed: tuple[ThreatFeedSource, IngestionResult]) -> None:
        result = engine.lookup("198.51.100.1", "ip")
        assert result.matched is True
        assert result.verdict in ("block", "quarantine", "warn")
        assert result.highest_severity == "high"

    def test_lookup_critical_ip_returns_block(self, engine: ThreatFeedEngine, populated_feed: tuple[ThreatFeedSource, IngestionResult]) -> None:
        result = engine.lookup("203.0.113.5", "ip")
        assert result.matched is True
        assert result.verdict == "block"
        assert result.highest_severity == "critical"

    def test_lookup_matching_domain(self, engine: ThreatFeedEngine, populated_feed: tuple[ThreatFeedSource, IngestionResult]) -> None:
        result = engine.lookup("evil.example.com", "domain")
        assert result.matched is True
        assert result.verdict == "quarantine"

    def test_lookup_matching_url(self, engine: ThreatFeedEngine, populated_feed: tuple[ThreatFeedSource, IngestionResult]) -> None:
        result = engine.lookup("http://malicious.example.org/payload", "url")
        assert result.matched is True
        assert result.verdict == "block"

    def test_lookup_missing_ip_returns_allow(self, engine: ThreatFeedEngine, populated_feed: tuple[ThreatFeedSource, IngestionResult]) -> None:
        result = engine.lookup("127.0.0.1", "ip")
        assert result.matched is False
        assert result.verdict == "allow"

    def test_lookup_case_insensitive_domain(self, engine: ThreatFeedEngine, populated_feed: tuple[ThreatFeedSource, IngestionResult]) -> None:
        result = engine.lookup("EVIL.EXAMPLE.COM", "domain")
        assert result.matched is True

    def test_lookup_empty_value_returns_allow(self, engine: ThreatFeedEngine, populated_feed: tuple[ThreatFeedSource, IngestionResult]) -> None:
        result = engine.lookup("", "ip")
        assert result.matched is False
        assert result.verdict == "allow"
        assert result.reasons

    def test_lookup_type_mismatch_no_match(self, engine: ThreatFeedEngine, populated_feed: tuple[ThreatFeedSource, IngestionResult]) -> None:
        # 198.51.100.1 is registered as "ip", not "domain"
        result = engine.lookup("198.51.100.1", "domain")
        assert result.matched is False

    def test_lookup_inactive_feed_not_matched(self, engine: ThreatFeedEngine, registered_feed: ThreatFeedSource) -> None:
        raw = [{"indicator_type": "ip", "value": "172.16.0.1", "severity": "critical", "confidence": 99}]
        engine.ingest_indicators(registered_feed.feed_id, raw)
        engine.deactivate_feed(registered_feed.feed_id)
        result = engine.lookup("172.16.0.1", "ip")
        assert result.matched is False
        assert result.verdict == "allow"

    def test_lookup_returns_matched_indicators_list(self, engine: ThreatFeedEngine, populated_feed: tuple[ThreatFeedSource, IngestionResult]) -> None:
        result = engine.lookup("203.0.113.5", "ip")
        assert isinstance(result.matched_indicators, list)
        assert len(result.matched_indicators) >= 1

    def test_lookup_result_confidence_set_on_match(self, engine: ThreatFeedEngine, populated_feed: tuple[ThreatFeedSource, IngestionResult]) -> None:
        result = engine.lookup("198.51.100.1", "ip")
        assert result.confidence > 0

    def test_lookup_result_to_dict_shape(self, engine: ThreatFeedEngine, populated_feed: tuple[ThreatFeedSource, IngestionResult]) -> None:
        result = engine.lookup("203.0.113.5", "ip")
        d = result.to_dict()
        assert "checked_at" in d
        assert "input_value" in d
        assert "input_type" in d
        assert "matched" in d
        assert "verdict" in d
        assert "matched_indicators" in d
        assert "highest_severity" in d
        assert "confidence" in d
        assert "reasons" in d

    def test_lookup_no_match_result_to_dict_shape(self, engine: ThreatFeedEngine, populated_feed: tuple[ThreatFeedSource, IngestionResult]) -> None:
        result = engine.lookup("1.2.3.4", "ip")
        d = result.to_dict()
        assert d["matched"] is False
        assert d["matched_indicators"] == []

    def test_lookup_reasons_populated_on_match(self, engine: ThreatFeedEngine, populated_feed: tuple[ThreatFeedSource, IngestionResult]) -> None:
        result = engine.lookup("203.0.113.5", "ip")
        assert isinstance(result.reasons, list)
        assert len(result.reasons) >= 1

    def test_lookup_reasons_populated_on_no_match(self, engine: ThreatFeedEngine, populated_feed: tuple[ThreatFeedSource, IngestionResult]) -> None:
        result = engine.lookup("clean.example.com", "domain")
        assert isinstance(result.reasons, list)
        assert len(result.reasons) >= 1

    def test_multi_feed_lookup_highest_severity_wins(self, engine: ThreatFeedEngine) -> None:
        f1 = engine.register_feed(name="Feed Low")
        f2 = engine.register_feed(name="Feed Critical")
        engine.ingest_indicators(f1.feed_id, [{"indicator_type": "ip", "value": "6.6.6.6", "severity": "low", "confidence": 50}])
        engine.ingest_indicators(f2.feed_id, [{"indicator_type": "ip", "value": "6.6.6.6", "severity": "critical", "confidence": 99}])
        result = engine.lookup("6.6.6.6", "ip")
        assert result.matched is True
        assert result.highest_severity == "critical"
        assert result.verdict == "block"


# ---------------------------------------------------------------------------
# Tests — Feed Statistics
# ---------------------------------------------------------------------------


class TestFeedStatistics:

    def test_feed_stats_totals(self, engine: ThreatFeedEngine, populated_feed: tuple[ThreatFeedSource, IngestionResult]) -> None:
        feed, _ = populated_feed
        stats = engine.feed_stats(feed.feed_id)
        assert stats["total_indicators"] == 5
        assert stats["feed_id"] == feed.feed_id

    def test_feed_stats_severity_distribution(self, engine: ThreatFeedEngine, populated_feed: tuple[ThreatFeedSource, IngestionResult]) -> None:
        feed, _ = populated_feed
        stats = engine.feed_stats(feed.feed_id)
        dist = stats["severity_distribution"]
        assert "critical" in dist
        assert "high" in dist
        assert dist["critical"] == 2
        assert dist["high"] == 2
        assert dist["medium"] == 1

    def test_feed_stats_type_distribution(self, engine: ThreatFeedEngine, populated_feed: tuple[ThreatFeedSource, IngestionResult]) -> None:
        feed, _ = populated_feed
        stats = engine.feed_stats(feed.feed_id)
        dist = stats["type_distribution"]
        assert dist.get("ip") == 2
        assert dist.get("domain") == 1

    def test_feed_stats_unknown_feed_raises(self, engine: ThreatFeedEngine) -> None:
        with pytest.raises(ThreatFeedIngestionError):
            engine.feed_stats("no-such-feed")

    def test_feed_stats_last_ingested_at_set(self, engine: ThreatFeedEngine, populated_feed: tuple[ThreatFeedSource, IngestionResult]) -> None:
        feed, _ = populated_feed
        stats = engine.feed_stats(feed.feed_id)
        assert stats["last_ingested_at"] is not None

    def test_feed_stats_status_active_after_ingest(self, engine: ThreatFeedEngine, populated_feed: tuple[ThreatFeedSource, IngestionResult]) -> None:
        feed, _ = populated_feed
        stats = engine.feed_stats(feed.feed_id)
        assert stats["status"] == "active"


# ---------------------------------------------------------------------------
# Tests — ThreatIndicator dataclass
# ---------------------------------------------------------------------------


class TestThreatIndicatorDataclass:

    def test_to_dict_contains_all_fields(self) -> None:
        ind = ThreatIndicator(
            indicator_id="ind-001",
            indicator_type="ip",
            value="1.1.1.1",
            severity="high",
            feed_id="feed-001",
            tags=["scan"],
            confidence=80,
        )
        d = ind.to_dict()
        for key in ("indicator_id", "indicator_type", "value", "severity", "feed_id", "tags", "confidence", "first_seen", "last_seen", "expires_at", "metadata"):
            assert key in d

    def test_to_dict_tags_are_copy(self) -> None:
        ind = ThreatIndicator(
            indicator_id="ind-002",
            indicator_type="domain",
            value="bad.com",
            severity="medium",
            feed_id="f1",
            tags=["apt"],
        )
        d = ind.to_dict()
        d["tags"].append("injected")
        assert "injected" not in ind.tags

    def test_to_dict_metadata_is_copy(self) -> None:
        ind = ThreatIndicator(
            indicator_id="ind-003",
            indicator_type="url",
            value="http://bad.io",
            severity="critical",
            feed_id="f1",
            metadata={"actor": "group-x"},
        )
        d = ind.to_dict()
        d["metadata"]["injected"] = True
        assert "injected" not in ind.metadata


# ---------------------------------------------------------------------------
# Tests — ThreatFeedSource dataclass
# ---------------------------------------------------------------------------


class TestThreatFeedSourceDataclass:

    def test_to_dict_contains_all_fields(self) -> None:
        src = ThreatFeedSource(
            feed_id="feed-abc",
            name="Test",
            feed_url="https://test.io",
            status="active",
            indicator_count=10,
        )
        d = src.to_dict()
        for key in ("feed_id", "name", "feed_url", "status", "indicator_count", "last_ingested_at", "error_message", "metadata"):
            assert key in d

    def test_to_dict_metadata_is_copy(self) -> None:
        src = ThreatFeedSource(
            feed_id="f",
            name="N",
            feed_url=None,
            status="pending",
            metadata={"key": "val"},
        )
        d = src.to_dict()
        d["metadata"]["injected"] = True
        assert "injected" not in src.metadata


# ---------------------------------------------------------------------------
# Tests — Severity to verdict mapping correctness
# ---------------------------------------------------------------------------


class TestSeverityVerdictMapping:

    @pytest.mark.parametrize(
        "severity,expected_verdict",
        [
            ("critical", "block"),
            ("high", "quarantine"),
            ("medium", "warn"),
            ("low", "allow"),
            ("info", "allow"),
        ],
    )
    def test_verdict_from_severity(
        self,
        engine: ThreatFeedEngine,
        registered_feed: ThreatFeedSource,
        severity: str,
        expected_verdict: str,
    ) -> None:
        value = f"target-{severity}.example.com"
        engine.ingest_indicators(
            registered_feed.feed_id,
            [{"indicator_type": "domain", "value": value, "severity": severity, "confidence": 80}],
        )
        result = engine.lookup(value, "domain")
        assert result.matched is True
        assert result.verdict == expected_verdict


# ---------------------------------------------------------------------------
# Tests — Cross-service integration: threat feed → attack correlation
# ---------------------------------------------------------------------------


class TestThreatFeedToAttackCorrelationBridge:
    """
    Validates that a ThreatMatchResult with verdict 'block' or 'quarantine'
    produces a CorrelationEvent that correctly escalates through
    app.services.attack_correlation.correlate_attack_events.
    """

    def test_block_verdict_produces_escalating_correlation_event(self, engine: ThreatFeedEngine, populated_feed: tuple[ThreatFeedSource, IngestionResult]) -> None:
        from app.services.attack_correlation import (
            build_correlation_event,
            correlate_attack_events,
        )

        match = engine.lookup("203.0.113.5", "ip")
        assert match.verdict == "block"

        event = build_correlation_event(
            event_id=_new_id(),
            action_type="network_egress",
            target=match.input_value,
            verdict=match.verdict,
            risk_score=_SEVERITY_SCORE.get(match.highest_severity or "high", 75),
            trace_id="trace-tf-001",
        )
        summary = correlate_attack_events([event])
        assert summary.verdict in ("block", "quarantine", "warn")
        assert summary.total_events == 1
        assert summary.high_risk_events == 1

    def test_multi_event_threat_stream_escalates_to_block(self, engine: ThreatFeedEngine) -> None:
        from app.services.attack_correlation import (
            build_correlation_event,
            correlate_attack_events,
        )

        feed = engine.register_feed(name="Threat Stream Feed")
        malicious_ips = [f"203.0.113.{i}" for i in range(1, 6)]
        engine.ingest_indicators(
            feed.feed_id,
            [{"indicator_type": "ip", "value": ip, "severity": "critical", "confidence": 95} for ip in malicious_ips],
        )

        events = []
        for ip in malicious_ips:
            match = engine.lookup(ip, "ip")
            assert match.matched is True
            events.append(
                build_correlation_event(
                    event_id=_new_id(),
                    action_type="connection_attempt",
                    target=ip,
                    verdict=match.verdict,
                    risk_score=_SEVERITY_SCORE.get(match.highest_severity or "critical", 95),
                    session_id="session-threat-001",
                )
            )

        summary = correlate_attack_events(events)
        assert summary.verdict == "block"
        assert summary.total_events == 5
        assert summary.high_risk_events == 5
        assert summary.escalation_score >= 85

    def test_allow_verdict_does_not_escalate(self, engine: ThreatFeedEngine) -> None:
        from app.services.attack_correlation import (
            build_correlation_event,
            correlate_attack_events,
        )

        match = engine.lookup("clean.example.com", "domain")
        assert match.matched is False
        assert match.verdict == "allow"

        event = build_correlation_event(
            event_id=_new_id(),
            action_type="dns_lookup",
            target="clean.example.com",
            verdict="allow",
            risk_score=0,
        )
        summary = correlate_attack_events([event])
        assert summary.verdict == "allow"
        assert summary.escalation_score == 0


# ---------------------------------------------------------------------------
# Tests — Engine flush / isolation
# ---------------------------------------------------------------------------


class TestEngineIsolation:

    def test_flush_clears_all_state(self, engine: ThreatFeedEngine) -> None:
        feed = engine.register_feed(name="Temp Feed")
        engine.ingest_indicators(feed.feed_id, [{"indicator_type": "ip", "value": "1.2.3.4", "severity": "high"}])
        engine.flush()
        assert engine.list_feeds() == []
        result = engine.lookup("1.2.3.4", "ip")
        assert result.matched is False

    def test_two_engines_are_isolated(self) -> None:
        e1 = ThreatFeedEngine()
        e2 = ThreatFeedEngine()
        f1 = e1.register_feed(name="E1 Feed")
        e1.ingest_indicators(f1.feed_id, [{"indicator_type": "ip", "value": "5.5.5.5", "severity": "critical"}])
        result = e2.lookup("5.5.5.5", "ip")
        assert result.matched is False
        e1.flush()
        e2.flush()

    def test_fixture_engine_is_fresh_per_test(self, engine: ThreatFeedEngine) -> None:
        assert engine.list_feeds() == []
