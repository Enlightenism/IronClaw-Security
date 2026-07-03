from __future__ import annotations

from collections.abc import Generator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Literal
import uuid

import pytest

# ---------------------------------------------------------------------------
# Type aliases
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
IndicatorLifecycleEvent = Literal[
    "ingested",
    "updated",
    "expired_auto",
    "deactivated_manual",
    "reactivated",
    "near_expiry_flagged",
]

_SEVERITY_RANK: list[str] = ["critical", "high", "medium", "low", "info"]
_VERDICT_FROM_SEVERITY: dict[str, ThreatMatchVerdict] = {
    "critical": "block",
    "high": "quarantine",
    "medium": "warn",
    "low": "allow",
    "info": "allow",
}
_NEAR_EXPIRY_THRESHOLD_HOURS: int = 24


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _new_id() -> str:
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Audit trail entry — mirrors app.services.audit_log contract
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class IndicatorAuditEntry:
    entry_id: str
    indicator_id: str
    feed_id: str
    event: IndicatorLifecycleEvent
    occurred_at: str
    actor: str
    reason: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "entry_id": self.entry_id,
            "indicator_id": self.indicator_id,
            "feed_id": self.feed_id,
            "event": self.event,
            "occurred_at": self.occurred_at,
            "actor": self.actor,
            "reason": self.reason,
            "metadata": dict(self.metadata),
        }


# ---------------------------------------------------------------------------
# ThreatIndicator with expiry-aware lifecycle
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class ThreatIndicator:
    indicator_id: str
    indicator_type: ThreatIndicatorType
    value: str
    severity: ThreatSeverity
    feed_id: str
    tags: list[str] = field(default_factory=list)
    confidence: int = 80
    first_seen: str = field(default_factory=lambda: _iso(_utc_now()))
    last_seen: str = field(default_factory=lambda: _iso(_utc_now()))
    expires_at: str | None = None
    is_expired: bool = False
    is_deactivated: bool = False
    near_expiry_flagged: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def is_active(self) -> bool:
        return not self.is_expired and not self.is_deactivated

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
            "is_expired": self.is_expired,
            "is_deactivated": self.is_deactivated,
            "near_expiry_flagged": self.near_expiry_flagged,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class ThreatFeedSource:
    feed_id: str
    name: str
    status: ThreatFeedStatus
    indicator_count: int = 0
    last_ingested_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "feed_id": self.feed_id,
            "name": self.name,
            "status": self.status,
            "indicator_count": self.indicator_count,
            "last_ingested_at": self.last_ingested_at,
        }


@dataclass(slots=True)
class ExpirySweepResult:
    swept_at: str
    expired_count: int
    near_expiry_count: int
    already_expired_skipped: int
    audit_entries: list[IndicatorAuditEntry] = field(default_factory=list)

    @property
    def success_count(self) -> int:
        return self.expired_count + self.near_expiry_count

    def to_dict(self) -> dict[str, Any]:
        return {
            "swept_at": self.swept_at,
            "expired_count": self.expired_count,
            "near_expiry_count": self.near_expiry_count,
            "already_expired_skipped": self.already_expired_skipped,
            "audit_entries": [e.to_dict() for e in self.audit_entries],
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


# ---------------------------------------------------------------------------
# IOC Expiry Engine
# ---------------------------------------------------------------------------


class IOCExpiryError(Exception):
    pass


class IOCExpiryEngine:
    """
    Manages the full expiry lifecycle for ThreatIndicator objects:
      - Automatic expiry detection during lookup (fail-closed on stale IOCs)
      - Near-expiry flagging with audit trail
      - Batch expiry sweep
      - Manual deactivation vs. automatic expiry — both produce distinct audit
        entries so the difference is preserved and queryable
      - Reactivation with a fresh expiry window
    """

    def __init__(
        self,
        near_expiry_threshold_hours: int = _NEAR_EXPIRY_THRESHOLD_HOURS,
    ) -> None:
        self._threshold_hours = near_expiry_threshold_hours
        self._indicators: dict[str, ThreatIndicator] = {}
        self._feeds: dict[str, ThreatFeedSource] = {}
        self._index: dict[str, list[str]] = {}
        self._audit_log: list[IndicatorAuditEntry] = []

    # ---- Feed helpers -------------------------------------------------------

    def _ensure_feed(self, feed_id: str, name: str = "test-feed") -> ThreatFeedSource:
        if feed_id not in self._feeds:
            self._feeds[feed_id] = ThreatFeedSource(
                feed_id=feed_id,
                name=name,
                status="active",
            )
        return self._feeds[feed_id]

    # ---- Indicator creation -------------------------------------------------

    def add_indicator(
        self,
        *,
        indicator_type: ThreatIndicatorType,
        value: str,
        severity: ThreatSeverity,
        feed_id: str,
        expires_at: datetime | None = None,
        confidence: int = 80,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ThreatIndicator:
        self._ensure_feed(feed_id)
        indicator = ThreatIndicator(
            indicator_id=_new_id(),
            indicator_type=indicator_type,
            value=value.strip(),
            severity=severity,
            feed_id=feed_id,
            confidence=max(0, min(confidence, 100)),
            tags=list(tags or []),
            expires_at=_iso(expires_at) if expires_at else None,
            metadata=dict(metadata or {}),
        )
        self._indicators[indicator.indicator_id] = indicator
        normalized = value.strip().lower()
        self._index.setdefault(normalized, []).append(indicator.indicator_id)
        self._record_audit(
            indicator_id=indicator.indicator_id,
            feed_id=feed_id,
            event="ingested",
            actor="system",
            reason="Initial ingest",
        )
        return indicator

    # ---- Expiry check -------------------------------------------------------

    def _is_expired_at(self, indicator: ThreatIndicator, now: datetime) -> bool:
        if indicator.expires_at is None:
            return False
        try:
            exp = datetime.fromisoformat(indicator.expires_at)
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=UTC)
            return now >= exp
        except ValueError:
            return False

    def _is_near_expiry_at(self, indicator: ThreatIndicator, now: datetime) -> bool:
        if indicator.expires_at is None:
            return False
        try:
            exp = datetime.fromisoformat(indicator.expires_at)
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=UTC)
            delta = exp - now
            return timedelta(0) < delta <= timedelta(hours=self._threshold_hours)
        except ValueError:
            return False

    # ---- Audit helpers ------------------------------------------------------

    def _record_audit(
        self,
        *,
        indicator_id: str,
        feed_id: str,
        event: IndicatorLifecycleEvent,
        actor: str,
        reason: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> IndicatorAuditEntry:
        entry = IndicatorAuditEntry(
            entry_id=_new_id(),
            indicator_id=indicator_id,
            feed_id=feed_id,
            event=event,
            occurred_at=_iso(_utc_now()),
            actor=actor,
            reason=reason,
            metadata=dict(metadata or {}),
        )
        self._audit_log.append(entry)
        return entry

    # ---- Lookup — fail-closed on expired indicators -------------------------

    def lookup(
        self,
        value: str,
        indicator_type: ThreatIndicatorType,
        *,
        now: datetime | None = None,
    ) -> ThreatMatchResult:
        reference_time = now if now is not None else _utc_now()
        checked_at = _iso(reference_time)
        normalized = value.strip().lower()

        if not normalized:
            return ThreatMatchResult(
                checked_at=checked_at,
                input_value=value,
                input_type=indicator_type,
                matched=False,
                verdict="allow",
                reasons=["Empty value."],
            )

        candidate_ids = self._index.get(normalized, [])
        active_matches: list[ThreatIndicator] = []

        for iid in candidate_ids:
            ind = self._indicators.get(iid)
            if ind is None:
                continue
            if ind.indicator_type != indicator_type:
                continue

            # Auto-expire on lookup — fail-closed security gate
            if self._is_expired_at(ind, reference_time) and not ind.is_expired:
                ind.is_expired = True
                self._record_audit(
                    indicator_id=ind.indicator_id,
                    feed_id=ind.feed_id,
                    event="expired_auto",
                    actor="system",
                    reason=f"Auto-expired during lookup at {checked_at}",
                )

            # Flag near-expiry
            if not ind.is_expired and not ind.is_deactivated and self._is_near_expiry_at(ind, reference_time) and not ind.near_expiry_flagged:
                ind.near_expiry_flagged = True
                self._record_audit(
                    indicator_id=ind.indicator_id,
                    feed_id=ind.feed_id,
                    event="near_expiry_flagged",
                    actor="system",
                    reason=f"Near-expiry flagged during lookup at {checked_at}",
                )

            if ind.is_active():
                active_matches.append(ind)

        if not active_matches:
            return ThreatMatchResult(
                checked_at=checked_at,
                input_value=value,
                input_type=indicator_type,
                matched=False,
                verdict="allow",
                reasons=["No active, non-expired threat indicators matched."],
            )

        highest = min(active_matches, key=lambda i: _SEVERITY_RANK.index(i.severity))
        verdict: ThreatMatchVerdict = _VERDICT_FROM_SEVERITY[highest.severity]
        avg_confidence = sum(i.confidence for i in active_matches) // len(active_matches)

        return ThreatMatchResult(
            checked_at=checked_at,
            input_value=value,
            input_type=indicator_type,
            matched=True,
            verdict=verdict,
            matched_indicators=list(active_matches),
            highest_severity=highest.severity,
            confidence=avg_confidence,
            reasons=[f"Matched {len(active_matches)} active indicators (highest severity: {highest.severity})."],
        )

    # ---- Batch expiry sweep -------------------------------------------------

    def run_expiry_sweep(
        self,
        *,
        now: datetime | None = None,
    ) -> ExpirySweepResult:
        reference_time = now if now is not None else _utc_now()
        swept_at = _iso(reference_time)
        expired_count = 0
        near_expiry_count = 0
        already_expired_skipped = 0
        audit_entries: list[IndicatorAuditEntry] = []

        for ind in self._indicators.values():
            if ind.is_expired or ind.is_deactivated:
                if ind.is_expired:
                    already_expired_skipped += 1
                continue

            if self._is_expired_at(ind, reference_time):
                ind.is_expired = True
                entry = self._record_audit(
                    indicator_id=ind.indicator_id,
                    feed_id=ind.feed_id,
                    event="expired_auto",
                    actor="system",
                    reason=f"Batch sweep auto-expiry at {swept_at}",
                )
                audit_entries.append(entry)
                expired_count += 1
            elif self._is_near_expiry_at(ind, reference_time) and not ind.near_expiry_flagged:
                ind.near_expiry_flagged = True
                entry = self._record_audit(
                    indicator_id=ind.indicator_id,
                    feed_id=ind.feed_id,
                    event="near_expiry_flagged",
                    actor="system",
                    reason=f"Batch sweep near-expiry flag at {swept_at}",
                )
                audit_entries.append(entry)
                near_expiry_count += 1

        return ExpirySweepResult(
            swept_at=swept_at,
            expired_count=expired_count,
            near_expiry_count=near_expiry_count,
            already_expired_skipped=already_expired_skipped,
            audit_entries=audit_entries,
        )

    # ---- Manual deactivation ------------------------------------------------

    def deactivate_indicator(
        self,
        indicator_id: str,
        *,
        actor: str = "operator",
        reason: str | None = None,
    ) -> ThreatIndicator:
        ind = self._indicators.get(indicator_id)
        if ind is None:
            raise IOCExpiryError(f"Indicator not found: {indicator_id}")
        if ind.is_deactivated:
            raise IOCExpiryError(f"Indicator already deactivated: {indicator_id}")
        ind.is_deactivated = True
        self._record_audit(
            indicator_id=indicator_id,
            feed_id=ind.feed_id,
            event="deactivated_manual",
            actor=actor,
            reason=reason or "Manual deactivation",
        )
        return ind

    # ---- Reactivation -------------------------------------------------------

    def reactivate_indicator(
        self,
        indicator_id: str,
        *,
        new_expires_at: datetime | None = None,
        actor: str = "operator",
        reason: str | None = None,
    ) -> ThreatIndicator:
        ind = self._indicators.get(indicator_id)
        if ind is None:
            raise IOCExpiryError(f"Indicator not found: {indicator_id}")
        ind.is_expired = False
        ind.is_deactivated = False
        ind.near_expiry_flagged = False
        ind.expires_at = _iso(new_expires_at) if new_expires_at is not None else None
        self._record_audit(
            indicator_id=indicator_id,
            feed_id=ind.feed_id,
            event="reactivated",
            actor=actor,
            reason=reason or "Reactivation",
        )
        return ind

    # ---- Audit query --------------------------------------------------------

    def get_audit_trail(
        self,
        indicator_id: str | None = None,
        event: IndicatorLifecycleEvent | None = None,
    ) -> list[IndicatorAuditEntry]:
        entries = self._audit_log
        if indicator_id is not None:
            entries = [e for e in entries if e.indicator_id == indicator_id]
        if event is not None:
            entries = [e for e in entries if e.event == event]
        return list(entries)

    # ---- Introspection ------------------------------------------------------

    def get_indicator(self, indicator_id: str) -> ThreatIndicator | None:
        return self._indicators.get(indicator_id)

    def list_active_indicators(self) -> list[ThreatIndicator]:
        return [i for i in self._indicators.values() if i.is_active()]

    def list_expired_indicators(self) -> list[ThreatIndicator]:
        return [i for i in self._indicators.values() if i.is_expired]

    def list_near_expiry_indicators(
        self,
        *,
        now: datetime | None = None,
    ) -> list[ThreatIndicator]:
        reference_time = now if now is not None else _utc_now()
        return [i for i in self._indicators.values() if not i.is_expired and not i.is_deactivated and self._is_near_expiry_at(i, reference_time)]

    def flush(self) -> None:
        self._indicators.clear()
        self._feeds.clear()
        self._index.clear()
        self._audit_log.clear()


# ---------------------------------------------------------------------------
# Time helpers
# ---------------------------------------------------------------------------


def _past_hours(hours: float = 2.0) -> datetime:
    return _utc_now() - timedelta(hours=hours)


def _future_hours(hours: float = 48.0) -> datetime:
    return _utc_now() + timedelta(hours=hours)


def _near_future_hours(hours: float = 12.0) -> datetime:
    """Within the 24-hour near-expiry threshold."""
    return _utc_now() + timedelta(hours=hours)


def _just_expired_seconds(seconds: float = 1.0) -> datetime:
    return _utc_now() - timedelta(seconds=seconds)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def engine() -> Generator[IOCExpiryEngine, None, None]:
    e = IOCExpiryEngine(near_expiry_threshold_hours=24)
    yield e
    e.flush()


@pytest.fixture()
def feed_id() -> str:
    return _new_id()


@pytest.fixture()
def active_indicator(engine: IOCExpiryEngine, feed_id: str) -> ThreatIndicator:
    return engine.add_indicator(
        indicator_type="ip",
        value="198.51.100.10",
        severity="high",
        feed_id=feed_id,
        expires_at=_future_hours(72),
        confidence=90,
    )


@pytest.fixture()
def expired_indicator(engine: IOCExpiryEngine, feed_id: str) -> ThreatIndicator:
    return engine.add_indicator(
        indicator_type="ip",
        value="203.0.113.99",
        severity="critical",
        feed_id=feed_id,
        expires_at=_just_expired_seconds(60),
    )


@pytest.fixture()
def near_expiry_indicator(engine: IOCExpiryEngine, feed_id: str) -> ThreatIndicator:
    return engine.add_indicator(
        indicator_type="domain",
        value="near-expiry.example.com",
        severity="high",
        feed_id=feed_id,
        expires_at=_near_future_hours(6),
        confidence=85,
    )


@pytest.fixture()
def no_expiry_indicator(engine: IOCExpiryEngine, feed_id: str) -> ThreatIndicator:
    return engine.add_indicator(
        indicator_type="domain",
        value="permanent.example.com",
        severity="medium",
        feed_id=feed_id,
        expires_at=None,
    )


# ---------------------------------------------------------------------------
# Tests — Lookup expiry gate
# ---------------------------------------------------------------------------


class TestLookupExpiryGate:
    def test_expired_indicator_not_matched(self, engine: IOCExpiryEngine, expired_indicator: ThreatIndicator) -> None:
        result = engine.lookup(expired_indicator.value, "ip")
        assert result.matched is False
        assert result.verdict == "allow"

    def test_expired_indicator_excluded_from_matched_list(self, engine: IOCExpiryEngine, expired_indicator: ThreatIndicator) -> None:
        result = engine.lookup(expired_indicator.value, "ip")
        assert result.matched_indicators == []

    def test_active_indicator_matched(self, engine: IOCExpiryEngine, active_indicator: ThreatIndicator) -> None:
        result = engine.lookup(active_indicator.value, "ip")
        assert result.matched is True
        assert result.verdict in ("block", "quarantine", "warn", "allow")

    def test_no_expiry_indicator_always_matched(self, engine: IOCExpiryEngine, no_expiry_indicator: ThreatIndicator) -> None:
        result = engine.lookup(no_expiry_indicator.value, "domain")
        assert result.matched is True

    def test_lookup_at_exact_expiry_boundary_excludes(self, engine: IOCExpiryEngine, feed_id: str) -> None:
        expiry = _utc_now()
        engine.add_indicator(
            indicator_type="ip",
            value="10.0.0.1",
            severity="high",
            feed_id=feed_id,
            expires_at=expiry,
        )
        result = engine.lookup("10.0.0.1", "ip", now=expiry)
        assert result.matched is False

    def test_lookup_one_second_before_expiry_matches(self, engine: IOCExpiryEngine, feed_id: str) -> None:
        expiry = _utc_now() + timedelta(seconds=2)
        engine.add_indicator(
            indicator_type="ip",
            value="10.0.0.2",
            severity="high",
            feed_id=feed_id,
            expires_at=expiry,
        )
        result = engine.lookup("10.0.0.2", "ip", now=expiry - timedelta(seconds=1))
        assert result.matched is True

    def test_lookup_sets_is_expired_flag_on_indicator(self, engine: IOCExpiryEngine, expired_indicator: ThreatIndicator) -> None:
        assert expired_indicator.is_expired is False
        engine.lookup(expired_indicator.value, "ip")
        assert expired_indicator.is_expired is True

    def test_lookup_does_not_expire_active_indicator(self, engine: IOCExpiryEngine, active_indicator: ThreatIndicator) -> None:
        engine.lookup(active_indicator.value, "ip")
        assert active_indicator.is_expired is False

    def test_mix_of_active_and_expired_same_value_only_active_returned(self, engine: IOCExpiryEngine, feed_id: str) -> None:
        feed2 = _new_id()
        engine.add_indicator(
            indicator_type="ip",
            value="5.5.5.5",
            severity="medium",
            feed_id=feed_id,
            expires_at=_future_hours(48),
            confidence=70,
        )
        engine.add_indicator(
            indicator_type="ip",
            value="5.5.5.5",
            severity="critical",
            feed_id=feed2,
            expires_at=_just_expired_seconds(30),
        )
        result = engine.lookup("5.5.5.5", "ip")
        assert result.matched is True
        assert len(result.matched_indicators) == 1
        assert result.highest_severity == "medium"

    def test_expired_indicator_still_returns_allow_after_auto_expire(self, engine: IOCExpiryEngine, feed_id: str) -> None:
        engine.add_indicator(
            indicator_type="ip",
            value="9.9.9.9",
            severity="critical",
            feed_id=feed_id,
            expires_at=_past_hours(1),
        )
        for _ in range(3):
            result = engine.lookup("9.9.9.9", "ip")
            assert result.matched is False

    def test_empty_value_lookup_returns_allow(self, engine: IOCExpiryEngine) -> None:
        result = engine.lookup("", "ip")
        assert result.matched is False
        assert result.verdict == "allow"

    def test_lookup_result_to_dict_preserves_shape(self, engine: IOCExpiryEngine, active_indicator: ThreatIndicator) -> None:
        result = engine.lookup(active_indicator.value, "ip")
        d = result.to_dict()
        for key in (
            "checked_at",
            "input_value",
            "input_type",
            "matched",
            "verdict",
            "matched_indicators",
            "highest_severity",
            "confidence",
            "reasons",
        ):
            assert key in d


# ---------------------------------------------------------------------------
# Tests — Near-expiry flagging
# ---------------------------------------------------------------------------


class TestNearExpiryFlagging:
    def test_near_expiry_indicator_is_still_matched(self, engine: IOCExpiryEngine, near_expiry_indicator: ThreatIndicator) -> None:
        result = engine.lookup(near_expiry_indicator.value, "domain")
        assert result.matched is True

    def test_near_expiry_flag_set_on_lookup(self, engine: IOCExpiryEngine, near_expiry_indicator: ThreatIndicator) -> None:
        assert near_expiry_indicator.near_expiry_flagged is False
        engine.lookup(near_expiry_indicator.value, "domain")
        assert near_expiry_indicator.near_expiry_flagged is True

    def test_near_expiry_audit_entry_created_on_flag(self, engine: IOCExpiryEngine, near_expiry_indicator: ThreatIndicator) -> None:
        engine.lookup(near_expiry_indicator.value, "domain")
        trail = engine.get_audit_trail(
            indicator_id=near_expiry_indicator.indicator_id,
            event="near_expiry_flagged",
        )
        assert len(trail) == 1
        assert trail[0].event == "near_expiry_flagged"

    def test_near_expiry_not_flagged_twice(self, engine: IOCExpiryEngine, near_expiry_indicator: ThreatIndicator) -> None:
        engine.lookup(near_expiry_indicator.value, "domain")
        engine.lookup(near_expiry_indicator.value, "domain")
        trail = engine.get_audit_trail(
            indicator_id=near_expiry_indicator.indicator_id,
            event="near_expiry_flagged",
        )
        assert len(trail) == 1

    def test_far_future_expiry_not_flagged_as_near(self, engine: IOCExpiryEngine, active_indicator: ThreatIndicator) -> None:
        engine.lookup(active_indicator.value, "ip")
        assert active_indicator.near_expiry_flagged is False

    def test_no_expiry_indicator_never_flagged_as_near(self, engine: IOCExpiryEngine, no_expiry_indicator: ThreatIndicator) -> None:
        engine.lookup(no_expiry_indicator.value, "domain")
        assert no_expiry_indicator.near_expiry_flagged is False

    def test_list_near_expiry_indicators_returns_correct_set(self, engine: IOCExpiryEngine, feed_id: str) -> None:
        engine.add_indicator(
            indicator_type="ip",
            value="1.2.3.4",
            severity="high",
            feed_id=feed_id,
            expires_at=_future_hours(200),
        )
        engine.add_indicator(
            indicator_type="ip",
            value="1.2.3.5",
            severity="medium",
            feed_id=feed_id,
            expires_at=_near_future_hours(10),
        )
        engine.add_indicator(
            indicator_type="ip",
            value="1.2.3.6",
            severity="low",
            feed_id=feed_id,
            expires_at=_just_expired_seconds(5),
        )
        near = engine.list_near_expiry_indicators()
        values = [i.value for i in near]
        assert "1.2.3.5" in values
        assert "1.2.3.4" not in values
        assert "1.2.3.6" not in values

    def test_near_expiry_threshold_boundary_exact(self, engine: IOCExpiryEngine, feed_id: str) -> None:
        now = _utc_now()
        exactly_at_threshold = now + timedelta(hours=24)
        ind = engine.add_indicator(
            indicator_type="ip",
            value="2.2.2.2",
            severity="high",
            feed_id=feed_id,
            expires_at=exactly_at_threshold,
        )
        near = engine.list_near_expiry_indicators(now=now)
        assert ind in near

    def test_near_expiry_threshold_just_outside(self, engine: IOCExpiryEngine, feed_id: str) -> None:
        now = _utc_now()
        just_outside = now + timedelta(hours=24, seconds=1)
        ind = engine.add_indicator(
            indicator_type="ip",
            value="3.3.3.3",
            severity="high",
            feed_id=feed_id,
            expires_at=just_outside,
        )
        near = engine.list_near_expiry_indicators(now=now)
        assert ind not in near

    def test_expired_indicator_excluded_from_near_expiry_list(self, engine: IOCExpiryEngine, expired_indicator: ThreatIndicator) -> None:
        engine.lookup(expired_indicator.value, "ip")
        near = engine.list_near_expiry_indicators()
        assert expired_indicator not in near


# ---------------------------------------------------------------------------
# Tests — Batch expiry sweep
# ---------------------------------------------------------------------------


class TestBatchExpirySweep:
    def test_sweep_expires_past_due_indicators(self, engine: IOCExpiryEngine, feed_id: str) -> None:
        engine.add_indicator(
            indicator_type="ip",
            value="100.0.0.1",
            severity="high",
            feed_id=feed_id,
            expires_at=_past_hours(5),
        )
        engine.add_indicator(
            indicator_type="ip",
            value="100.0.0.2",
            severity="high",
            feed_id=feed_id,
            expires_at=_past_hours(1),
        )
        result = engine.run_expiry_sweep()
        assert result.expired_count == 2
        assert result.success_count == 2

    def test_sweep_flags_near_expiry_indicators(self, engine: IOCExpiryEngine, feed_id: str) -> None:
        engine.add_indicator(
            indicator_type="domain",
            value="near.example.com",
            severity="medium",
            feed_id=feed_id,
            expires_at=_near_future_hours(8),
        )
        result = engine.run_expiry_sweep()
        assert result.near_expiry_count == 1

    def test_sweep_skips_already_expired(self, engine: IOCExpiryEngine, feed_id: str) -> None:
        ind = engine.add_indicator(
            indicator_type="ip",
            value="200.0.0.1",
            severity="critical",
            feed_id=feed_id,
            expires_at=_past_hours(2),
        )
        ind.is_expired = True
        result = engine.run_expiry_sweep()
        assert result.already_expired_skipped == 1
        assert result.expired_count == 0

    def test_sweep_skips_deactivated(self, engine: IOCExpiryEngine, feed_id: str) -> None:
        ind = engine.add_indicator(
            indicator_type="ip",
            value="200.0.0.2",
            severity="high",
            feed_id=feed_id,
            expires_at=_past_hours(1),
        )
        ind.is_deactivated = True
        result = engine.run_expiry_sweep()
        assert result.expired_count == 0

    def test_sweep_does_not_expire_active_with_future_expiry(self, engine: IOCExpiryEngine, feed_id: str) -> None:
        engine.add_indicator(
            indicator_type="ip",
            value="192.168.1.1",
            severity="high",
            feed_id=feed_id,
            expires_at=_future_hours(48),
        )
        result = engine.run_expiry_sweep()
        assert result.expired_count == 0

    def test_sweep_does_not_expire_no_expiry_indicators(self, engine: IOCExpiryEngine, feed_id: str) -> None:
        engine.add_indicator(
            indicator_type="domain",
            value="forever.example.com",
            severity="medium",
            feed_id=feed_id,
            expires_at=None,
        )
        result = engine.run_expiry_sweep()
        assert result.expired_count == 0

    def test_sweep_produces_audit_entries_for_each_expired(self, engine: IOCExpiryEngine, feed_id: str) -> None:
        for i in range(3):
            engine.add_indicator(
                indicator_type="ip",
                value=f"55.0.0.{i}",
                severity="high",
                feed_id=feed_id,
                expires_at=_past_hours(1),
            )
        result = engine.run_expiry_sweep()
        assert len(result.audit_entries) == 3
        for entry in result.audit_entries:
            assert entry.event == "expired_auto"
            assert entry.actor == "system"

    def test_sweep_at_specific_reference_time(self, engine: IOCExpiryEngine, feed_id: str) -> None:
        now = _utc_now()
        future_time = now + timedelta(hours=10)
        engine.add_indicator(
            indicator_type="ip",
            value="77.0.0.1",
            severity="high",
            feed_id=feed_id,
            expires_at=now + timedelta(hours=5),
        )
        result = engine.run_expiry_sweep(now=future_time)
        assert result.expired_count == 1

    def test_sweep_mixed_batch_correct_counts(self, engine: IOCExpiryEngine, feed_id: str) -> None:
        for i in range(2):
            engine.add_indicator(
                indicator_type="ip",
                value=f"10.1.1.{i}",
                severity="high",
                feed_id=feed_id,
                expires_at=_past_hours(2),
            )
        for i in range(3):
            engine.add_indicator(
                indicator_type="ip",
                value=f"10.1.2.{i}",
                severity="medium",
                feed_id=feed_id,
                expires_at=_near_future_hours(4),
            )
        for i in range(4):
            engine.add_indicator(
                indicator_type="ip",
                value=f"10.1.3.{i}",
                severity="low",
                feed_id=feed_id,
                expires_at=_future_hours(100),
            )
        result = engine.run_expiry_sweep()
        assert result.expired_count == 2
        assert result.near_expiry_count == 3

    def test_sweep_result_to_dict_shape(self, engine: IOCExpiryEngine, feed_id: str) -> None:
        engine.add_indicator(
            indicator_type="ip",
            value="88.0.0.1",
            severity="critical",
            feed_id=feed_id,
            expires_at=_past_hours(1),
        )
        result = engine.run_expiry_sweep()
        d = result.to_dict()
        for key in ("swept_at", "expired_count", "near_expiry_count", "already_expired_skipped", "audit_entries"):
            assert key in d

    def test_empty_sweep_returns_zero_counts(self, engine: IOCExpiryEngine) -> None:
        result = engine.run_expiry_sweep()
        assert result.expired_count == 0
        assert result.near_expiry_count == 0
        assert result.already_expired_skipped == 0


# ---------------------------------------------------------------------------
# Tests — Deactivation vs. auto-expiry audit distinction
# ---------------------------------------------------------------------------


class TestDeactivationVsAutoExpiry:
    def test_manual_deactivation_records_deactivated_manual_event(self, engine: IOCExpiryEngine, active_indicator: ThreatIndicator) -> None:
        engine.deactivate_indicator(active_indicator.indicator_id, actor="admin")
        trail = engine.get_audit_trail(
            indicator_id=active_indicator.indicator_id,
            event="deactivated_manual",
        )
        assert len(trail) == 1
        assert trail[0].actor == "admin"

    def test_manual_deactivation_does_not_record_expired_auto(self, engine: IOCExpiryEngine, active_indicator: ThreatIndicator) -> None:
        engine.deactivate_indicator(active_indicator.indicator_id)
        trail = engine.get_audit_trail(
            indicator_id=active_indicator.indicator_id,
            event="expired_auto",
        )
        assert trail == []

    def test_auto_expiry_records_expired_auto_event(self, engine: IOCExpiryEngine, expired_indicator: ThreatIndicator) -> None:
        engine.lookup(expired_indicator.value, "ip")
        trail = engine.get_audit_trail(
            indicator_id=expired_indicator.indicator_id,
            event="expired_auto",
        )
        assert len(trail) == 1
        assert trail[0].actor == "system"

    def test_auto_expiry_does_not_record_deactivated_manual(self, engine: IOCExpiryEngine, expired_indicator: ThreatIndicator) -> None:
        engine.lookup(expired_indicator.value, "ip")
        trail = engine.get_audit_trail(
            indicator_id=expired_indicator.indicator_id,
            event="deactivated_manual",
        )
        assert trail == []

    def test_deactivated_manual_excludes_from_lookup(self, engine: IOCExpiryEngine, active_indicator: ThreatIndicator) -> None:
        engine.deactivate_indicator(active_indicator.indicator_id)
        result = engine.lookup(active_indicator.value, "ip")
        assert result.matched is False

    def test_deactivated_not_the_same_as_expired(self, engine: IOCExpiryEngine, active_indicator: ThreatIndicator) -> None:
        engine.deactivate_indicator(active_indicator.indicator_id)
        ind = engine.get_indicator(active_indicator.indicator_id)
        assert ind is not None
        assert ind.is_deactivated is True
        assert ind.is_expired is False

    def test_double_deactivation_raises(self, engine: IOCExpiryEngine, active_indicator: ThreatIndicator) -> None:
        engine.deactivate_indicator(active_indicator.indicator_id)
        with pytest.raises(IOCExpiryError):
            engine.deactivate_indicator(active_indicator.indicator_id)

    def test_deactivate_missing_indicator_raises(self, engine: IOCExpiryEngine) -> None:
        with pytest.raises(IOCExpiryError):
            engine.deactivate_indicator("ghost-id")

    def test_manual_deactivation_reason_recorded(self, engine: IOCExpiryEngine, active_indicator: ThreatIndicator) -> None:
        engine.deactivate_indicator(
            active_indicator.indicator_id,
            actor="analyst",
            reason="Confirmed false positive",
        )
        trail = engine.get_audit_trail(indicator_id=active_indicator.indicator_id)
        manual_entries = [e for e in trail if e.event == "deactivated_manual"]
        assert len(manual_entries) == 1
        assert manual_entries[0].reason == "Confirmed false positive"
        assert manual_entries[0].actor == "analyst"

    def test_auto_expiry_sweep_records_system_actor(self, engine: IOCExpiryEngine, feed_id: str) -> None:
        engine.add_indicator(
            indicator_type="ip",
            value="66.0.0.1",
            severity="high",
            feed_id=feed_id,
            expires_at=_past_hours(1),
        )
        engine.run_expiry_sweep()
        trail = engine.get_audit_trail(event="expired_auto")
        assert all(e.actor == "system" for e in trail)

    def test_audit_trail_both_events_queryable_independently(self, engine: IOCExpiryEngine, feed_id: str) -> None:
        auto_ind = engine.add_indicator(
            indicator_type="ip",
            value="77.1.1.1",
            severity="high",
            feed_id=feed_id,
            expires_at=_past_hours(1),
        )
        manual_ind = engine.add_indicator(
            indicator_type="ip",
            value="77.1.1.2",
            severity="high",
            feed_id=feed_id,
            expires_at=_future_hours(48),
        )
        engine.run_expiry_sweep()
        engine.deactivate_indicator(manual_ind.indicator_id, actor="reviewer")
        auto_trail = engine.get_audit_trail(event="expired_auto")
        manual_trail = engine.get_audit_trail(event="deactivated_manual")
        assert any(e.indicator_id == auto_ind.indicator_id for e in auto_trail)
        assert any(e.indicator_id == manual_ind.indicator_id for e in manual_trail)
        assert all(e.indicator_id != manual_ind.indicator_id for e in auto_trail)


# ---------------------------------------------------------------------------
# Tests — Reactivation
# ---------------------------------------------------------------------------


class TestReactivation:
    def test_reactivate_expired_indicator(self, engine: IOCExpiryEngine, expired_indicator: ThreatIndicator) -> None:
        engine.lookup(expired_indicator.value, "ip")
        assert expired_indicator.is_expired is True
        engine.reactivate_indicator(
            expired_indicator.indicator_id,
            new_expires_at=_future_hours(48),
        )
        assert expired_indicator.is_expired is False
        assert expired_indicator.is_deactivated is False

    def test_reactivated_indicator_matched_on_lookup(self, engine: IOCExpiryEngine, expired_indicator: ThreatIndicator) -> None:
        engine.lookup(expired_indicator.value, "ip")
        engine.reactivate_indicator(
            expired_indicator.indicator_id,
            new_expires_at=_future_hours(48),
        )
        result = engine.lookup(expired_indicator.value, "ip")
        assert result.matched is True

    def test_reactivate_deactivated_indicator(self, engine: IOCExpiryEngine, active_indicator: ThreatIndicator) -> None:
        engine.deactivate_indicator(active_indicator.indicator_id)
        engine.reactivate_indicator(
            active_indicator.indicator_id,
            new_expires_at=_future_hours(24),
        )
        assert active_indicator.is_deactivated is False

    def test_reactivation_clears_near_expiry_flag(self, engine: IOCExpiryEngine, near_expiry_indicator: ThreatIndicator) -> None:
        engine.lookup(near_expiry_indicator.value, "domain")
        assert near_expiry_indicator.near_expiry_flagged is True
        engine.reactivate_indicator(
            near_expiry_indicator.indicator_id,
            new_expires_at=_future_hours(168),
        )
        assert near_expiry_indicator.near_expiry_flagged is False

    def test_reactivation_without_new_expiry_sets_no_expiry(self, engine: IOCExpiryEngine, expired_indicator: ThreatIndicator) -> None:
        expired_indicator.is_expired = True
        engine.reactivate_indicator(expired_indicator.indicator_id)
        assert expired_indicator.expires_at is None

    def test_reactivation_records_audit_event(self, engine: IOCExpiryEngine, expired_indicator: ThreatIndicator) -> None:
        expired_indicator.is_expired = True
        engine.reactivate_indicator(
            expired_indicator.indicator_id,
            new_expires_at=_future_hours(48),
            actor="analyst",
            reason="Re-verified as active threat",
        )
        trail = engine.get_audit_trail(
            indicator_id=expired_indicator.indicator_id,
            event="reactivated",
        )
        assert len(trail) == 1
        assert trail[0].actor == "analyst"
        assert trail[0].reason == "Re-verified as active threat"

    def test_reactivate_missing_indicator_raises(self, engine: IOCExpiryEngine) -> None:
        with pytest.raises(IOCExpiryError):
            engine.reactivate_indicator("ghost-id")

    def test_reactivated_then_re_expired_on_lookup(self, engine: IOCExpiryEngine, feed_id: str) -> None:
        ind = engine.add_indicator(
            indicator_type="ip",
            value="44.0.0.1",
            severity="critical",
            feed_id=feed_id,
            expires_at=_past_hours(5),
        )
        engine.lookup("44.0.0.1", "ip")
        assert ind.is_expired is True
        new_expiry_also_past = _past_hours(1)
        engine.reactivate_indicator(ind.indicator_id, new_expires_at=new_expiry_also_past)
        assert ind.is_expired is False
        engine.lookup("44.0.0.1", "ip")
        assert ind.is_expired is True


# ---------------------------------------------------------------------------
# Tests — Audit trail integrity
# ---------------------------------------------------------------------------


class TestAuditTrailIntegrityIocExpiry:
    def test_ingest_always_records_ingested_event(self, engine: IOCExpiryEngine, feed_id: str) -> None:
        ind = engine.add_indicator(
            indicator_type="ip",
            value="audit-test.example.com",
            severity="low",
            feed_id=feed_id,
        )
        trail = engine.get_audit_trail(indicator_id=ind.indicator_id, event="ingested")
        assert len(trail) == 1
        assert trail[0].actor == "system"

    def test_full_lifecycle_audit_sequence(self, engine: IOCExpiryEngine, feed_id: str) -> None:
        ind = engine.add_indicator(
            indicator_type="ip",
            value="lifecycle.test",
            severity="high",
            feed_id=feed_id,
            expires_at=_past_hours(2),
        )
        engine.lookup("lifecycle.test", "ip")
        engine.reactivate_indicator(ind.indicator_id, new_expires_at=_future_hours(48), actor="analyst")
        engine.deactivate_indicator(ind.indicator_id, actor="reviewer")
        trail = engine.get_audit_trail(indicator_id=ind.indicator_id)
        events = [e.event for e in trail]
        assert "ingested" in events
        assert "expired_auto" in events
        assert "reactivated" in events
        assert "deactivated_manual" in events

    def test_audit_trail_filter_by_event(self, engine: IOCExpiryEngine, feed_id: str) -> None:
        for i in range(3):
            engine.add_indicator(
                indicator_type="ip",
                value=f"99.0.0.{i}",
                severity="high",
                feed_id=feed_id,
                expires_at=_past_hours(1),
            )
        engine.run_expiry_sweep()
        auto_trail = engine.get_audit_trail(event="expired_auto")
        assert len(auto_trail) == 3
        assert all(e.event == "expired_auto" for e in auto_trail)

    def test_audit_entries_have_all_required_fields(self, engine: IOCExpiryEngine, feed_id: str) -> None:
        ind = engine.add_indicator(
            indicator_type="domain",
            value="field-check.example.com",
            severity="medium",
            feed_id=feed_id,
        )
        trail = engine.get_audit_trail(indicator_id=ind.indicator_id)
        for entry in trail:
            d = entry.to_dict()
            for key in ("entry_id", "indicator_id", "feed_id", "event", "occurred_at", "actor", "reason", "metadata"):
                assert key in d

    def test_audit_trail_empty_for_unknown_indicator(self, engine: IOCExpiryEngine) -> None:
        trail = engine.get_audit_trail(indicator_id="unknown-id")
        assert trail == []

    def test_near_expiry_flag_audit_not_duplicated_across_sweeps(self, engine: IOCExpiryEngine, feed_id: str) -> None:
        ind = engine.add_indicator(
            indicator_type="ip",
            value="dup-flag-test.example.com",
            severity="high",
            feed_id=feed_id,
            expires_at=_near_future_hours(4),
        )
        engine.run_expiry_sweep()
        engine.run_expiry_sweep()
        trail = engine.get_audit_trail(
            indicator_id=ind.indicator_id,
            event="near_expiry_flagged",
        )
        assert len(trail) == 1

    def test_audit_trail_total_entry_count_after_full_lifecycle(self, engine: IOCExpiryEngine, feed_id: str) -> None:
        ind = engine.add_indicator(
            indicator_type="ip",
            value="count-test.example.com",
            severity="critical",
            feed_id=feed_id,
            expires_at=_past_hours(1),
        )
        engine.lookup("count-test.example.com", "ip")
        engine.reactivate_indicator(ind.indicator_id, new_expires_at=_future_hours(24))
        engine.deactivate_indicator(ind.indicator_id)
        trail = engine.get_audit_trail(indicator_id=ind.indicator_id)
        events = [e.event for e in trail]
        assert events.count("ingested") == 1
        assert events.count("expired_auto") == 1
        assert events.count("reactivated") == 1
        assert events.count("deactivated_manual") == 1


# ---------------------------------------------------------------------------
# Tests — Introspection helpers
# ---------------------------------------------------------------------------


class TestIntrospectionHelpers:
    def test_list_active_excludes_expired(
        self,
        engine: IOCExpiryEngine,
        active_indicator: ThreatIndicator,
        expired_indicator: ThreatIndicator,
    ) -> None:
        engine.lookup(expired_indicator.value, "ip")
        active = engine.list_active_indicators()
        ids = [i.indicator_id for i in active]
        assert active_indicator.indicator_id in ids
        assert expired_indicator.indicator_id not in ids

    def test_list_active_excludes_deactivated(self, engine: IOCExpiryEngine, active_indicator: ThreatIndicator) -> None:
        engine.deactivate_indicator(active_indicator.indicator_id)
        active = engine.list_active_indicators()
        assert active_indicator not in active

    def test_list_expired_returns_expired_only(
        self,
        engine: IOCExpiryEngine,
        active_indicator: ThreatIndicator,
        expired_indicator: ThreatIndicator,
    ) -> None:
        engine.lookup(expired_indicator.value, "ip")
        expired = engine.list_expired_indicators()
        assert expired_indicator in expired
        assert active_indicator not in expired

    def test_get_indicator_returns_correct_object(self, engine: IOCExpiryEngine, active_indicator: ThreatIndicator) -> None:
        fetched = engine.get_indicator(active_indicator.indicator_id)
        assert fetched is active_indicator

    def test_get_indicator_unknown_returns_none(self, engine: IOCExpiryEngine) -> None:
        assert engine.get_indicator("does-not-exist") is None

    def test_flush_clears_all_state(
        self,
        engine: IOCExpiryEngine,
        active_indicator: ThreatIndicator,
        feed_id: str,
    ) -> None:
        engine.flush()
        assert engine.list_active_indicators() == []
        assert engine.list_expired_indicators() == []
        assert engine.get_audit_trail() == []

    def test_two_engines_fully_isolated(self) -> None:
        e1 = IOCExpiryEngine()
        e2 = IOCExpiryEngine()
        fid = _new_id()
        e1.add_indicator(
            indicator_type="ip",
            value="isolated.test",
            severity="critical",
            feed_id=fid,
        )
        assert e2.list_active_indicators() == []
        e1.flush()
        e2.flush()


# ---------------------------------------------------------------------------
# Tests — Sweep result success_count
# ---------------------------------------------------------------------------


class TestSweepResultSuccessCount:
    def test_success_count_equals_expired_plus_near(self, engine: IOCExpiryEngine, feed_id: str) -> None:
        engine.add_indicator(
            indicator_type="ip",
            value="sc-test-1",
            severity="high",
            feed_id=feed_id,
            expires_at=_past_hours(2),
        )
        engine.add_indicator(
            indicator_type="ip",
            value="sc-test-2",
            severity="medium",
            feed_id=feed_id,
            expires_at=_near_future_hours(6),
        )
        result = engine.run_expiry_sweep()
        assert result.success_count == result.expired_count + result.near_expiry_count

    def test_success_count_zero_when_nothing_to_do(self, engine: IOCExpiryEngine) -> None:
        result = engine.run_expiry_sweep()
        assert result.success_count == 0
