from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Annotated, Any, Literal
import uuid

from fastapi import APIRouter, Body, Depends, FastAPI, HTTPException, Path
from fastapi.testclient import TestClient

# ---------------------------------------------------------------------------
# Canonical type aliases — mirror app.services.threat_feed_service contract
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
_SEVERITY_RANK: list[str] = ["critical", "high", "medium", "low", "info"]


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _new_id() -> str:
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Inline data models — mirror production schemas exactly
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
# Inline stub service — full in-memory implementation of the threat feed
# engine, isolated per test via dependency injection overrides.
# ---------------------------------------------------------------------------


class ThreatFeedIngestionError(Exception):
    pass


class _ThreatFeedService:
    def __init__(self) -> None:
        self._feeds: dict[str, ThreatFeedSource] = {}
        self._indicators: dict[str, ThreatIndicator] = {}
        self._index: dict[str, list[str]] = {}

    def register_feed(
        self,
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

    def ingest_indicators(
        self,
        feed_id: str,
        raw_indicators: list[dict[str, Any]],
    ) -> IngestionResult:
        feed = self._feeds.get(feed_id)
        if feed is None:
            raise ThreatFeedIngestionError(f"Feed not found: {feed_id}")
        added = updated = skipped = 0
        errors: list[str] = []
        for raw in raw_indicators:
            try:
                itype: ThreatIndicatorType = raw["indicator_type"]
                value: str = (raw.get("value") or "").strip()
                severity: ThreatSeverity = raw.get("severity", "medium")
                confidence = max(0, min(int(raw.get("confidence", 80)), 100))
                tags: list[str] = list(raw.get("tags") or [])
                expires_at: str | None = raw.get("expires_at")
                meta: dict[str, Any] = dict(raw.get("metadata") or {})
                if not value:
                    skipped += 1
                    continue
                normalized = value.lower()
                existing_ids = self._index.get(normalized, [])
                match = next(
                    (self._indicators[eid] for eid in existing_ids if self._indicators[eid].feed_id == feed_id),
                    None,
                )
                if match is not None:
                    match.severity = severity
                    match.confidence = confidence
                    match.tags = tags
                    match.last_seen = _utc_now()
                    match.expires_at = expires_at
                    match.metadata = meta
                    updated += 1
                else:
                    ind = ThreatIndicator(
                        indicator_id=_new_id(),
                        indicator_type=itype,
                        value=value,
                        severity=severity,
                        feed_id=feed_id,
                        tags=tags,
                        confidence=confidence,
                        expires_at=expires_at,
                        metadata=meta,
                    )
                    self._indicators[ind.indicator_id] = ind
                    self._index.setdefault(normalized, []).append(ind.indicator_id)
                    added += 1
            except (KeyError, ValueError, TypeError) as exc:
                errors.append(f"Skipped malformed indicator: {exc}")
        feed.indicator_count += added
        feed.status = "error" if errors and (added + updated) == 0 else "active"
        if errors:
            feed.error_message = errors[-1]
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

    def lookup(self, value: str, indicator_type: ThreatIndicatorType) -> ThreatMatchResult:
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
        highest_sev = min(matched, key=lambda i: _SEVERITY_RANK.index(i.severity)).severity
        avg_confidence = sum(i.confidence for i in matched) // len(matched)
        return ThreatMatchResult(
            checked_at=checked_at,
            input_value=value,
            input_type=indicator_type,
            matched=True,
            verdict=_VERDICT_FROM_SEVERITY[highest_sev],
            matched_indicators=matched,
            highest_severity=highest_sev,
            confidence=avg_confidence,
            reasons=[f"Matched {len(matched)} active indicator(s) with highest severity '{highest_sev}'."],
        )

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


# ---------------------------------------------------------------------------
# DI token — a plain sentinel used as a FastAPI dependency key.
# Production wiring replaces this with the real get_threat_feed_service.
# ---------------------------------------------------------------------------


def get_threat_feed_service() -> _ThreatFeedService:  # pragma: no cover
    raise NotImplementedError("Dependency must be overridden in tests.")


# ---------------------------------------------------------------------------
# Router builder — mirrors the production app.api.threat_feeds router shape
# ---------------------------------------------------------------------------


def _build_router() -> APIRouter:
    router = APIRouter(prefix="/api/threat-feeds", tags=["threat-intelligence"])

    @router.post("/feeds", status_code=201)
    def register_feed(
        payload: Annotated[dict[str, Any], Body()],
        svc: Annotated[_ThreatFeedService, Depends(get_threat_feed_service)],
    ) -> dict[str, Any]:
        name: str = payload.get("name", "").strip()
        if not name:
            raise HTTPException(status_code=422, detail="Field 'name' is required.")
        feed_url: str | None = payload.get("feed_url")
        metadata: dict[str, Any] = dict(payload.get("metadata") or {})
        try:
            feed = svc.register_feed(name=name, feed_url=feed_url, metadata=metadata)
        except ThreatFeedIngestionError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return {"status": "registered", "feed": feed.to_dict()}

    @router.get("/feeds")
    def list_feeds(
        svc: Annotated[_ThreatFeedService, Depends(get_threat_feed_service)],
    ) -> dict[str, Any]:
        feeds = svc.list_feeds()
        return {"status": "ok", "feeds": [f.to_dict() for f in feeds], "total": len(feeds)}

    @router.get("/feeds/{feed_id}")
    def get_feed(
        feed_id: Annotated[str, Path()],
        svc: Annotated[_ThreatFeedService, Depends(get_threat_feed_service)],
    ) -> dict[str, Any]:
        feed = svc.get_feed(feed_id)
        if feed is None:
            raise HTTPException(status_code=404, detail=f"Feed not found: {feed_id}")
        return {"status": "ok", "feed": feed.to_dict()}

    @router.post("/feeds/{feed_id}/ingest", status_code=200)
    def ingest_indicators(
        feed_id: Annotated[str, Path()],
        payload: Annotated[dict[str, Any], Body()],
        svc: Annotated[_ThreatFeedService, Depends(get_threat_feed_service)],
    ) -> dict[str, Any]:
        raw_indicators: list[dict[str, Any]] = payload.get("indicators") or []
        if not isinstance(raw_indicators, list):
            raise HTTPException(status_code=422, detail="Field 'indicators' must be a list.")
        try:
            result = svc.ingest_indicators(feed_id, raw_indicators)
        except ThreatFeedIngestionError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return {"status": "ok", "result": result.to_dict()}

    @router.post("/lookup")
    def lookup_indicator(
        payload: Annotated[dict[str, Any], Body()],
        svc: Annotated[_ThreatFeedService, Depends(get_threat_feed_service)],
    ) -> dict[str, Any]:
        value: str = (payload.get("value") or "").strip()
        indicator_type: str = (payload.get("indicator_type") or "").strip()
        if not value:
            raise HTTPException(status_code=422, detail="Field 'value' is required.")
        if not indicator_type:
            raise HTTPException(status_code=422, detail="Field 'indicator_type' is required.")
        result = svc.lookup(value, indicator_type)  # type: ignore[arg-type]
        return {"status": "ok", "result": result.to_dict()}

    @router.get("/feeds/{feed_id}/stats")
    def feed_stats(
        feed_id: Annotated[str, Path()],
        svc: Annotated[_ThreatFeedService, Depends(get_threat_feed_service)],
    ) -> dict[str, Any]:
        try:
            stats = svc.feed_stats(feed_id)
        except ThreatFeedIngestionError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return {"status": "ok", "stats": stats}

    @router.post("/feeds/{feed_id}/deactivate")
    def deactivate_feed(
        feed_id: Annotated[str, Path()],
        svc: Annotated[_ThreatFeedService, Depends(get_threat_feed_service)],
    ) -> dict[str, Any]:
        success = svc.deactivate_feed(feed_id)
        if not success:
            raise HTTPException(status_code=404, detail=f"Feed not found: {feed_id}")
        return {"status": "deactivated", "feed_id": feed_id}

    return router


def _build_test_app() -> FastAPI:
    app = FastAPI()
    app.include_router(_build_router())
    return app


# ---------------------------------------------------------------------------
# Fixture helpers — one isolated service + app per test
# ---------------------------------------------------------------------------


def _fresh_app_and_service() -> tuple[FastAPI, _ThreatFeedService]:
    svc = _ThreatFeedService()
    app = _build_test_app()
    app.dependency_overrides[get_threat_feed_service] = lambda: svc
    return app, svc


def _client_with_service() -> tuple[TestClient, _ThreatFeedService]:
    app, svc = _fresh_app_and_service()
    return TestClient(app, raise_server_exceptions=True), svc


# ---------------------------------------------------------------------------
# Tests — POST /api/threat-feeds/feeds  (register)
# ---------------------------------------------------------------------------


class TestRegisterFeedEndpoint:
    def test_register_feed_returns_201(self) -> None:
        app, _ = _fresh_app_and_service()
        try:
            with TestClient(app) as client:
                response = client.post(
                    "/api/threat-feeds/feeds",
                    json={"name": "MISP IOC Feed", "feed_url": "https://misp.example.com/feed"},
                )
        finally:
            app.dependency_overrides.clear()

        assert response.status_code == 201

    def test_register_feed_response_shape(self) -> None:
        app, _ = _fresh_app_and_service()
        try:
            with TestClient(app) as client:
                response = client.post(
                    "/api/threat-feeds/feeds",
                    json={"name": "Shape Test Feed"},
                )
        finally:
            app.dependency_overrides.clear()

        payload = response.json()
        assert payload["status"] == "registered"
        feed = payload["feed"]
        for key in ("feed_id", "name", "feed_url", "status", "indicator_count", "last_ingested_at", "error_message", "metadata"):
            assert key in feed, f"Missing key: {key}"

    def test_register_feed_persists_name_and_url(self) -> None:
        app, _ = _fresh_app_and_service()
        try:
            with TestClient(app) as client:
                response = client.post(
                    "/api/threat-feeds/feeds",
                    json={"name": "Persist Test", "feed_url": "https://feed.example.io"},
                )
        finally:
            app.dependency_overrides.clear()

        feed = response.json()["feed"]
        assert feed["name"] == "Persist Test"
        assert feed["feed_url"] == "https://feed.example.io"
        assert feed["status"] == "pending"

    def test_register_feed_without_url_accepted(self) -> None:
        app, _ = _fresh_app_and_service()
        try:
            with TestClient(app) as client:
                response = client.post("/api/threat-feeds/feeds", json={"name": "No URL Feed"})
        finally:
            app.dependency_overrides.clear()

        assert response.status_code == 201
        assert response.json()["feed"]["feed_url"] is None

    def test_register_feed_with_metadata(self) -> None:
        app, _ = _fresh_app_and_service()
        try:
            with TestClient(app) as client:
                response = client.post(
                    "/api/threat-feeds/feeds",
                    json={"name": "Meta Feed", "metadata": {"source": "misp", "tlp": "white"}},
                )
        finally:
            app.dependency_overrides.clear()

        feed = response.json()["feed"]
        assert feed["metadata"]["source"] == "misp"
        assert feed["metadata"]["tlp"] == "white"

    def test_register_feed_empty_name_returns_422(self) -> None:
        app, _ = _fresh_app_and_service()
        try:
            with TestClient(app) as client:
                response = client.post("/api/threat-feeds/feeds", json={"name": ""})
        finally:
            app.dependency_overrides.clear()

        assert response.status_code == 422

    def test_register_feed_missing_name_returns_422(self) -> None:
        app, _ = _fresh_app_and_service()
        try:
            with TestClient(app) as client:
                response = client.post("/api/threat-feeds/feeds", json={"feed_url": "https://x.io"})
        finally:
            app.dependency_overrides.clear()

        assert response.status_code == 422

    def test_register_feed_whitespace_name_returns_422(self) -> None:
        app, _ = _fresh_app_and_service()
        try:
            with TestClient(app) as client:
                response = client.post("/api/threat-feeds/feeds", json={"name": "   "})
        finally:
            app.dependency_overrides.clear()

        assert response.status_code == 422

    def test_register_feed_assigns_unique_ids(self) -> None:
        app, _ = _fresh_app_and_service()
        try:
            with TestClient(app) as client:
                r1 = client.post("/api/threat-feeds/feeds", json={"name": "Feed A"})
                r2 = client.post("/api/threat-feeds/feeds", json={"name": "Feed B"})
        finally:
            app.dependency_overrides.clear()

        assert r1.json()["feed"]["feed_id"] != r2.json()["feed"]["feed_id"]

    def test_register_feed_empty_body_returns_422(self) -> None:
        app, _ = _fresh_app_and_service()
        try:
            with TestClient(app) as client:
                response = client.post("/api/threat-feeds/feeds", json={})
        finally:
            app.dependency_overrides.clear()

        assert response.status_code == 422


# ---------------------------------------------------------------------------
# Tests — GET /api/threat-feeds/feeds  (list)
# ---------------------------------------------------------------------------


class TestListFeedsEndpoint:
    def test_list_feeds_empty_returns_200(self) -> None:
        app, _ = _fresh_app_and_service()
        try:
            with TestClient(app) as client:
                response = client.get("/api/threat-feeds/feeds")
        finally:
            app.dependency_overrides.clear()

        assert response.status_code == 200
        payload = response.json()
        assert payload["status"] == "ok"
        assert payload["feeds"] == []
        assert payload["total"] == 0

    def test_list_feeds_returns_registered_feeds(self) -> None:
        app, svc = _fresh_app_and_service()
        svc.register_feed(name="Alpha")
        svc.register_feed(name="Beta")
        svc.register_feed(name="Gamma")
        try:
            with TestClient(app) as client:
                response = client.get("/api/threat-feeds/feeds")
        finally:
            app.dependency_overrides.clear()

        payload = response.json()
        assert payload["total"] == 3
        names = {f["name"] for f in payload["feeds"]}
        assert names == {"Alpha", "Beta", "Gamma"}

    def test_list_feeds_response_shape(self) -> None:
        app, svc = _fresh_app_and_service()
        svc.register_feed(name="Shape Check")
        try:
            with TestClient(app) as client:
                response = client.get("/api/threat-feeds/feeds")
        finally:
            app.dependency_overrides.clear()

        payload = response.json()
        assert "status" in payload
        assert "feeds" in payload
        assert "total" in payload
        assert isinstance(payload["feeds"], list)

    def test_list_feeds_each_feed_has_required_keys(self) -> None:
        app, svc = _fresh_app_and_service()
        svc.register_feed(name="Key Check Feed")
        try:
            with TestClient(app) as client:
                response = client.get("/api/threat-feeds/feeds")
        finally:
            app.dependency_overrides.clear()

        feed = response.json()["feeds"][0]
        for key in ("feed_id", "name", "status", "indicator_count"):
            assert key in feed


# ---------------------------------------------------------------------------
# Tests — GET /api/threat-feeds/feeds/{feed_id}  (get single)
# ---------------------------------------------------------------------------


class TestGetFeedEndpoint:
    def test_get_feed_returns_200(self) -> None:
        app, svc = _fresh_app_and_service()
        feed = svc.register_feed(name="Fetch Me")
        try:
            with TestClient(app) as client:
                response = client.get(f"/api/threat-feeds/feeds/{feed.feed_id}")
        finally:
            app.dependency_overrides.clear()

        assert response.status_code == 200

    def test_get_feed_returns_correct_feed(self) -> None:
        app, svc = _fresh_app_and_service()
        feed = svc.register_feed(name="Specific Feed", feed_url="https://specific.io")
        try:
            with TestClient(app) as client:
                response = client.get(f"/api/threat-feeds/feeds/{feed.feed_id}")
        finally:
            app.dependency_overrides.clear()

        payload = response.json()
        assert payload["status"] == "ok"
        assert payload["feed"]["feed_id"] == feed.feed_id
        assert payload["feed"]["name"] == "Specific Feed"
        assert payload["feed"]["feed_url"] == "https://specific.io"

    def test_get_feed_missing_id_returns_404(self) -> None:
        app, _ = _fresh_app_and_service()
        try:
            with TestClient(app) as client:
                response = client.get("/api/threat-feeds/feeds/nonexistent-feed-id")
        finally:
            app.dependency_overrides.clear()

        assert response.status_code == 404
        assert "not found" in response.json()["detail"].lower()

    def test_get_feed_response_shape(self) -> None:
        app, svc = _fresh_app_and_service()
        feed = svc.register_feed(name="Shape Feed")
        try:
            with TestClient(app) as client:
                response = client.get(f"/api/threat-feeds/feeds/{feed.feed_id}")
        finally:
            app.dependency_overrides.clear()

        payload = response.json()
        assert "status" in payload
        assert "feed" in payload
        for key in ("feed_id", "name", "status", "indicator_count", "feed_url"):
            assert key in payload["feed"]


# ---------------------------------------------------------------------------
# Tests — POST /api/threat-feeds/feeds/{feed_id}/ingest
# ---------------------------------------------------------------------------


class TestIngestIndicatorsEndpoint:
    def test_ingest_indicators_returns_200(self) -> None:
        app, svc = _fresh_app_and_service()
        feed = svc.register_feed(name="Ingest Feed")
        payload = {
            "indicators": [
                {"indicator_type": "ip", "value": "198.51.100.1", "severity": "high", "confidence": 90},
                {"indicator_type": "domain", "value": "evil.example.com", "severity": "critical"},
            ]
        }
        try:
            with TestClient(app) as client:
                response = client.post(f"/api/threat-feeds/feeds/{feed.feed_id}/ingest", json=payload)
        finally:
            app.dependency_overrides.clear()

        assert response.status_code == 200

    def test_ingest_response_shape(self) -> None:
        app, svc = _fresh_app_and_service()
        feed = svc.register_feed(name="Shape Ingest Feed")
        try:
            with TestClient(app) as client:
                response = client.post(
                    f"/api/threat-feeds/feeds/{feed.feed_id}/ingest",
                    json={"indicators": [{"indicator_type": "ip", "value": "1.2.3.4", "severity": "low"}]},
                )
        finally:
            app.dependency_overrides.clear()

        payload = response.json()
        assert payload["status"] == "ok"
        result = payload["result"]
        for key in ("feed_id", "ingested_at", "indicators_added", "indicators_updated", "indicators_skipped", "errors", "success"):
            assert key in result, f"Missing key in result: {key}"

    def test_ingest_reports_correct_added_count(self) -> None:
        app, svc = _fresh_app_and_service()
        feed = svc.register_feed(name="Count Test Feed")
        try:
            with TestClient(app) as client:
                response = client.post(
                    f"/api/threat-feeds/feeds/{feed.feed_id}/ingest",
                    json={
                        "indicators": [
                            {"indicator_type": "ip", "value": "10.0.0.1", "severity": "high"},
                            {"indicator_type": "ip", "value": "10.0.0.2", "severity": "medium"},
                            {"indicator_type": "domain", "value": "bad.example.net", "severity": "critical"},
                        ]
                    },
                )
        finally:
            app.dependency_overrides.clear()

        result = response.json()["result"]
        assert result["indicators_added"] == 3
        assert result["indicators_updated"] == 0
        assert result["success"] is True

    def test_ingest_to_missing_feed_returns_404(self) -> None:
        app, _ = _fresh_app_and_service()
        try:
            with TestClient(app) as client:
                response = client.post(
                    "/api/threat-feeds/feeds/nonexistent-feed/ingest",
                    json={"indicators": [{"indicator_type": "ip", "value": "1.1.1.1", "severity": "high"}]},
                )
        finally:
            app.dependency_overrides.clear()

        assert response.status_code == 404
        assert "not found" in response.json()["detail"].lower()

    def test_ingest_indicators_field_not_list_returns_422(self) -> None:
        app, svc = _fresh_app_and_service()
        feed = svc.register_feed(name="Bad Payload Feed")
        try:
            with TestClient(app) as client:
                response = client.post(
                    f"/api/threat-feeds/feeds/{feed.feed_id}/ingest",
                    json={"indicators": "not-a-list"},
                )
        finally:
            app.dependency_overrides.clear()

        assert response.status_code == 422

    def test_ingest_empty_indicators_list_accepted(self) -> None:
        app, svc = _fresh_app_and_service()
        feed = svc.register_feed(name="Empty Ingest Feed")
        try:
            with TestClient(app) as client:
                response = client.post(
                    f"/api/threat-feeds/feeds/{feed.feed_id}/ingest",
                    json={"indicators": []},
                )
        finally:
            app.dependency_overrides.clear()

        assert response.status_code == 200
        result = response.json()["result"]
        assert result["indicators_added"] == 0
        assert result["success"] is True

    def test_ingest_skips_empty_value_indicators(self) -> None:
        app, svc = _fresh_app_and_service()
        feed = svc.register_feed(name="Skip Test Feed")
        try:
            with TestClient(app) as client:
                response = client.post(
                    f"/api/threat-feeds/feeds/{feed.feed_id}/ingest",
                    json={"indicators": [{"indicator_type": "ip", "value": "", "severity": "high"}]},
                )
        finally:
            app.dependency_overrides.clear()

        result = response.json()["result"]
        assert result["indicators_skipped"] == 1
        assert result["indicators_added"] == 0

    def test_ingest_updates_existing_indicator_from_same_feed(self) -> None:
        app, svc = _fresh_app_and_service()
        feed = svc.register_feed(name="Update Test Feed")
        svc.ingest_indicators(feed.feed_id, [{"indicator_type": "ip", "value": "5.5.5.5", "severity": "low", "confidence": 40}])
        try:
            with TestClient(app) as client:
                response = client.post(
                    f"/api/threat-feeds/feeds/{feed.feed_id}/ingest",
                    json={"indicators": [{"indicator_type": "ip", "value": "5.5.5.5", "severity": "critical", "confidence": 99}]},
                )
        finally:
            app.dependency_overrides.clear()

        result = response.json()["result"]
        assert result["indicators_updated"] == 1
        assert result["indicators_added"] == 0

    def test_ingest_missing_indicators_key_treated_as_empty(self) -> None:
        app, svc = _fresh_app_and_service()
        feed = svc.register_feed(name="No Key Feed")
        try:
            with TestClient(app) as client:
                response = client.post(
                    f"/api/threat-feeds/feeds/{feed.feed_id}/ingest",
                    json={},
                )
        finally:
            app.dependency_overrides.clear()

        assert response.status_code == 200
        assert response.json()["result"]["indicators_added"] == 0


# ---------------------------------------------------------------------------
# Tests — POST /api/threat-feeds/lookup
# ---------------------------------------------------------------------------


class TestLookupEndpoint:
    def test_lookup_matched_ip_returns_block_verdict(self) -> None:
        app, svc = _fresh_app_and_service()
        feed = svc.register_feed(name="Lookup Feed")
        svc.ingest_indicators(feed.feed_id, [{"indicator_type": "ip", "value": "203.0.113.5", "severity": "critical", "confidence": 95}])
        try:
            with TestClient(app) as client:
                response = client.post(
                    "/api/threat-feeds/lookup",
                    json={"value": "203.0.113.5", "indicator_type": "ip"},
                )
        finally:
            app.dependency_overrides.clear()

        assert response.status_code == 200
        result = response.json()["result"]
        assert result["matched"] is True
        assert result["verdict"] == "block"
        assert result["highest_severity"] == "critical"

    def test_lookup_unmatched_returns_allow(self) -> None:
        app, _ = _fresh_app_and_service()
        try:
            with TestClient(app) as client:
                response = client.post(
                    "/api/threat-feeds/lookup",
                    json={"value": "clean.example.com", "indicator_type": "domain"},
                )
        finally:
            app.dependency_overrides.clear()

        result = response.json()["result"]
        assert result["matched"] is False
        assert result["verdict"] == "allow"

    def test_lookup_response_shape(self) -> None:
        app, _ = _fresh_app_and_service()
        try:
            with TestClient(app) as client:
                response = client.post(
                    "/api/threat-feeds/lookup",
                    json={"value": "10.0.0.1", "indicator_type": "ip"},
                )
        finally:
            app.dependency_overrides.clear()

        result = response.json()["result"]
        for key in ("checked_at", "input_value", "input_type", "matched", "verdict", "matched_indicators", "highest_severity", "confidence", "reasons"):
            assert key in result, f"Missing key in lookup result: {key}"

    def test_lookup_missing_value_returns_422(self) -> None:
        app, _ = _fresh_app_and_service()
        try:
            with TestClient(app) as client:
                response = client.post(
                    "/api/threat-feeds/lookup",
                    json={"indicator_type": "ip"},
                )
        finally:
            app.dependency_overrides.clear()

        assert response.status_code == 422

    def test_lookup_missing_indicator_type_returns_422(self) -> None:
        app, _ = _fresh_app_and_service()
        try:
            with TestClient(app) as client:
                response = client.post(
                    "/api/threat-feeds/lookup",
                    json={"value": "1.2.3.4"},
                )
        finally:
            app.dependency_overrides.clear()

        assert response.status_code == 422

    def test_lookup_empty_value_returns_422(self) -> None:
        app, _ = _fresh_app_and_service()
        try:
            with TestClient(app) as client:
                response = client.post(
                    "/api/threat-feeds/lookup",
                    json={"value": "", "indicator_type": "ip"},
                )
        finally:
            app.dependency_overrides.clear()

        assert response.status_code == 422

    def test_lookup_inactive_feed_not_matched(self) -> None:
        app, svc = _fresh_app_and_service()
        feed = svc.register_feed(name="Inactive Lookup Feed")
        svc.ingest_indicators(feed.feed_id, [{"indicator_type": "ip", "value": "172.16.0.1", "severity": "critical", "confidence": 99}])
        svc.deactivate_feed(feed.feed_id)
        try:
            with TestClient(app) as client:
                response = client.post(
                    "/api/threat-feeds/lookup",
                    json={"value": "172.16.0.1", "indicator_type": "ip"},
                )
        finally:
            app.dependency_overrides.clear()

        result = response.json()["result"]
        assert result["matched"] is False
        assert result["verdict"] == "allow"

    def test_lookup_case_insensitive_match(self) -> None:
        app, svc = _fresh_app_and_service()
        feed = svc.register_feed(name="Case Feed")
        svc.ingest_indicators(feed.feed_id, [{"indicator_type": "domain", "value": "evil.example.com", "severity": "high"}])
        try:
            with TestClient(app) as client:
                response = client.post(
                    "/api/threat-feeds/lookup",
                    json={"value": "EVIL.EXAMPLE.COM", "indicator_type": "domain"},
                )
        finally:
            app.dependency_overrides.clear()

        assert response.json()["result"]["matched"] is True

    def test_lookup_type_mismatch_no_match(self) -> None:
        app, svc = _fresh_app_and_service()
        feed = svc.register_feed(name="Type Mismatch Feed")
        svc.ingest_indicators(feed.feed_id, [{"indicator_type": "ip", "value": "9.9.9.9", "severity": "critical"}])
        try:
            with TestClient(app) as client:
                response = client.post(
                    "/api/threat-feeds/lookup",
                    json={"value": "9.9.9.9", "indicator_type": "domain"},
                )
        finally:
            app.dependency_overrides.clear()

        assert response.json()["result"]["matched"] is False

    def test_lookup_matched_indicators_list_populated(self) -> None:
        app, svc = _fresh_app_and_service()
        feed = svc.register_feed(name="Indicator List Feed")
        svc.ingest_indicators(feed.feed_id, [{"indicator_type": "hash_sha256", "value": "abc123def456", "severity": "high", "confidence": 88}])
        try:
            with TestClient(app) as client:
                response = client.post(
                    "/api/threat-feeds/lookup",
                    json={"value": "abc123def456", "indicator_type": "hash_sha256"},
                )
        finally:
            app.dependency_overrides.clear()

        result = response.json()["result"]
        assert len(result["matched_indicators"]) >= 1
        ind = result["matched_indicators"][0]
        for key in ("indicator_id", "indicator_type", "value", "severity", "feed_id", "confidence"):
            assert key in ind

    def test_lookup_verdict_for_each_severity(self) -> None:
        cases = [
            ("critical", "block"),
            ("high", "quarantine"),
            ("medium", "warn"),
            ("low", "allow"),
            ("info", "allow"),
        ]
        for severity, expected_verdict in cases:
            app, svc = _fresh_app_and_service()
            feed = svc.register_feed(name=f"Verdict Feed {severity}")
            value = f"verdict-test-{severity}.example.com"
            svc.ingest_indicators(feed.feed_id, [{"indicator_type": "domain", "value": value, "severity": severity, "confidence": 80}])
            try:
                with TestClient(app) as client:
                    response = client.post(
                        "/api/threat-feeds/lookup",
                        json={"value": value, "indicator_type": "domain"},
                    )
            finally:
                app.dependency_overrides.clear()

            result = response.json()["result"]
            assert result["verdict"] == expected_verdict, f"Expected verdict '{expected_verdict}' for severity '{severity}', got '{result['verdict']}'"


# ---------------------------------------------------------------------------
# Tests — GET /api/threat-feeds/feeds/{feed_id}/stats
# ---------------------------------------------------------------------------


class TestFeedStatsEndpoint:
    def test_feed_stats_returns_200(self) -> None:
        app, svc = _fresh_app_and_service()
        feed = svc.register_feed(name="Stats Feed")
        svc.ingest_indicators(
            feed.feed_id,
            [
                {"indicator_type": "ip", "value": "10.1.1.1", "severity": "high"},
                {"indicator_type": "domain", "value": "stats.example.com", "severity": "critical"},
            ],
        )
        try:
            with TestClient(app) as client:
                response = client.get(f"/api/threat-feeds/feeds/{feed.feed_id}/stats")
        finally:
            app.dependency_overrides.clear()

        assert response.status_code == 200

    def test_feed_stats_response_shape(self) -> None:
        app, svc = _fresh_app_and_service()
        feed = svc.register_feed(name="Stats Shape Feed")
        svc.ingest_indicators(feed.feed_id, [{"indicator_type": "ip", "value": "11.11.11.11", "severity": "low"}])
        try:
            with TestClient(app) as client:
                response = client.get(f"/api/threat-feeds/feeds/{feed.feed_id}/stats")
        finally:
            app.dependency_overrides.clear()

        payload = response.json()
        assert payload["status"] == "ok"
        stats = payload["stats"]
        for key in ("feed_id", "status", "total_indicators", "severity_distribution", "type_distribution", "last_ingested_at"):
            assert key in stats, f"Missing key in stats: {key}"

    def test_feed_stats_total_matches_ingested(self) -> None:
        app, svc = _fresh_app_and_service()
        feed = svc.register_feed(name="Total Count Feed")
        svc.ingest_indicators(feed.feed_id, [{"indicator_type": "ip", "value": f"192.0.2.{i}", "severity": "medium"} for i in range(1, 6)])
        try:
            with TestClient(app) as client:
                response = client.get(f"/api/threat-feeds/feeds/{feed.feed_id}/stats")
        finally:
            app.dependency_overrides.clear()

        stats = response.json()["stats"]
        assert stats["total_indicators"] == 5

    def test_feed_stats_severity_distribution_correct(self) -> None:
        app, svc = _fresh_app_and_service()
        feed = svc.register_feed(name="Severity Dist Feed")
        svc.ingest_indicators(
            feed.feed_id,
            [
                {"indicator_type": "ip", "value": "1.0.0.1", "severity": "critical"},
                {"indicator_type": "ip", "value": "1.0.0.2", "severity": "critical"},
                {"indicator_type": "ip", "value": "1.0.0.3", "severity": "high"},
                {"indicator_type": "ip", "value": "1.0.0.4", "severity": "medium"},
            ],
        )
        try:
            with TestClient(app) as client:
                response = client.get(f"/api/threat-feeds/feeds/{feed.feed_id}/stats")
        finally:
            app.dependency_overrides.clear()

        dist = response.json()["stats"]["severity_distribution"]
        assert dist["critical"] == 2
        assert dist["high"] == 1
        assert dist["medium"] == 1

    def test_feed_stats_type_distribution_correct(self) -> None:
        app, svc = _fresh_app_and_service()
        feed = svc.register_feed(name="Type Dist Feed")
        svc.ingest_indicators(
            feed.feed_id,
            [
                {"indicator_type": "ip", "value": "2.0.0.1", "severity": "high"},
                {"indicator_type": "ip", "value": "2.0.0.2", "severity": "high"},
                {"indicator_type": "domain", "value": "dist.example.com", "severity": "medium"},
            ],
        )
        try:
            with TestClient(app) as client:
                response = client.get(f"/api/threat-feeds/feeds/{feed.feed_id}/stats")
        finally:
            app.dependency_overrides.clear()

        dist = response.json()["stats"]["type_distribution"]
        assert dist["ip"] == 2
        assert dist["domain"] == 1

    def test_feed_stats_missing_feed_returns_404(self) -> None:
        app, _ = _fresh_app_and_service()
        try:
            with TestClient(app) as client:
                response = client.get("/api/threat-feeds/feeds/ghost-feed-id/stats")
        finally:
            app.dependency_overrides.clear()

        assert response.status_code == 404
        assert "not found" in response.json()["detail"].lower()

    def test_feed_stats_status_active_after_ingest(self) -> None:
        app, svc = _fresh_app_and_service()
        feed = svc.register_feed(name="Active Status Feed")
        svc.ingest_indicators(feed.feed_id, [{"indicator_type": "ip", "value": "3.3.3.3", "severity": "info"}])
        try:
            with TestClient(app) as client:
                response = client.get(f"/api/threat-feeds/feeds/{feed.feed_id}/stats")
        finally:
            app.dependency_overrides.clear()

        assert response.json()["stats"]["status"] == "active"


# ---------------------------------------------------------------------------
# Tests — POST /api/threat-feeds/feeds/{feed_id}/deactivate
# ---------------------------------------------------------------------------


class TestDeactivateFeedEndpoint:
    def test_deactivate_feed_returns_200(self) -> None:
        app, svc = _fresh_app_and_service()
        feed = svc.register_feed(name="Deactivate Me")
        try:
            with TestClient(app) as client:
                response = client.post(f"/api/threat-feeds/feeds/{feed.feed_id}/deactivate")
        finally:
            app.dependency_overrides.clear()

        assert response.status_code == 200

    def test_deactivate_feed_response_shape(self) -> None:
        app, svc = _fresh_app_and_service()
        feed = svc.register_feed(name="Shape Deactivate Feed")
        try:
            with TestClient(app) as client:
                response = client.post(f"/api/threat-feeds/feeds/{feed.feed_id}/deactivate")
        finally:
            app.dependency_overrides.clear()

        payload = response.json()
        assert payload["status"] == "deactivated"
        assert payload["feed_id"] == feed.feed_id

    def test_deactivate_feed_sets_status_inactive(self) -> None:
        app, svc = _fresh_app_and_service()
        feed = svc.register_feed(name="Status Check Deactivate")
        try:
            with TestClient(app) as client:
                client.post(f"/api/threat-feeds/feeds/{feed.feed_id}/deactivate")
                response = client.get(f"/api/threat-feeds/feeds/{feed.feed_id}")
        finally:
            app.dependency_overrides.clear()

        assert response.json()["feed"]["status"] == "inactive"

    def test_deactivate_missing_feed_returns_404(self) -> None:
        app, _ = _fresh_app_and_service()
        try:
            with TestClient(app) as client:
                response = client.post("/api/threat-feeds/feeds/nonexistent-id/deactivate")
        finally:
            app.dependency_overrides.clear()

        assert response.status_code == 404
        assert "not found" in response.json()["detail"].lower()

    def test_deactivate_feed_blocks_subsequent_lookups(self) -> None:
        app, svc = _fresh_app_and_service()
        feed = svc.register_feed(name="Block After Deactivate Feed")
        svc.ingest_indicators(feed.feed_id, [{"indicator_type": "ip", "value": "55.55.55.55", "severity": "critical", "confidence": 99}])
        try:
            with TestClient(app) as client:
                client.post(f"/api/threat-feeds/feeds/{feed.feed_id}/deactivate")
                response = client.post(
                    "/api/threat-feeds/lookup",
                    json={"value": "55.55.55.55", "indicator_type": "ip"},
                )
        finally:
            app.dependency_overrides.clear()

        result = response.json()["result"]
        assert result["matched"] is False
        assert result["verdict"] == "allow"

    def test_deactivate_then_reactivate_via_ingest(self) -> None:
        app, svc = _fresh_app_and_service()
        feed = svc.register_feed(name="Reactivate Feed")
        svc.ingest_indicators(feed.feed_id, [{"indicator_type": "ip", "value": "66.66.66.66", "severity": "high"}])
        svc.deactivate_feed(feed.feed_id)
        try:
            with TestClient(app) as client:
                client.post(
                    f"/api/threat-feeds/feeds/{feed.feed_id}/ingest",
                    json={"indicators": [{"indicator_type": "ip", "value": "77.77.77.77", "severity": "medium"}]},
                )
                response = client.get(f"/api/threat-feeds/feeds/{feed.feed_id}")
        finally:
            app.dependency_overrides.clear()

        assert response.json()["feed"]["status"] == "active"


# ---------------------------------------------------------------------------
# Tests — Cross-endpoint integration flows
# ---------------------------------------------------------------------------


class TestCrossEndpointFlows:
    def test_register_ingest_lookup_full_flow(self) -> None:
        app, _ = _fresh_app_and_service()
        try:
            with TestClient(app) as client:
                reg = client.post("/api/threat-feeds/feeds", json={"name": "Full Flow Feed"})
                assert reg.status_code == 201
                feed_id = reg.json()["feed"]["feed_id"]

                ing = client.post(
                    f"/api/threat-feeds/feeds/{feed_id}/ingest",
                    json={
                        "indicators": [
                            {"indicator_type": "ip", "value": "198.51.100.99", "severity": "critical", "confidence": 97},
                            {"indicator_type": "domain", "value": "flow.evil.example", "severity": "high"},
                        ]
                    },
                )
                assert ing.status_code == 200
                assert ing.json()["result"]["indicators_added"] == 2

                lookup = client.post(
                    "/api/threat-feeds/lookup",
                    json={"value": "198.51.100.99", "indicator_type": "ip"},
                )
                assert lookup.status_code == 200
                assert lookup.json()["result"]["matched"] is True
                assert lookup.json()["result"]["verdict"] == "block"
        finally:
            app.dependency_overrides.clear()

    def test_register_ingest_stats_deactivate_flow(self) -> None:
        app, _ = _fresh_app_and_service()
        try:
            with TestClient(app) as client:
                reg = client.post("/api/threat-feeds/feeds", json={"name": "Multi Step Feed"})
                feed_id = reg.json()["feed"]["feed_id"]

                client.post(
                    f"/api/threat-feeds/feeds/{feed_id}/ingest",
                    json={"indicators": [{"indicator_type": "ip", "value": f"10.20.{i}.1", "severity": "medium"} for i in range(5)]},
                )

                stats = client.get(f"/api/threat-feeds/feeds/{feed_id}/stats")
                assert stats.status_code == 200
                assert stats.json()["stats"]["total_indicators"] == 5
                assert stats.json()["stats"]["status"] == "active"

                deact = client.post(f"/api/threat-feeds/feeds/{feed_id}/deactivate")
                assert deact.status_code == 200
                assert deact.json()["status"] == "deactivated"

                feed_check = client.get(f"/api/threat-feeds/feeds/{feed_id}")
                assert feed_check.json()["feed"]["status"] == "inactive"
        finally:
            app.dependency_overrides.clear()

    def test_multiple_feeds_isolation_in_lookup(self) -> None:
        app, svc = _fresh_app_and_service()
        f1 = svc.register_feed(name="Feed One Isolation")
        f2 = svc.register_feed(name="Feed Two Isolation")
        svc.ingest_indicators(f1.feed_id, [{"indicator_type": "ip", "value": "100.100.100.1", "severity": "critical"}])
        svc.ingest_indicators(f2.feed_id, [{"indicator_type": "ip", "value": "200.200.200.1", "severity": "info"}])
        try:
            with TestClient(app) as client:
                r1 = client.post(
                    "/api/threat-feeds/lookup",
                    json={"value": "100.100.100.1", "indicator_type": "ip"},
                )
                r2 = client.post(
                    "/api/threat-feeds/lookup",
                    json={"value": "200.200.200.1", "indicator_type": "ip"},
                )
        finally:
            app.dependency_overrides.clear()

        assert r1.json()["result"]["verdict"] == "block"
        assert r2.json()["result"]["verdict"] == "allow"

    def test_list_feeds_reflects_registered_feeds(self) -> None:
        app, _ = _fresh_app_and_service()
        try:
            with TestClient(app) as client:
                for name in ("Alpha", "Beta", "Gamma", "Delta"):
                    client.post("/api/threat-feeds/feeds", json={"name": name})
                response = client.get("/api/threat-feeds/feeds")
        finally:
            app.dependency_overrides.clear()

        payload = response.json()
        assert payload["total"] == 4
        names = {f["name"] for f in payload["feeds"]}
        assert names == {"Alpha", "Beta", "Gamma", "Delta"}

    def test_dependency_overrides_are_cleared_after_each_test(self) -> None:
        app1, svc1 = _fresh_app_and_service()
        app2, svc2 = _fresh_app_and_service()
        feed1 = svc1.register_feed(name="App1 Feed")
        svc1.ingest_indicators(feed1.feed_id, [{"indicator_type": "ip", "value": "44.44.44.44", "severity": "critical"}])
        try:
            with TestClient(app1) as client1:
                r1 = client1.post(
                    "/api/threat-feeds/lookup",
                    json={"value": "44.44.44.44", "indicator_type": "ip"},
                )
        finally:
            app1.dependency_overrides.clear()

        try:
            with TestClient(app2) as client2:
                r2 = client2.post(
                    "/api/threat-feeds/lookup",
                    json={"value": "44.44.44.44", "indicator_type": "ip"},
                )
        finally:
            app2.dependency_overrides.clear()

        assert r1.json()["result"]["matched"] is True
        assert r2.json()["result"]["matched"] is False
