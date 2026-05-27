from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from app.ui.sessionrisk import (
    SessionRiskFilterOption,
    SessionRiskRelatedLink,
    SessionRiskResponse,
    SessionRiskReviewItem,
    SessionRiskSeverityBreakdown,
    SessionRiskSignalItem,
    SessionRiskSummaryCard,
    SessionRiskTimelineEvent,
    router,
)

# ---------------------------------------------------------------------------
# Test app — GET /api/ui/session-risk/{session_id}
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def client() -> TestClient:
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


SESSION_A = "sess-001"
SESSION_B = "sess-002"
SESSION_PADDED = "  sess-003  "
SESSION_PADDED_CLEAN = "sess-003"


# ---------------------------------------------------------------------------
# GET /api/ui/session-risk/{session_id} — 200 + shape
# ---------------------------------------------------------------------------


class TestSessionRiskStatus:
    def test_status_200(self, client: TestClient) -> None:
        response = client.get(f"/api/ui/session-risk/{SESSION_A}")
        assert response.status_code == 200

    def test_response_is_json(self, client: TestClient) -> None:
        response = client.get(f"/api/ui/session-risk/{SESSION_A}")
        assert response.headers["content-type"].startswith("application/json")

    def test_response_model_parses(self, client: TestClient) -> None:
        data = client.get(f"/api/ui/session-risk/{SESSION_A}").json()
        model = SessionRiskResponse(**data)
        assert isinstance(model, SessionRiskResponse)

    def test_different_session_ids_both_200(self, client: TestClient) -> None:
        for sid in (SESSION_A, SESSION_B):
            response = client.get(f"/api/ui/session-risk/{sid}")
            assert response.status_code == 200, f"Expected 200 for {sid}"


# ---------------------------------------------------------------------------
# Top-level shape
# ---------------------------------------------------------------------------


class TestSessionRiskShape:
    def test_top_level_fields_present(self, client: TestClient) -> None:
        data = client.get(f"/api/ui/session-risk/{SESSION_A}").json()
        required = {
            "title",
            "description",
            "session_id",
            "client_id",
            "overall_risk_level",
            "policy_mode",
            "generated_at",
            "summary_cards",
            "severity_breakdown",
            "signals",
            "recent_reviews",
            "timeline",
            "available_filters",
            "related_links",
            "metadata",
        }
        for field in required:
            assert field in data, f"Missing top-level field '{field}'"

    def test_title_is_str(self, client: TestClient) -> None:
        data = client.get(f"/api/ui/session-risk/{SESSION_A}").json()
        assert isinstance(data["title"], str)
        assert len(data["title"]) > 0

    def test_description_is_str(self, client: TestClient) -> None:
        data = client.get(f"/api/ui/session-risk/{SESSION_A}").json()
        assert isinstance(data["description"], str)
        assert len(data["description"]) > 0

    def test_session_id_matches_path(self, client: TestClient) -> None:
        data = client.get(f"/api/ui/session-risk/{SESSION_A}").json()
        assert data["session_id"] == SESSION_A

    def test_client_id_nullable(self, client: TestClient) -> None:
        data = client.get(f"/api/ui/session-risk/{SESSION_A}").json()
        assert data["client_id"] is None or isinstance(data["client_id"], str)

    def test_client_id_query_param_accepted(self, client: TestClient) -> None:
        response = client.get(
            f"/api/ui/session-risk/{SESSION_A}",
            params={"client_id": "client-xyz"},
        )
        assert response.status_code == 200
        assert response.json()["client_id"] == "client-xyz"

    def test_client_id_blank_normalized_to_none(self, client: TestClient) -> None:
        response = client.get(
            f"/api/ui/session-risk/{SESSION_A}",
            params={"client_id": "   "},
        )
        assert response.status_code == 200
        assert response.json()["client_id"] is None

    def test_overall_risk_level_valid(self, client: TestClient) -> None:
        data = client.get(f"/api/ui/session-risk/{SESSION_A}").json()
        assert data["overall_risk_level"] in {"low", "medium", "high", "critical"}

    def test_policy_mode_is_str(self, client: TestClient) -> None:
        data = client.get(f"/api/ui/session-risk/{SESSION_A}").json()
        assert isinstance(data["policy_mode"], str)
        assert len(data["policy_mode"]) > 0

    def test_policy_mode_default(self, client: TestClient) -> None:
        data = client.get(f"/api/ui/session-risk/{SESSION_A}").json()
        assert data["policy_mode"] == "review"

    def test_generated_at_is_str(self, client: TestClient) -> None:
        data = client.get(f"/api/ui/session-risk/{SESSION_A}").json()
        assert isinstance(data["generated_at"], str)
        assert len(data["generated_at"]) > 0


# ---------------------------------------------------------------------------
# Risk level defaults (empty session — no events)
# ---------------------------------------------------------------------------


class TestSessionRiskDefaults:
    def test_default_risk_level_is_low(self, client: TestClient) -> None:
        data = client.get(f"/api/ui/session-risk/{SESSION_A}").json()
        assert data["overall_risk_level"] == "low"

    def test_default_metadata_empty_state(self, client: TestClient) -> None:
        data = client.get(f"/api/ui/session-risk/{SESSION_A}").json()
        assert data["metadata"]["empty_state"] is True
        assert data["metadata"]["session_found"] is False

    def test_default_recent_reviews_empty(self, client: TestClient) -> None:
        data = client.get(f"/api/ui/session-risk/{SESSION_A}").json()
        assert data["recent_reviews"] == []

    def test_default_timeline_empty(self, client: TestClient) -> None:
        data = client.get(f"/api/ui/session-risk/{SESSION_A}").json()
        assert data["timeline"] == []


# ---------------------------------------------------------------------------
# summary_cards shape
# ---------------------------------------------------------------------------


class TestSessionRiskSummaryCards:
    def test_summary_cards_is_list(self, client: TestClient) -> None:
        data = client.get(f"/api/ui/session-risk/{SESSION_A}").json()
        assert isinstance(data["summary_cards"], list)

    def test_summary_cards_not_empty(self, client: TestClient) -> None:
        data = client.get(f"/api/ui/session-risk/{SESSION_A}").json()
        assert len(data["summary_cards"]) > 0

    def test_summary_cards_required_fields(self, client: TestClient) -> None:
        data = client.get(f"/api/ui/session-risk/{SESSION_A}").json()
        for card in data["summary_cards"]:
            assert "key" in card
            assert "label" in card
            assert "value" in card
            assert "tone" in card

    def test_summary_cards_model_parses(self, client: TestClient) -> None:
        data = client.get(f"/api/ui/session-risk/{SESSION_A}").json()
        for card in data["summary_cards"]:
            model = SessionRiskSummaryCard(**card)
            assert isinstance(model.key, str)
            assert isinstance(model.label, str)
            assert isinstance(model.value, str)
            assert isinstance(model.tone, str)

    def test_summary_card_keys_present(self, client: TestClient) -> None:
        data = client.get(f"/api/ui/session-risk/{SESSION_A}").json()
        keys = {c["key"] for c in data["summary_cards"]}
        assert "risk_level" in keys
        assert "highest_risk" in keys
        assert "pending_reviews" in keys
        assert "total_events" in keys

    def test_summary_card_risk_level_tone(self, client: TestClient) -> None:
        data = client.get(f"/api/ui/session-risk/{SESSION_A}").json()
        risk_card = next(c for c in data["summary_cards"] if c["key"] == "risk_level")
        assert risk_card["tone"] == "success"

    def test_summary_card_pending_reviews_zero(self, client: TestClient) -> None:
        data = client.get(f"/api/ui/session-risk/{SESSION_A}").json()
        pr_card = next(c for c in data["summary_cards"] if c["key"] == "pending_reviews")
        assert pr_card["value"] == "0"
        assert pr_card["tone"] == "success"


# ---------------------------------------------------------------------------
# severity_breakdown shape
# ---------------------------------------------------------------------------


class TestSessionRiskSeverityBreakdown:
    def test_severity_breakdown_present(self, client: TestClient) -> None:
        data = client.get(f"/api/ui/session-risk/{SESSION_A}").json()
        assert "severity_breakdown" in data

    def test_severity_breakdown_fields(self, client: TestClient) -> None:
        sb = client.get(f"/api/ui/session-risk/{SESSION_A}").json()["severity_breakdown"]
        assert "critical" in sb
        assert "high" in sb
        assert "medium" in sb
        assert "low" in sb

    def test_severity_breakdown_model_parses(self, client: TestClient) -> None:
        sb = client.get(f"/api/ui/session-risk/{SESSION_A}").json()["severity_breakdown"]
        model = SessionRiskSeverityBreakdown(**sb)
        assert model.critical == 0
        assert model.high == 0
        assert model.medium == 0
        assert model.low == 0

    def test_severity_breakdown_all_zero_default(self, client: TestClient) -> None:
        sb = client.get(f"/api/ui/session-risk/{SESSION_A}").json()["severity_breakdown"]
        assert sb["critical"] == 0
        assert sb["high"] == 0
        assert sb["medium"] == 0
        assert sb["low"] == 0

    def test_severity_breakdown_all_ints(self, client: TestClient) -> None:
        sb = client.get(f"/api/ui/session-risk/{SESSION_A}").json()["severity_breakdown"]
        for key in ("critical", "high", "medium", "low"):
            assert isinstance(sb[key], int)


# ---------------------------------------------------------------------------
# signals shape
# ---------------------------------------------------------------------------


class TestSessionRiskSignals:
    def test_signals_is_list(self, client: TestClient) -> None:
        data = client.get(f"/api/ui/session-risk/{SESSION_A}").json()
        assert isinstance(data["signals"], list)

    def test_signals_not_empty(self, client: TestClient) -> None:
        data = client.get(f"/api/ui/session-risk/{SESSION_A}").json()
        assert len(data["signals"]) > 0

    def test_signals_required_fields(self, client: TestClient) -> None:
        data = client.get(f"/api/ui/session-risk/{SESSION_A}").json()
        for signal in data["signals"]:
            assert "key" in signal
            assert "label" in signal
            assert "value" in signal
            assert "tone" in signal

    def test_signals_model_parses(self, client: TestClient) -> None:
        data = client.get(f"/api/ui/session-risk/{SESSION_A}").json()
        for signal in data["signals"]:
            model = SessionRiskSignalItem(**signal)
            assert isinstance(model.key, str)
            assert isinstance(model.label, str)
            assert isinstance(model.value, str)

    def test_signal_session_id_matches(self, client: TestClient) -> None:
        data = client.get(f"/api/ui/session-risk/{SESSION_A}").json()
        session_signal = next((s for s in data["signals"] if s["key"] == "session_id"), None)
        assert session_signal is not None
        assert session_signal["value"] == SESSION_A

    def test_signal_policy_mode_present(self, client: TestClient) -> None:
        data = client.get(f"/api/ui/session-risk/{SESSION_A}").json()
        pm_signal = next((s for s in data["signals"] if s["key"] == "policy_mode"), None)
        assert pm_signal is not None
        assert isinstance(pm_signal["value"], str)

    def test_signal_risk_level_present(self, client: TestClient) -> None:
        data = client.get(f"/api/ui/session-risk/{SESSION_A}").json()
        rl_signal = next((s for s in data["signals"] if s["key"] == "risk_level"), None)
        assert rl_signal is not None
        assert rl_signal["tone"] in {"danger", "warning", "success", "neutral"}

    def test_signal_pending_reviews_default_success(self, client: TestClient) -> None:
        data = client.get(f"/api/ui/session-risk/{SESSION_A}").json()
        pr_signal = next((s for s in data["signals"] if s["key"] == "pending_reviews"), None)
        assert pr_signal is not None
        assert pr_signal["value"] == "0"
        assert pr_signal["tone"] == "success"


# ---------------------------------------------------------------------------
# available_filters shape
# ---------------------------------------------------------------------------


class TestSessionRiskFilters:
    def test_available_filters_is_list(self, client: TestClient) -> None:
        data = client.get(f"/api/ui/session-risk/{SESSION_A}").json()
        assert isinstance(data["available_filters"], list)

    def test_available_filters_not_empty(self, client: TestClient) -> None:
        data = client.get(f"/api/ui/session-risk/{SESSION_A}").json()
        assert len(data["available_filters"]) > 0

    def test_available_filters_required_fields(self, client: TestClient) -> None:
        data = client.get(f"/api/ui/session-risk/{SESSION_A}").json()
        for f in data["available_filters"]:
            assert "value" in f
            assert "label" in f

    def test_available_filters_model_parses(self, client: TestClient) -> None:
        data = client.get(f"/api/ui/session-risk/{SESSION_A}").json()
        for f in data["available_filters"]:
            model = SessionRiskFilterOption(**f)
            assert isinstance(model.value, str)
            assert isinstance(model.label, str)

    def test_filter_all_present(self, client: TestClient) -> None:
        data = client.get(f"/api/ui/session-risk/{SESSION_A}").json()
        values = {f["value"] for f in data["available_filters"]}
        assert "all" in values
        assert "executions" in values
        assert "reviews" in values
        assert "policy" in values


# ---------------------------------------------------------------------------
# related_links shape
# ---------------------------------------------------------------------------


class TestSessionRiskRelatedLinks:
    def test_related_links_is_list(self, client: TestClient) -> None:
        data = client.get(f"/api/ui/session-risk/{SESSION_A}").json()
        assert isinstance(data["related_links"], list)

    def test_related_links_not_empty(self, client: TestClient) -> None:
        data = client.get(f"/api/ui/session-risk/{SESSION_A}").json()
        assert len(data["related_links"]) > 0

    def test_related_links_required_fields(self, client: TestClient) -> None:
        data = client.get(f"/api/ui/session-risk/{SESSION_A}").json()
        for link in data["related_links"]:
            assert "label" in link
            assert "href" in link

    def test_related_links_model_parses(self, client: TestClient) -> None:
        data = client.get(f"/api/ui/session-risk/{SESSION_A}").json()
        for link in data["related_links"]:
            model = SessionRiskRelatedLink(**link)
            assert isinstance(model.label, str)
            assert isinstance(model.href, str)

    def test_related_links_contain_session_id(self, client: TestClient) -> None:
        data = client.get(f"/api/ui/session-risk/{SESSION_A}").json()
        hrefs = [link["href"] for link in data["related_links"]]
        assert any(SESSION_A in href for href in hrefs)

    def test_related_links_hrefs_start_with_slash(self, client: TestClient) -> None:
        data = client.get(f"/api/ui/session-risk/{SESSION_A}").json()
        for link in data["related_links"]:
            assert link["href"].startswith("/")


# ---------------------------------------------------------------------------
# metadata shape
# ---------------------------------------------------------------------------


class TestSessionRiskMetadata:
    def test_metadata_is_dict(self, client: TestClient) -> None:
        data = client.get(f"/api/ui/session-risk/{SESSION_A}").json()
        assert isinstance(data["metadata"], dict)

    def test_metadata_empty_state_key(self, client: TestClient) -> None:
        data = client.get(f"/api/ui/session-risk/{SESSION_A}").json()
        assert "empty_state" in data["metadata"]
        assert isinstance(data["metadata"]["empty_state"], bool)

    def test_metadata_session_found_key(self, client: TestClient) -> None:
        data = client.get(f"/api/ui/session-risk/{SESSION_A}").json()
        assert "session_found" in data["metadata"]
        assert isinstance(data["metadata"]["session_found"], bool)

    def test_metadata_integration_mode_key(self, client: TestClient) -> None:
        data = client.get(f"/api/ui/session-risk/{SESSION_A}").json()
        assert "integration_mode" in data["metadata"]
        assert data["metadata"]["integration_mode"] == "ui-shell"


# ---------------------------------------------------------------------------
# Model unit tests — no HTTP needed
# ---------------------------------------------------------------------------


class TestSessionRiskModels:
    def test_session_risk_filter_option(self) -> None:
        model = SessionRiskFilterOption(value="all", label="All activity")
        assert model.value == "all"
        assert model.label == "All activity"

    def test_session_risk_severity_breakdown_defaults(self) -> None:
        model = SessionRiskSeverityBreakdown()
        assert model.critical == 0
        assert model.high == 0
        assert model.medium == 0
        assert model.low == 0

    def test_session_risk_summary_card_defaults(self) -> None:
        model = SessionRiskSummaryCard(key="k", label="L", value="V")
        assert model.tone == "neutral"

    def test_session_risk_signal_item_defaults(self) -> None:
        model = SessionRiskSignalItem(key="k", label="L", value="V")
        assert model.tone == "neutral"

    def test_session_risk_timeline_event_defaults(self) -> None:
        model = SessionRiskTimelineEvent(
            timestamp="2026-04-27T00:00:00Z",
            title="Test event",
            status="blocked",
            summary="A blocked call",
            source="policy-engine",
        )
        assert model.risk_score == 0
        assert model.severity == "low"
        assert model.metadata == {}

    def test_session_risk_review_item(self) -> None:
        model = SessionRiskReviewItem(
            review_id="rev-001",
            title="Review",
            status="pending",
            priority="high",
            href="/reviews/rev-001",
        )
        assert model.review_id == "rev-001"

    def test_session_risk_related_link(self) -> None:
        model = SessionRiskRelatedLink(label="Queue", href="/reviews/queue")
        assert model.label == "Queue"
        assert model.href == "/reviews/queue"

    def test_session_risk_response_defaults(self) -> None:
        model = SessionRiskResponse(
            title="T",
            description="D",
            session_id="s1",
            overall_risk_level="low",
            policy_mode="review",
            generated_at="2026-04-27T00:00:00Z",
        )
        assert model.summary_cards == []
        assert model.signals == []
        assert model.recent_reviews == []
        assert model.timeline == []
        assert model.available_filters == []
        assert model.related_links == []
        assert model.metadata == {}
        assert model.client_id is None
