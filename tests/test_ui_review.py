from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from app.ui.reviews.detail import ReviewItemDetailResponse
from app.ui.reviews.detail import router as detail_router
from app.ui.reviews.queue import ReviewQueueResponse
from app.ui.reviews.queue import router as queue_router


@pytest.fixture(scope="module")
def client() -> TestClient:
    app = FastAPI()
    app.include_router(queue_router)
    app.include_router(detail_router)
    return TestClient(app)


# ---------------------------------------------------------------------------
# GET /ui/reviews/queue
# ---------------------------------------------------------------------------


class TestReviewQueue:
    def test_status_200(self, client: TestClient) -> None:
        response = client.get("/ui/reviews/queue")
        assert response.status_code == 200

    def test_response_shape(self, client: TestClient) -> None:
        data = client.get("/ui/reviews/queue").json()
        assert "items" in data
        assert "total" in data
        assert "pending" in data
        assert "approved" in data
        assert "rejected" in data

    def test_response_model_parses(self, client: TestClient) -> None:
        data = client.get("/ui/reviews/queue").json()
        model = ReviewQueueResponse(**data)
        assert isinstance(model.items, list)
        assert isinstance(model.total, int)
        assert isinstance(model.pending, int)
        assert isinstance(model.approved, int)
        assert isinstance(model.rejected, int)

    def test_total_matches_items_length(self, client: TestClient) -> None:
        data = client.get("/ui/reviews/queue").json()
        assert data["total"] == len(data["items"])

    def test_counts_sum_correctly(self, client: TestClient) -> None:
        data = client.get("/ui/reviews/queue").json()
        items = data["items"]
        assert data["pending"] == sum(1 for i in items if i["reviewstatus"] == "pending")
        assert data["approved"] == sum(1 for i in items if i["reviewstatus"] == "approved")
        assert data["rejected"] == sum(1 for i in items if i["reviewstatus"] == "rejected")

    def test_items_have_required_fields(self, client: TestClient) -> None:
        data = client.get("/ui/reviews/queue").json()
        required = {
            "reviewitemid",
            "executionid",
            "timestamp",
            "reviewstatus",
            "actiontype",
            "target",
            "riskscore",
            "executionstate",
            "responsestatus",
            "policyverdict",
            "shouldexecute",
            "haltedbyboundary",
        }
        for item in data["items"]:
            for field in required:
                assert field in item, f"Missing field '{field}' in queue item"

    def test_items_reviewstatus_valid_values(self, client: TestClient) -> None:
        data = client.get("/ui/reviews/queue").json()
        valid = {"pending", "approved", "rejected"}
        for item in data["items"]:
            assert item["reviewstatus"] in valid

    def test_items_riskscore_is_int(self, client: TestClient) -> None:
        data = client.get("/ui/reviews/queue").json()
        for item in data["items"]:
            assert isinstance(item["riskscore"], int)

    def test_items_booleans(self, client: TestClient) -> None:
        data = client.get("/ui/reviews/queue").json()
        for item in data["items"]:
            assert isinstance(item["shouldexecute"], bool)
            assert isinstance(item["haltedbyboundary"], bool)

    def test_returns_items(self, client: TestClient) -> None:
        data = client.get("/ui/reviews/queue").json()
        assert data["total"] > 0
        assert len(data["items"]) > 0


# ---------------------------------------------------------------------------
# GET /ui/reviews/detail/{reviewitemid}
# ---------------------------------------------------------------------------


class TestReviewDetail:
    KNOWN_IDS = ("review-202", "review-203")
    UNKNOWN_ID = "review-does-not-exist"

    def test_status_200_known_id(self, client: TestClient) -> None:
        for rid in self.KNOWN_IDS:
            response = client.get(f"/ui/reviews/detail/{rid}")
            assert response.status_code == 200, f"Expected 200 for {rid}"

    def test_status_404_unknown_id(self, client: TestClient) -> None:
        response = client.get(f"/ui/reviews/detail/{self.UNKNOWN_ID}")
        assert response.status_code == 404

    def test_404_detail_message(self, client: TestClient) -> None:
        data = client.get(f"/ui/reviews/detail/{self.UNKNOWN_ID}").json()
        assert "detail" in data

    def test_response_shape(self, client: TestClient) -> None:
        data = client.get("/ui/reviews/detail/review-202").json()
        required = {
            "reviewitemid",
            "reviewstatus",
            "timestamp",
            "updatedat",
            "executionid",
            "actiontype",
            "target",
            "content",
            "riskscore",
            "executionstate",
            "responsestatus",
            "policyverdict",
            "shouldexecute",
            "haltedbyboundary",
            "traceid",
            "requestid",
            "decisionid",
            "reasons",
            "decisionoptions",
        }
        for field in required:
            assert field in data, f"Missing top-level field '{field}'"

    def test_response_model_parses(self, client: TestClient) -> None:
        data = client.get("/ui/reviews/detail/review-202").json()
        model = ReviewItemDetailResponse(**data)
        assert model.reviewitemid == "review-202"

    def test_reviewitemid_matches_path(self, client: TestClient) -> None:
        for rid in self.KNOWN_IDS:
            data = client.get(f"/ui/reviews/detail/{rid}").json()
            assert data["reviewitemid"] == rid

    def test_reviewstatus_valid_value(self, client: TestClient) -> None:
        valid = {"pending", "approved", "rejected"}
        for rid in self.KNOWN_IDS:
            data = client.get(f"/ui/reviews/detail/{rid}").json()
            assert data["reviewstatus"] in valid

    def test_riskscore_is_int(self, client: TestClient) -> None:
        for rid in self.KNOWN_IDS:
            data = client.get(f"/ui/reviews/detail/{rid}").json()
            assert isinstance(data["riskscore"], int)

    def test_booleans(self, client: TestClient) -> None:
        for rid in self.KNOWN_IDS:
            data = client.get(f"/ui/reviews/detail/{rid}").json()
            assert isinstance(data["shouldexecute"], bool)
            assert isinstance(data["haltedbyboundary"], bool)

    def test_reasons_is_list(self, client: TestClient) -> None:
        for rid in self.KNOWN_IDS:
            data = client.get(f"/ui/reviews/detail/{rid}").json()
            assert isinstance(data["reasons"], list)

    def test_reasons_shape(self, client: TestClient) -> None:
        data = client.get("/ui/reviews/detail/review-202").json()
        assert len(data["reasons"]) > 0
        for reason in data["reasons"]:
            assert "source" in reason
            assert "label" in reason
            assert "details" in reason

    def test_decisionoptions_shape(self, client: TestClient) -> None:
        data = client.get("/ui/reviews/detail/review-202").json()
        opts = data["decisionoptions"]
        assert "canapprove" in opts
        assert "canreject" in opts
        assert "canresolve" in opts
        assert isinstance(opts["canapprove"], bool)
        assert isinstance(opts["canreject"], bool)
        assert isinstance(opts["canresolve"], bool)

    def test_decisionoptions_pending_logic(self, client: TestClient) -> None:
        data = client.get("/ui/reviews/detail/review-202").json()
        assert data["reviewstatus"] == "pending"
        assert data["decisionoptions"]["canapprove"] is True
        assert data["decisionoptions"]["canreject"] is True
        assert data["decisionoptions"]["canresolve"] is False

    def test_content_is_str(self, client: TestClient) -> None:
        for rid in self.KNOWN_IDS:
            data = client.get(f"/ui/reviews/detail/{rid}").json()
            assert isinstance(data["content"], str)

    def test_review_202_high_risk_blocked(self, client: TestClient) -> None:
        data = client.get("/ui/reviews/detail/review-202").json()
        assert data["riskscore"] >= 90
        assert data["policyverdict"] == "block"
        assert data["haltedbyboundary"] is True
        assert data["shouldexecute"] is False

    def test_review_203_mid_risk_queued(self, client: TestClient) -> None:
        data = client.get("/ui/reviews/detail/review-203").json()
        assert data["policyverdict"] == "block"
        assert data["responsestatus"] == "queuedforreview"
        assert data["shouldexecute"] is False
        assert data["haltedbyboundary"] is True
