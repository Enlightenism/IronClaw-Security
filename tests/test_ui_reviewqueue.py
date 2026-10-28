from __future__ import annotations

from fastapi.testclient import TestClient

from app.ui.reviews.queue import ReviewQueueItem, ReviewQueueResponse

# ---------------------------------------------------------------------------
# GET /ui/reviews/queue — 200 and queue list shape
# ---------------------------------------------------------------------------


class TestReviewQueueEndpoint:
    def test_status_200(self, test_client: TestClient) -> None:
        response = test_client.get("/ui/reviews/queue")
        assert response.status_code == 200

    def test_content_type_json(self, test_client: TestClient) -> None:
        response = test_client.get("/ui/reviews/queue")
        assert "application/json" in response.headers["content-type"]

    def test_response_top_level_shape(self, test_client: TestClient) -> None:
        data = test_client.get("/ui/reviews/queue").json()
        assert "items" in data
        assert "total" in data
        assert "pending" in data
        assert "approved" in data
        assert "rejected" in data

    def test_response_model_parses(self, test_client: TestClient) -> None:
        data = test_client.get("/ui/reviews/queue").json()
        model = ReviewQueueResponse(**data)
        assert isinstance(model.items, list)
        assert isinstance(model.total, int)
        assert isinstance(model.pending, int)
        assert isinstance(model.approved, int)
        assert isinstance(model.rejected, int)

    def test_items_is_list(self, test_client: TestClient) -> None:
        data = test_client.get("/ui/reviews/queue").json()
        assert isinstance(data["items"], list)

    def test_total_matches_items_length(self, test_client: TestClient) -> None:
        data = test_client.get("/ui/reviews/queue").json()
        assert data["total"] == len(data["items"])

    def test_pending_count_correct(self, test_client: TestClient) -> None:
        data = test_client.get("/ui/reviews/queue").json()
        expected = sum(1 for i in data["items"] if i["reviewstatus"] == "pending")
        assert data["pending"] == expected

    def test_approved_count_correct(self, test_client: TestClient) -> None:
        data = test_client.get("/ui/reviews/queue").json()
        expected = sum(1 for i in data["items"] if i["reviewstatus"] == "approved")
        assert data["approved"] == expected

    def test_rejected_count_correct(self, test_client: TestClient) -> None:
        data = test_client.get("/ui/reviews/queue").json()
        expected = sum(1 for i in data["items"] if i["reviewstatus"] == "rejected")
        assert data["rejected"] == expected

    def test_counts_sum_to_total(self, test_client: TestClient) -> None:
        data = test_client.get("/ui/reviews/queue").json()
        assert data["pending"] + data["approved"] + data["rejected"] == data["total"]

    def test_items_non_empty(self, test_client: TestClient) -> None:
        data = test_client.get("/ui/reviews/queue").json()
        assert data["total"] > 0
        assert len(data["items"]) > 0

    def test_items_required_fields_present(self, test_client: TestClient) -> None:
        data = test_client.get("/ui/reviews/queue").json()
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

    def test_items_parse_as_review_queue_item(self, test_client: TestClient) -> None:
        data = test_client.get("/ui/reviews/queue").json()
        for raw in data["items"]:
            model = ReviewQueueItem(**raw)
            assert model.reviewitemid

    def test_items_reviewstatus_valid_values(self, test_client: TestClient) -> None:
        data = test_client.get("/ui/reviews/queue").json()
        valid = {"pending", "approved", "rejected"}
        for item in data["items"]:
            assert item["reviewstatus"] in valid, f"Invalid reviewstatus '{item['reviewstatus']}'"

    def test_items_riskscore_is_int(self, test_client: TestClient) -> None:
        data = test_client.get("/ui/reviews/queue").json()
        for item in data["items"]:
            assert isinstance(item["riskscore"], int)

    def test_items_shouldexecute_is_bool(self, test_client: TestClient) -> None:
        data = test_client.get("/ui/reviews/queue").json()
        for item in data["items"]:
            assert isinstance(item["shouldexecute"], bool)

    def test_items_haltedbyboundary_is_bool(self, test_client: TestClient) -> None:
        data = test_client.get("/ui/reviews/queue").json()
        for item in data["items"]:
            assert isinstance(item["haltedbyboundary"], bool)

    def test_items_reviewitemid_is_str(self, test_client: TestClient) -> None:
        data = test_client.get("/ui/reviews/queue").json()
        for item in data["items"]:
            assert isinstance(item["reviewitemid"], str)
            assert item["reviewitemid"] != ""

    def test_items_executionid_is_str(self, test_client: TestClient) -> None:
        data = test_client.get("/ui/reviews/queue").json()
        for item in data["items"]:
            assert isinstance(item["executionid"], str)
            assert item["executionid"] != ""

    def test_items_timestamp_is_str(self, test_client: TestClient) -> None:
        data = test_client.get("/ui/reviews/queue").json()
        for item in data["items"]:
            assert isinstance(item["timestamp"], str)
            assert item["timestamp"] != ""

    def test_items_actiontype_is_str(self, test_client: TestClient) -> None:
        data = test_client.get("/ui/reviews/queue").json()
        for item in data["items"]:
            assert isinstance(item["actiontype"], str)
            assert item["actiontype"] != ""

    def test_items_target_is_str(self, test_client: TestClient) -> None:
        data = test_client.get("/ui/reviews/queue").json()
        for item in data["items"]:
            assert isinstance(item["target"], str)
            assert item["target"] != ""

    def test_items_policyverdict_is_str(self, test_client: TestClient) -> None:
        data = test_client.get("/ui/reviews/queue").json()
        for item in data["items"]:
            assert isinstance(item["policyverdict"], str)
            assert item["policyverdict"] != ""

    def test_items_responsestatus_is_str(self, test_client: TestClient) -> None:
        data = test_client.get("/ui/reviews/queue").json()
        for item in data["items"]:
            assert isinstance(item["responsestatus"], str)
            assert item["responsestatus"] != ""

    def test_demo_items_present(self, test_client: TestClient) -> None:
        data = test_client.get("/ui/reviews/queue").json()
        ids = {item["reviewitemid"] for item in data["items"]}
        assert "review-demo-001" in ids
        assert "review-demo-002" in ids
        assert "review-demo-003" in ids

    def test_demo_pending_items_have_dryrun_state(self, test_client: TestClient) -> None:
        data = test_client.get("/ui/reviews/queue").json()
        pending = [i for i in data["items"] if i["reviewstatus"] == "pending"]
        for item in pending:
            assert item["executionstate"] == "dryrun"

    def test_demo_approved_item_has_completed_status(self, test_client: TestClient) -> None:
        data = test_client.get("/ui/reviews/queue").json()
        approved = [i for i in data["items"] if i["reviewstatus"] == "approved"]
        assert len(approved) >= 1
        for item in approved:
            assert item["responsestatus"] == "completed"

    def test_demo_pending_items_queued_for_review(self, test_client: TestClient) -> None:
        data = test_client.get("/ui/reviews/queue").json()
        pending = [i for i in data["items"] if i["reviewstatus"] == "pending"]
        for item in pending:
            assert item["responsestatus"] == "queuedforreview"
            assert item["policyverdict"] == "block"
            assert item["shouldexecute"] is False
            assert item["haltedbyboundary"] is True

    def test_demo_item_002_halted_by_boundary(self, test_client: TestClient) -> None:
        data = test_client.get("/ui/reviews/queue").json()
        item = next((i for i in data["items"] if i["reviewitemid"] == "review-demo-002"), None)
        assert item is not None
        assert item["haltedbyboundary"] is True
        assert item["shouldexecute"] is False

    def test_demo_item_001_halted_by_boundary(self, test_client: TestClient) -> None:
        data = test_client.get("/ui/reviews/queue").json()
        item = next((i for i in data["items"] if i["reviewitemid"] == "review-demo-001"), None)
        assert item is not None
        assert item["haltedbyboundary"] is True
        assert item["shouldexecute"] is False

    def test_demo_item_001_actiontype(self, test_client: TestClient) -> None:
        data = test_client.get("/ui/reviews/queue").json()
        item = next((i for i in data["items"] if i["reviewitemid"] == "review-demo-001"), None)
        assert item is not None
        assert item["actiontype"] == "httpfetch"

    def test_demo_item_002_actiontype_toolcall(self, test_client: TestClient) -> None:
        data = test_client.get("/ui/reviews/queue").json()
        item = next((i for i in data["items"] if i["reviewitemid"] == "review-demo-002"), None)
        assert item is not None
        assert item["actiontype"] == "toolcall"

    def test_demo_item_003_approved_and_executed(self, test_client: TestClient) -> None:
        data = test_client.get("/ui/reviews/queue").json()
        item = next((i for i in data["items"] if i["reviewitemid"] == "review-demo-003"), None)
        assert item is not None
        assert item["reviewstatus"] == "approved"
        assert item["executionstate"] == "executed"
        assert item["policyverdict"] == "allow"
        assert item["shouldexecute"] is True
        assert item["haltedbyboundary"] is False
