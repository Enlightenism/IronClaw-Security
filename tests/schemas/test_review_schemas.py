from __future__ import annotations

from datetime import UTC

from pydantic import ValidationError
import pytest

from app.schemas.review import (
    ReviewAssignment,
    ReviewDecision,
    ReviewDecisionCreate,
    ReviewItemType,
    ReviewQueueItem,
    ReviewQueueListResponse,
    ReviewStatus,
)

# ---------------------------------------------------------------------------
# Enums — complete value coverage + round-trips
# ---------------------------------------------------------------------------


def test_review_status_values():
    assert set(ReviewStatus) == {
        ReviewStatus.pending,
        ReviewStatus.approved,
        ReviewStatus.rejected,
        ReviewStatus.escalated,
    }


@pytest.mark.parametrize("value", ["pending", "approved", "rejected", "escalated"])
def test_review_status_from_string(value):
    assert ReviewStatus(value).value == value


@pytest.mark.parametrize("member", list(ReviewStatus))
def test_review_status_round_trip(member):
    assert ReviewStatus(member.value) == member


def test_review_status_invalid():
    with pytest.raises(ValueError):
        ReviewStatus("unknown")


def test_review_item_type_values():
    assert set(ReviewItemType) == {
        ReviewItemType.scan,
        ReviewItemType.tool_call,
        ReviewItemType.prompt,
        ReviewItemType.execution,
        ReviewItemType.policy_change,
    }


@pytest.mark.parametrize("value", ["scan", "tool_call", "prompt", "execution", "policy_change"])
def test_review_item_type_from_string(value):
    assert ReviewItemType(value).value == value


@pytest.mark.parametrize("member", list(ReviewItemType))
def test_review_item_type_round_trip(member):
    assert ReviewItemType(member.value) == member


def test_review_item_type_invalid():
    with pytest.raises(ValueError):
        ReviewItemType("network")


# ---------------------------------------------------------------------------
# ReviewQueueItem — required fields, defaults, bounds
# ---------------------------------------------------------------------------

_BASE_ITEM = dict(item_id="item-001")


def test_review_queue_item_minimal():
    item = ReviewQueueItem(**_BASE_ITEM)
    assert item.item_id == "item-001"
    assert item.status == ReviewStatus.pending
    assert item.item_type == ReviewItemType.scan
    assert item.risk_score == 0
    assert item.priority == 0


def test_review_queue_item_missing_item_id_rejected():
    with pytest.raises(ValidationError):
        ReviewQueueItem()


def test_review_queue_item_status_defaults_pending():
    item = ReviewQueueItem(**_BASE_ITEM)
    assert item.status == ReviewStatus.pending


def test_review_queue_item_risk_score_default_zero():
    item = ReviewQueueItem(**_BASE_ITEM)
    assert item.risk_score == 0


def test_review_queue_item_priority_default_zero():
    item = ReviewQueueItem(**_BASE_ITEM)
    assert item.priority == 0


def test_review_queue_item_list_fields_default_empty():
    item = ReviewQueueItem(**_BASE_ITEM)
    assert item.matched_rules == []
    assert item.categories == []


def test_review_queue_item_optional_fields_default_none():
    item = ReviewQueueItem(**_BASE_ITEM)
    assert item.source_id is None
    assert item.session_id is None
    assert item.calling_agent_id is None
    assert item.verdict is None
    assert item.summary is None
    assert item.assigned_to is None
    assert item.notes is None
    assert item.updated_at is None
    assert item.resolved_at is None


def test_review_queue_item_metadata_defaults_empty():
    item = ReviewQueueItem(**_BASE_ITEM)
    assert item.metadata == {}


def test_review_queue_item_risk_score_zero():
    item = ReviewQueueItem(**{**_BASE_ITEM, "risk_score": 0})
    assert item.risk_score == 0


def test_review_queue_item_risk_score_max():
    item = ReviewQueueItem(**{**_BASE_ITEM, "risk_score": 100})
    assert item.risk_score == 100


def test_review_queue_item_risk_score_below_zero_rejected():
    with pytest.raises(ValidationError):
        ReviewQueueItem(**{**_BASE_ITEM, "risk_score": -1})


def test_review_queue_item_risk_score_above_100_rejected():
    with pytest.raises(ValidationError):
        ReviewQueueItem(**{**_BASE_ITEM, "risk_score": 101})


def test_review_queue_item_priority_zero():
    item = ReviewQueueItem(**{**_BASE_ITEM, "priority": 0})
    assert item.priority == 0


def test_review_queue_item_priority_max():
    item = ReviewQueueItem(**{**_BASE_ITEM, "priority": 10})
    assert item.priority == 10


def test_review_queue_item_priority_below_zero_rejected():
    with pytest.raises(ValidationError):
        ReviewQueueItem(**{**_BASE_ITEM, "priority": -1})


def test_review_queue_item_priority_above_10_rejected():
    with pytest.raises(ValidationError):
        ReviewQueueItem(**{**_BASE_ITEM, "priority": 11})


def test_review_queue_item_created_at_timezone_aware():
    item = ReviewQueueItem(**_BASE_ITEM)
    assert item.created_at.tzinfo is not None
    assert item.created_at.tzinfo == UTC


def test_review_queue_item_all_statuses_accepted():
    for status in ReviewStatus:
        item = ReviewQueueItem(**{**_BASE_ITEM, "status": status})
        assert item.status == status


def test_review_queue_item_all_item_types_accepted():
    for item_type in ReviewItemType:
        item = ReviewQueueItem(**{**_BASE_ITEM, "item_type": item_type})
        assert item.item_type == item_type


def test_review_queue_item_full_construction():
    from datetime import datetime

    now = datetime.now(UTC)
    item = ReviewQueueItem(
        item_id="item-full",
        item_type=ReviewItemType.tool_call,
        status=ReviewStatus.escalated,
        source_id="scan-001",
        session_id="sess-abc",
        calling_agent_id="agent-007",
        risk_score=85,
        verdict="block",
        summary="Detected injection",
        matched_rules=["rule-001"],
        categories=["injection"],
        assigned_to="reviewer-1",
        priority=9,
        notes="Urgent review needed",
        metadata={"env": "prod"},
        updated_at=now,
        resolved_at=now,
    )
    assert item.item_id == "item-full"
    assert item.status == ReviewStatus.escalated
    assert item.risk_score == 85
    assert item.priority == 9
    assert item.assigned_to == "reviewer-1"
    assert "rule-001" in item.matched_rules


def test_review_queue_item_orm_compat():
    assert ReviewQueueItem.model_config.get("from_attributes") is True


# ---------------------------------------------------------------------------
# ReviewAssignment — required fields, assigned_at timezone, optional defaults
# ---------------------------------------------------------------------------

_BASE_ASSIGNMENT = dict(item_id="item-001", assigned_to="reviewer-1")


def test_review_assignment_minimal():
    a = ReviewAssignment(**_BASE_ASSIGNMENT)
    assert a.item_id == "item-001"
    assert a.assigned_to == "reviewer-1"


def test_review_assignment_missing_item_id_rejected():
    with pytest.raises(ValidationError):
        ReviewAssignment(assigned_to="reviewer-1")


def test_review_assignment_missing_assigned_to_rejected():
    with pytest.raises(ValidationError):
        ReviewAssignment(item_id="item-001")


def test_review_assignment_optional_fields_default_none():
    a = ReviewAssignment(**_BASE_ASSIGNMENT)
    assert a.assignment_id is None
    assert a.assigned_by is None
    assert a.notes is None


def test_review_assignment_assigned_at_timezone_aware():
    a = ReviewAssignment(**_BASE_ASSIGNMENT)
    assert a.assigned_at.tzinfo is not None
    assert a.assigned_at.tzinfo == UTC


def test_review_assignment_explicit_assigned_at_preserved():
    from datetime import datetime

    ts = datetime(2026, 6, 16, 10, 0, 0, tzinfo=UTC)
    a = ReviewAssignment(**{**_BASE_ASSIGNMENT, "assigned_at": ts})
    assert a.assigned_at == ts


def test_review_assignment_full_construction():
    a = ReviewAssignment(
        assignment_id="assign-001",
        item_id="item-002",
        assigned_to="lead-reviewer",
        assigned_by="system",
        notes="High priority",
    )
    assert a.assignment_id == "assign-001"
    assert a.assigned_by == "system"
    assert a.notes == "High priority"


def test_review_assignment_orm_compat():
    assert ReviewAssignment.model_config.get("from_attributes") is True


# ---------------------------------------------------------------------------
# ReviewDecisionCreate — required fields, optional defaults
# ---------------------------------------------------------------------------

_BASE_DECISION_CREATE = dict(item_id="item-001", decision=ReviewStatus.approved)


def test_review_decision_create_minimal():
    d = ReviewDecisionCreate(**_BASE_DECISION_CREATE)
    assert d.item_id == "item-001"
    assert d.decision == ReviewStatus.approved


def test_review_decision_create_missing_item_id_rejected():
    with pytest.raises(ValidationError):
        ReviewDecisionCreate(decision=ReviewStatus.approved)


def test_review_decision_create_missing_decision_rejected():
    with pytest.raises(ValidationError):
        ReviewDecisionCreate(item_id="item-001")


def test_review_decision_create_optional_fields_default_none():
    d = ReviewDecisionCreate(**_BASE_DECISION_CREATE)
    assert d.reviewer_id is None
    assert d.reasoning is None
    assert d.override_verdict is None


def test_review_decision_create_metadata_defaults_empty():
    d = ReviewDecisionCreate(**_BASE_DECISION_CREATE)
    assert d.metadata == {}


def test_review_decision_create_all_decisions_accepted():
    for status in ReviewStatus:
        d = ReviewDecisionCreate(item_id="item-x", decision=status)
        assert d.decision == status


def test_review_decision_create_full_construction():
    d = ReviewDecisionCreate(
        item_id="item-002",
        decision=ReviewStatus.rejected,
        reviewer_id="rev-007",
        reasoning="Pattern matches known injection",
        override_verdict="block",
        metadata={"source": "manual"},
    )
    assert d.reviewer_id == "rev-007"
    assert d.reasoning == "Pattern matches known injection"
    assert d.override_verdict == "block"
    assert d.metadata["source"] == "manual"


def test_review_decision_create_orm_compat():
    assert ReviewDecisionCreate.model_config.get("from_attributes") is True


# ---------------------------------------------------------------------------
# ReviewDecision — decided_at timezone-aware + optional field defaults
# ---------------------------------------------------------------------------

_BASE_DECISION = dict(item_id="item-001", decision=ReviewStatus.approved)


def test_review_decision_minimal():
    d = ReviewDecision(**_BASE_DECISION)
    assert d.item_id == "item-001"
    assert d.decision == ReviewStatus.approved


def test_review_decision_optional_fields_default_none():
    d = ReviewDecision(**_BASE_DECISION)
    assert d.decision_id is None
    assert d.reviewer_id is None
    assert d.reasoning is None
    assert d.override_verdict is None


def test_review_decision_metadata_defaults_empty():
    d = ReviewDecision(**_BASE_DECISION)
    assert d.metadata == {}


def test_review_decision_decided_at_timezone_aware():
    d = ReviewDecision(**_BASE_DECISION)
    assert d.decided_at.tzinfo is not None
    assert d.decided_at.tzinfo == UTC


def test_review_decision_explicit_decided_at_preserved():
    from datetime import datetime

    ts = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)
    d = ReviewDecision(**{**_BASE_DECISION, "decided_at": ts})
    assert d.decided_at == ts


def test_review_decision_full_construction():
    from datetime import datetime

    now = datetime.now(UTC)
    d = ReviewDecision(
        decision_id="dec-001",
        item_id="item-003",
        decision=ReviewStatus.escalated,
        reviewer_id="lead",
        reasoning="Requires security team escalation",
        override_verdict="quarantine",
        metadata={"ticket": "SEC-42"},
        decided_at=now,
    )
    assert d.decision_id == "dec-001"
    assert d.decision == ReviewStatus.escalated
    assert d.override_verdict == "quarantine"
    assert d.metadata["ticket"] == "SEC-42"


def test_review_decision_orm_compat():
    assert ReviewDecision.model_config.get("from_attributes") is True


# ---------------------------------------------------------------------------
# ReviewQueueListResponse — shape, count, pending_count, escalated_count defaults
# ---------------------------------------------------------------------------


def test_review_queue_list_response_empty():
    resp = ReviewQueueListResponse(count=0, items=[])
    assert resp.count == 0
    assert resp.items == []
    assert resp.pending_count == 0
    assert resp.escalated_count == 0


def test_review_queue_list_response_pending_count_defaults_zero():
    resp = ReviewQueueListResponse(count=0, items=[])
    assert resp.pending_count == 0


def test_review_queue_list_response_escalated_count_defaults_zero():
    resp = ReviewQueueListResponse(count=0, items=[])
    assert resp.escalated_count == 0


def test_review_queue_list_response_with_items():
    item = ReviewQueueItem(item_id="item-001")
    resp = ReviewQueueListResponse(count=1, items=[item], pending_count=1)
    assert resp.count == 1
    assert len(resp.items) == 1
    assert resp.items[0].item_id == "item-001"
    assert resp.pending_count == 1


def test_review_queue_list_response_full():
    items = [ReviewQueueItem(item_id=f"item-{i}") for i in range(3)]
    resp = ReviewQueueListResponse(
        count=3,
        items=items,
        pending_count=2,
        escalated_count=1,
    )
    assert resp.count == 3
    assert resp.pending_count == 2
    assert resp.escalated_count == 1


def test_review_queue_list_response_count_below_zero_rejected():
    with pytest.raises(ValidationError):
        ReviewQueueListResponse(count=-1, items=[])


def test_review_queue_list_response_pending_count_below_zero_rejected():
    with pytest.raises(ValidationError):
        ReviewQueueListResponse(count=0, items=[], pending_count=-1)


def test_review_queue_list_response_escalated_count_below_zero_rejected():
    with pytest.raises(ValidationError):
        ReviewQueueListResponse(count=0, items=[], escalated_count=-1)


def test_review_queue_list_response_orm_compat():
    assert ReviewQueueListResponse.model_config.get("from_attributes") is True
