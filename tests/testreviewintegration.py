from __future__ import annotations

from app.review.incidentservice import IncidentRecord, IncidentService
from app.review.reviewqueueservice import ReviewPriority, ReviewQueueService, ReviewStatus


def test_register_and_escalate_incident_into_review_queue() -> None:
    queue = ReviewQueueService()
    service = IncidentService(review_queue=queue)

    result = service.register_and_escalate(
        IncidentRecord(
            incident_id="inc_001",
            title="Prompt injection escalation",
            summary="High-confidence hostile prompt pattern detected in analyst session.",
            severity="high",
            session_id="sess_123",
            artifact_id="artifact_789",
            reasons=["policy escalation", "hostile pattern"],
            evidence=[{"type": "signal", "name": "prompt_injection", "score": 0.98}],
        ),
    )

    assert result.incident_id == "inc_001"
    assert result.review_id.startswith("rev_")
    assert result.queued is True
    assert result.priority == ReviewPriority.HIGH.value
    assert result.status == ReviewStatus.PENDING.value

    queued = queue.get(result.review_id)
    assert queued is not None
    assert queued.source.value == "incident"
    assert queued.source_id == "inc_001"
    assert queued.priority == ReviewPriority.HIGH
    assert queued.status == ReviewStatus.PENDING
    assert queued.title == "Prompt injection escalation"
    assert "policy escalation" in queued.reasons
    assert "hostile pattern" in queued.reasons
    assert "severity:high" in queued.reasons
    assert "session:sess_123" in queued.reasons
    assert "artifact:artifact_789" in queued.reasons
    assert any(item.get("type") == "signal" for item in queued.evidence)
    assert any(item.get("type") == "session" for item in queued.evidence)
    assert any(item.get("type") == "artifact" for item in queued.evidence)
    assert any(item.get("type") == "incident" for item in queued.evidence)

    serialized = queue.get_review(result.review_id)
    assert serialized is not None
    assert serialized["source"] == "incident"
    assert serialized["priority"] == ReviewPriority.HIGH.value
    assert serialized["review_id"] == result.review_id

    listed = queue.list_reviews(status=ReviewStatus.PENDING.value)
    assert any(item["review_id"] == result.review_id for item in listed)
    assert queue.list_items()[0].review_id == result.review_id


def test_escalating_same_incident_updates_existing_review_item() -> None:
    queue = ReviewQueueService()
    service = IncidentService(review_queue=queue)

    first = service.register_and_escalate(
        IncidentRecord(
            incident_id="inc_002",
            title="Suspicious output delivery",
            summary="Potential risky artifact delivery path detected.",
            severity="medium",
            reasons=["artifact anomaly"],
        ),
    )

    second = service.register_and_escalate(
        IncidentRecord(
            incident_id="inc_002",
            title="Suspicious output delivery updated",
            summary="Potential risky artifact delivery path confirmed by secondary signal.",
            severity="critical",
            reasons=["artifact anomaly", "secondary confirmation"],
            evidence=[{"type": "signal", "name": "secondary_confirmation", "score": 1.0}],
        ),
    )

    assert first.review_id == second.review_id

    queued = queue.get(first.review_id)
    assert queued is not None
    assert queued.priority == ReviewPriority.CRITICAL
    assert queued.title == "Suspicious output delivery updated"
    assert queued.summary == "Potential risky artifact delivery path confirmed by secondary signal."
    assert "artifact anomaly" in queued.reasons
    assert "secondary confirmation" in queued.reasons
    assert "severity:critical" in queued.reasons
    assert any(item.get("name") == "secondary_confirmation" for item in queued.evidence)


def test_escalate_to_review_queue_raises_for_unknown_incident() -> None:
    queue = ReviewQueueService()
    service = IncidentService(review_queue=queue)

    try:
        service.escalate_to_review_queue("inc_missing")
        raised = False
    except KeyError as exc:
        raised = True
        assert str(exc) == "'incident not found: inc_missing'"

    assert raised is True
