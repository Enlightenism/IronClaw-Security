from __future__ import annotations

from app.ui.actionhistory import build_action_history_view


def test_build_action_history_view_counts_statuses_and_builds_kpis() -> None:
    view = build_action_history_view(
        actions=[
            {
                "actionid": "act-001",
                "actiontype": "httpfetch",
                "target": "https://example.com",
                "status": "allowed",
                "finalriskscore": 1,
                "requestedunits": 1,
                "usage": {
                    "remainingunits": 9,
                    "walletbalance": 4,
                    "reason": "authorized",
                },
            },
            {
                "actionid": "act-002",
                "actiontype": "toolcall",
                "target": "shell",
                "status": "review",
                "finalriskscore": 5,
                "requestedunits": 2,
                "usage": {
                    "remainingunits": 0,
                    "walletbalance": 0,
                    "reason": "blocked_by_security_review",
                },
            },
            {
                "actionid": "act-003",
                "actiontype": "command",
                "target": "rm -rf /",
                "status": "quarantined",
                "finalriskscore": 10,
                "requestedunits": 3,
                "usage": {
                    "remainingunits": 0,
                    "walletbalance": -1,
                    "reason": "blocked_by_security_review",
                },
            },
            {
                "actionid": "act-004",
                "actiontype": "browseropen",
                "target": "https://denied.example",
                "status": "denied",
                "finalriskscore": 7,
                "requestedunits": 1,
                "usage": {
                    "remainingunits": 0,
                    "walletbalance": 0,
                    "reason": "denied",
                },
            },
        ],
        requested_by="tester",
        ownerkey="owner-601",
        status="allowed",
    )

    assert view.title == "Action History"
    assert view.total == 4
    assert view.allowed_count == 1
    assert view.review_count == 1
    assert view.quarantined_count == 1
    assert view.denied_count == 1
    assert view.metadata["requested_by"] == "tester"
    assert view.filters["ownerkey"] == "owner-601"
    assert view.filters["status"] == "allowed"
    assert len(view.kpis) == 5
    assert any(kpi.label == "Allowed" and kpi.value == "1" for kpi in view.kpis)


def test_build_action_history_view_maps_item_fields_and_tones() -> None:
    view = build_action_history_view(
        actions=[
            {
                "executionid": "exec-001",
                "actiontype": "httpfetch",
                "target": "https://example.com/docs",
                "status": "allowed",
                "clientid": "client-601",
                "sessionid": "session-601",
                "ownerkey": "owner-601",
                "finalriskscore": 2,
                "requestedunits": 1,
                "message": "Action approved for execution.",
                "policyverdict": "allow",
                "executorname": "secure-runtime",
                "promptinjection": {
                    "detected": False,
                },
                "usage": {
                    "executionid": "exec-001",
                    "remainingunits": 12,
                    "walletbalance": 8,
                    "reason": "authorized",
                },
                "metadata": {
                    "source": "web",
                },
            },
        ],
    )

    item = view.items[0]
    assert item.actionid == "exec-001"
    assert item.actiontype == "httpfetch"
    assert item.target == "https://example.com/docs"
    assert item.status == "allowed"
    assert item.status_tone == "good"
    assert item.clientid == "client-601"
    assert item.sessionid == "session-601"
    assert item.ownerkey == "owner-601"
    assert item.riskscore == 2
    assert item.risk_tone == "good"
    assert item.requestedunits == 1
    assert item.remainingunits == "12"
    assert item.walletbalance == "8"
    assert item.usage_tone == "good"
    assert item.promptinjectiondetected is False
    assert item.reason == "Action approved for execution."
    assert item.policyverdict == "allow"
    assert item.executorname == "secure-runtime"
    assert "status=allowed" in item.summary
    assert item.metadata["source"] == "web"


def test_build_action_history_view_handles_missing_fields_with_safe_defaults() -> None:
    view = build_action_history_view(
        actions=[
            {
                "status": "review",
            },
        ],
    )

    item = view.items[0]
    assert item.actionid == "action-1"
    assert item.actiontype == "unknown"
    assert item.target == "unknown"
    assert item.clientid == "—"
    assert item.sessionid == "—"
    assert item.ownerkey == "—"
    assert item.timestamp == "—"
    assert item.reason == "—"
    assert item.policyverdict == "—"
    assert item.executorname == "—"
    assert item.remainingunits == "—"
    assert item.walletbalance == "—"
    assert item.status_tone == "warning"


def test_build_action_history_view_marks_prompt_injection_detection() -> None:
    view = build_action_history_view(
        actions=[
            {
                "actionid": "act-flagged",
                "actiontype": "toolcall",
                "target": "shell",
                "status": "quarantined",
                "finalriskscore": 11,
                "promptinjection": {
                    "flagged": True,
                },
                "usage": {
                    "remainingunits": 0,
                    "walletbalance": 0,
                },
            },
        ],
    )

    item = view.items[0]
    assert item.promptinjectiondetected is True
    assert item.risk_tone == "critical"
    assert item.status_tone == "critical"
