from __future__ import annotations

from pydantic import ValidationError
import pytest

from app.api.notifications import PolicyBlockRequest
from app.services.notification_service import (
    DeliveryResult,
    DispatchResult,
    EmailConfig,
    NotificationEngine,
    NotificationEvent,
    NotificationPayload,
    PagerDutyConfig,
    SlackConfig,
    SuppressionRule,
    build_notification_engine,
    build_notification_payload,
    default_channels_for_severity,
    default_severity_for_event,
    dispatch_incident_notification,
    dispatch_notification,
    dispatch_policy_block,
    dispatch_review_event,
    dispatch_sandbox_threat,
    dispatch_system_health,
    summarize_dispatch_result,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def email_config() -> EmailConfig:
    return EmailConfig(
        smtp_host="smtp.test.local",
        smtp_port=587,
        sender_address="ironclaw@test.local",
        recipients=("ops@test.local", "soc@test.local"),
        use_tls=True,
        username="ironclaw",
        password="secret",
    )


@pytest.fixture()
def slack_config() -> SlackConfig:
    return SlackConfig(
        webhook_url="https://hooks.slack.test/T000/B000/XXXX",
        channel="#ironclaw-alerts",
        username="IronClaw-Security",
        icon_emoji=":shield:",
        mention_on_critical="@oncall",
    )


@pytest.fixture()
def pagerduty_config() -> PagerDutyConfig:
    return PagerDutyConfig(
        routing_key="rk-ironclaw-test-0000",
        service_name="IronClaw-Security",
        default_severity="critical",
        dedup_key_prefix="ironclaw",
    )


@pytest.fixture()
def dry_engine(
    email_config: EmailConfig,
    slack_config: SlackConfig,
    pagerduty_config: PagerDutyConfig,
) -> NotificationEngine:
    return build_notification_engine(
        email_config=email_config,
        slack_config=slack_config,
        pagerduty_config=pagerduty_config,
        dry_run=True,
    )


@pytest.fixture()
def bare_engine() -> NotificationEngine:
    return build_notification_engine(dry_run=True)


@pytest.fixture()
def critical_payload() -> NotificationPayload:
    return build_notification_payload(
        event=NotificationEvent.INCIDENT_ESCALATED,
        title="Critical Incident",
        body="Incident has escalated to critical.",
        source_id="inc-001",
        source_type="incident",
        severity="critical",
        org_id="org-test",
        agent_id="agent-001",
        session_id="session-abc",
        trace_id="trace-xyz",
        metadata={"region": "us-west"},
    )


@pytest.fixture()
def info_payload() -> NotificationPayload:
    return build_notification_payload(
        event=NotificationEvent.REVIEW_ITEM_APPROVED,
        title="Review Approved",
        body="Review item has been approved.",
        source_id="rev-100",
        source_type="review_item",
    )


# ---------------------------------------------------------------------------
# EmailConfig
# ---------------------------------------------------------------------------


class TestEmailConfig:
    def test_to_dict_excludes_password(self, email_config: EmailConfig) -> None:
        d = email_config.to_dict()
        assert "password" not in d
        assert d["smtp_host"] == "smtp.test.local"
        assert d["smtp_port"] == 587
        assert d["sender_address"] == "ironclaw@test.local"
        assert d["recipients"] == ["ops@test.local", "soc@test.local"]
        assert d["use_tls"] is True
        assert d["username"] == "ironclaw"

    def test_frozen(self, email_config: EmailConfig) -> None:
        with pytest.raises((AttributeError, TypeError)):
            email_config.smtp_host = "changed"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# SlackConfig
# ---------------------------------------------------------------------------


class TestSlackConfig:
    def test_to_dict_excludes_webhook_url(self, slack_config: SlackConfig) -> None:
        d = slack_config.to_dict()
        assert "webhook_url" not in d
        assert d["channel"] == "#ironclaw-alerts"
        assert d["username"] == "IronClaw-Security"
        assert d["icon_emoji"] == ":shield:"
        assert d["mention_on_critical"] == "@oncall"

    def test_frozen(self, slack_config: SlackConfig) -> None:
        with pytest.raises((AttributeError, TypeError)):
            slack_config.channel = "changed"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# PagerDutyConfig
# ---------------------------------------------------------------------------


class TestPagerDutyConfig:
    def test_to_dict_excludes_routing_key(self, pagerduty_config: PagerDutyConfig) -> None:
        d = pagerduty_config.to_dict()
        assert "routing_key" not in d
        assert d["service_name"] == "IronClaw-Security"
        assert d["default_severity"] == "critical"
        assert d["dedup_key_prefix"] == "ironclaw"

    def test_frozen(self, pagerduty_config: PagerDutyConfig) -> None:
        with pytest.raises((AttributeError, TypeError)):
            pagerduty_config.routing_key = "changed"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# NotificationPayload
# ---------------------------------------------------------------------------


class TestNotificationPayload:
    def test_to_dict_all_fields(self, critical_payload: NotificationPayload) -> None:
        d = critical_payload.to_dict()
        assert d["event"] == NotificationEvent.INCIDENT_ESCALATED.value
        assert d["severity"] == "critical"
        assert d["title"] == "Critical Incident"
        assert d["body"] == "Incident has escalated to critical."
        assert d["source_id"] == "inc-001"
        assert d["source_type"] == "incident"
        assert d["org_id"] == "org-test"
        assert d["agent_id"] == "agent-001"
        assert d["session_id"] == "session-abc"
        assert d["trace_id"] == "trace-xyz"
        assert d["metadata"] == {"region": "us-west"}
        assert "created_at" in d

    def test_created_at_is_iso_string(self, critical_payload: NotificationPayload) -> None:
        from datetime import datetime

        dt = datetime.fromisoformat(critical_payload.created_at)
        assert dt.tzinfo is not None

    def test_frozen(self, critical_payload: NotificationPayload) -> None:
        with pytest.raises((AttributeError, TypeError)):
            critical_payload.title = "changed"  # type: ignore[misc]

    def test_metadata_default_is_empty(self) -> None:
        p = build_notification_payload(
            event=NotificationEvent.ALERT_CREATED,
            title="t",
            body="b",
            source_id="s",
            source_type="st",
        )
        assert p.metadata == {}


# ---------------------------------------------------------------------------
# DeliveryResult
# ---------------------------------------------------------------------------


class TestDeliveryResult:
    def test_succeeded_on_sent(self) -> None:
        r = DeliveryResult(
            channel="email",
            status="sent",
            payload_event="alert_created",
            payload_severity="warning",
            source_id="src-1",
        )
        assert r.succeeded is True
        assert r.failed is False

    def test_succeeded_on_simulated(self) -> None:
        r = DeliveryResult(
            channel="slack",
            status="simulated",
            payload_event="alert_created",
            payload_severity="info",
            source_id="src-2",
        )
        assert r.succeeded is True
        assert r.failed is False

    def test_failed_status(self) -> None:
        r = DeliveryResult(
            channel="pagerduty",
            status="failed",
            payload_event="incident_escalated",
            payload_severity="critical",
            source_id="src-3",
            error="connection refused",
        )
        assert r.failed is True
        assert r.succeeded is False

    def test_suppressed_is_not_failed_not_succeeded(self) -> None:
        r = DeliveryResult(
            channel="email",
            status="suppressed",
            payload_event="review_item_submitted",
            payload_severity="info",
            source_id="src-4",
            detail="Suppressed: maintenance window",
        )
        assert r.failed is False
        assert r.succeeded is False

    def test_to_dict_shape(self) -> None:
        r = DeliveryResult(
            channel="slack",
            status="sent",
            payload_event="policy_block",
            payload_severity="critical",
            source_id="dec-001",
            detail="Slack posted",
            error=None,
        )
        d = r.to_dict()
        assert d["channel"] == "slack"
        assert d["status"] == "sent"
        assert d["payload_event"] == "policy_block"
        assert d["payload_severity"] == "critical"
        assert d["source_id"] == "dec-001"
        assert d["detail"] == "Slack posted"
        assert d["error"] is None
        assert "delivered_at" in d


# ---------------------------------------------------------------------------
# DispatchResult
# ---------------------------------------------------------------------------


class TestDispatchResult:
    def _make_result(
        self,
        payload: NotificationPayload,
        statuses: list[tuple[str, str]],
    ) -> DispatchResult:
        results = [
            DeliveryResult(
                channel=ch,  # type: ignore[arg-type]
                status=st,  # type: ignore[arg-type]
                payload_event=payload.event.value,
                payload_severity=payload.severity,
                source_id=payload.source_id,
            )
            for ch, st in statuses
        ]
        return DispatchResult(payload=payload, results=results)

    def test_all_succeeded_true(self, critical_payload: NotificationPayload) -> None:
        r = self._make_result(critical_payload, [("slack", "sent"), ("email", "simulated")])
        assert r.all_succeeded is True
        assert r.any_failed is False

    def test_any_failed_true(self, critical_payload: NotificationPayload) -> None:
        r = self._make_result(critical_payload, [("slack", "sent"), ("pagerduty", "failed")])
        assert r.all_succeeded is False
        assert r.any_failed is True

    def test_channels_attempted(self, critical_payload: NotificationPayload) -> None:
        r = self._make_result(
            critical_payload,
            [("slack", "sent"), ("email", "sent"), ("pagerduty", "simulated")],
        )
        assert r.channels_attempted == ["slack", "email", "pagerduty"]

    def test_to_dict_shape(self, critical_payload: NotificationPayload) -> None:
        r = self._make_result(critical_payload, [("slack", "sent")])
        d = r.to_dict()
        assert "payload" in d
        assert "results" in d
        assert d["all_succeeded"] is True
        assert d["any_failed"] is False
        assert d["channels_attempted"] == ["slack"]
        assert "dispatched_at" in d

    def test_summary_shape(self, critical_payload: NotificationPayload) -> None:
        r = self._make_result(critical_payload, [("slack", "sent")])
        s = r.summary()
        assert s["event"] == NotificationEvent.INCIDENT_ESCALATED.value
        assert s["severity"] == "critical"
        assert s["source_id"] == "inc-001"
        assert s["all_succeeded"] is True
        assert s["any_failed"] is False
        assert "dispatched_at" in s


# ---------------------------------------------------------------------------
# SuppressionRule
# ---------------------------------------------------------------------------


class TestSuppressionRule:
    def test_matches_exact_event_and_channel(self, critical_payload: NotificationPayload) -> None:
        rule = SuppressionRule(
            rule_id="r-1",
            event=NotificationEvent.INCIDENT_ESCALATED,
            severity=None,
            channel="slack",
            reason="test suppression",
        )
        assert rule.matches(critical_payload, "slack") is True
        assert rule.matches(critical_payload, "email") is False

    def test_matches_severity_only(self, critical_payload: NotificationPayload) -> None:
        rule = SuppressionRule(
            rule_id="r-2",
            event=None,
            severity="critical",
            channel=None,
            reason="all critical suppressed",
        )
        assert rule.matches(critical_payload, "slack") is True
        assert rule.matches(critical_payload, "pagerduty") is True

    def test_no_match_wrong_event(self, critical_payload: NotificationPayload) -> None:
        rule = SuppressionRule(
            rule_id="r-3",
            event=NotificationEvent.ALERT_CREATED,
            severity=None,
            channel=None,
            reason="unrelated event",
        )
        assert rule.matches(critical_payload, "slack") is False

    def test_inactive_rule_never_matches(self, critical_payload: NotificationPayload) -> None:
        rule = SuppressionRule(
            rule_id="r-4",
            event=None,
            severity=None,
            channel=None,
            reason="inactive",
            active=False,
        )
        assert rule.matches(critical_payload, "slack") is False

    def test_wildcard_rule_matches_all_channels(self, critical_payload: NotificationPayload) -> None:
        rule = SuppressionRule(
            rule_id="r-5",
            event=None,
            severity=None,
            channel=None,
            reason="suppress everything",
        )
        for ch in ("email", "slack", "pagerduty"):
            assert rule.matches(critical_payload, ch) is True  # type: ignore[arg-type]

    def test_matches_channel_and_severity(self, info_payload: NotificationPayload) -> None:
        rule = SuppressionRule(
            rule_id="r-6",
            event=None,
            severity="info",
            channel="slack",
            reason="info slack suppressed",
        )
        assert rule.matches(info_payload, "slack") is True
        assert rule.matches(info_payload, "email") is False


# ---------------------------------------------------------------------------
# build_notification_engine
# ---------------------------------------------------------------------------


class TestBuildNotificationEngine:
    def test_dry_run_defaults_to_false(self) -> None:
        eng = build_notification_engine()
        assert eng.dry_run is False

    def test_dry_run_true(self) -> None:
        eng = build_notification_engine(dry_run=True)
        assert eng.dry_run is True

    def test_configs_stored(
        self,
        email_config: EmailConfig,
        slack_config: SlackConfig,
        pagerduty_config: PagerDutyConfig,
    ) -> None:
        eng = build_notification_engine(
            email_config=email_config,
            slack_config=slack_config,
            pagerduty_config=pagerduty_config,
        )
        assert eng.email_config is email_config
        assert eng.slack_config is slack_config
        assert eng.pagerduty_config is pagerduty_config

    def test_no_configs_is_valid(self) -> None:
        eng = build_notification_engine()
        assert eng.email_config is None
        assert eng.slack_config is None
        assert eng.pagerduty_config is None


# ---------------------------------------------------------------------------
# build_notification_payload
# ---------------------------------------------------------------------------


class TestBuildNotificationPayload:
    def test_severity_resolved_from_event_when_not_given(self) -> None:
        p = build_notification_payload(
            event=NotificationEvent.POLICY_BLOCK,
            title="t",
            body="b",
            source_id="s",
            source_type="st",
        )
        assert p.severity == "critical"

    def test_explicit_severity_overrides_default(self) -> None:
        p = build_notification_payload(
            event=NotificationEvent.POLICY_BLOCK,
            title="t",
            body="b",
            source_id="s",
            source_type="st",
            severity="info",
        )
        assert p.severity == "info"

    def test_optional_fields_default_none(self) -> None:
        p = build_notification_payload(
            event=NotificationEvent.ALERT_CREATED,
            title="t",
            body="b",
            source_id="s",
            source_type="st",
        )
        assert p.org_id is None
        assert p.agent_id is None
        assert p.session_id is None
        assert p.trace_id is None

    def test_metadata_passed_through(self) -> None:
        p = build_notification_payload(
            event=NotificationEvent.AUDIT_ANOMALY,
            title="t",
            body="b",
            source_id="s",
            source_type="st",
            metadata={"key": "value"},
        )
        assert p.metadata == {"key": "value"}


# ---------------------------------------------------------------------------
# default_channels_for_severity
# ---------------------------------------------------------------------------


class TestDefaultChannelsForSeverity:
    def test_info_returns_slack_only(self) -> None:
        assert default_channels_for_severity("info") == ["slack"]

    def test_warning_returns_slack_and_email(self) -> None:
        assert default_channels_for_severity("warning") == ["slack", "email"]

    def test_critical_returns_all_three(self) -> None:
        assert default_channels_for_severity("critical") == ["slack", "email", "pagerduty"]

    def test_unknown_falls_back_to_slack(self) -> None:
        result = default_channels_for_severity("unknown")  # type: ignore[arg-type]
        assert result == ["slack"]


# ---------------------------------------------------------------------------
# default_severity_for_event
# ---------------------------------------------------------------------------


class TestDefaultSeverityForEvent:
    @pytest.mark.parametrize(
        ("event", "expected"),
        [
            (NotificationEvent.ALERT_CREATED, "warning"),
            (NotificationEvent.ALERT_ESCALATED, "critical"),
            (NotificationEvent.INCIDENT_OPENED, "warning"),
            (NotificationEvent.INCIDENT_ESCALATED, "critical"),
            (NotificationEvent.INCIDENT_RESOLVED, "info"),
            (NotificationEvent.POLICY_ALLOW, "info"),
            (NotificationEvent.POLICY_BLOCK, "critical"),
            (NotificationEvent.POLICY_QUARANTINE, "warning"),
            (NotificationEvent.REVIEW_ITEM_SUBMITTED, "info"),
            (NotificationEvent.REVIEW_ITEM_APPROVED, "info"),
            (NotificationEvent.REVIEW_ITEM_REJECTED, "warning"),
            (NotificationEvent.SANDBOX_THREAT_DETECTED, "critical"),
            (NotificationEvent.AUDIT_ANOMALY, "warning"),
            (NotificationEvent.SYSTEM_HEALTH_DEGRADED, "critical"),
        ],
    )
    def test_event_severity_map(self, event: NotificationEvent, expected: str) -> None:
        assert default_severity_for_event(event) == expected


# ---------------------------------------------------------------------------
# NotificationEngine.dispatch (dry_run)
# ---------------------------------------------------------------------------


class TestNotificationEngineDispatch:
    def test_email_dry_run_returns_simulated(self, dry_engine: NotificationEngine, critical_payload: NotificationPayload) -> None:
        result = dry_engine.dispatch(critical_payload, ["email"])
        assert len(result.results) == 1
        assert result.results[0].channel == "email"
        assert result.results[0].status == "simulated"
        assert result.results[0].succeeded is True

    def test_slack_dry_run_returns_simulated(self, dry_engine: NotificationEngine, critical_payload: NotificationPayload) -> None:
        result = dry_engine.dispatch(critical_payload, ["slack"])
        assert result.results[0].channel == "slack"
        assert result.results[0].status == "simulated"

    def test_pagerduty_dry_run_returns_simulated(self, dry_engine: NotificationEngine, critical_payload: NotificationPayload) -> None:
        result = dry_engine.dispatch(critical_payload, ["pagerduty"])
        assert result.results[0].channel == "pagerduty"
        assert result.results[0].status == "simulated"

    def test_multi_channel_dispatch(self, dry_engine: NotificationEngine, critical_payload: NotificationPayload) -> None:
        result = dry_engine.dispatch(critical_payload, ["slack", "email", "pagerduty"])
        assert len(result.results) == 3
        assert result.all_succeeded is True
        assert result.any_failed is False
        assert result.channels_attempted == ["slack", "email", "pagerduty"]

    def test_missing_email_config_returns_failed(self, bare_engine: NotificationEngine, critical_payload: NotificationPayload) -> None:
        result = bare_engine.dispatch(critical_payload, ["email"])
        assert result.results[0].status == "failed"
        assert result.results[0].error is not None
        assert result.any_failed is True

    def test_missing_slack_config_returns_failed(self, bare_engine: NotificationEngine, critical_payload: NotificationPayload) -> None:
        result = bare_engine.dispatch(critical_payload, ["slack"])
        assert result.results[0].status == "failed"

    def test_missing_pagerduty_config_returns_failed(self, bare_engine: NotificationEngine, critical_payload: NotificationPayload) -> None:
        result = bare_engine.dispatch(critical_payload, ["pagerduty"])
        assert result.results[0].status == "failed"

    def test_unsupported_channel_returns_failed(self, bare_engine: NotificationEngine, critical_payload: NotificationPayload) -> None:
        result = bare_engine.dispatch(critical_payload, ["webhook"])  # type: ignore[list-item]
        assert result.results[0].status == "failed"

    def test_dispatch_appends_to_delivery_log(self, dry_engine: NotificationEngine, critical_payload: NotificationPayload) -> None:
        dry_engine.clear_log()
        dry_engine.dispatch(critical_payload, ["slack", "email"])
        log = dry_engine.delivery_log()
        assert len(log) == 2

    def test_clear_log(self, dry_engine: NotificationEngine, critical_payload: NotificationPayload) -> None:
        dry_engine.dispatch(critical_payload, ["slack"])
        dry_engine.clear_log()
        assert dry_engine.delivery_log() == []

    def test_delivery_log_returns_copy(self, dry_engine: NotificationEngine, critical_payload: NotificationPayload) -> None:
        dry_engine.clear_log()
        dry_engine.dispatch(critical_payload, ["slack"])
        log1 = dry_engine.delivery_log()
        log2 = dry_engine.delivery_log()
        assert log1 is not log2


# ---------------------------------------------------------------------------
# NotificationEngine suppression
# ---------------------------------------------------------------------------


class TestNotificationEngineSuppressionIntegration:
    def test_suppressed_channel_returns_suppressed_status(self, dry_engine: NotificationEngine, critical_payload: NotificationPayload) -> None:
        rule = SuppressionRule(
            rule_id="sup-slack",
            event=None,
            severity=None,
            channel="slack",
            reason="maintenance",
        )
        dry_engine.register_suppression(rule)
        result = dry_engine.dispatch(critical_payload, ["slack", "email"])
        slack_r = next(r for r in result.results if r.channel == "slack")
        email_r = next(r for r in result.results if r.channel == "email")
        assert slack_r.status == "suppressed"
        assert email_r.status == "simulated"
        dry_engine.suppression_rules.clear()

    def test_suppressed_result_not_counted_as_failed(self, dry_engine: NotificationEngine, info_payload: NotificationPayload) -> None:
        rule = SuppressionRule(
            rule_id="sup-all-info",
            event=None,
            severity="info",
            channel=None,
            reason="info suppressed globally",
        )
        dry_engine.register_suppression(rule)
        result = dry_engine.dispatch(info_payload, ["slack"])
        assert result.results[0].status == "suppressed"
        assert result.any_failed is False
        dry_engine.suppression_rules.clear()

    def test_register_suppression_appends_rule(self, bare_engine: NotificationEngine) -> None:
        rule = SuppressionRule(
            rule_id="r-reg",
            event=None,
            severity=None,
            channel=None,
            reason="test",
        )
        bare_engine.register_suppression(rule)
        assert rule in bare_engine.suppression_rules


# ---------------------------------------------------------------------------
# dispatch_notification
# ---------------------------------------------------------------------------


class TestDispatchNotification:
    def test_defaults_channels_from_severity(self, dry_engine: NotificationEngine, critical_payload: NotificationPayload) -> None:
        dry_engine.clear_log()
        result = dispatch_notification(dry_engine, critical_payload)
        assert set(result.channels_attempted) == {"slack", "email", "pagerduty"}

    def test_explicit_channels_override_defaults(self, dry_engine: NotificationEngine, critical_payload: NotificationPayload) -> None:
        result = dispatch_notification(dry_engine, critical_payload, channels=["slack"])
        assert result.channels_attempted == ["slack"]

    def test_info_payload_defaults_to_slack_only(self, dry_engine: NotificationEngine, info_payload: NotificationPayload) -> None:
        result = dispatch_notification(dry_engine, info_payload)
        assert result.channels_attempted == ["slack"]


# ---------------------------------------------------------------------------
# dispatch_policy_block
# ---------------------------------------------------------------------------


class TestDispatchPolicyBlock:
    def test_block_verdict_uses_policy_block_event(self, dry_engine: NotificationEngine) -> None:
        result = dispatch_policy_block(
            dry_engine,
            decision_id="dec-001",
            verdict="block",
            summary="Prompt injection detected.",
        )
        assert result.payload.event == NotificationEvent.POLICY_BLOCK
        assert result.payload.source_id == "dec-001"
        assert result.payload.source_type == "policy_decision"
        assert result.payload.metadata["verdict"] == "block"

    def test_allow_verdict_uses_policy_allow_event(self, dry_engine: NotificationEngine) -> None:
        result = dispatch_policy_block(
            dry_engine,
            decision_id="dec-002",
            verdict="allow",
            summary="Allowed by policy.",
        )
        assert result.payload.event == NotificationEvent.POLICY_ALLOW
        assert result.payload.severity == "info"
        assert result.payload.metadata["verdict"] == "allow"

    @pytest.mark.parametrize("verdict", ["warn", "quarantine", "unexpected"])
    def test_non_allow_verdict_fails_closed_to_policy_block_event(
        self,
        dry_engine: NotificationEngine,
        verdict: str,
    ) -> None:
        result = dispatch_policy_block(
            dry_engine,
            decision_id="dec-002",
            verdict=verdict,
            summary="Non-binary policy outcome.",
        )
        assert result.payload.event == NotificationEvent.POLICY_BLOCK
        assert result.payload.metadata["verdict"] == "block"

    def test_optional_fields_propagated(self, dry_engine: NotificationEngine) -> None:
        result = dispatch_policy_block(
            dry_engine,
            decision_id="dec-003",
            verdict="block",
            summary="Test.",
            agent_id="agent-42",
            session_id="sess-99",
            trace_id="trace-11",
            org_id="org-7",
        )
        assert result.payload.agent_id == "agent-42"
        assert result.payload.session_id == "sess-99"
        assert result.payload.trace_id == "trace-11"
        assert result.payload.org_id == "org-7"

    def test_custom_channels_respected(self, dry_engine: NotificationEngine) -> None:
        result = dispatch_policy_block(
            dry_engine,
            decision_id="dec-004",
            verdict="block",
            summary="Test.",
            channels=["slack"],
        )
        assert result.channels_attempted == ["slack"]


@pytest.mark.parametrize("verdict", ["allow", "block"])
def test_policy_notification_request_accepts_binary_verdicts(verdict: str) -> None:
    request = PolicyBlockRequest(
        decision_id="dec-api-001",
        verdict=verdict,
        summary="Policy decision.",
    )
    assert request.verdict == verdict


@pytest.mark.parametrize("verdict", ["warn", "quarantine", "review"])
def test_policy_notification_request_rejects_legacy_verdicts(verdict: str) -> None:
    with pytest.raises(ValidationError):
        PolicyBlockRequest(
            decision_id="dec-api-002",
            verdict=verdict,
            summary="Legacy policy decision.",
        )


# ---------------------------------------------------------------------------
# dispatch_incident_notification
# ---------------------------------------------------------------------------


class TestDispatchIncidentNotification:
    def test_incident_opened(self, dry_engine: NotificationEngine) -> None:
        result = dispatch_incident_notification(
            dry_engine,
            incident_id="inc-500",
            incident_title="DB Connection Failure",
            event=NotificationEvent.INCIDENT_OPENED,
        )
        assert result.payload.event == NotificationEvent.INCIDENT_OPENED
        assert result.payload.source_id == "inc-500"
        assert result.payload.source_type == "incident"
        assert "inc-500" in result.payload.body

    def test_explicit_severity_overrides(self, dry_engine: NotificationEngine) -> None:
        result = dispatch_incident_notification(
            dry_engine,
            incident_id="inc-501",
            incident_title="Minor Blip",
            event=NotificationEvent.INCIDENT_OPENED,
            severity="info",
        )
        assert result.payload.severity == "info"

    def test_incident_resolved_is_info_severity_by_default(self, dry_engine: NotificationEngine) -> None:
        result = dispatch_incident_notification(
            dry_engine,
            incident_id="inc-502",
            incident_title="Resolved",
            event=NotificationEvent.INCIDENT_RESOLVED,
        )
        assert result.payload.severity == "info"


# ---------------------------------------------------------------------------
# dispatch_sandbox_threat
# ---------------------------------------------------------------------------


class TestDispatchSandboxThreat:
    def test_basic_dispatch(self, dry_engine: NotificationEngine) -> None:
        result = dispatch_sandbox_threat(
            dry_engine,
            task_id="task-001",
            threat_summary="Malicious code execution detected.",
        )
        assert result.payload.event == NotificationEvent.SANDBOX_THREAT_DETECTED
        assert result.payload.source_id == "task-001"
        assert result.payload.source_type == "sandbox_task"
        assert result.payload.severity == "critical"

    def test_optional_ids_propagated(self, dry_engine: NotificationEngine) -> None:
        result = dispatch_sandbox_threat(
            dry_engine,
            task_id="task-002",
            threat_summary="RCE attempt.",
            agent_id="agent-x",
            session_id="sess-y",
            trace_id="trace-z",
            org_id="org-a",
        )
        assert result.payload.agent_id == "agent-x"
        assert result.payload.session_id == "sess-y"
        assert result.payload.trace_id == "trace-z"
        assert result.payload.org_id == "org-a"

    def test_custom_channels(self, dry_engine: NotificationEngine) -> None:
        result = dispatch_sandbox_threat(
            dry_engine,
            task_id="task-003",
            threat_summary="Test.",
            channels=["pagerduty"],
        )
        assert result.channels_attempted == ["pagerduty"]


# ---------------------------------------------------------------------------
# dispatch_review_event
# ---------------------------------------------------------------------------


class TestDispatchReviewEvent:
    @pytest.mark.parametrize(
        "event",
        [
            NotificationEvent.REVIEW_ITEM_SUBMITTED,
            NotificationEvent.REVIEW_ITEM_APPROVED,
            NotificationEvent.REVIEW_ITEM_REJECTED,
        ],
    )
    def test_review_events(self, dry_engine: NotificationEngine, event: NotificationEvent) -> None:
        result = dispatch_review_event(
            dry_engine,
            item_id="rev-200",
            event=event,
        )
        assert result.payload.event == event
        assert result.payload.source_id == "rev-200"
        assert result.payload.source_type == "review_item"

    def test_reviewer_id_in_body(self, dry_engine: NotificationEngine) -> None:
        result = dispatch_review_event(
            dry_engine,
            item_id="rev-201",
            event=NotificationEvent.REVIEW_ITEM_APPROVED,
            reviewer_id="reviewer-99",
        )
        assert "reviewer-99" in result.payload.body
        assert result.payload.metadata.get("reviewer_id") == "reviewer-99"

    def test_system_reviewer_when_none(self, dry_engine: NotificationEngine) -> None:
        result = dispatch_review_event(
            dry_engine,
            item_id="rev-202",
            event=NotificationEvent.REVIEW_ITEM_SUBMITTED,
        )
        assert "system" in result.payload.body


# ---------------------------------------------------------------------------
# dispatch_system_health
# ---------------------------------------------------------------------------


class TestDispatchSystemHealth:
    def test_basic_dispatch(self, dry_engine: NotificationEngine) -> None:
        result = dispatch_system_health(
            dry_engine,
            component="supabase",
            detail="Connection pool exhausted.",
        )
        assert result.payload.event == NotificationEvent.SYSTEM_HEALTH_DEGRADED
        assert result.payload.severity == "critical"
        assert result.payload.source_type == "system_health"
        assert "supabase" in result.payload.source_id
        assert result.payload.metadata.get("component") == "supabase"

    def test_severity_override(self, dry_engine: NotificationEngine) -> None:
        result = dispatch_system_health(
            dry_engine,
            component="cache",
            detail="Slow response.",
            severity="warning",
        )
        assert result.payload.severity == "warning"

    def test_custom_channels(self, dry_engine: NotificationEngine) -> None:
        result = dispatch_system_health(
            dry_engine,
            component="auth",
            detail="Auth service degraded.",
            channels=["email"],
        )
        assert result.channels_attempted == ["email"]


# ---------------------------------------------------------------------------
# summarize_dispatch_result
# ---------------------------------------------------------------------------


class TestSummarizeDispatchResult:
    def test_summary_keys_present(self, dry_engine: NotificationEngine, critical_payload: NotificationPayload) -> None:
        result = dispatch_notification(dry_engine, critical_payload, channels=["slack"])
        summary = summarize_dispatch_result(result)
        assert summary["event"] == NotificationEvent.INCIDENT_ESCALATED.value
        assert summary["severity"] == "critical"
        assert summary["source_id"] == "inc-001"
        assert summary["source_type"] == "incident"
        assert "slack" in summary["channels_attempted"]
        assert summary["all_succeeded"] is True
        assert summary["any_failed"] is False
        assert summary["result_count"] == 1
        assert "dispatched_at" in summary

    def test_summary_any_failed_true(self, bare_engine: NotificationEngine, critical_payload: NotificationPayload) -> None:
        result = dispatch_notification(bare_engine, critical_payload, channels=["slack"])
        summary = summarize_dispatch_result(result)
        assert summary["any_failed"] is True
        assert summary["all_succeeded"] is False
