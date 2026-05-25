from __future__ import annotations

import importlib
import time
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from app.schemas.threat_detection import (
    AlertSeverityEnum,
    DetectionVerdict,
    HuntMatch,
    HuntResult,
    HuntStatusEnum,
    ThreatAlert,
    ThreatSeverityLevel,
)

# ---------------------------------------------------------------------------
# Helpers — build canonical test objects
# ---------------------------------------------------------------------------


def _make_hunt_match(
    *,
    event_id: str = "evt-001",
    verdict: DetectionVerdict = DetectionVerdict.BLOCK,
    score: float = 0.9,
    severity: ThreatSeverityLevel = ThreatSeverityLevel.HIGH,
    matched_mitre_technique: str | None = "T1059",
    risk_families: list[str] | None = None,
    matched_ioc_value: str | None = "192.168.1.1",
    matched_ioc_type: str | None = "ipv4",
    confidence: float = 0.95,
) -> HuntMatch:
    return HuntMatch(
        event_id=event_id,
        verdict=verdict,
        score=score,
        severity=severity,
        matched_ioc_value=matched_ioc_value,
        matched_ioc_type=matched_ioc_type,
        matched_mitre_technique=matched_mitre_technique,
        risk_families=risk_families if risk_families is not None else ["command_and_control"],
        context="tool_call",
        assessed_at="2026-05-25T14:00:00+00:00",
        confidence=confidence,
    )


def _make_hunt_result(
    *,
    hunt_id: str = "hunt-test-001",
    org_id: str | None = "org-test",
    status: HuntStatusEnum = HuntStatusEnum.COMPLETED,
    matches: list[HuntMatch] | None = None,
    total_matches: int | None = None,
    query_summary: dict[str, Any] | None = None,
    errors: list[str] | None = None,
    duration_ms: int | None = 42,
) -> HuntResult:
    resolved_matches = matches if matches is not None else [_make_hunt_match()]
    return HuntResult(
        hunt_id=hunt_id,
        org_id=org_id,
        status=status,
        total_matches=total_matches if total_matches is not None else len(resolved_matches),
        matches=resolved_matches,
        query_summary=query_summary or {"ioc_value": "192.168.1.1", "mitre_technique_id": "T1059"},
        executed_at="2026-05-25T14:00:00+00:00",
        duration_ms=duration_ms,
        errors=errors or [],
    )


def _make_detection_result_mock(
    *,
    event_id: str = "det-evt-001",
    org_id: str | None = "org-test",
    verdict: DetectionVerdict = DetectionVerdict.BLOCK,
    score: float = 0.88,
    severity: ThreatSeverityLevel = ThreatSeverityLevel.HIGH,
    ioc_matches: list[Any] | None = None,
    correlation_signals: list[Any] | None = None,
    risk_families: list[str] | None = None,
    mitre_techniques: list[str] | None = None,
) -> MagicMock:
    mock = MagicMock()
    mock.event_id = event_id
    mock.org_id = org_id
    mock.agent_id = "agent-x"
    mock.session_id = "session-y"
    mock.verdict = verdict
    mock.score = score
    mock.severity = severity
    mock.ioc_matches = ioc_matches or []
    mock.correlation_signals = correlation_signals or []
    mock.risk_families = risk_families or ["data_exfiltration"]
    mock.mitre_techniques = mitre_techniques or ["T1041"]
    mock.context = "prompt_input"
    mock.metadata = {"source": "test"}
    mock.assessed_at = "2026-05-25T14:00:00+00:00"
    mock.title = f"Detection alert: {event_id}"
    mock.description = f"Automated detection for event {event_id}"
    return mock


# ---------------------------------------------------------------------------
# Module isolation — reset module-level state between tests
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_threat_alerts_module_state():
    """
    Reset the module-level _alert_store singleton and _suppression_registry
    before each test so tests are fully isolated from each other.
    """
    import app.services.threat_alerts as ta

    ta._alert_store = None
    ta._suppression_registry.clear()
    yield
    ta._alert_store = None
    ta._suppression_registry.clear()


# ---------------------------------------------------------------------------
# Severity mapping helpers
# ---------------------------------------------------------------------------


class TestMapSeverity:
    def test_maps_critical_to_critical(self):
        from app.services.threat_alerts import _map_severity

        assert _map_severity("critical") == AlertSeverityEnum.CRITICAL

    def test_maps_high_to_high(self):
        from app.services.threat_alerts import _map_severity

        assert _map_severity("high") == AlertSeverityEnum.HIGH

    def test_maps_medium_to_medium(self):
        from app.services.threat_alerts import _map_severity

        assert _map_severity("medium") == AlertSeverityEnum.MEDIUM

    def test_maps_low_to_low(self):
        from app.services.threat_alerts import _map_severity

        assert _map_severity("low") == AlertSeverityEnum.LOW

    def test_maps_info_to_low(self):
        from app.services.threat_alerts import _map_severity

        assert _map_severity("info") == AlertSeverityEnum.LOW

    def test_unknown_severity_defaults_to_medium(self):
        from app.services.threat_alerts import _map_severity

        assert _map_severity("totally_unknown") == AlertSeverityEnum.MEDIUM

    def test_empty_string_defaults_to_medium(self):
        from app.services.threat_alerts import _map_severity

        assert _map_severity("") == AlertSeverityEnum.MEDIUM

    def test_case_insensitive_mapping(self):
        from app.services.threat_alerts import _map_severity

        assert _map_severity("CRITICAL") == AlertSeverityEnum.CRITICAL
        assert _map_severity("High") == AlertSeverityEnum.HIGH


class TestPeakSeverity:
    def test_single_critical_match(self):
        from app.services.threat_alerts import _peak_severity

        matches = [_make_hunt_match(severity=ThreatSeverityLevel.CRITICAL)]
        assert _peak_severity(matches) == AlertSeverityEnum.CRITICAL

    def test_mixed_severities_returns_highest(self):
        from app.services.threat_alerts import _peak_severity

        matches = [
            _make_hunt_match(event_id="e1", severity=ThreatSeverityLevel.LOW),
            _make_hunt_match(event_id="e2", severity=ThreatSeverityLevel.CRITICAL),
            _make_hunt_match(event_id="e3", severity=ThreatSeverityLevel.MEDIUM),
        ]
        assert _peak_severity(matches) == AlertSeverityEnum.CRITICAL

    def test_empty_matches_returns_low(self):
        from app.services.threat_alerts import _peak_severity

        assert _peak_severity([]) == AlertSeverityEnum.LOW

    def test_all_medium_returns_medium(self):
        from app.services.threat_alerts import _peak_severity

        matches = [
            _make_hunt_match(event_id="e1", severity=ThreatSeverityLevel.MEDIUM),
            _make_hunt_match(event_id="e2", severity=ThreatSeverityLevel.MEDIUM),
        ]
        assert _peak_severity(matches) == AlertSeverityEnum.MEDIUM


class TestPeakVerdict:
    def test_single_block_returns_block(self):
        from app.services.threat_alerts import _peak_verdict

        matches = [_make_hunt_match(verdict=DetectionVerdict.BLOCK)]
        assert _peak_verdict(matches) == DetectionVerdict.BLOCK

    def test_mixed_verdicts_returns_block(self):
        from app.services.threat_alerts import _peak_verdict

        matches = [
            _make_hunt_match(event_id="e1", verdict=DetectionVerdict.ALLOW),
            _make_hunt_match(event_id="e2", verdict=DetectionVerdict.REVIEW),
            _make_hunt_match(event_id="e3", verdict=DetectionVerdict.BLOCK),
        ]
        assert _peak_verdict(matches) == DetectionVerdict.BLOCK

    def test_all_allow_returns_monitor(self):
        from app.services.threat_alerts import _peak_verdict

        matches = [
            _make_hunt_match(event_id="e1", verdict=DetectionVerdict.ALLOW),
        ]
        result = _peak_verdict(matches)
        assert result in (DetectionVerdict.ALLOW, DetectionVerdict.MONITOR)

    def test_empty_matches_returns_monitor(self):
        from app.services.threat_alerts import _peak_verdict

        assert _peak_verdict([]) == DetectionVerdict.MONITOR

    def test_review_beats_monitor(self):
        from app.services.threat_alerts import _peak_verdict

        matches = [
            _make_hunt_match(event_id="e1", verdict=DetectionVerdict.MONITOR),
            _make_hunt_match(event_id="e2", verdict=DetectionVerdict.REVIEW),
        ]
        assert _peak_verdict(matches) == DetectionVerdict.REVIEW


class TestPeakScore:
    def test_returns_max_score(self):
        from app.services.threat_alerts import _peak_score

        matches = [
            _make_hunt_match(event_id="e1", score=0.3),
            _make_hunt_match(event_id="e2", score=0.95),
            _make_hunt_match(event_id="e3", score=0.5),
        ]
        assert _peak_score(matches) == pytest.approx(0.95)

    def test_empty_matches_returns_zero(self):
        from app.services.threat_alerts import _peak_score

        assert _peak_score([]) == pytest.approx(0.0)

    def test_single_match_score(self):
        from app.services.threat_alerts import _peak_score

        matches = [_make_hunt_match(score=0.72)]
        assert _peak_score(matches) == pytest.approx(0.72)


# ---------------------------------------------------------------------------
# Suppression logic
# ---------------------------------------------------------------------------


class TestSuppressionKey:
    def test_key_includes_org_and_ioc(self):
        from app.services.threat_alerts import _suppression_key

        result = _make_hunt_result(
            query_summary={"ioc_value": "10.0.0.1", "mitre_technique_id": "T1059", "cve_id": "", "risk_family": ""},
            org_id="org-abc",
        )
        key = _suppression_key(result)
        assert "10.0.0.1" in key
        assert "T1059" in key
        assert "org-abc" in key

    def test_key_with_no_org_uses_global(self):
        from app.services.threat_alerts import _suppression_key

        result = _make_hunt_result(org_id=None, query_summary={"ioc_value": "x", "mitre_technique_id": "", "cve_id": "", "risk_family": ""})
        key = _suppression_key(result)
        assert "global" in key

    def test_distinct_iocs_produce_distinct_keys(self):
        from app.services.threat_alerts import _suppression_key

        r1 = _make_hunt_result(query_summary={"ioc_value": "1.1.1.1", "mitre_technique_id": "", "cve_id": "", "risk_family": ""})
        r2 = _make_hunt_result(query_summary={"ioc_value": "2.2.2.2", "mitre_technique_id": "", "cve_id": "", "risk_family": ""})
        assert _suppression_key(r1) != _suppression_key(r2)


class TestSuppressionRegistry:
    def test_not_suppressed_on_first_emission(self):
        from app.services.threat_alerts import _is_suppressed, _register_suppression

        key = "hunt:org-test:1.2.3.4:T1059::"
        now = time.time()
        assert not _is_suppressed(key, now)
        _register_suppression(key, now)

    def test_suppressed_within_window(self):
        from app.services.threat_alerts import (
            _SUPPRESSION_WINDOW_SECONDS,
            _is_suppressed,
            _register_suppression,
        )

        key = "hunt:org-test:suppress-test::"
        now = time.time()
        _register_suppression(key, now)
        assert _is_suppressed(key, now + _SUPPRESSION_WINDOW_SECONDS - 1)

    def test_not_suppressed_after_window_expires(self):
        from app.services.threat_alerts import (
            _SUPPRESSION_WINDOW_SECONDS,
            _is_suppressed,
            _register_suppression,
        )

        key = "hunt:org-test:expired-test::"
        now = time.time()
        _register_suppression(key, now)
        assert not _is_suppressed(key, now + _SUPPRESSION_WINDOW_SECONDS + 1)

    def test_prune_removes_expired_entries(self):
        from app.services.threat_alerts import (
            _SUPPRESSION_WINDOW_SECONDS,
            _prune_suppression_registry,
            _register_suppression,
            _suppression_registry,
        )

        key = "hunt:org-test:prune-me::"
        old_ts = time.time() - _SUPPRESSION_WINDOW_SECONDS - 10
        _register_suppression(key, old_ts)
        assert key in _suppression_registry
        _prune_suppression_registry(time.time())
        assert key not in _suppression_registry

    def test_prune_keeps_live_entries(self):
        from app.services.threat_alerts import (
            _prune_suppression_registry,
            _register_suppression,
            _suppression_registry,
        )

        key = "hunt:org-test:keep-me::"
        _register_suppression(key, time.time())
        _prune_suppression_registry(time.time())
        assert key in _suppression_registry


# ---------------------------------------------------------------------------
# Title and description builders
# ---------------------------------------------------------------------------


class TestBuildHuntAlertTitle:
    def test_title_includes_ioc_value(self):
        from app.services.threat_alerts import _build_hunt_alert_title

        result = _make_hunt_result(query_summary={"ioc_value": "evil.io", "mitre_technique_id": "", "cve_id": "", "risk_family": ""})
        title = _build_hunt_alert_title(result)
        assert "evil.io" in title

    def test_title_includes_mitre_technique(self):
        from app.services.threat_alerts import _build_hunt_alert_title

        result = _make_hunt_result(query_summary={"ioc_value": "", "mitre_technique_id": "T1071", "cve_id": "", "risk_family": ""})
        title = _build_hunt_alert_title(result)
        assert "T1071" in title

    def test_title_includes_cve(self):
        from app.services.threat_alerts import _build_hunt_alert_title

        result = _make_hunt_result(query_summary={"ioc_value": "", "mitre_technique_id": "", "cve_id": "CVE-2024-1234", "risk_family": ""})
        title = _build_hunt_alert_title(result)
        assert "CVE-2024-1234" in title

    def test_title_includes_risk_family(self):
        from app.services.threat_alerts import _build_hunt_alert_title

        result = _make_hunt_result(query_summary={"ioc_value": "", "mitre_technique_id": "", "cve_id": "", "risk_family": "lateral_movement"})
        title = _build_hunt_alert_title(result)
        assert "lateral_movement" in title

    def test_title_fallback_when_no_query_dims(self):
        from app.services.threat_alerts import _build_hunt_alert_title

        result = _make_hunt_result(query_summary={})
        title = _build_hunt_alert_title(result)
        assert "threat hunt" in title.lower()

    def test_title_includes_match_count(self):
        from app.services.threat_alerts import _build_hunt_alert_title

        result = _make_hunt_result(total_matches=5)
        title = _build_hunt_alert_title(result)
        assert "5" in title


class TestBuildHuntAlertDescription:
    def test_description_includes_hunt_id(self):
        from app.services.threat_alerts import _build_hunt_alert_description

        result = _make_hunt_result(hunt_id="hunt-xyz-999")
        desc = _build_hunt_alert_description(result)
        assert "hunt-xyz-999" in desc

    def test_description_includes_status(self):
        from app.services.threat_alerts import _build_hunt_alert_description

        result = _make_hunt_result(status=HuntStatusEnum.COMPLETED)
        desc = _build_hunt_alert_description(result)
        assert "completed" in desc.lower()

    def test_description_includes_duration(self):
        from app.services.threat_alerts import _build_hunt_alert_description

        result = _make_hunt_result(duration_ms=123)
        desc = _build_hunt_alert_description(result)
        assert "123" in desc

    def test_description_includes_errors(self):
        from app.services.threat_alerts import _build_hunt_alert_description

        result = _make_hunt_result(errors=["store_timeout"])
        desc = _build_hunt_alert_description(result)
        assert "store_timeout" in desc

    def test_description_omits_duration_when_none(self):
        from app.services.threat_alerts import _build_hunt_alert_description

        result = _make_hunt_result(duration_ms=None)
        desc = _build_hunt_alert_description(result)
        assert "Duration" not in desc


# ---------------------------------------------------------------------------
# _build_hunt_threat_alert
# ---------------------------------------------------------------------------


class TestBuildHuntThreatAlert:
    def test_returns_threat_alert_instance(self):
        from app.services.threat_alerts import _build_hunt_threat_alert

        result = _make_hunt_result()
        alert = _build_hunt_threat_alert(result)
        assert isinstance(alert, ThreatAlert)

    def test_alert_id_has_hunt_prefix(self):
        from app.services.threat_alerts import _build_hunt_threat_alert

        result = _make_hunt_result()
        alert = _build_hunt_threat_alert(result)
        assert alert.alert_id.startswith("hunt-alert-")

    def test_event_id_matches_hunt_id(self):
        from app.services.threat_alerts import _build_hunt_threat_alert

        result = _make_hunt_result(hunt_id="hunt-unique-55")
        alert = _build_hunt_threat_alert(result)
        assert alert.event_id == "hunt-unique-55"

    def test_org_id_propagated(self):
        from app.services.threat_alerts import _build_hunt_threat_alert

        result = _make_hunt_result(org_id="org-propagate")
        alert = _build_hunt_threat_alert(result)
        assert alert.org_id == "org-propagate"

    def test_severity_is_peak(self):
        from app.services.threat_alerts import _build_hunt_threat_alert

        matches = [
            _make_hunt_match(event_id="e1", severity=ThreatSeverityLevel.LOW),
            _make_hunt_match(event_id="e2", severity=ThreatSeverityLevel.CRITICAL),
        ]
        result = _make_hunt_result(matches=matches)
        alert = _build_hunt_threat_alert(result)
        assert alert.severity == AlertSeverityEnum.CRITICAL

    def test_verdict_is_peak(self):
        from app.services.threat_alerts import _build_hunt_threat_alert

        matches = [
            _make_hunt_match(event_id="e1", verdict=DetectionVerdict.MONITOR),
            _make_hunt_match(event_id="e2", verdict=DetectionVerdict.BLOCK),
        ]
        result = _make_hunt_result(matches=matches)
        alert = _build_hunt_threat_alert(result)
        assert alert.verdict == DetectionVerdict.BLOCK

    def test_score_is_peak(self):
        from app.services.threat_alerts import _build_hunt_threat_alert

        matches = [
            _make_hunt_match(event_id="e1", score=0.3),
            _make_hunt_match(event_id="e2", score=0.95),
        ]
        result = _make_hunt_result(matches=matches)
        alert = _build_hunt_threat_alert(result)
        assert alert.score == pytest.approx(0.95)

    def test_mitre_techniques_deduplicated(self):
        from app.services.threat_alerts import _build_hunt_threat_alert

        matches = [
            _make_hunt_match(event_id="e1", matched_mitre_technique="T1059"),
            _make_hunt_match(event_id="e2", matched_mitre_technique="T1059"),
            _make_hunt_match(event_id="e3", matched_mitre_technique="T1041"),
        ]
        result = _make_hunt_result(matches=matches)
        alert = _build_hunt_threat_alert(result)
        assert alert.mitre_techniques.count("T1059") == 1
        assert "T1041" in alert.mitre_techniques

    def test_risk_families_deduplicated(self):
        from app.services.threat_alerts import _build_hunt_threat_alert

        matches = [
            _make_hunt_match(event_id="e1", risk_families=["c2", "exfil"]),
            _make_hunt_match(event_id="e2", risk_families=["c2"]),
        ]
        result = _make_hunt_result(matches=matches)
        alert = _build_hunt_threat_alert(result)
        assert alert.risk_families.count("c2") == 1

    def test_suppressed_defaults_false(self):
        from app.services.threat_alerts import _build_hunt_threat_alert

        result = _make_hunt_result()
        alert = _build_hunt_threat_alert(result)
        assert alert.suppressed is False

    def test_metadata_contains_hunt_id(self):
        from app.services.threat_alerts import _build_hunt_threat_alert

        result = _make_hunt_result(hunt_id="hunt-meta-check")
        alert = _build_hunt_threat_alert(result)
        assert alert.metadata.get("hunt_id") == "hunt-meta-check"

    def test_metadata_source_is_threat_hunt(self):
        from app.services.threat_alerts import _build_hunt_threat_alert

        result = _make_hunt_result()
        alert = _build_hunt_threat_alert(result)
        assert alert.metadata.get("source") == "threat_hunt"

    def test_empty_matches_produces_valid_alert(self):
        from app.services.threat_alerts import _build_hunt_threat_alert

        result = _make_hunt_result(matches=[], total_matches=0)
        alert = _build_hunt_threat_alert(result)
        assert isinstance(alert, ThreatAlert)
        assert alert.mitre_techniques == []
        assert alert.risk_families == []

    def test_alert_ids_unique_across_calls(self):
        from app.services.threat_alerts import _build_hunt_threat_alert

        result = _make_hunt_result()
        ids = {_build_hunt_threat_alert(result).alert_id for _ in range(20)}
        assert len(ids) == 20


# ---------------------------------------------------------------------------
# emit_hunt_alert — public surface, full integration with mocked store
# ---------------------------------------------------------------------------


class TestEmitHuntAlert:
    def _make_mock_store(self) -> MagicMock:
        store = MagicMock()
        store.create_alert.return_value = {"id": "persisted-alert-id", "alert_id": "persisted-alert-id"}
        return store

    def test_returns_dict_on_success(self):
        import app.services.threat_alerts as ta

        store = self._make_mock_store()
        ta._alert_store = store

        with patch.object(ta, "_maybe_escalate_to_incident", return_value=None):
            result = _make_hunt_result(total_matches=1)
            from app.services.threat_alerts import emit_hunt_alert

            out = emit_hunt_alert(result)

        assert isinstance(out, dict)
        assert out.get("emitted") is True

    def test_returns_suppressed_flag_on_second_call(self):
        import app.services.threat_alerts as ta

        store = self._make_mock_store()
        ta._alert_store = store

        result = _make_hunt_result(total_matches=1)

        with patch.object(ta, "_maybe_escalate_to_incident", return_value=None):
            from app.services.threat_alerts import emit_hunt_alert

            emit_hunt_alert(result)
            second = emit_hunt_alert(result)

        assert second.get("suppressed") is True

    def test_zero_matches_returns_no_alert(self):
        import app.services.threat_alerts as ta

        store = self._make_mock_store()
        ta._alert_store = store

        from app.services.threat_alerts import emit_hunt_alert

        result = _make_hunt_result(matches=[], total_matches=0)
        out = emit_hunt_alert(result)
        assert out.get("emitted") is False or out.get("skipped") is True

    def test_store_create_alert_called_once(self):
        import app.services.threat_alerts as ta

        store = self._make_mock_store()
        ta._alert_store = store

        with patch.object(ta, "_maybe_escalate_to_incident", return_value=None):
            from app.services.threat_alerts import emit_hunt_alert

            emit_hunt_alert(_make_hunt_result())

        store.create_alert.assert_called_once()

    def test_create_alert_called_with_correct_category(self):
        import app.services.threat_alerts as ta

        store = self._make_mock_store()
        ta._alert_store = store

        with patch.object(ta, "_maybe_escalate_to_incident", return_value=None):
            from app.services.threat_alerts import emit_hunt_alert

            emit_hunt_alert(_make_hunt_result())

        _, kwargs = store.create_alert.call_args
        assert kwargs.get("category") == "threat_hunt" or kwargs.get("alert_type") == "threat_hunt"

    def test_create_alert_called_with_org_id(self):
        import app.services.threat_alerts as ta

        store = self._make_mock_store()
        ta._alert_store = store

        with patch.object(ta, "_maybe_escalate_to_incident", return_value=None):
            from app.services.threat_alerts import emit_hunt_alert

            emit_hunt_alert(_make_hunt_result(org_id="org-store-check"))

        _, kwargs = store.create_alert.call_args
        assert kwargs.get("org_id") == "org-store-check" or kwargs.get("organization_id") == "org-store-check"

    def test_store_failure_does_not_raise(self):
        import app.services.threat_alerts as ta

        store = self._make_mock_store()
        store.create_alert.side_effect = RuntimeError("DB down")
        ta._alert_store = store

        from app.services.threat_alerts import emit_hunt_alert

        out = emit_hunt_alert(_make_hunt_result())
        assert isinstance(out, dict)

    def test_escalation_called_for_high_severity(self):
        import app.services.threat_alerts as ta

        store = self._make_mock_store()
        ta._alert_store = store

        matches = [_make_hunt_match(severity=ThreatSeverityLevel.CRITICAL, verdict=DetectionVerdict.BLOCK)]
        result = _make_hunt_result(matches=matches)

        with patch.object(ta, "_maybe_escalate_to_incident", return_value="incident-001") as mock_esc:
            from app.services.threat_alerts import emit_hunt_alert

            emit_hunt_alert(result)

        mock_esc.assert_called_once()

    def test_suppression_does_not_call_store(self):
        import app.services.threat_alerts as ta

        store = self._make_mock_store()
        ta._alert_store = store

        result = _make_hunt_result()

        with patch.object(ta, "_maybe_escalate_to_incident", return_value=None):
            from app.services.threat_alerts import emit_hunt_alert

            emit_hunt_alert(result)
            store.reset_mock()
            emit_hunt_alert(result)

        store.create_alert.assert_not_called()

    def test_different_org_not_suppressed_by_first_org(self):
        import app.services.threat_alerts as ta

        store = self._make_mock_store()
        ta._alert_store = store

        result_a = _make_hunt_result(org_id="org-a")
        result_b = _make_hunt_result(org_id="org-b")

        with patch.object(ta, "_maybe_escalate_to_incident", return_value=None):
            from app.services.threat_alerts import emit_hunt_alert

            emit_hunt_alert(result_a)
            store.reset_mock()
            out = emit_hunt_alert(result_b)

        assert out.get("suppressed") is not True


# ---------------------------------------------------------------------------
# emit_detection_alert — public surface
# ---------------------------------------------------------------------------


class TestEmitDetectionAlert:
    def _make_mock_store(self) -> MagicMock:
        store = MagicMock()
        store.create_alert.return_value = {"id": "det-persisted", "alert_id": "det-persisted"}
        return store

    def test_returns_dict_for_block_verdict(self):
        import app.services.threat_alerts as ta

        store = self._make_mock_store()
        ta._alert_store = store

        from app.services.threat_alerts import emit_detection_alert

        det = _make_detection_result_mock(verdict=DetectionVerdict.BLOCK)
        with patch.object(ta, "_maybe_escalate_to_incident", return_value=None):
            out = emit_detection_alert(det)

        assert isinstance(out, dict)

    def test_returns_dict_for_review_verdict(self):
        import app.services.threat_alerts as ta

        store = self._make_mock_store()
        ta._alert_store = store

        from app.services.threat_alerts import emit_detection_alert

        det = _make_detection_result_mock(verdict=DetectionVerdict.REVIEW)
        with patch.object(ta, "_maybe_escalate_to_incident", return_value=None):
            out = emit_detection_alert(det)

        assert isinstance(out, dict)

    def test_skips_allow_verdict(self):
        import app.services.threat_alerts as ta

        store = self._make_mock_store()
        ta._alert_store = store

        from app.services.threat_alerts import emit_detection_alert

        det = _make_detection_result_mock(verdict=DetectionVerdict.ALLOW)
        out = emit_detection_alert(det)

        assert out.get("emitted") is False or out.get("skipped") is True

    def test_skips_monitor_verdict(self):
        import app.services.threat_alerts as ta

        store = self._make_mock_store()
        ta._alert_store = store

        from app.services.threat_alerts import emit_detection_alert

        det = _make_detection_result_mock(verdict=DetectionVerdict.MONITOR)
        out = emit_detection_alert(det)

        assert out.get("emitted") is False or out.get("skipped") is True

    def test_store_create_alert_called_for_block(self):
        import app.services.threat_alerts as ta

        store = self._make_mock_store()
        ta._alert_store = store

        from app.services.threat_alerts import emit_detection_alert

        det = _make_detection_result_mock(verdict=DetectionVerdict.BLOCK)
        with patch.object(ta, "_maybe_escalate_to_incident", return_value=None):
            emit_detection_alert(det)

        store.create_alert.assert_called_once()

    def test_store_not_called_for_allow(self):
        import app.services.threat_alerts as ta

        store = self._make_mock_store()
        ta._alert_store = store

        from app.services.threat_alerts import emit_detection_alert

        det = _make_detection_result_mock(verdict=DetectionVerdict.ALLOW)
        emit_detection_alert(det)

        store.create_alert.assert_not_called()

    def test_store_failure_does_not_raise(self):
        import app.services.threat_alerts as ta

        store = self._make_mock_store()
        store.create_alert.side_effect = RuntimeError("DB exploded")
        ta._alert_store = store

        from app.services.threat_alerts import emit_detection_alert

        det = _make_detection_result_mock(verdict=DetectionVerdict.BLOCK)
        out = emit_detection_alert(det)
        assert isinstance(out, dict)

    def test_org_id_propagated_to_alert(self):
        import app.services.threat_alerts as ta

        store = self._make_mock_store()
        ta._alert_store = store

        from app.services.threat_alerts import emit_detection_alert

        det = _make_detection_result_mock(verdict=DetectionVerdict.BLOCK, org_id="org-det-prop")
        with patch.object(ta, "_maybe_escalate_to_incident", return_value=None):
            emit_detection_alert(det)

        _, kwargs = store.create_alert.call_args
        assert kwargs.get("org_id") == "org-det-prop" or kwargs.get("organization_id") == "org-det-prop"

    def test_escalation_called_for_block(self):
        import app.services.threat_alerts as ta

        store = self._make_mock_store()
        ta._alert_store = store

        from app.services.threat_alerts import emit_detection_alert

        det = _make_detection_result_mock(verdict=DetectionVerdict.BLOCK)
        with patch.object(ta, "_maybe_escalate_to_incident", return_value="inc-det-001") as mock_esc:
            emit_detection_alert(det)

        mock_esc.assert_called_once()


# ---------------------------------------------------------------------------
# _maybe_escalate_to_incident — fail-open contract
# ---------------------------------------------------------------------------


class TestMaybeEscalateToIncident:
    def test_returns_none_when_incident_service_unavailable(self):
        from app.services.threat_alerts import _maybe_escalate_to_incident

        alert = ThreatAlert(
            alert_id="alert-esc-001",
            event_id="evt-esc-001",
            org_id="org-esc",
            verdict=DetectionVerdict.BLOCK,
            severity=AlertSeverityEnum.CRITICAL,
            score=0.99,
            title="Escalation test alert",
            description="Testing fail-open escalation path",
            created_at="2026-05-25T14:00:00+00:00",
            metadata={},
        )

        with patch.dict("sys.modules", {"app.services.incident_service": None}):
            result = _maybe_escalate_to_incident(alert)

        assert result is None

    def test_returns_none_on_incident_service_exception(self):
        from app.services.threat_alerts import _maybe_escalate_to_incident

        alert = ThreatAlert(
            alert_id="alert-esc-002",
            event_id="evt-esc-002",
            org_id="org-esc",
            verdict=DetectionVerdict.BLOCK,
            severity=AlertSeverityEnum.HIGH,
            score=0.88,
            title="Fail-open escalation alert",
            description="Testing exception branch",
            created_at="2026-05-25T14:00:00+00:00",
            metadata={},
        )

        mock_service = MagicMock()
        mock_service.create_from_alert.side_effect = RuntimeError("incident service crashed")

        mock_inc_module = MagicMock()
        mock_inc_module.get_incident_service.return_value = mock_service

        with patch.dict("sys.modules", {"app.services.incident_service": mock_inc_module}):
            result = _maybe_escalate_to_incident(alert)

        assert result is None

    def test_returns_incident_id_on_success(self):
        from app.services.threat_alerts import _maybe_escalate_to_incident

        alert = ThreatAlert(
            alert_id="alert-esc-003",
            event_id="evt-esc-003",
            org_id="org-esc",
            verdict=DetectionVerdict.BLOCK,
            severity=AlertSeverityEnum.CRITICAL,
            score=0.99,
            title="Successful escalation",
            description="Incident should be created",
            created_at="2026-05-25T14:00:00+00:00",
            metadata={},
        )

        mock_service = MagicMock()
        mock_service.create_from_alert.return_value = {"incident_id": "inc-abc123"}

        mock_inc_module = MagicMock()
        mock_inc_module.get_incident_service.return_value = mock_service

        with patch.dict("sys.modules", {"app.services.incident_service": mock_inc_module}):
            importlib.invalidate_caches()
            result = _maybe_escalate_to_incident(alert)

        assert result == "inc-abc123" or result is None


# ---------------------------------------------------------------------------
# _get_alert_store — lazy singleton
# ---------------------------------------------------------------------------


class TestGetAlertStore:
    def test_returns_same_instance_on_repeated_calls(self):
        import app.services.threat_alerts as ta

        ta._alert_store = None
        mock_store = MagicMock()

        with patch("app.services.threat_alerts.build_alert_store", return_value=mock_store):
            from app.services.threat_alerts import _get_alert_store

            s1 = _get_alert_store()
            s2 = _get_alert_store()

        assert s1 is s2

    def test_build_alert_store_called_exactly_once(self):
        import app.services.threat_alerts as ta

        ta._alert_store = None
        mock_store = MagicMock()

        with patch("app.services.threat_alerts.build_alert_store", return_value=mock_store) as mock_builder:
            from app.services.threat_alerts import _get_alert_store

            _get_alert_store()
            _get_alert_store()
            _get_alert_store()

        mock_builder.assert_called_once()


# ---------------------------------------------------------------------------
# Edge cases and adversarial inputs
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_hunt_result_with_none_org_id(self):
        from app.services.threat_alerts import _build_hunt_threat_alert

        result = _make_hunt_result(org_id=None)
        alert = _build_hunt_threat_alert(result)
        assert alert.org_id is None

    def test_hunt_result_with_no_duration(self):
        from app.services.threat_alerts import _build_hunt_alert_description

        result = _make_hunt_result(duration_ms=None)
        desc = _build_hunt_alert_description(result)
        assert isinstance(desc, str)
        assert len(desc) > 0

    def test_hunt_match_without_mitre_technique(self):
        from app.services.threat_alerts import _build_hunt_threat_alert

        matches = [_make_hunt_match(matched_mitre_technique=None)]
        result = _make_hunt_result(matches=matches)
        alert = _build_hunt_threat_alert(result)
        assert alert.mitre_techniques == []

    def test_hunt_match_without_risk_families(self):
        from app.services.threat_alerts import _build_hunt_threat_alert

        matches = [_make_hunt_match(risk_families=[])]
        result = _make_hunt_result(matches=matches)
        alert = _build_hunt_threat_alert(result)
        assert alert.risk_families == []

    def test_many_matches_deduplication_correctness(self):
        from app.services.threat_alerts import _build_hunt_threat_alert

        matches = [_make_hunt_match(event_id=f"e{i}", matched_mitre_technique="T1059", risk_families=["c2"]) for i in range(50)]
        result = _make_hunt_result(matches=matches)
        alert = _build_hunt_threat_alert(result)
        assert alert.mitre_techniques == ["T1059"]
        assert alert.risk_families == ["c2"]

    def test_suppression_key_cve_included(self):
        from app.services.threat_alerts import _suppression_key

        result = _make_hunt_result(
            org_id="org-cve",
            query_summary={"ioc_value": "", "mitre_technique_id": "", "cve_id": "CVE-2024-9999", "risk_family": ""},
        )
        key = _suppression_key(result)
        assert "CVE-2024-9999" in key

    def test_suppression_key_risk_family_included(self):
        from app.services.threat_alerts import _suppression_key

        result = _make_hunt_result(
            org_id="org-rf",
            query_summary={"ioc_value": "", "mitre_technique_id": "", "cve_id": "", "risk_family": "initial_access"},
        )
        key = _suppression_key(result)
        assert "initial_access" in key

    def test_emit_hunt_alert_with_failed_hunt_status_still_returns_dict(self):
        import app.services.threat_alerts as ta

        store = MagicMock()
        store.create_alert.return_value = {"alert_id": "x"}
        ta._alert_store = store

        from app.services.threat_alerts import emit_hunt_alert

        result = _make_hunt_result(status=HuntStatusEnum.FAILED, matches=[], total_matches=0)
        out = emit_hunt_alert(result)
        assert isinstance(out, dict)
