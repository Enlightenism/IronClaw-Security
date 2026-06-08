from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from app.core.trust_engine import (
    TrustProfile,
    _clamp,
    get_trust,
    invalidate_cache,
    list_trust_events,
    record_event,
    reset_trust,
    restore_agent,
    suspend_agent,
    trust_stats,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_profile(
    agent_id: str = "agent-test",
    trust_score: float = 0.75,
    is_suspended: bool = False,
    suspension_reason: str | None = None,
    event_count: int = 0,
    last_event_type: str | None = None,
) -> TrustProfile:
    now = "2025-01-01T00:00:00+00:00"
    return TrustProfile(
        agent_id=agent_id,
        trust_score=trust_score,
        event_count=event_count,
        last_event_type=last_event_type,
        last_event_at=None,
        created_at=now,
        updated_at=now,
        is_suspended=is_suspended,
        suspension_reason=suspension_reason,
        metadata={},
    )


def _db_row(
    agent_id: str = "agent-db",
    trust_score: float = 0.65,
    is_suspended: bool = False,
) -> dict:
    now = "2025-01-01T00:00:00+00:00"
    return {
        "agent_id": agent_id,
        "trust_score": trust_score,
        "event_count": 2,
        "last_event_type": "anomaly_detected",
        "last_event_at": now,
        "created_at": now,
        "updated_at": now,
        "is_suspended": is_suspended,
        "suspension_reason": None,
        "metadata": {},
    }


def _patched_no_db(agent_id: str | None = None):
    invalidate_cache(agent_id)
    return patch.multiple(
        "app.core.trust_engine",
        _fetch_profile_from_db=MagicMock(return_value=None),
        _upsert_profile_to_db=MagicMock(return_value=None),
        _insert_trust_event_to_db=MagicMock(return_value=None),
    )


# ---------------------------------------------------------------------------
# _clamp
# ---------------------------------------------------------------------------


class TestClamp:
    def test_floor_is_zero(self):
        assert _clamp(-999.0) == 0.0

    def test_ceiling_is_one(self):
        assert _clamp(999.0) == 1.0

    def test_mid_value_unchanged(self):
        assert _clamp(0.5) == 0.5

    def test_exactly_zero(self):
        assert _clamp(0.0) == 0.0

    def test_exactly_one(self):
        assert _clamp(1.0) == 1.0


# ---------------------------------------------------------------------------
# get_trust — default (no DB row)
# ---------------------------------------------------------------------------


class TestGetTrustDefault:
    def test_no_db_entry_returns_default_profile(self):
        invalidate_cache(None)
        with patch("app.core.trust_engine._fetch_profile_from_db", return_value=None):
            profile = get_trust("agent-default-test")

        assert isinstance(profile, TrustProfile)
        assert profile.trust_score == 0.75
        assert profile.is_suspended is False

    def test_empty_agent_id_returns_unknown_key_no_raise(self):
        invalidate_cache(None)
        for bad in ("", "   "):
            profile = get_trust(bad)
            assert profile.agent_id == "unknown"
            assert profile.trust_score == 0.75

    def test_blank_agent_id_does_not_raise(self):
        invalidate_cache(None)
        try:
            get_trust("   ")
        except Exception as e:
            pytest.fail(f"get_trust raised: {e}")


# ---------------------------------------------------------------------------
# get_trust — cache hit
# ---------------------------------------------------------------------------


class TestGetTrustCache:
    def test_second_call_does_not_hit_db(self):
        invalidate_cache(None)
        fetch_mock = MagicMock(return_value=None)
        with patch("app.core.trust_engine._fetch_profile_from_db", fetch_mock):
            get_trust("agent-cache-hit")
            get_trust("agent-cache-hit")

        assert fetch_mock.call_count == 1

    def test_cache_returns_same_profile_object_data(self):
        invalidate_cache(None)
        with patch("app.core.trust_engine._fetch_profile_from_db", return_value=None):
            p1 = get_trust("agent-same-cache")
            p2 = get_trust("agent-same-cache")

        assert p1.trust_score == p2.trust_score
        assert p1.agent_id == p2.agent_id


# ---------------------------------------------------------------------------
# get_trust — cache miss → DB row hydration
# ---------------------------------------------------------------------------


class TestGetTrustDbHydration:
    def test_cache_miss_loads_profile_from_db_row(self):
        aid = "agent-db-hydrate"
        invalidate_cache(aid)
        row = _db_row(agent_id=aid, trust_score=0.65)

        with patch("app.core.trust_engine._fetch_profile_from_db", return_value=row):
            profile = get_trust(aid)

        assert profile.agent_id == aid
        assert round(profile.trust_score, 6) == 0.65
        assert profile.event_count == 2

    def test_db_row_is_then_cached_on_next_call(self):
        aid = "agent-db-cached"
        invalidate_cache(aid)
        row = _db_row(agent_id=aid, trust_score=0.55)
        fetch_mock = MagicMock(return_value=row)

        with patch("app.core.trust_engine._fetch_profile_from_db", fetch_mock):
            get_trust(aid)
            get_trust(aid)

        assert fetch_mock.call_count == 1


# ---------------------------------------------------------------------------
# record_event — score decay per event type
# ---------------------------------------------------------------------------


class TestRecordEventDecay:
    def test_anomaly_detected_decay_005(self):
        aid = "agent-anomaly"
        with _patched_no_db(aid):
            event = record_event(aid, "anomaly_detected")
        assert round(event.delta, 6) == round(-0.05, 6)

    def test_policy_violation_decay_008(self):
        aid = "agent-policy-viol"
        with _patched_no_db(aid):
            event = record_event(aid, "policy_violation")
        assert round(event.delta, 6) == round(-0.08, 6)

    def test_prompt_injection_reduces_score_by_015(self):
        aid = "agent-injection-test"
        with _patched_no_db(aid):
            event = record_event(aid, "prompt_injection_attempt")
        assert round(event.delta, 6) == round(-0.15, 6)
        assert round(event.new_score, 6) == round(0.75 - 0.15, 6)

    def test_tool_call_blocked_decay_010(self):
        aid = "agent-tool-blocked"
        with _patched_no_db(aid):
            event = record_event(aid, "tool_call_blocked")
        assert round(event.delta, 6) == round(-0.10, 6)

    def test_sandbox_escape_reduces_score_by_020(self):
        aid = "agent-sandbox-test"
        with _patched_no_db(aid):
            event = record_event(aid, "sandbox_escape_attempt")
        assert round(event.delta, 6) == round(-0.20, 6)
        assert round(event.new_score, 6) == round(0.75 - 0.20, 6)

    def test_data_exfiltration_decay_020(self):
        aid = "agent-exfil"
        with _patched_no_db(aid):
            event = record_event(aid, "data_exfiltration_attempt")
        assert round(event.delta, 6) == round(-0.20, 6)

    def test_role_hijack_decay_015(self):
        aid = "agent-hijack"
        with _patched_no_db(aid):
            event = record_event(aid, "role_hijack_attempt")
        assert round(event.delta, 6) == round(-0.15, 6)

    def test_review_escalation_decay_007(self):
        aid = "agent-escalation"
        with _patched_no_db(aid):
            event = record_event(aid, "review_escalation")
        assert round(event.delta, 6) == round(-0.07, 6)

    def test_trust_reset_restores_score_to_075(self):
        aid = "agent-reset-test"
        low_profile = _make_profile(aid, trust_score=0.30)
        with _patched_no_db(aid):
            with patch("app.core.trust_engine.get_trust", return_value=low_profile):
                event = record_event(aid, "trust_reset")
        assert round(event.new_score, 6) == 0.75

    def test_trust_restored_increases_score(self):
        aid = "agent-restored-test"
        decayed = _make_profile(aid, trust_score=0.60)
        with _patched_no_db(aid):
            with patch("app.core.trust_engine.get_trust", return_value=decayed):
                event = record_event(aid, "trust_restored")
        assert event.new_score > event.previous_score

    def test_manual_adjustment_negative_030(self):
        aid = "agent-manual-test"
        with _patched_no_db(aid):
            event = record_event(aid, "manual_adjustment", metadata={"adjustment": -0.30})
        assert round(event.delta, 6) == round(-0.30, 6)
        assert round(event.new_score, 6) == round(0.75 - 0.30, 6)

    def test_manual_adjustment_positive_010(self):
        aid = "agent-manual-pos"
        low = _make_profile(aid, trust_score=0.50)
        with _patched_no_db(aid):
            with patch("app.core.trust_engine.get_trust", return_value=low):
                event = record_event(aid, "manual_adjustment", metadata={"adjustment": 0.10})
        assert round(event.new_score, 6) == round(0.60, 6)

    def test_score_cannot_go_below_zero(self):
        aid = "agent-floor"
        near_zero = _make_profile(aid, trust_score=0.02)
        with _patched_no_db(aid):
            with patch("app.core.trust_engine.get_trust", return_value=near_zero):
                event = record_event(aid, "sandbox_escape_attempt")
        assert event.new_score == 0.0

    def test_score_cannot_exceed_ceiling(self):
        aid = "agent-ceiling"
        near_max = _make_profile(aid, trust_score=0.98)
        with _patched_no_db(aid):
            with patch("app.core.trust_engine.get_trust", return_value=near_max):
                event = record_event(aid, "manual_adjustment", metadata={"adjustment": 0.50})
        assert event.new_score == 1.0


# ---------------------------------------------------------------------------
# record_event — suspension triggers
# ---------------------------------------------------------------------------


class TestRecordEventSuspensionTriggers:
    def test_sandbox_escape_sets_suspended_on_upserted_profile(self):
        aid = "agent-sandbox-suspend"
        invalidate_cache(aid)
        upserted: list[TrustProfile] = []

        def _capture(p: TrustProfile) -> None:
            upserted.append(p)

        with patch.multiple(
            "app.core.trust_engine",
            _fetch_profile_from_db=MagicMock(return_value=None),
            _upsert_profile_to_db=MagicMock(side_effect=_capture),
            _insert_trust_event_to_db=MagicMock(return_value=None),
        ):
            record_event(aid, "sandbox_escape_attempt")

        assert upserted, "upsert was never called"
        assert upserted[0].is_suspended is True

    def test_data_exfiltration_sets_suspended(self):
        aid = "agent-exfil-suspend"
        invalidate_cache(aid)
        upserted: list[TrustProfile] = []

        def _capture(p: TrustProfile) -> None:
            upserted.append(p)

        with patch.multiple(
            "app.core.trust_engine",
            _fetch_profile_from_db=MagicMock(return_value=None),
            _upsert_profile_to_db=MagicMock(side_effect=_capture),
            _insert_trust_event_to_db=MagicMock(return_value=None),
        ):
            record_event(aid, "data_exfiltration_attempt")

        assert upserted[0].is_suspended is True

    def test_score_at_or_below_010_triggers_auto_suspension(self):
        aid = "agent-autosuspend"
        invalidate_cache(aid)
        upserted: list[TrustProfile] = []

        def _capture(p: TrustProfile) -> None:
            upserted.append(p)

        low_score_profile = _make_profile(aid, trust_score=0.12)

        with patch.multiple(
            "app.core.trust_engine",
            _fetch_profile_from_db=MagicMock(return_value=None),
            _upsert_profile_to_db=MagicMock(side_effect=_capture),
            _insert_trust_event_to_db=MagicMock(return_value=None),
        ):
            with patch("app.core.trust_engine.get_trust", return_value=low_score_profile):
                record_event(aid, "anomaly_detected")

        assert upserted, "upsert was never called"
        assert upserted[0].is_suspended is True

    def test_already_suspended_agent_not_double_suspended(self):
        aid = "agent-already-suspended"
        invalidate_cache(aid)
        upserted: list[TrustProfile] = []

        def _capture(p: TrustProfile) -> None:
            upserted.append(p)

        suspended_profile = _make_profile(
            aid,
            trust_score=0.05,
            is_suspended=True,
            suspension_reason="prior reason",
        )

        with patch.multiple(
            "app.core.trust_engine",
            _fetch_profile_from_db=MagicMock(return_value=None),
            _upsert_profile_to_db=MagicMock(side_effect=_capture),
            _insert_trust_event_to_db=MagicMock(return_value=None),
        ):
            with patch("app.core.trust_engine.get_trust", return_value=suspended_profile):
                record_event(aid, "anomaly_detected")

        assert upserted[0].is_suspended is True
        assert upserted[0].suspension_reason == "prior reason"


# ---------------------------------------------------------------------------
# record_event — cache eviction after write
# ---------------------------------------------------------------------------


class TestRecordEventCacheEviction:
    def test_cache_is_evicted_after_record_event(self):
        aid = "agent-cache-evict"
        invalidate_cache(aid)
        fetch_mock = MagicMock(return_value=None)

        with patch.multiple(
            "app.core.trust_engine",
            _fetch_profile_from_db=fetch_mock,
            _upsert_profile_to_db=MagicMock(return_value=None),
            _insert_trust_event_to_db=MagicMock(return_value=None),
        ):
            get_trust(aid)
            assert fetch_mock.call_count == 1

            record_event(aid, "anomaly_detected")
            get_trust(aid)

        assert fetch_mock.call_count == 2


# ---------------------------------------------------------------------------
# record_event — validation
# ---------------------------------------------------------------------------


class TestRecordEventValidation:
    def test_empty_agent_id_raises_value_error(self):
        with pytest.raises(ValueError, match="agent_id"):
            record_event("", "anomaly_detected")

    def test_blank_agent_id_raises_value_error(self):
        with pytest.raises(ValueError, match="agent_id"):
            record_event("   ", "anomaly_detected")

    def test_event_has_correct_agent_id(self):
        aid = "agent-event-id-check"
        with _patched_no_db(aid):
            event = record_event(aid, "anomaly_detected")
        assert event.agent_id == aid

    def test_event_has_non_empty_event_id(self):
        aid = "agent-event-uuid"
        with _patched_no_db(aid):
            event = record_event(aid, "anomaly_detected")
        assert event.event_id and len(event.event_id) > 0

    def test_event_has_recorded_at(self):
        aid = "agent-event-ts"
        with _patched_no_db(aid):
            event = record_event(aid, "anomaly_detected")
        assert event.recorded_at and len(event.recorded_at) > 0


# ---------------------------------------------------------------------------
# reset_trust
# ---------------------------------------------------------------------------


class TestResetTrust:
    def test_reset_trust_delegates_to_record_event_trust_reset(self):
        aid = "agent-reset-delegate"
        with patch("app.core.trust_engine.record_event") as mock_record:
            mock_record.return_value = MagicMock()
            reset_trust(aid)
        mock_record.assert_called_once_with(aid, "trust_reset", None)

    def test_reset_trust_returns_event(self):
        aid = "agent-reset-returns"
        with _patched_no_db(aid):
            low = _make_profile(aid, trust_score=0.20)
            with patch("app.core.trust_engine.get_trust", return_value=low):
                event = reset_trust(aid)
        assert round(event.new_score, 6) == 0.75

    def test_reset_trust_raises_on_blank_agent_id(self):
        with pytest.raises(ValueError, match="agent_id"):
            reset_trust("")


# ---------------------------------------------------------------------------
# suspend_agent
# ---------------------------------------------------------------------------


class TestSuspendAgent:
    def test_sets_suspended_true_score_zero_and_reason(self):
        aid = "agent-suspend-direct"
        invalidate_cache(aid)
        upserted: list[TrustProfile] = []

        def _capture(p: TrustProfile) -> None:
            upserted.append(p)

        with patch.multiple(
            "app.core.trust_engine",
            _fetch_profile_from_db=MagicMock(return_value=None),
            _upsert_profile_to_db=MagicMock(side_effect=_capture),
            _insert_trust_event_to_db=MagicMock(return_value=None),
        ):
            result = suspend_agent(aid, reason="policy escalation")

        assert result.is_suspended is True
        assert result.trust_score == 0.0
        assert result.suspension_reason == "policy escalation"

    def test_upsert_called_on_suspend(self):
        aid = "agent-suspend-upsert"
        invalidate_cache(aid)
        upsert_mock = MagicMock(return_value=None)

        with patch.multiple(
            "app.core.trust_engine",
            _fetch_profile_from_db=MagicMock(return_value=None),
            _upsert_profile_to_db=upsert_mock,
            _insert_trust_event_to_db=MagicMock(return_value=None),
        ):
            suspend_agent(aid, reason="test")

        assert upsert_mock.called

    def test_cache_evicted_after_suspend(self):
        aid = "agent-suspend-evict"
        invalidate_cache(aid)
        fetch_mock = MagicMock(return_value=None)

        with patch.multiple(
            "app.core.trust_engine",
            _fetch_profile_from_db=fetch_mock,
            _upsert_profile_to_db=MagicMock(return_value=None),
            _insert_trust_event_to_db=MagicMock(return_value=None),
        ):
            get_trust(aid)
            assert fetch_mock.call_count == 1

            suspend_agent(aid, reason="evict test")
            get_trust(aid)

        assert fetch_mock.call_count == 2

    def test_default_suspension_reason_used_when_none_given(self):
        aid = "agent-suspend-default-reason"
        invalidate_cache(aid)
        upserted: list[TrustProfile] = []

        def _capture(p: TrustProfile) -> None:
            upserted.append(p)

        with patch.multiple(
            "app.core.trust_engine",
            _fetch_profile_from_db=MagicMock(return_value=None),
            _upsert_profile_to_db=MagicMock(side_effect=_capture),
            _insert_trust_event_to_db=MagicMock(return_value=None),
        ):
            suspend_agent(aid, reason="Manual suspension")

        assert upserted[0].suspension_reason is not None


# ---------------------------------------------------------------------------
# restore_agent
# ---------------------------------------------------------------------------


class TestRestoreAgent:
    def test_clears_suspension_and_restores_score(self):
        aid = "agent-restore-direct"
        invalidate_cache(aid)

        with patch.multiple(
            "app.core.trust_engine",
            _fetch_profile_from_db=MagicMock(return_value=None),
            _upsert_profile_to_db=MagicMock(return_value=None),
            _insert_trust_event_to_db=MagicMock(return_value=None),
        ):
            result = restore_agent(aid, restore_score=0.75)

        assert result.is_suspended is False
        assert round(result.trust_score, 6) == 0.75
        assert result.suspension_reason is None

    def test_trust_events_row_inserted_on_restore(self):
        aid = "agent-restore-event"
        invalidate_cache(aid)
        insert_mock = MagicMock(return_value=None)

        with patch.multiple(
            "app.core.trust_engine",
            _fetch_profile_from_db=MagicMock(return_value=None),
            _upsert_profile_to_db=MagicMock(return_value=None),
            _insert_trust_event_to_db=insert_mock,
        ):
            restore_agent(aid, restore_score=0.75)

        insert_mock.assert_called_once()

    def test_upsert_called_on_restore(self):
        aid = "agent-restore-upsert"
        invalidate_cache(aid)
        upsert_mock = MagicMock(return_value=None)

        with patch.multiple(
            "app.core.trust_engine",
            _fetch_profile_from_db=MagicMock(return_value=None),
            _upsert_profile_to_db=upsert_mock,
            _insert_trust_event_to_db=MagicMock(return_value=None),
        ):
            restore_agent(aid, restore_score=0.75)

        upsert_mock.assert_called_once()

    def test_cache_evicted_after_restore(self):
        aid = "agent-restore-evict"
        invalidate_cache(aid)
        fetch_mock = MagicMock(return_value=None)

        with patch.multiple(
            "app.core.trust_engine",
            _fetch_profile_from_db=fetch_mock,
            _upsert_profile_to_db=MagicMock(return_value=None),
            _insert_trust_event_to_db=MagicMock(return_value=None),
        ):
            get_trust(aid)
            assert fetch_mock.call_count == 1

            restore_agent(aid, restore_score=0.75)
            get_trust(aid)

        assert fetch_mock.call_count == 2

    def test_restore_with_custom_score(self):
        aid = "agent-restore-custom"
        invalidate_cache(aid)

        with patch.multiple(
            "app.core.trust_engine",
            _fetch_profile_from_db=MagicMock(return_value=None),
            _upsert_profile_to_db=MagicMock(return_value=None),
            _insert_trust_event_to_db=MagicMock(return_value=None),
        ):
            result = restore_agent(aid, restore_score=0.50)

        assert round(result.trust_score, 6) == 0.50


# ---------------------------------------------------------------------------
# list_trust_events — patching _persistence_list_trust_events
# ---------------------------------------------------------------------------


class TestListTrustEvents:
    def test_returns_empty_list_when_persistence_raises(self):
        with patch(
            "app.core.trust_engine._persistence_list_trust_events",
            side_effect=Exception("DB unavailable"),
        ):
            result = list_trust_events("agent-list-test")
        assert result == []

    def test_does_not_raise_when_persistence_raises(self):
        with patch(
            "app.core.trust_engine._persistence_list_trust_events",
            side_effect=Exception("DB unavailable"),
        ):
            try:
                list_trust_events("agent-noexc")
            except Exception as e:
                pytest.fail(f"list_trust_events raised: {e}")

    def test_returns_list_from_persistence(self):
        now = "2025-01-01T00:00:00+00:00"
        rows = [
            {
                "event_id": "e1",
                "agent_id": "agent-list-rows",
                "event_type": "anomaly_detected",
                "previous_score": 0.75,
                "new_score": 0.70,
                "delta": -0.05,
                "metadata": {},
                "recorded_at": now,
            }
        ]
        with patch(
            "app.core.trust_engine._persistence_list_trust_events",
            return_value=rows,
        ):
            result = list_trust_events("agent-list-rows")

        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0]["event_id"] == "e1"

    def test_returns_empty_list_when_no_rows(self):
        with patch(
            "app.core.trust_engine._persistence_list_trust_events",
            return_value=[],
        ):
            result = list_trust_events("agent-no-rows")

        assert result == []

    def test_passes_limit_and_offset_to_persistence(self):
        persistence_mock = MagicMock(return_value=[])
        with patch(
            "app.core.trust_engine._persistence_list_trust_events",
            persistence_mock,
        ):
            list_trust_events("agent-pagination", limit=10, offset=20)

        persistence_mock.assert_called_once_with("agent-pagination", limit=10, offset=20)


# ---------------------------------------------------------------------------
# invalidate_cache
# ---------------------------------------------------------------------------


class TestInvalidateCache:
    def test_invalidate_specific_agent_evicts_only_that_agent(self):
        invalidate_cache(None)
        with patch("app.core.trust_engine._fetch_profile_from_db", return_value=None):
            get_trust("agent-a-evict")
            get_trust("agent-b-evict")

        invalidate_cache("agent-a-evict")

        fetch_mock = MagicMock(return_value=None)
        with patch("app.core.trust_engine._fetch_profile_from_db", fetch_mock):
            get_trust("agent-a-evict")
            get_trust("agent-b-evict")

        assert fetch_mock.call_count == 1

    def test_invalidate_none_clears_entire_cache(self):
        invalidate_cache(None)
        with patch("app.core.trust_engine._fetch_profile_from_db", return_value=None):
            get_trust("agent-x-clear")
            get_trust("agent-y-clear")

        invalidate_cache(None)

        stats = trust_stats()
        assert stats["cached_profiles"] == 0


# ---------------------------------------------------------------------------
# trust_stats
# ---------------------------------------------------------------------------


class TestTrustStats:
    def test_returns_required_keys(self):
        stats = trust_stats()
        required = {
            "cached_profiles",
            "cache_ttl_seconds",
            "default_score",
            "score_floor",
            "score_ceiling",
        }
        assert required.issubset(stats.keys())

    def test_values_are_correct_types(self):
        stats = trust_stats()
        assert isinstance(stats["cached_profiles"], int)
        assert isinstance(stats["cache_ttl_seconds"], float)
        assert stats["default_score"] == 0.75
        assert stats["score_floor"] == 0.0
        assert stats["score_ceiling"] == 1.0

    def test_cached_profiles_count_increases_after_get_trust(self):
        invalidate_cache(None)
        before = trust_stats()["cached_profiles"]
        with patch("app.core.trust_engine._fetch_profile_from_db", return_value=None):
            get_trust("agent-stats-count")
        after = trust_stats()["cached_profiles"]
        assert after == before + 1
