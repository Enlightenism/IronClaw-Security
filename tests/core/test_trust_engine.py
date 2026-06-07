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
    restore_agent,
    suspend_agent,
    trust_stats,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _noop_upsert(*_a, **_kw) -> None:
    pass


def _noop_insert(*_a, **_kw) -> None:
    pass


def _mock_db_unavailable():
    qb = MagicMock()
    qb.select.return_value = qb
    qb.eq.return_value = qb
    qb.maybe_single.return_value = qb
    qb.order.return_value = qb
    qb.range.return_value = qb
    qb.execute.side_effect = Exception("DB unavailable")

    client = MagicMock()
    client.table.return_value = qb
    return client


def _patched_no_db(agent_id: str | None = None):
    if agent_id is not None:
        invalidate_cache(agent_id)
    else:
        invalidate_cache(None)

    return patch.multiple(
        "app.core.trust_engine",
        _fetch_profile_from_db=MagicMock(return_value=None),
        _upsert_profile_to_db=MagicMock(return_value=None),
        _insert_trust_event_to_db=MagicMock(return_value=None),
    )


# ---------------------------------------------------------------------------
# get_trust
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


class TestGetTrustCache:
    def test_second_call_does_not_hit_db(self):
        invalidate_cache(None)
        fetch_mock = MagicMock(return_value=None)
        with patch("app.core.trust_engine._fetch_profile_from_db", fetch_mock):
            get_trust("agent-cache-test")
            get_trust("agent-cache-test")

        assert fetch_mock.call_count == 1


# ---------------------------------------------------------------------------
# record_event
# ---------------------------------------------------------------------------


class TestRecordEventDecay:
    def test_prompt_injection_reduces_score_by_015(self):
        aid = "agent-injection-test"
        invalidate_cache(aid)
        with _patched_no_db(aid):
            event = record_event(aid, "prompt_injection_attempt")

        assert round(event.delta, 6) == round(-0.15, 6)
        assert round(event.new_score, 6) == round(0.75 - 0.15, 6)

    def test_sandbox_escape_reduces_score_by_020(self):
        aid = "agent-sandbox-test"
        invalidate_cache(aid)
        with _patched_no_db(aid):
            event = record_event(aid, "sandbox_escape_attempt")

        assert round(event.delta, 6) == round(-0.20, 6)
        assert round(event.new_score, 6) == round(0.75 - 0.20, 6)

    def test_sandbox_escape_sets_suspended_on_returned_profile(self):
        aid = "agent-sandbox-suspend"
        invalidate_cache(aid)
        upserted: list[TrustProfile] = []

        def _capture_upsert(p: TrustProfile) -> None:
            upserted.append(p)

        with patch.multiple(
            "app.core.trust_engine",
            _fetch_profile_from_db=MagicMock(return_value=None),
            _upsert_profile_to_db=MagicMock(side_effect=_capture_upsert),
            _insert_trust_event_to_db=MagicMock(return_value=None),
        ):
            record_event(aid, "sandbox_escape_attempt")

        assert upserted, "upsert was never called"
        assert upserted[0].is_suspended is True

    def test_trust_reset_restores_score_to_075(self):
        aid = "agent-reset-test"
        invalidate_cache(aid)
        with _patched_no_db(aid):
            record_event(aid, "prompt_injection_attempt")
            invalidate_cache(aid)
            event = record_event(aid, "trust_reset")

        assert round(event.new_score, 6) == 0.75

    def test_trust_restored_increases_score(self):
        aid = "agent-restored-test"
        invalidate_cache(aid)
        with _patched_no_db(aid):
            record_event(aid, "prompt_injection_attempt")
            invalidate_cache(aid)
            decayed = TrustProfile(
                agent_id=aid,
                trust_score=0.60,
                event_count=1,
                last_event_type="prompt_injection_attempt",
                last_event_at=None,
                created_at="",
                updated_at="",
                is_suspended=False,
                suspension_reason=None,
                metadata={},
            )
            with patch("app.core.trust_engine.get_trust", return_value=decayed):
                event = record_event(aid, "trust_restored")

        assert event.new_score > event.previous_score

    def test_manual_adjustment_negative_030(self):
        aid = "agent-manual-test"
        invalidate_cache(aid)
        with _patched_no_db(aid):
            event = record_event(aid, "manual_adjustment", metadata={"adjustment": -0.30})

        assert round(event.delta, 6) == round(-0.30, 6)
        assert round(event.new_score, 6) == round(0.75 - 0.30, 6)


class TestRecordEventValidation:
    def test_empty_agent_id_raises_value_error(self):
        with pytest.raises(ValueError, match="agent_id"):
            record_event("", "anomaly_detected")

    def test_blank_agent_id_raises_value_error(self):
        with pytest.raises(ValueError, match="agent_id"):
            record_event("   ", "anomaly_detected")


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
# Auto-suspension threshold
# ---------------------------------------------------------------------------


class TestAutoSuspensionThreshold:
    def test_score_at_or_below_010_triggers_suspension(self):
        aid = "agent-autosuspend"
        invalidate_cache(aid)
        upserted: list[TrustProfile] = []

        def _capture(p: TrustProfile) -> None:
            upserted.append(p)

        low_score_profile = TrustProfile(
            agent_id=aid,
            trust_score=0.12,
            event_count=5,
            last_event_type="anomaly_detected",
            last_event_at=None,
            created_at="",
            updated_at="",
            is_suspended=False,
            suspension_reason=None,
            metadata={},
        )

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


# ---------------------------------------------------------------------------
# list_trust_events
# ---------------------------------------------------------------------------


class TestListTrustEvents:
    def test_returns_empty_list_when_db_unavailable(self):
        with patch("app.core.trust_engine._get_client", return_value=_mock_db_unavailable()):
            result = list_trust_events("agent-list-test")

        assert result == []

    def test_does_not_raise_when_db_unavailable(self):
        with patch("app.core.trust_engine._get_client", return_value=_mock_db_unavailable()):
            try:
                list_trust_events("agent-noexc")
            except Exception as e:
                pytest.fail(f"list_trust_events raised: {e}")


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
