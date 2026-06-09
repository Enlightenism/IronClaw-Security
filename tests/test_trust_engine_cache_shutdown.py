from __future__ import annotations

import threading
import time
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

import app.core.trust_engine as trust_engine_mod
from app.core.trust_engine import (
    TrustProfile,
    invalidate_all_cache,
)
from app.main import _shutdown_trust_engine_cache

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_fake_profile(agent_id: str = "agent-test") -> TrustProfile:
    now = "2026-01-01T00:00:00+00:00"
    return TrustProfile(
        agent_id=agent_id,
        trust_score=0.75,
        event_count=0,
        last_event_type=None,
        last_event_at=None,
        created_at=now,
        updated_at=now,
        is_suspended=False,
        suspension_reason=None,
        metadata={},
    )


def _seed_cache(*agent_ids: str) -> None:
    """Seed _profile_cache with fake entries (bypasses TTL for test isolation)."""
    with trust_engine_mod._lock:
        for agent_id in agent_ids:
            trust_engine_mod._profile_cache[agent_id] = (
                _make_fake_profile(agent_id),
                time.monotonic() + 60.0,
            )


def _clear_cache() -> None:
    with trust_engine_mod._lock:
        trust_engine_mod._profile_cache.clear()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def clean_cache():
    """Guarantee an empty cache before and after every test."""
    _clear_cache()
    yield
    _clear_cache()


# ---------------------------------------------------------------------------
# TestTrustEngineCacheShutdown
# ---------------------------------------------------------------------------


class TestTrustEngineCacheShutdown:
    def test_invalidate_all_cache_preferred_over_direct_clear(self) -> None:
        """
        _shutdown_trust_engine_cache() must resolve and call invalidate_all_cache
        via _optional_attr. The private-dict fallback path must NOT be taken.
        """
        _seed_cache("agent-alpha", "agent-beta")

        called_with_module: list[str] = []
        called_with_attr: list[str] = []

        mock_invalidate = MagicMock()

        with patch.object(trust_engine_mod, "invalidate_all_cache", mock_invalidate):
            import app.main as main_mod  # noqa: PLC0415

            real_optional_attr = main_mod._optional_attr

            def recording_optional_attr(module_path: str, attr_name: str) -> Any:
                called_with_module.append(module_path)
                called_with_attr.append(attr_name)
                return real_optional_attr(module_path, attr_name)

            with patch.object(main_mod, "_optional_attr", side_effect=recording_optional_attr):
                _shutdown_trust_engine_cache()

        assert "app.core.trust_engine" in called_with_module
        assert "invalidate_all_cache" in called_with_attr

        mock_invalidate.assert_called_once()
        assert mock_invalidate.call_count == 1

    def test_invalidate_all_cache_clears_cache(self) -> None:
        """
        invalidate_all_cache() must clear _profile_cache entirely.
        """
        _seed_cache("agent-1", "agent-2", "agent-3")

        with trust_engine_mod._lock:
            assert len(trust_engine_mod._profile_cache) == 3

        invalidate_all_cache()

        with trust_engine_mod._lock:
            assert len(trust_engine_mod._profile_cache) == 0

    def test_invalidate_all_cache_thread_safe(self) -> None:
        """
        Concurrent writers seeding the cache must not cause exceptions when
        invalidate_all_cache() is called from the main thread concurrently.
        """
        exceptions: list[Exception] = []
        stop_event = threading.Event()

        def writer(agent_prefix: str) -> None:
            idx = 0
            while not stop_event.is_set():
                agent_id = f"{agent_prefix}-{idx}"
                try:
                    with trust_engine_mod._lock:
                        trust_engine_mod._profile_cache[agent_id] = (
                            _make_fake_profile(agent_id),
                            time.monotonic() + 60.0,
                        )
                except Exception as exc:  # noqa: BLE001
                    exceptions.append(exc)
                idx += 1
                time.sleep(0.0001)

        threads = [threading.Thread(target=writer, args=(f"writer-{i}",), daemon=True) for i in range(4)]
        for t in threads:
            t.start()

        time.sleep(0.05)

        try:
            invalidate_all_cache()
        except Exception as exc:  # noqa: BLE001
            exceptions.append(exc)
        finally:
            stop_event.set()
            for t in threads:
                t.join(timeout=2.0)

        assert exceptions == [], f"Thread-safety violations: {exceptions}"

        with trust_engine_mod._lock:
            assert isinstance(trust_engine_mod._profile_cache, dict)

    def test_invalidate_all_cache_in_all_exports(self) -> None:
        """
        invalidate_all_cache must be declared in app.core.trust_engine.__all__
        so it is part of the stable public surface.
        """
        assert hasattr(trust_engine_mod, "__all__"), "app.core.trust_engine must define __all__"
        assert "invalidate_all_cache" in trust_engine_mod.__all__, "invalidate_all_cache must be present in app.core.trust_engine.__all__"
