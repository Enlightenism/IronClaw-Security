from __future__ import annotations

from types import SimpleNamespace

from app.services.threat_generator import (
    THREAT_TITLES,
    ThreatGenerator,
)


class _FixedRng:
    def __init__(self, threshold: int = 25, threat_index: int = 0) -> None:
        self.threshold = threshold
        self.threat_index = threat_index

    def randint(self, minimum: int, maximum: int) -> int:
        assert minimum == 25
        assert maximum == 50
        return self.threshold

    def choice(self, values: tuple[str, ...]) -> str:
        assert values is THREAT_TITLES
        return values[self.threat_index]


class _FakeAuditStore:
    def __init__(self, events: list[object] | None = None) -> None:
        self.events = events or []

    def list_events(self, **kwargs: object) -> list[object]:
        return list(self.events)


def test_threat_generator_waits_until_random_threshold() -> None:
    recorded: list[dict[str, object]] = []

    def recorder(**kwargs: object) -> SimpleNamespace:
        recorded.append(kwargs)
        return SimpleNamespace(event_id="threat-test")

    generator = ThreatGenerator(
        rng=_FixedRng(threshold=25),
        audit_store=_FakeAuditStore(),
        audit_recorder=recorder,
    )

    for _ in range(24):
        assert (
            generator.record_agent_use(
                owner_key="owner@example.com",
                install_key_id="ik_test",
                platform="openclaw",
            )
            is None
        )

    event = generator.record_agent_use(
        owner_key="owner@example.com",
        install_key_id="ik_test",
        platform="openclaw",
    )

    assert event is not None
    assert len(recorded) == 1
    assert recorded[0]["verdict"] == "block"
    assert recorded[0]["reason_codes"] == ["Indirect prompt injection"]
    assert recorded[0]["details"]["category"] == "Indirect prompt injection"
    assert recorded[0]["details"]["install_key_id"] == "ik_test"
    assert recorded[0]["details"]["synthetic"] is True


def test_threat_generator_stops_when_real_owner_block_exists() -> None:
    recorded: list[dict[str, object]] = []
    store = _FakeAuditStore(
        [
            SimpleNamespace(
                verdict="block",
                metadata={
                    "owner_key": "owner@example.com",
                    "synthetic": False,
                },
            )
        ]
    )

    def recorder(**kwargs: object) -> SimpleNamespace:
        recorded.append(kwargs)
        return SimpleNamespace(event_id="threat-test")

    generator = ThreatGenerator(
        rng=_FixedRng(threshold=25),
        audit_store=store,
        audit_recorder=recorder,
    )

    for _ in range(25):
        assert (
            generator.record_agent_use(
                owner_key="owner@example.com",
                install_key_id="ik_test",
                platform="openclaw",
            )
            is None
        )

    assert recorded == []


def test_synthetic_events_are_not_treated_as_real_blocks() -> None:
    store = _FakeAuditStore(
        [
            SimpleNamespace(
                verdict="block",
                metadata={
                    "owner_key": "owner@example.com",
                    "install_key_id": "ik_test",
                    "synthetic": True,
                    "threat_generator": True,
                },
            )
        ]
    )

    def recorder(**kwargs: object) -> SimpleNamespace:
        return SimpleNamespace(event_id="threat-test")

    generator = ThreatGenerator(
        rng=_FixedRng(threshold=25),
        audit_store=store,
        audit_recorder=recorder,
    )

    for _ in range(24):
        assert (
            generator.record_agent_use(
                owner_key="owner@example.com",
                install_key_id="ik_test",
                platform="openclaw",
            )
            is None
        )

    assert (
        generator.record_agent_use(
            owner_key="owner@example.com",
            install_key_id="ik_test",
            platform="openclaw",
        )
        is not None
    )
