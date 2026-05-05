from __future__ import annotations

import json

from services.release_policy_decision_store import ReleasePolicyDecisionStore


def test_record_decision_persists_jsonl_and_returns_decision(tmp_path) -> None:
    result_file = tmp_path / "release-policy-decisions.jsonl"
    store = ReleasePolicyDecisionStore(result_file=result_file, max_recent_decisions=10)

    decision = store.record_decision(
        channel="production",
        allowed=True,
        requested_version="1.0.0",
        minimum_upgrade_from="1.0.0",
        decision_reason="all checks passed",
        actor="pytest",
        metadata={"source": "unit-test"},
    )

    assert result_file.exists()
    assert decision.channel == "production"
    assert decision.allowed is True
    assert decision.actor == "pytest"

    lines = result_file.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1

    payload = json.loads(lines[0])
    assert payload["decision_id"] == decision.decision_id
    assert payload["channel"] == "production"
    assert payload["allowed"] is True
    assert payload["requested_version"] == "1.0.0"
    assert payload["minimum_upgrade_from"] == "1.0.0"
    assert payload["decision_reason"] == "all checks passed"
    assert payload["actor"] == "pytest"
    assert payload["metadata"]["source"] == "unit-test"


def test_list_recent_returns_only_bounded_latest_entries(tmp_path) -> None:
    result_file = tmp_path / "release-policy-decisions.jsonl"
    store = ReleasePolicyDecisionStore(result_file=result_file, max_recent_decisions=3)

    store.record_decision(
        channel="dev",
        allowed=True,
        requested_version="1.0.0-dev",
        minimum_upgrade_from="1.0.0",
        decision_reason="dev allowed",
        actor="pytest",
    )
    store.record_decision(
        channel="staging",
        allowed=True,
        requested_version="1.0.0-rc1",
        minimum_upgrade_from="1.0.0",
        decision_reason="staging allowed",
        actor="pytest",
    )
    store.record_decision(
        channel="production",
        allowed=False,
        requested_version="1.0.0",
        minimum_upgrade_from="1.0.0",
        decision_reason="manual approval required",
        actor="pytest",
    )
    store.record_decision(
        channel="production",
        allowed=True,
        requested_version="1.0.1",
        minimum_upgrade_from="1.0.0",
        decision_reason="approval granted",
        actor="pytest",
    )

    recent = store.list_recent(limit=10)

    assert len(recent) == 3
    assert [item.channel for item in recent] == ["staging", "production", "production"]
    assert recent[-1].requested_version == "1.0.1"
    assert recent[-1].allowed is True


def test_load_from_disk_returns_recent_decisions(tmp_path) -> None:
    result_file = tmp_path / "release-policy-decisions.jsonl"
    store = ReleasePolicyDecisionStore(result_file=result_file, max_recent_decisions=5)

    store.record_decision(
        channel="dev",
        allowed=True,
        requested_version="1.0.0-dev",
        minimum_upgrade_from="1.0.0",
        decision_reason="dev ok",
        actor="pytest",
    )
    store.record_decision(
        channel="production",
        allowed=False,
        requested_version="1.0.0",
        minimum_upgrade_from="1.0.0",
        decision_reason="blocked pending review",
        actor="pytest",
        metadata={"ticket": "RC-42"},
    )

    loaded = store.load_from_disk(limit=2)

    assert len(loaded) == 2
    assert loaded[0].channel == "dev"
    assert loaded[1].channel == "production"
    assert loaded[1].allowed is False
    assert loaded[1].metadata["ticket"] == "RC-42"


def test_load_from_disk_returns_empty_when_file_missing(tmp_path) -> None:
    result_file = tmp_path / "missing-release-policy-decisions.jsonl"
    store = ReleasePolicyDecisionStore(result_file=result_file)

    assert store.load_from_disk(limit=5) == []