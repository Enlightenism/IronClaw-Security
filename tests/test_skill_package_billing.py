from __future__ import annotations


import json
import os
import threading
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch


import pytest


from ironclaw_skill.billing import (
    BillingContext,
    BillingEvent,
    BillingPolicy,
    BillingResult,
    IronClawBillingError,
    MemoryBillingHook,
    StubBillingHook,
    build_billing_context_from_request_context,
    charge_units,
    create_billing_hook,
    load_billing_policy,
)



# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------



@pytest.fixture()
def stub_policy() -> BillingPolicy:
    return BillingPolicy(provider="stub")



@pytest.fixture()
def memory_policy(tmp_path: Path) -> BillingPolicy:
    return BillingPolicy(
        provider="memory",
        default_balance=100,
        block_on_exhausted=True,
        ledger_path=tmp_path / "ledger.jsonl",
    )



@pytest.fixture()
def memory_hook(memory_policy: BillingPolicy) -> MemoryBillingHook:
    return MemoryBillingHook(memory_policy)



@pytest.fixture()
def stub_hook(stub_policy: BillingPolicy) -> StubBillingHook:
    return StubBillingHook(stub_policy)



# ---------------------------------------------------------------------------
# BillingPolicy.cost_for
# ---------------------------------------------------------------------------



class TestBillingPolicyCostForUnit:
    def test_scan_returns_units_per_scan(self):
        policy = BillingPolicy(units_per_scan=3)
        assert policy.cost_for("scan") == 3

    def test_action_policy_returns_units(self):
        policy = BillingPolicy(units_per_action_policy=2)
        assert policy.cost_for("action_policy") == 2

    def test_action_decision_returns_units(self):
        policy = BillingPolicy(units_per_action_decision=4)
        assert policy.cost_for("action_decision") == 4

    def test_execute_returns_units_per_execute(self):
        policy = BillingPolicy(units_per_execute=5)
        assert policy.cost_for("execute") == 5

    def test_unknown_operation_returns_zero(self):
        policy = BillingPolicy()
        assert policy.cost_for("unknown") == 0

    def test_arbitrary_operation_returns_zero(self):
        policy = BillingPolicy()
        assert policy.cost_for("nonexistent_op") == 0

    def test_operation_is_case_insensitive(self):
        policy = BillingPolicy(units_per_scan=7)
        assert policy.cost_for("SCAN") == 7

    def test_operation_strips_whitespace(self):
        policy = BillingPolicy(units_per_execute=3)
        assert policy.cost_for("  execute  ") == 3



# ---------------------------------------------------------------------------
# load_billing_policy — env resolution
# ---------------------------------------------------------------------------



class TestLoadBillingPolicy:
    def test_defaults_with_no_env(self, monkeypatch: pytest.MonkeyPatch):
        for key in [
            "IRONCLAW_BILLING_PROVIDER",
            "IRONCLAW_UNITS_PER_SCAN",
            "IRONCLAW_UNITS_PER_ACTION_POLICY",
            "IRONCLAW_UNITS_PER_ACTION_DECISION",
            "IRONCLAW_UNITS_PER_EXECUTE",
            "IRONCLAW_BILLING_BLOCK_ON_EXHAUSTED",
            "IRONCLAW_BILLING_DEFAULT_BALANCE",
            "IRONCLAW_BILLING_LEDGER_PATH",
        ]:
            monkeypatch.delenv(key, raising=False)
        policy = load_billing_policy()
        assert policy.provider == "stub"
        assert policy.units_per_scan == 1
        assert policy.units_per_action_policy == 1
        assert policy.units_per_action_decision == 1
        assert policy.units_per_execute == 2
        assert policy.block_on_exhausted is False
        assert policy.default_balance == 0

    def test_provider_memory_from_env(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("IRONCLAW_BILLING_PROVIDER", "memory")
        policy = load_billing_policy()
        assert policy.provider == "memory"

    def test_provider_stub_from_env(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("IRONCLAW_BILLING_PROVIDER", "stub")
        policy = load_billing_policy()
        assert policy.provider == "stub"

    def test_invalid_provider_raises(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("IRONCLAW_BILLING_PROVIDER", "stripe")
        with pytest.raises(IronClawBillingError, match="Unsupported billing provider"):
            load_billing_policy()

    def test_units_per_scan_from_env(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("IRONCLAW_UNITS_PER_SCAN", "5")
        policy = load_billing_policy()
        assert policy.units_per_scan == 5

    def test_units_per_execute_from_env(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("IRONCLAW_UNITS_PER_EXECUTE", "10")
        policy = load_billing_policy()
        assert policy.units_per_execute == 10

    def test_block_on_exhausted_true_from_env(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("IRONCLAW_BILLING_BLOCK_ON_EXHAUSTED", "true")
        policy = load_billing_policy()
        assert policy.block_on_exhausted is True

    def test_block_on_exhausted_false_from_env(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("IRONCLAW_BILLING_BLOCK_ON_EXHAUSTED", "false")
        policy = load_billing_policy()
        assert policy.block_on_exhausted is False

    def test_block_on_exhausted_1_truthy(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("IRONCLAW_BILLING_BLOCK_ON_EXHAUSTED", "1")
        policy = load_billing_policy()
        assert policy.block_on_exhausted is True

    def test_default_balance_from_env(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("IRONCLAW_BILLING_DEFAULT_BALANCE", "500")
        policy = load_billing_policy()
        assert policy.default_balance == 500

    def test_negative_units_raises(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("IRONCLAW_UNITS_PER_SCAN", "-1")
        with pytest.raises(IronClawBillingError):
            load_billing_policy()

    def test_invalid_int_raises(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("IRONCLAW_UNITS_PER_SCAN", "not_a_number")
        with pytest.raises(IronClawBillingError):
            load_billing_policy()

    def test_ledger_path_from_env(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
        ledger = tmp_path / "custom_ledger.jsonl"
        monkeypatch.setenv("IRONCLAW_BILLING_LEDGER_PATH", str(ledger))
        policy = load_billing_policy()
        assert policy.ledger_path == ledger.resolve()



# ---------------------------------------------------------------------------
# StubBillingHook
# ---------------------------------------------------------------------------



class TestStubBillingHook:
    def test_charge_returns_ok_true(self, stub_hook: StubBillingHook):
        result = stub_hook.charge(operation="scan")
        assert result.ok is True

    def test_charge_status_is_noop(self, stub_hook: StubBillingHook):
        result = stub_hook.charge(operation="scan")
        assert result.status == "noop"

    def test_charge_provider_is_stub(self, stub_hook: StubBillingHook):
        result = stub_hook.charge(operation="scan")
        assert result.provider == "stub"

    def test_charge_uses_policy_cost(self, stub_policy: BillingPolicy):
        stub_policy = BillingPolicy(provider="stub", units_per_scan=7)
        hook = StubBillingHook(stub_policy)
        result = hook.charge(operation="scan")
        assert result.units_charged == 7

    def test_charge_overrides_units(self, stub_hook: StubBillingHook):
        result = stub_hook.charge(operation="scan", units=99)
        assert result.units_charged == 99

    def test_charge_negative_units_clamped_to_zero(self, stub_hook: StubBillingHook):
        result = stub_hook.charge(operation="scan", units=-5)
        assert result.units_charged == 0

    def test_charge_balance_before_is_none(self, stub_hook: StubBillingHook):
        result = stub_hook.charge(operation="scan")
        assert result.balance_before is None

    def test_charge_balance_after_is_none(self, stub_hook: StubBillingHook):
        result = stub_hook.charge(operation="scan")
        assert result.balance_after is None

    def test_charge_event_attached(self, stub_hook: StubBillingHook):
        result = stub_hook.charge(operation="scan")
        assert result.event is not None
        assert isinstance(result.event, BillingEvent)

    def test_charge_event_reason_is_stub(self, stub_hook: StubBillingHook):
        result = stub_hook.charge(operation="scan")
        assert result.event is not None
        assert result.event.reason == "stub_billing_provider"

    def test_charge_all_operations(self, stub_hook: StubBillingHook):
        for op in ("scan", "action_policy", "action_decision", "execute", "unknown"):
            result = stub_hook.charge(operation=op)  # type: ignore[arg-type]
            assert result.ok is True

    def test_charge_with_context(self, stub_hook: StubBillingHook):
        ctx = BillingContext(request_id="req-abc", client_id="client-1")
        result = stub_hook.charge(operation="scan", context=ctx)
        assert result.ok is True
        assert result.event is not None
        assert result.event.request_id == "req-abc"

    def test_charge_with_metadata(self, stub_hook: StubBillingHook):
        result = stub_hook.charge(operation="execute", metadata={"source": "test"})
        assert result.event is not None
        assert result.event.metadata == {"source": "test"}

    def test_charge_no_context_request_id_is_none(self, stub_hook: StubBillingHook):
        result = stub_hook.charge(operation="scan")
        assert result.event is not None
        assert result.event.request_id is None

    def test_to_dict_serializable(self, stub_hook: StubBillingHook):
        result = stub_hook.charge(operation="scan")
        payload = result.to_dict()
        assert json.dumps(payload)  # must not raise

    def test_result_reason_is_stub(self, stub_hook: StubBillingHook):
        result = stub_hook.charge(operation="scan")
        assert result.reason == "stub_billing_provider"



# ---------------------------------------------------------------------------
# MemoryBillingHook — accepted path
# ---------------------------------------------------------------------------



class TestMemoryBillingHookAccepted:
    def test_charge_returns_ok_true(self, memory_hook: MemoryBillingHook):
        result = memory_hook.charge(operation="scan")
        assert result.ok is True

    def test_charge_status_is_accepted(self, memory_hook: MemoryBillingHook):
        result = memory_hook.charge(operation="scan")
        assert result.status == "accepted"

    def test_charge_provider_is_memory(self, memory_hook: MemoryBillingHook):
        result = memory_hook.charge(operation="scan")
        assert result.provider == "memory"

    def test_charge_reduces_balance(self, memory_hook: MemoryBillingHook):
        before = memory_hook.balance
        memory_hook.charge(operation="scan")
        assert memory_hook.balance == before - 1

    def test_charge_execute_deducts_two_units(self, memory_hook: MemoryBillingHook):
        before = memory_hook.balance
        memory_hook.charge(operation="execute")
        assert memory_hook.balance == before - 2

    def test_charge_balance_before_and_after_correct(self, memory_hook: MemoryBillingHook):
        before = memory_hook.balance
        result = memory_hook.charge(operation="scan")
        assert result.balance_before == before
        assert result.balance_after == before - 1

    def test_charge_units_override(self, memory_hook: MemoryBillingHook):
        before = memory_hook.balance
        result = memory_hook.charge(operation="scan", units=10)
        assert result.units_charged == 10
        assert memory_hook.balance == before - 10

    def test_charge_negative_units_clamped(self, memory_hook: MemoryBillingHook):
        before = memory_hook.balance
        result = memory_hook.charge(operation="scan", units=-3)
        assert result.units_charged == 0
        assert memory_hook.balance == before

    def test_charge_event_attached(self, memory_hook: MemoryBillingHook):
        result = memory_hook.charge(operation="scan")
        assert result.event is not None

    def test_charge_event_timestamp_positive(self, memory_hook: MemoryBillingHook):
        result = memory_hook.charge(operation="scan")
        assert result.event is not None
        assert result.event.timestamp > 0

    def test_charge_reason_is_none_on_accepted(self, memory_hook: MemoryBillingHook):
        result = memory_hook.charge(operation="scan")
        assert result.reason is None

    def test_charge_with_context_propagates_request_id(self, memory_hook: MemoryBillingHook):
        ctx = BillingContext(request_id="req-999")
        result = memory_hook.charge(operation="scan", context=ctx)
        assert result.event is not None
        assert result.event.request_id == "req-999"

    def test_charge_with_metadata_propagated(self, memory_hook: MemoryBillingHook):
        result = memory_hook.charge(operation="execute", metadata={"tier": "pro"})
        assert result.event is not None
        assert result.event.metadata == {"tier": "pro"}

    def test_consecutive_charges_reduce_balance(self, memory_hook: MemoryBillingHook):
        start = memory_hook.balance
        for _ in range(5):
            memory_hook.charge(operation="scan")
        assert memory_hook.balance == start - 5

    def test_to_dict_json_serializable(self, memory_hook: MemoryBillingHook):
        result = memory_hook.charge(operation="scan")
        assert json.dumps(result.to_dict())



# ---------------------------------------------------------------------------
# MemoryBillingHook — rejected / exhausted path
# ---------------------------------------------------------------------------



class TestMemoryBillingHookRejected:
    def test_charge_rejected_when_exhausted_and_blocking(self, tmp_path: Path):
        policy = BillingPolicy(
            provider="memory",
            default_balance=0,
            block_on_exhausted=True,
            ledger_path=tmp_path / "ledger.jsonl",
        )
        hook = MemoryBillingHook(policy)
        result = hook.charge(operation="scan")
        assert result.ok is False
        assert result.status == "rejected"

    def test_rejected_balance_unchanged(self, tmp_path: Path):
        policy = BillingPolicy(
            provider="memory",
            default_balance=0,
            block_on_exhausted=True,
            ledger_path=tmp_path / "ledger.jsonl",
        )
        hook = MemoryBillingHook(policy)
        hook.charge(operation="scan")
        assert hook.balance == 0

    def test_rejected_units_charged_zero(self, tmp_path: Path):
        policy = BillingPolicy(
            provider="memory",
            default_balance=0,
            block_on_exhausted=True,
            ledger_path=tmp_path / "ledger.jsonl",
        )
        hook = MemoryBillingHook(policy)
        result = hook.charge(operation="scan")
        assert result.units_charged == 0

    def test_rejected_reason_insufficient_units(self, tmp_path: Path):
        policy = BillingPolicy(
            provider="memory",
            default_balance=0,
            block_on_exhausted=True,
            ledger_path=tmp_path / "ledger.jsonl",
        )
        hook = MemoryBillingHook(policy)
        result = hook.charge(operation="scan")
        assert result.reason == "insufficient_units"

    def test_no_block_allows_negative_balance(self, tmp_path: Path):
        policy = BillingPolicy(
            provider="memory",
            default_balance=0,
            block_on_exhausted=False,
            ledger_path=tmp_path / "ledger.jsonl",
        )
        hook = MemoryBillingHook(policy)
        result = hook.charge(operation="scan")
        assert result.ok is True
        assert hook.balance == -1

    def test_partial_balance_insufficient_blocks(self, tmp_path: Path):
        policy = BillingPolicy(
            provider="memory",
            default_balance=1,
            block_on_exhausted=True,
            ledger_path=tmp_path / "ledger.jsonl",
        )
        hook = MemoryBillingHook(policy)
        result = hook.charge(operation="execute")  # costs 2
        assert result.ok is False
        assert hook.balance == 1



# ---------------------------------------------------------------------------
# MemoryBillingHook — reset_balance
# ---------------------------------------------------------------------------



class TestMemoryBillingHookResetBalance:
    def test_reset_sets_balance(self, memory_hook: MemoryBillingHook):
        memory_hook.reset_balance(500)
        assert memory_hook.balance == 500

    def test_reset_to_zero_allowed(self, memory_hook: MemoryBillingHook):
        memory_hook.reset_balance(0)
        assert memory_hook.balance == 0

    def test_reset_negative_raises(self, memory_hook: MemoryBillingHook):
        with pytest.raises(IronClawBillingError, match="reset balance must be >= 0"):
            memory_hook.reset_balance(-1)

    def test_reset_then_charge_uses_new_balance(self, memory_hook: MemoryBillingHook):
        memory_hook.reset_balance(10)
        memory_hook.charge(operation="scan")
        assert memory_hook.balance == 9



# ---------------------------------------------------------------------------
# MemoryBillingHook — ledger persistence
# ---------------------------------------------------------------------------



class TestMemoryBillingHookLedger:
    def test_ledger_file_created_on_charge(self, memory_hook: MemoryBillingHook):
        memory_hook.charge(operation="scan")
        assert memory_hook.ledger_path.exists()

    def test_ledger_line_is_valid_json(self, memory_hook: MemoryBillingHook):
        memory_hook.charge(operation="scan")
        line = memory_hook.ledger_path.read_text(encoding="utf-8").strip().splitlines()[0]
        payload = json.loads(line)
        assert payload["operation"] == "scan"
        assert payload["status"] == "accepted"

    def test_ledger_appends_multiple_entries(self, memory_hook: MemoryBillingHook):
        for op in ("scan", "execute", "action_policy"):
            memory_hook.charge(operation=op)  # type: ignore[arg-type]
        lines = memory_hook.ledger_path.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 3

    def test_ledger_rejected_event_appended(self, tmp_path: Path):
        policy = BillingPolicy(
            provider="memory",
            default_balance=0,
            block_on_exhausted=True,
            ledger_path=tmp_path / "ledger.jsonl",
        )
        hook = MemoryBillingHook(policy)
        hook.charge(operation="scan")
        lines = hook.ledger_path.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 1
        payload = json.loads(lines[0])
        assert payload["status"] == "rejected"

    def test_ledger_entries_contain_timestamp(self, memory_hook: MemoryBillingHook):
        memory_hook.charge(operation="scan")
        line = memory_hook.ledger_path.read_text(encoding="utf-8").strip().splitlines()[0]
        payload = json.loads(line)
        assert payload["timestamp"] > 0

    def test_ledger_parent_dirs_created(self, tmp_path: Path):
        deep_path = tmp_path / "a" / "b" / "c" / "ledger.jsonl"
        policy = BillingPolicy(
            provider="memory",
            default_balance=100,
            ledger_path=deep_path,
        )
        hook = MemoryBillingHook(policy)
        hook.charge(operation="scan")
        assert deep_path.exists()



# ---------------------------------------------------------------------------
# MemoryBillingHook — thread safety
# ---------------------------------------------------------------------------



class TestMemoryBillingHookThreadSafety:
    def test_concurrent_charges_no_race(self, tmp_path: Path):
        policy = BillingPolicy(
            provider="memory",
            default_balance=1000,
            block_on_exhausted=False,
            ledger_path=tmp_path / "ledger.jsonl",
        )
        hook = MemoryBillingHook(policy)
        errors: list[Exception] = []

        def _worker():
            try:
                for _ in range(10):
                    hook.charge(operation="scan")
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=_worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert hook.balance == 1000 - 100



# ---------------------------------------------------------------------------
# create_billing_hook
# ---------------------------------------------------------------------------



class TestCreateBillingHook:
    def test_stub_policy_returns_stub_hook(self):
        policy = BillingPolicy(provider="stub")
        hook = create_billing_hook(policy)
        assert isinstance(hook, StubBillingHook)

    def test_memory_policy_returns_memory_hook(self, tmp_path: Path):
        policy = BillingPolicy(provider="memory", ledger_path=tmp_path / "ledger.jsonl")
        hook = create_billing_hook(policy)
        assert isinstance(hook, MemoryBillingHook)

    def test_unsupported_provider_raises(self):
        policy = BillingPolicy(provider="stub")
        object.__setattr__(policy, "provider", "stripe")
        with pytest.raises(IronClawBillingError, match="Unsupported billing provider"):
            create_billing_hook(policy)

    def test_no_policy_uses_env_defaults(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.delenv("IRONCLAW_BILLING_PROVIDER", raising=False)
        hook = create_billing_hook()
        assert isinstance(hook, StubBillingHook)



# ---------------------------------------------------------------------------
# charge_units — top-level convenience
# ---------------------------------------------------------------------------



class TestChargeUnits:
    def test_uses_provided_hook(self):
        policy = BillingPolicy(provider="stub")
        hook = StubBillingHook(policy)
        result = charge_units(operation="scan", hook=hook)
        assert result.ok is True

    def test_creates_default_hook_when_none(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.delenv("IRONCLAW_BILLING_PROVIDER", raising=False)
        result = charge_units(operation="scan")
        assert result.ok is True

    def test_passes_context_to_hook(self):
        policy = BillingPolicy(provider="stub")
        hook = StubBillingHook(policy)
        ctx = BillingContext(request_id="req-ctx-test")
        result = charge_units(operation="scan", hook=hook, context=ctx)
        assert result.event is not None
        assert result.event.request_id == "req-ctx-test"

    def test_passes_metadata_to_hook(self):
        policy = BillingPolicy(provider="stub")
        hook = StubBillingHook(policy)
        result = charge_units(operation="execute", hook=hook, metadata={"key": "val"})
        assert result.event is not None
        assert result.event.metadata == {"key": "val"}

    def test_passes_units_override_to_hook(self):
        policy = BillingPolicy(provider="stub")
        hook = StubBillingHook(policy)
        result = charge_units(operation="scan", hook=hook, units=42)
        assert result.units_charged == 42

    def test_all_operations_succeed_stub(self):
        policy = BillingPolicy(provider="stub")
        hook = StubBillingHook(policy)
        for op in ("scan", "action_policy", "action_decision", "execute", "unknown"):
            r = charge_units(operation=op, hook=hook)  # type: ignore[arg-type]
            assert r.ok is True



# ---------------------------------------------------------------------------
# build_billing_context_from_request_context
# ---------------------------------------------------------------------------



class TestBuildBillingContextFromRequestContext:
    def _make_ctx(self, **kwargs: Any) -> Any:
        ctx = MagicMock()
        for k, v in kwargs.items():
            setattr(ctx, k, v)
        return ctx

    def test_maps_request_id(self):
        ctx = self._make_ctx(request_id="req-1")
        bc = build_billing_context_from_request_context(ctx)
        assert bc.request_id == "req-1"

    def test_maps_client_id(self):
        ctx = self._make_ctx(client_id="client-abc")
        bc = build_billing_context_from_request_context(ctx)
        assert bc.client_id == "client-abc"

    def test_maps_session_id(self):
        ctx = self._make_ctx(session_id="sess-xyz")
        bc = build_billing_context_from_request_context(ctx)
        assert bc.session_id == "sess-xyz"

    def test_maps_user_id(self):
        ctx = self._make_ctx(user_id="user-99")
        bc = build_billing_context_from_request_context(ctx)
        assert bc.user_id == "user-99"

    def test_maps_tenant_id(self):
        ctx = self._make_ctx(tenant_id="tenant-7")
        bc = build_billing_context_from_request_context(ctx)
        assert bc.tenant_id == "tenant-7"

    def test_maps_source_platform(self):
        ctx = self._make_ctx(source_platform="vscode")
        bc = build_billing_context_from_request_context(ctx)
        assert bc.source_platform == "vscode"

    def test_missing_attr_maps_to_none(self):
        ctx = MagicMock(spec=[])
        bc = build_billing_context_from_request_context(ctx)
        assert bc.request_id is None
        assert bc.client_id is None

    def test_whitespace_only_normalizes_to_none(self):
        ctx = self._make_ctx(request_id="   ", client_id="\t")
        bc = build_billing_context_from_request_context(ctx)
        assert bc.request_id is None
        assert bc.client_id is None

    def test_none_value_maps_to_none(self):
        ctx = self._make_ctx(request_id=None)
        bc = build_billing_context_from_request_context(ctx)
        assert bc.request_id is None

    def test_all_fields_populated(self):
        ctx = self._make_ctx(
            request_id="r1",
            client_id="c1",
            session_id="s1",
            user_id="u1",
            tenant_id="t1",
            source_platform="cli",
        )
        bc = build_billing_context_from_request_context(ctx)
        assert bc.request_id == "r1"
        assert bc.client_id == "c1"
        assert bc.session_id == "s1"
        assert bc.user_id == "u1"
        assert bc.tenant_id == "t1"
        assert bc.source_platform == "cli"

    def test_to_dict_serializable(self):
        ctx = self._make_ctx(request_id="r1", client_id="c1")
        bc = build_billing_context_from_request_context(ctx)
        assert json.dumps(bc.to_dict())



# ---------------------------------------------------------------------------
# BillingContext.to_dict
# ---------------------------------------------------------------------------



class TestBillingContextToDict:
    def test_all_fields_present(self):
        bc = BillingContext(
            request_id="req",
            client_id="cli",
            session_id="ses",
            user_id="usr",
            tenant_id="ten",
            source_platform="api",
        )
        d = bc.to_dict()
        assert d["request_id"] == "req"
        assert d["client_id"] == "cli"
        assert d["session_id"] == "ses"
        assert d["user_id"] == "usr"
        assert d["tenant_id"] == "ten"
        assert d["source_platform"] == "api"

    def test_none_fields_preserved(self):
        bc = BillingContext()
        d = bc.to_dict()
        assert d["request_id"] is None



# ---------------------------------------------------------------------------
# BillingEvent.to_dict
# ---------------------------------------------------------------------------



class TestBillingEventToDict:
    def test_serializable(self):
        hook = StubBillingHook(BillingPolicy(provider="stub"))
        result = hook.charge(operation="scan")
        assert result.event is not None
        assert json.dumps(result.event.to_dict())

    def test_operation_field_present(self):
        hook = StubBillingHook(BillingPolicy(provider="stub"))
        result = hook.charge(operation="execute")
        assert result.event is not None
        assert result.event.to_dict()["operation"] == "execute"



# ---------------------------------------------------------------------------
# BillingResult.to_dict
# ---------------------------------------------------------------------------



class TestBillingResultToDict:
    def test_event_nested_in_dict(self):
        hook = StubBillingHook(BillingPolicy(provider="stub"))
        result = hook.charge(operation="scan")
        d = result.to_dict()
        assert "event" in d
        assert isinstance(d["event"], dict)

    def test_ok_field_present(self):
        hook = StubBillingHook(BillingPolicy(provider="stub"))
        result = hook.charge(operation="scan")
        assert result.to_dict()["ok"] is True

    def test_units_charged_field_present(self):
        hook = StubBillingHook(BillingPolicy(provider="stub", units_per_scan=3))
        result = hook.charge(operation="scan")
        assert result.to_dict()["units_charged"] == 3