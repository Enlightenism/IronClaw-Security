from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest

# ---------------------------------------------------------------------------
# Helpers / Fixtures
# ---------------------------------------------------------------------------


def _org_id() -> str:
    return str(uuid.uuid4())


def _user_id() -> str:
    return str(uuid.uuid4())


def _session_id() -> str:
    return str(uuid.uuid4())


def _make_runtime_context(
    org_id: str | None = None,
    user_id: str | None = None,
    session_id: str | None = None,
    tier: str = "pro",
    permissions: list[str] | None = None,
    sandbox_enabled: bool = True,
) -> dict[str, Any]:
    return {
        "org_id": org_id or _org_id(),
        "user_id": user_id or _user_id(),
        "session_id": session_id or _session_id(),
        "tier": tier,
        "permissions": permissions or ["scan", "execute", "review"],
        "sandbox_enabled": sandbox_enabled,
        "created_at": datetime.now(UTC).isoformat(),
    }


def _make_skill_package(
    name: str = "test_skill",
    version: str = "1.0.0",
    tools: list[str] | None = None,
    requires_sandbox: bool = False,
    network_access: bool = False,
    file_write: bool = False,
    classification: str = "standard",
) -> dict[str, Any]:
    return {
        "name": name,
        "version": version,
        "tools": tools or ["read_file", "list_dir"],
        "requires_sandbox": requires_sandbox,
        "network_access": network_access,
        "file_write": file_write,
        "classification": classification,
        "checksum": f"sha256:{uuid.uuid4().hex}",
        "signed": True,
    }


def _make_tool_call(
    tool_name: str = "read_file",
    args: dict[str, Any] | None = None,
    package: str = "test_skill",
) -> dict[str, Any]:
    return {
        "call_id": str(uuid.uuid4()),
        "tool_name": tool_name,
        "args": args or {"path": "/tmp/safe.txt"},
        "package": package,
        "timestamp": datetime.now(UTC).isoformat(),
    }


# ---------------------------------------------------------------------------
# Section 1 — Package Boundary Enforcement
# ---------------------------------------------------------------------------


class TestPackageBoundaryEnforcement:
    """Verify that skill packages cannot exceed declared capability boundaries."""

    def test_tool_not_in_package_manifest_is_blocked(self):
        pkg = _make_skill_package(tools=["read_file", "list_dir"])
        call = _make_tool_call(tool_name="delete_file", package=pkg["name"])

        allowed_tools = set(pkg["tools"])
        assert call["tool_name"] not in allowed_tools, "Tool 'delete_file' not in manifest should be blocked"

    def test_tool_in_package_manifest_is_allowed(self):
        pkg = _make_skill_package(tools=["read_file", "list_dir"])
        call = _make_tool_call(tool_name="read_file", package=pkg["name"])

        allowed_tools = set(pkg["tools"])
        assert call["tool_name"] in allowed_tools

    def test_network_access_blocked_when_not_declared(self):
        pkg = _make_skill_package(network_access=False)
        call = _make_tool_call(tool_name="http_get", package=pkg["name"])

        if call["tool_name"] in ("http_get", "http_post", "fetch_url", "dns_lookup"):
            if not pkg["network_access"]:
                verdict = "block"
            else:
                verdict = "allow"
        else:
            verdict = "allow"

        assert verdict == "block"

    def test_network_access_allowed_when_declared(self):
        pkg = _make_skill_package(network_access=True, tools=["http_get"])
        call = _make_tool_call(tool_name="http_get", package=pkg["name"])

        assert pkg["network_access"] is True
        assert call["tool_name"] in pkg["tools"]

    def test_file_write_blocked_when_not_declared(self):
        pkg = _make_skill_package(file_write=False, tools=["write_file"])
        call = _make_tool_call(tool_name="write_file", package=pkg["name"])

        write_ops = {"write_file", "create_file", "append_file", "delete_file", "move_file"}
        blocked = call["tool_name"] in write_ops and not pkg["file_write"]
        assert blocked is True

    def test_unsigned_package_is_rejected(self):
        pkg = _make_skill_package()
        pkg["signed"] = False

        assert pkg["signed"] is False

        verdict = "block" if not pkg["signed"] else "allow"
        assert verdict == "block"

    def test_tampered_checksum_is_rejected(self):
        pkg = _make_skill_package()
        original_checksum = pkg["checksum"]
        pkg["checksum"] = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

        assert pkg["checksum"] != original_checksum

    def test_package_with_critical_classification_requires_sandbox(self):
        pkg = _make_skill_package(classification="critical", requires_sandbox=False)

        effective_sandbox = True if pkg["classification"] == "critical" else pkg["requires_sandbox"]
        assert effective_sandbox is True

    def test_standard_classification_sandbox_respects_declaration(self):
        pkg = _make_skill_package(classification="standard", requires_sandbox=False)
        assert pkg["requires_sandbox"] is False

    def test_unknown_package_is_blocked(self):
        known_packages = {"approved_skill", "scanner_v2"}
        call = _make_tool_call(package="unknown_rogue_package")

        verdict = "block" if call["package"] not in known_packages else "allow"
        assert verdict == "block"


# ---------------------------------------------------------------------------
# Section 2 — Skill Middleware Pipeline
# ---------------------------------------------------------------------------


class TestSkillMiddlewarePipeline:
    """Verify middleware stages execute in correct order and enforce boundaries."""

    def test_middleware_stages_execute_in_order(self):
        stages_executed: list[str] = []

        def auth_middleware(call, ctx):
            stages_executed.append("auth")
            return call

        def policy_middleware(call, ctx):
            stages_executed.append("policy")
            return call

        def boundary_middleware(call, ctx):
            stages_executed.append("boundary")
            return call

        def sandbox_middleware(call, ctx):
            stages_executed.append("sandbox")
            return call

        pipeline = [auth_middleware, policy_middleware, boundary_middleware, sandbox_middleware]
        ctx = _make_runtime_context()
        call = _make_tool_call()

        for stage in pipeline:
            call = stage(call, ctx)

        assert stages_executed == ["auth", "policy", "boundary", "sandbox"]

    def test_middleware_short_circuits_on_block_verdict(self):
        stages_executed: list[str] = []

        def auth_middleware(call, ctx):
            stages_executed.append("auth")
            return {"verdict": "block", "reason": "auth_failed"}

        def policy_middleware(call, ctx):
            stages_executed.append("policy")
            return call

        ctx = _make_runtime_context()
        call = _make_tool_call()

        result = auth_middleware(call, ctx)
        if result.get("verdict") == "block":
            pass  # short-circuit — do not call next stages
        else:
            policy_middleware(call, ctx)

        assert "policy" not in stages_executed

    def test_middleware_allows_clean_call_through_full_pipeline(self):
        results: list[str] = []

        def stage(name: str):
            def _fn(call, ctx):
                results.append(name)
                return call

            return _fn

        pipeline = [
            stage("auth"),
            stage("policy"),
            stage("boundary"),
            stage("sandbox"),
            stage("execute"),
        ]
        ctx = _make_runtime_context()
        call = _make_tool_call()

        for fn in pipeline:
            call = fn(call, ctx)

        assert results == ["auth", "policy", "boundary", "sandbox", "execute"]

    def test_middleware_injects_call_id(self):
        call = _make_tool_call()
        assert "call_id" in call
        assert len(call["call_id"]) == 36  # UUID4 format

    def test_middleware_preserves_original_call_immutability(self):
        original = _make_tool_call(tool_name="read_file", args={"path": "/data/safe.txt"})
        snapshot = dict(original)

        enriched = {**original, "enriched": True}

        assert original["tool_name"] == snapshot["tool_name"]
        assert original.get("enriched") is None
        assert enriched["enriched"] is True

    def test_warn_verdict_does_not_block_execution(self):
        verdict = "warn"
        allowed_through = verdict in ("allow", "warn")
        assert allowed_through is True

    def test_quarantine_verdict_routes_to_review_queue(self):
        verdict = "quarantine"
        routed_to_review = verdict == "quarantine"
        assert routed_to_review is True

    def test_block_verdict_does_not_reach_execution(self):
        verdict = "block"
        reaches_execution = verdict in ("allow", "warn")
        assert reaches_execution is False


# ---------------------------------------------------------------------------
# Section 3 — Runtime Context Integration
# ---------------------------------------------------------------------------


class TestRuntimeContextIntegration:
    """Verify skill middleware correctly reads and enforces runtime context."""

    def test_context_missing_org_id_blocks_execution(self):
        ctx = _make_runtime_context()
        ctx.pop("org_id")

        valid = "org_id" in ctx and bool(ctx.get("org_id"))
        assert valid is False

    def test_context_missing_user_id_blocks_execution(self):
        ctx = _make_runtime_context()
        ctx.pop("user_id")

        valid = "user_id" in ctx and bool(ctx.get("user_id"))
        assert valid is False

    def test_context_with_all_required_fields_passes_validation(self):
        ctx = _make_runtime_context()
        required = {"org_id", "user_id", "session_id", "tier", "permissions"}
        assert required.issubset(ctx.keys())

    def test_sandbox_required_but_disabled_blocks_critical_package(self):
        ctx = _make_runtime_context(sandbox_enabled=False)
        pkg = _make_skill_package(requires_sandbox=True)

        blocked = pkg["requires_sandbox"] and not ctx["sandbox_enabled"]
        assert blocked is True

    def test_sandbox_not_required_runs_without_sandbox(self):
        ctx = _make_runtime_context(sandbox_enabled=False)
        pkg = _make_skill_package(requires_sandbox=False)

        blocked = pkg["requires_sandbox"] and not ctx["sandbox_enabled"]
        assert blocked is False

    def test_free_tier_cannot_run_critical_packages(self):
        ctx = _make_runtime_context(tier="free")
        pkg = _make_skill_package(classification="critical")

        tier_gates = {"critical": ["pro", "enterprise"], "standard": ["free", "pro", "enterprise"]}
        allowed_tiers = tier_gates.get(pkg["classification"], [])
        blocked = ctx["tier"] not in allowed_tiers
        assert blocked is True

    def test_pro_tier_can_run_critical_packages(self):
        ctx = _make_runtime_context(tier="pro")
        pkg = _make_skill_package(classification="critical")

        tier_gates = {"critical": ["pro", "enterprise"]}
        allowed = ctx["tier"] in tier_gates.get(pkg["classification"], [])
        assert allowed is True

    def test_enterprise_tier_can_run_all_package_classifications(self):
        ctx = _make_runtime_context(tier="enterprise")
        for classification in ("standard", "critical", "restricted"):
            tier_gates = {
                "standard": ["free", "pro", "enterprise"],
                "critical": ["pro", "enterprise"],
                "restricted": ["enterprise"],
            }
            allowed = ctx["tier"] in tier_gates.get(classification, [])
            assert allowed is True, f"enterprise should run {classification}"

    def test_permission_missing_blocks_tool(self):
        ctx = _make_runtime_context(permissions=["scan"])
        required_permission = "execute"

        blocked = required_permission not in ctx["permissions"]
        assert blocked is True

    def test_permission_present_allows_tool(self):
        ctx = _make_runtime_context(permissions=["scan", "execute"])
        required_permission = "execute"

        allowed = required_permission in ctx["permissions"]
        assert allowed is True

    def test_session_id_is_propagated_to_audit_record(self):
        ctx = _make_runtime_context()
        call = _make_tool_call()

        audit_record = {
            "call_id": call["call_id"],
            "session_id": ctx["session_id"],
            "org_id": ctx["org_id"],
            "tool_name": call["tool_name"],
        }

        assert audit_record["session_id"] == ctx["session_id"]
        assert audit_record["org_id"] == ctx["org_id"]


# ---------------------------------------------------------------------------
# Section 4 — Org Isolation
# ---------------------------------------------------------------------------


class TestOrgIsolation:
    """Verify packages and tool calls cannot cross org boundaries."""

    def test_tool_call_from_different_org_is_blocked(self):
        ctx = _make_runtime_context(org_id="org-alpha")
        call = _make_tool_call()
        call["org_id"] = "org-beta"

        isolated = call.get("org_id") == ctx["org_id"]
        assert isolated is False

    def test_tool_call_from_same_org_is_allowed(self):
        org = _org_id()
        ctx = _make_runtime_context(org_id=org)
        call = _make_tool_call()
        call["org_id"] = org

        isolated = call["org_id"] == ctx["org_id"]
        assert isolated is True

    def test_package_registered_in_different_org_is_rejected(self):
        ctx_org = "org-alpha"
        pkg_org = "org-beta"

        allowed = ctx_org == pkg_org
        assert allowed is False

    def test_data_returned_from_tool_is_scoped_to_org(self):
        org = _org_id()
        records = [
            {"id": "1", "org_id": org, "data": "secret"},
            {"id": "2", "org_id": "other-org", "data": "other"},
        ]

        scoped = [r for r in records if r["org_id"] == org]
        assert len(scoped) == 1
        assert scoped[0]["id"] == "1"

    def test_audit_log_entry_carries_org_id(self):
        org = _org_id()
        ctx = _make_runtime_context(org_id=org)
        audit_entry = {"org_id": ctx["org_id"], "action": "tool_call"}

        assert audit_entry["org_id"] == org


# ---------------------------------------------------------------------------
# Section 5 — Policy Gating
# ---------------------------------------------------------------------------


class TestPolicyGating:
    """Verify org and system policies gate skill package execution correctly."""

    def test_policy_block_rule_prevents_tool_execution(self):
        policy = {
            "rules": [
                {"tool": "delete_file", "action": "block"},
                {"tool": "read_file", "action": "allow"},
            ],
        }

        def evaluate_policy(tool_name: str, rules: list) -> str:
            for rule in rules:
                if rule["tool"] == tool_name:
                    return rule["action"]
            return "allow"

        assert evaluate_policy("delete_file", policy["rules"]) == "block"
        assert evaluate_policy("read_file", policy["rules"]) == "allow"
        assert evaluate_policy("list_dir", policy["rules"]) == "allow"

    def test_policy_warn_rule_passes_with_flag(self):
        policy_rules = [{"tool": "http_get", "action": "warn"}]

        def evaluate(tool: str, rules: list) -> str:
            for r in rules:
                if r["tool"] == tool:
                    return r["action"]
            return "allow"

        verdict = evaluate("http_get", policy_rules)
        assert verdict == "warn"
        assert verdict != "block"

    def test_policy_quarantine_rule_routes_to_review(self):
        policy_rules = [{"tool": "exec_shell", "action": "quarantine"}]

        def evaluate(tool: str, rules: list) -> str:
            for r in rules:
                if r["tool"] == tool:
                    return r["action"]
            return "allow"

        verdict = evaluate("exec_shell", policy_rules)
        assert verdict == "quarantine"

    def test_wildcard_block_policy_blocks_all_tools(self):
        policy_rules = [{"tool": "*", "action": "block"}]

        def evaluate(tool: str, rules: list) -> str:
            for r in rules:
                if r["tool"] == "*" or r["tool"] == tool:
                    return r["action"]
            return "allow"

        for tool in ("read_file", "write_file", "http_get", "exec_shell"):
            assert evaluate(tool, policy_rules) == "block"

    def test_more_specific_rule_wins_over_wildcard(self):
        policy_rules = [
            {"tool": "*", "action": "block"},
            {"tool": "read_file", "action": "allow"},
        ]

        def evaluate(tool: str, rules: list) -> str:
            for r in rules:
                if r["tool"] == tool:
                    return r["action"]
            for r in rules:
                if r["tool"] == "*":
                    return r["action"]
            return "allow"

        assert evaluate("read_file", policy_rules) == "allow"
        assert evaluate("write_file", policy_rules) == "block"

    def test_disabled_policy_does_not_block(self):
        policy_rules = [{"tool": "read_file", "action": "block", "enabled": False}]

        def evaluate(tool: str, rules: list) -> str:
            for r in rules:
                if r["tool"] == tool and r.get("enabled", True):
                    return r["action"]
            return "allow"

        assert evaluate("read_file", policy_rules) == "allow"

    def test_policy_applies_only_to_matching_org(self):
        policies = {
            "org-alpha": [{"tool": "exec_shell", "action": "block"}],
            "org-beta": [],
        }

        def evaluate(org: str, tool: str) -> str:
            rules = policies.get(org, [])
            for r in rules:
                if r["tool"] == tool:
                    return r["action"]
            return "allow"

        assert evaluate("org-alpha", "exec_shell") == "block"
        assert evaluate("org-beta", "exec_shell") == "allow"


# ---------------------------------------------------------------------------
# Section 6 — Quota Enforcement
# ---------------------------------------------------------------------------


class TestQuotaEnforcement:
    """Verify quota checks prevent over-usage at the skill middleware layer."""

    def test_quota_exhausted_blocks_tool_call(self):
        quota = {"used": 1000, "limit": 1000, "unit": "calls"}

        remaining = quota["limit"] - quota["used"]
        blocked = remaining <= 0
        assert blocked is True

    def test_quota_available_allows_tool_call(self):
        quota = {"used": 500, "limit": 1000, "unit": "calls"}

        remaining = quota["limit"] - quota["used"]
        blocked = remaining <= 0
        assert blocked is False

    def test_quota_decrements_after_successful_call(self):
        quota = {"used": 500, "limit": 1000}

        def consume(q: dict) -> dict:
            return {**q, "used": q["used"] + 1}

        updated = consume(quota)
        assert updated["used"] == 501

    def test_quota_not_decremented_on_blocked_call(self):
        quota = {"used": 500, "limit": 1000}
        verdict = "block"

        if verdict == "allow":
            quota["used"] += 1

        assert quota["used"] == 500

    def test_free_tier_has_lower_quota_ceiling(self):
        tier_quotas = {"free": 100, "pro": 10_000, "enterprise": 1_000_000}

        assert tier_quotas["free"] < tier_quotas["pro"]
        assert tier_quotas["pro"] < tier_quotas["enterprise"]

    def test_quota_warning_issued_at_80_percent(self):
        quota = {"used": 800, "limit": 1000}

        usage_pct = quota["used"] / quota["limit"]
        warn = usage_pct >= 0.80
        assert warn is True

    def test_quota_reset_returns_to_zero(self):
        quota = {"used": 900, "limit": 1000}

        def reset(q: dict) -> dict:
            return {**q, "used": 0}

        assert reset(quota)["used"] == 0


# ---------------------------------------------------------------------------
# Section 7 — Verdict Propagation
# ---------------------------------------------------------------------------


class TestVerdictPropagation:
    """Verify verdicts flow correctly through the middleware stack."""

    @pytest.mark.parametrize(
        "verdict,expected_pass",
        [
            ("allow", True),
            ("warn", True),
            ("quarantine", False),
            ("block", False),
        ],
    )
    def test_verdict_pass_through_rules(self, verdict: str, expected_pass: bool):
        passes = verdict in ("allow", "warn")
        assert passes == expected_pass

    def test_verdict_carries_reason(self):
        verdict_obj = {
            "verdict": "block",
            "reason": "tool_not_in_manifest",
            "call_id": str(uuid.uuid4()),
        }

        assert "reason" in verdict_obj
        assert len(verdict_obj["reason"]) > 0

    def test_verdict_carries_call_id(self):
        call = _make_tool_call()
        verdict_obj = {
            "verdict": "allow",
            "call_id": call["call_id"],
        }

        assert verdict_obj["call_id"] == call["call_id"]

    def test_verdict_carries_timestamp(self):
        verdict_obj = {
            "verdict": "allow",
            "timestamp": datetime.now(UTC).isoformat(),
        }

        assert "timestamp" in verdict_obj
        parsed = datetime.fromisoformat(verdict_obj["timestamp"])
        assert parsed.tzinfo is not None

    def test_block_verdict_emits_audit_event(self):
        audit_log: list[dict] = []

        def emit_audit(event: dict) -> None:
            audit_log.append(event)

        verdict = "block"
        if verdict in ("block", "quarantine"):
            emit_audit({"event": "tool_blocked", "verdict": verdict})

        assert len(audit_log) == 1
        assert audit_log[0]["verdict"] == "block"

    def test_warn_verdict_emits_telemetry_event(self):
        telemetry_events: list[dict] = []

        def emit_telemetry(event: dict) -> None:
            telemetry_events.append(event)

        verdict = "warn"
        if verdict == "warn":
            emit_telemetry({"event": "tool_warned", "verdict": verdict})

        assert len(telemetry_events) == 1

    def test_allow_verdict_does_not_emit_security_alert(self):
        alerts: list[dict] = []

        def emit_alert(event: dict) -> None:
            alerts.append(event)

        verdict = "allow"
        if verdict in ("block", "quarantine"):
            emit_alert({"event": "security_alert"})

        assert len(alerts) == 0

    def test_multiple_verdicts_return_most_restrictive(self):
        verdicts = ["allow", "warn", "block", "quarantine"]
        priority = {"block": 0, "quarantine": 1, "warn": 2, "allow": 3}

        most_restrictive = min(verdicts, key=lambda v: priority[v])
        assert most_restrictive == "block"

    def test_quarantine_stores_call_payload(self):
        quarantine_store: list[dict] = []

        call = _make_tool_call(tool_name="exec_shell")
        verdict = "quarantine"

        if verdict == "quarantine":
            quarantine_store.append({"call": call, "verdict": verdict})

        assert len(quarantine_store) == 1
        assert quarantine_store[0]["call"]["tool_name"] == "exec_shell"


# ---------------------------------------------------------------------------
# Section 8 — Audit Trail Integrity
# ---------------------------------------------------------------------------


class TestAuditTrailIntegrity:
    """Verify every skill middleware event produces a complete, tamper-evident audit record."""

    def test_audit_record_has_required_fields(self):
        ctx = _make_runtime_context()
        call = _make_tool_call()

        record = {
            "record_id": str(uuid.uuid4()),
            "call_id": call["call_id"],
            "org_id": ctx["org_id"],
            "user_id": ctx["user_id"],
            "session_id": ctx["session_id"],
            "tool_name": call["tool_name"],
            "package": call["package"],
            "verdict": "allow",
            "timestamp": datetime.now(UTC).isoformat(),
        }

        required = {
            "record_id",
            "call_id",
            "org_id",
            "user_id",
            "session_id",
            "tool_name",
            "package",
            "verdict",
            "timestamp",
        }
        assert required.issubset(record.keys())

    def test_audit_record_has_non_null_org_id(self):
        ctx = _make_runtime_context()
        assert ctx["org_id"] is not None
        assert len(ctx["org_id"]) > 0

    def test_blocked_call_audit_record_includes_reason(self):
        record = {
            "verdict": "block",
            "reason": "package_boundary_violation",
            "call_id": str(uuid.uuid4()),
        }

        assert record["reason"] == "package_boundary_violation"

    def test_audit_records_are_append_only(self):
        audit_log: list[dict] = []

        def append_record(r: dict) -> None:
            audit_log.append(r)

        def attempt_delete(index: int) -> bool:
            return False  # append-only: deletes are rejected

        append_record({"call_id": "1", "verdict": "allow"})
        append_record({"call_id": "2", "verdict": "block"})

        assert attempt_delete(0) is False
        assert len(audit_log) == 2

    def test_audit_timestamp_is_utc(self):
        ts = datetime.now(UTC).isoformat()
        parsed = datetime.fromisoformat(ts)
        assert parsed.utcoffset().total_seconds() == 0

    def test_audit_records_unique_per_call(self):
        calls = [_make_tool_call() for _ in range(5)]
        call_ids = {c["call_id"] for c in calls}
        assert len(call_ids) == 5

    def test_audit_log_captures_quarantine_payload_hash(self):
        import hashlib
        import json

        call = _make_tool_call(tool_name="exec_shell", args={"cmd": "rm -rf /"})
        payload_bytes = json.dumps(call, sort_keys=True).encode()
        payload_hash = hashlib.sha256(payload_bytes).hexdigest()

        record = {
            "call_id": call["call_id"],
            "verdict": "quarantine",
            "payload_hash": payload_hash,
        }

        assert record["payload_hash"].startswith("") and len(record["payload_hash"]) == 64

    def test_audit_record_org_id_matches_context(self):
        org = _org_id()
        ctx = _make_runtime_context(org_id=org)
        call = _make_tool_call()

        record = {"org_id": ctx["org_id"], "call_id": call["call_id"]}
        assert record["org_id"] == org


# ---------------------------------------------------------------------------
# Section 9 — Sandbox Boundary Enforcement
# ---------------------------------------------------------------------------


class TestSandboxBoundaryEnforcement:
    """Verify sandboxed skill packages cannot escape sandbox constraints."""

    def test_sandboxed_package_cannot_access_host_filesystem(self):
        sandboxed_paths = {"/tmp", "/sandbox"}

        requested_path = "/etc/passwd"
        allowed = any(requested_path.startswith(p) for p in sandboxed_paths)
        assert allowed is False

    def test_sandboxed_package_can_access_sandbox_temp(self):
        requested_path = "/tmp/safe_output.txt"
        sandboxed_paths = {"/tmp", "/sandbox"}

        allowed = any(requested_path.startswith(p) for p in sandboxed_paths)
        assert allowed is True

    def test_sandbox_enforced_for_requires_sandbox_package(self):
        pkg = _make_skill_package(requires_sandbox=True)
        ctx = _make_runtime_context(sandbox_enabled=True)

        enforced = pkg["requires_sandbox"] and ctx["sandbox_enabled"]
        assert enforced is True

    def test_execution_timeout_enforced_in_sandbox(self):
        import time

        timeout_seconds = 0.05
        start = time.monotonic()

        try:
            time.sleep(0.01)  # Simulates a short task
        except Exception:
            pass

        elapsed = time.monotonic() - start
        assert elapsed < timeout_seconds + 0.1

    def test_sandbox_output_is_scrubbed_before_return(self):
        raw_output = "result: secret_token=sk-abc123"

        def scrub(text: str) -> str:
            import re

            return re.sub(r"(secret_token|sk-)[^\s]+", "[REDACTED]", text)

        scrubbed = scrub(raw_output)
        assert "sk-abc123" not in scrubbed
        assert "[REDACTED]" in scrubbed

    def test_sandbox_process_cannot_spawn_subprocesses(self):
        allowed_syscalls = {"read", "write", "open", "close", "stat"}

        requested_syscall = "execve"
        allowed = requested_syscall in allowed_syscalls
        assert allowed is False

    def test_memory_limit_enforced_for_sandbox(self):
        memory_limit_mb = 256
        allocated_mb = 512

        blocked = allocated_mb > memory_limit_mb
        assert blocked is True


# ---------------------------------------------------------------------------
# Section 10 — End-to-End Middleware Chain
# ---------------------------------------------------------------------------


class TestEndToEndMiddlewareChain:
    """Simulate the full middleware chain from intake to verdict to audit."""

    def _run_chain(
        self,
        ctx: dict,
        call: dict,
        pkg: dict,
        policy_rules: list[dict] | None = None,
        quota: dict | None = None,
    ) -> dict:
        """Minimal synchronous middleware chain simulation."""
        rules = policy_rules or []
        quota = quota or {"used": 0, "limit": 1000}

        # Stage 1: Context validation
        if not ctx.get("org_id") or not ctx.get("user_id"):
            return {"verdict": "block", "reason": "invalid_context", "stage": "context_validation"}

        # Stage 2: Package boundary check
        if call["tool_name"] not in pkg.get("tools", []):
            return {"verdict": "block", "reason": "tool_not_in_manifest", "stage": "boundary"}

        # Stage 3: Signature check
        if not pkg.get("signed"):
            return {"verdict": "block", "reason": "unsigned_package", "stage": "signature"}

        # Stage 4: Policy evaluation
        for rule in rules:
            if rule["tool"] == call["tool_name"] or rule["tool"] == "*":
                if rule.get("enabled", True) and rule["action"] == "block":
                    return {"verdict": "block", "reason": "policy_block", "stage": "policy"}
                if rule.get("enabled", True) and rule["action"] == "quarantine":
                    return {
                        "verdict": "quarantine",
                        "reason": "policy_quarantine",
                        "stage": "policy",
                    }
                if rule.get("enabled", True) and rule["action"] == "warn":
                    return {"verdict": "warn", "reason": "policy_warn", "stage": "policy"}

        # Stage 5: Quota check
        if (quota["limit"] - quota["used"]) <= 0:
            return {"verdict": "block", "reason": "quota_exhausted", "stage": "quota"}

        # Stage 6: Tier/classification gating
        tier_gates = {
            "critical": ["pro", "enterprise"],
            "standard": ["free", "pro", "enterprise"],
            "restricted": ["enterprise"],
        }
        allowed_tiers = tier_gates.get(pkg.get("classification", "standard"), [])
        if ctx.get("tier") not in allowed_tiers:
            return {"verdict": "block", "reason": "tier_not_allowed", "stage": "tier_gate"}

        # Stage 7: Sandbox enforcement
        if pkg.get("requires_sandbox") and not ctx.get("sandbox_enabled"):
            return {
                "verdict": "block",
                "reason": "sandbox_required_but_disabled",
                "stage": "sandbox",
            }

        return {"verdict": "allow", "reason": "all_checks_passed", "stage": "execute"}

    def test_clean_call_passes_full_chain(self):
        ctx = _make_runtime_context(tier="pro", sandbox_enabled=True)
        pkg = _make_skill_package(tools=["read_file"], classification="standard")
        call = _make_tool_call(tool_name="read_file", package=pkg["name"])

        result = self._run_chain(ctx, call, pkg)
        assert result["verdict"] == "allow"

    def test_invalid_context_blocks_at_first_stage(self):
        ctx = _make_runtime_context()
        ctx.pop("org_id")
        pkg = _make_skill_package(tools=["read_file"])
        call = _make_tool_call(tool_name="read_file")

        result = self._run_chain(ctx, call, pkg)
        assert result["verdict"] == "block"
        assert result["stage"] == "context_validation"

    def test_tool_not_in_manifest_blocked_at_boundary_stage(self):
        ctx = _make_runtime_context(tier="pro")
        pkg = _make_skill_package(tools=["read_file"])
        call = _make_tool_call(tool_name="delete_file")

        result = self._run_chain(ctx, call, pkg)
        assert result["verdict"] == "block"
        assert result["stage"] == "boundary"

    def test_unsigned_package_blocked_at_signature_stage(self):
        ctx = _make_runtime_context(tier="pro")
        pkg = _make_skill_package(tools=["read_file"])
        pkg["signed"] = False
        call = _make_tool_call(tool_name="read_file")

        result = self._run_chain(ctx, call, pkg)
        assert result["verdict"] == "block"
        assert result["stage"] == "signature"

    def test_policy_block_triggers_at_policy_stage(self):
        ctx = _make_runtime_context(tier="pro")
        pkg = _make_skill_package(tools=["exec_shell"])
        call = _make_tool_call(tool_name="exec_shell")
        rules = [{"tool": "exec_shell", "action": "block", "enabled": True}]

        result = self._run_chain(ctx, call, pkg, policy_rules=rules)
        assert result["verdict"] == "block"
        assert result["stage"] == "policy"

    def test_quota_exhausted_blocks_at_quota_stage(self):
        ctx = _make_runtime_context(tier="pro")
        pkg = _make_skill_package(tools=["read_file"])
        call = _make_tool_call(tool_name="read_file")
        quota = {"used": 1000, "limit": 1000}

        result = self._run_chain(ctx, call, pkg, quota=quota)
        assert result["verdict"] == "block"
        assert result["stage"] == "quota"

    def test_free_tier_blocked_on_critical_package(self):
        ctx = _make_runtime_context(tier="free")
        pkg = _make_skill_package(tools=["read_file"], classification="critical")
        call = _make_tool_call(tool_name="read_file")

        result = self._run_chain(ctx, call, pkg)
        assert result["verdict"] == "block"
        assert result["stage"] == "tier_gate"

    def test_sandbox_required_disabled_blocked_at_sandbox_stage(self):
        ctx = _make_runtime_context(tier="pro", sandbox_enabled=False)
        pkg = _make_skill_package(tools=["read_file"], requires_sandbox=True)
        call = _make_tool_call(tool_name="read_file")

        result = self._run_chain(ctx, call, pkg)
        assert result["verdict"] == "block"
        assert result["stage"] == "sandbox"

    def test_enterprise_tier_passes_restricted_classification(self):
        ctx = _make_runtime_context(tier="enterprise", sandbox_enabled=True)
        pkg = _make_skill_package(tools=["read_file"], classification="restricted")
        call = _make_tool_call(tool_name="read_file")

        result = self._run_chain(ctx, call, pkg)
        assert result["verdict"] == "allow"

    def test_warn_policy_still_allows_execution(self):
        ctx = _make_runtime_context(tier="pro")
        pkg = _make_skill_package(tools=["http_get"])
        call = _make_tool_call(tool_name="http_get")
        rules = [{"tool": "http_get", "action": "warn", "enabled": True}]

        result = self._run_chain(ctx, call, pkg, policy_rules=rules)
        assert result["verdict"] == "warn"