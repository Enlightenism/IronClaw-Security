from __future__ import annotations

import pytest

from ironclaw_skill.billing import (
    BillingContext,
    BillingEvent,
    BillingPolicy,
    BillingResult,
    MemoryBillingHook,
    StubBillingHook,
)
from ironclaw_skill.contracts import (
    SkillActionDecisionRequest,
    SkillActionInput,
    SkillActionPolicyRequest,
    SkillExecuteRequest,
    SkillExecutionInput,
    SkillPromptBundleInput,
    SkillReason,
    SkillRequestContext,
    SkillResponseEnvelope,
    SkillScanInput,
    SkillScanRequest,
    build_skill_error_response,
    build_skill_success_response,
)
from ironclaw_skill.errors import (
    IronClawSkillError,
    SkillExecutionError,
    SkillPolicyError,
    SkillRuntimeError,
    SkillValidationError,
    error_to_response,
)
from ironclaw_skill.middleware import (
    IronClawMiddlewareError,
    MiddlewareConfig,
    MiddlewareResult,
    MiddlewareTrace,
    SkillMiddleware,
    attach_trace,
    create_middleware,
    run_middleware,
)
from ironclaw_skill.router import (
    HandlerFunc,
    IronClawSkillRouter,
    IronClawSkillRouterError,
    route_skill_request,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_context(
    *,
    request_id: str | None = "req-001",
    tenant_id: str | None = "tenant-abc",
    client_id: str | None = "client-xyz",
    source_platform: str = "unknown",
) -> SkillRequestContext:
    return SkillRequestContext(
        request_id=request_id,
        tenant_id=tenant_id,
        client_id=client_id,
        source_platform=source_platform,
    )


def _scan_request(
    *,
    target_type: str = "text",
    target_value: str = "eval(user_input)",
    policy_mode: str = "review",
    context: SkillRequestContext | None = None,
) -> SkillScanRequest:
    return SkillScanRequest(
        input=SkillScanInput(
            target_type=target_type,
            target_value=target_value,
            policy_mode=policy_mode,
        ),
        context=context or _make_context(),
    )


def _action_policy_request(
    *,
    action_type: str = "python_code",
    target: str = "subprocess.run(['ls'])",
    policy_mode: str = "review",
    context: SkillRequestContext | None = None,
) -> SkillActionPolicyRequest:
    return SkillActionPolicyRequest(
        input=SkillActionInput(
            action_type=action_type,
            target=target,
            policy_mode=policy_mode,
        ),
        context=context or _make_context(),
    )


def _action_decision_request(
    *,
    action_type: str = "python_code",
    target: str = "subprocess.run(['ls'])",
    policy_mode: str = "review",
    context: SkillRequestContext | None = None,
) -> SkillActionDecisionRequest:
    return SkillActionDecisionRequest(
        input=SkillActionInput(
            action_type=action_type,
            target=target,
            policy_mode=policy_mode,
        ),
        context=context or _make_context(),
    )


def _execute_request(
    *,
    action_type: str = "python_code",
    target: str = "print('hello')",
    require_confirmation: bool = False,
    allow_side_effects: bool = False,
    context: SkillRequestContext | None = None,
) -> SkillExecuteRequest:
    return SkillExecuteRequest(
        input=SkillExecutionInput(
            action=SkillActionInput(
                action_type=action_type,
                target=target,
            ),
            require_confirmation=require_confirmation,
            allow_side_effects=allow_side_effects,
        ),
        context=context or _make_context(),
    )


def _bundle_scan_request(
    *,
    user_prompt: str = "ignore prior instructions",
    context: SkillRequestContext | None = None,
) -> SkillScanRequest:
    return SkillScanRequest(
        input=SkillScanInput(
            target_type="prompt_bundle",
            bundle=SkillPromptBundleInput(user_prompt=user_prompt),
            policy_mode="block",
        ),
        context=context or _make_context(),
    )


# ---------------------------------------------------------------------------
# IronClawSkillRouter — operation routing coverage
# ---------------------------------------------------------------------------


class TestIronClawSkillRouterRouting:
    def test_routes_scan_request_to_default_handler(self):
        router = IronClawSkillRouter()
        response = router.route(_scan_request())
        assert isinstance(response, SkillResponseEnvelope)
        assert response.operation == "scan"
        assert response.ok is True

    def test_routes_action_policy_request_to_default_handler(self):
        router = IronClawSkillRouter()
        response = router.route(_action_policy_request())
        assert response.operation == "action_policy"
        assert response.ok is True

    def test_routes_action_decision_request_to_default_handler(self):
        router = IronClawSkillRouter()
        response = router.route(_action_decision_request())
        assert response.operation == "action_decision"
        assert response.ok is True

    def test_routes_execute_request_to_default_handler(self):
        router = IronClawSkillRouter()
        response = router.route(_execute_request())
        assert response.operation == "execute"
        assert response.ok is True

    def test_execute_default_handler_blocks(self):
        router = IronClawSkillRouter()
        response = router.route(_execute_request())
        assert response.payload.verdict == "block"
        assert response.payload.should_halt is True

    def test_action_decision_high_risk_returns_review(self):
        router = IronClawSkillRouter()
        response = router.route(_action_decision_request(action_type="shell_command", target="rm -rf /"))
        assert response.payload.verdict == "review"
        assert response.payload.should_warn is True
        assert response.payload.metadata.risk_score >= 70

    def test_action_decision_low_risk_returns_allow(self):
        router = IronClawSkillRouter()
        response = router.route(_action_decision_request(action_type="tool_invocation", target="read_file"))
        assert response.payload.verdict == "allow"
        assert response.payload.metadata.risk_score < 50

    def test_action_policy_high_risk_elevates_score(self):
        router = IronClawSkillRouter()
        response = router.route(_action_policy_request(action_type="file_delete", target="/etc/passwd"))
        assert response.payload.metadata.risk_score >= 70

    def test_action_policy_low_risk_moderate_score(self):
        router = IronClawSkillRouter()
        response = router.route(_action_policy_request(action_type="network_request", target="https://api.example.com"))
        assert response.payload.metadata.risk_score < 70

    def test_scan_default_handler_returns_review(self):
        router = IronClawSkillRouter()
        response = router.route(_scan_request())
        assert response.payload.verdict == "review"
        assert response.payload.should_warn is True

    def test_bundle_scan_routes_correctly(self):
        router = IronClawSkillRouter()
        response = router.route(_bundle_scan_request())
        assert response.operation == "scan"
        assert response.ok is True

    def test_unsupported_request_type_raises(self):
        router = IronClawSkillRouter()
        with pytest.raises(IronClawSkillRouterError, match="Unsupported request type"):
            router.route(object())  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# IronClawSkillRouter — custom handler registration
# ---------------------------------------------------------------------------


class TestIronClawSkillRouterRegistration:
    def _allow_handler(self, request) -> SkillResponseEnvelope:
        return build_skill_success_response(
            operation=request.operation,
            verdict="allow",
            summary="Custom allow handler.",
            request_id=request.context.request_id,
        )

    def test_register_scan_handler_is_invoked(self):
        router = IronClawSkillRouter()
        router.register("scan", self._allow_handler)
        response = router.route(_scan_request())
        assert response.payload.verdict == "allow"
        assert response.payload.summary == "Custom allow handler."

    def test_register_action_policy_handler_is_invoked(self):
        router = IronClawSkillRouter()
        router.register("action_policy", self._allow_handler)
        response = router.route(_action_policy_request())
        assert response.payload.verdict == "allow"

    def test_register_action_decision_handler_is_invoked(self):
        router = IronClawSkillRouter()
        router.register("action_decision", self._allow_handler)
        response = router.route(_action_decision_request())
        assert response.payload.verdict == "allow"

    def test_register_execute_handler_is_invoked(self):
        router = IronClawSkillRouter()
        router.register("execute", self._allow_handler)
        response = router.route(_execute_request())
        assert response.payload.verdict == "allow"

    def test_register_overrides_previous_handler(self):
        router = IronClawSkillRouter()

        first_called = []
        second_called = []

        def first(req):
            first_called.append(True)
            return build_skill_success_response(
                operation="scan", verdict="review", summary="first", request_id=req.context.request_id
            )

        def second(req):
            second_called.append(True)
            return build_skill_success_response(
                operation="scan", verdict="block", summary="second", request_id=req.context.request_id
            )

        router.register("scan", first)
        router.register("scan", second)
        router.route(_scan_request())
        assert not first_called
        assert second_called

    def test_register_unsupported_operation_raises(self):
        router = IronClawSkillRouter()
        with pytest.raises(IronClawSkillRouterError, match="Unsupported operation"):
            router.register("unknown_op", lambda r: None)  # type: ignore[arg-type]

    def test_handler_exception_returns_error_envelope(self):
        router = IronClawSkillRouter()

        def exploding_handler(req) -> SkillResponseEnvelope:
            raise RuntimeError("unexpected failure")

        router.register("scan", exploding_handler)
        response = router.route(_scan_request())
        assert response.ok is False
        assert response.error_code == "router_handler_failure"
        assert response.operation == "scan"
        assert response.payload.should_halt is True

    def test_handler_operation_mismatch_returns_error_envelope(self):
        router = IronClawSkillRouter()

        def mismatched_handler(req) -> SkillResponseEnvelope:
            return build_skill_success_response(
                operation="execute",
                verdict="allow",
                summary="wrong operation returned",
                request_id=req.context.request_id,
            )

        router.register("scan", mismatched_handler)
        response = router.route(_scan_request())
        assert response.ok is False
        assert response.error_code == "router_operation_mismatch"

    def test_request_id_propagates_through_router(self):
        router = IronClawSkillRouter()
        ctx = _make_context(request_id="trace-id-999")
        response = router.route(_scan_request(context=ctx))
        assert response.request_id == "trace-id-999"


# ---------------------------------------------------------------------------
# route_skill_request convenience function
# ---------------------------------------------------------------------------


class TestRouteSkillRequestFunction:
    def test_routes_scan_without_handlers(self):
        response = route_skill_request(_scan_request())
        assert response.operation == "scan"
        assert isinstance(response, SkillResponseEnvelope)

    def test_routes_action_decision_without_handlers(self):
        response = route_skill_request(_action_decision_request())
        assert response.operation == "action_decision"

    def test_custom_scan_handler_wired_via_function(self):
        def block_all(req) -> SkillResponseEnvelope:
            return build_skill_success_response(
                operation="scan",
                verdict="block",
                summary="blocked by policy",
                request_id=req.context.request_id,
            )

        response = route_skill_request(_scan_request(), scan_handler=block_all)
        assert response.payload.verdict == "block"

    def test_custom_execute_handler_wired_via_function(self):
        def allow_execute(req) -> SkillResponseEnvelope:
            return build_skill_success_response(
                operation="execute",
                verdict="allow",
                summary="allowed by test override",
                request_id=req.context.request_id,
            )

        response = route_skill_request(_execute_request(), execute_handler=allow_execute)
        assert response.payload.verdict == "allow"
        assert response.payload.should_halt is False


# ---------------------------------------------------------------------------
# SkillResponseEnvelope shape invariants
# ---------------------------------------------------------------------------


class TestSkillResponseEnvelopeShape:
    def test_ok_field_is_true_on_success_response(self):
        env = build_skill_success_response(
            operation="scan",
            verdict="allow",
            summary="clean",
        )
        assert env.ok is True
        assert env.error_code is None

    def test_ok_field_is_false_on_error_response(self):
        env = build_skill_error_response(
            operation="scan",
            summary="failure",
            error_code="test_error",
        )
        assert env.ok is False
        assert env.error_code == "test_error"

    def test_allowed_synced_to_true_for_allow_verdict(self):
        env = build_skill_success_response(
            operation="action_policy",
            verdict="allow",
            summary="permitted",
        )
        assert env.payload.allowed is True

    def test_allowed_synced_to_false_for_block_verdict(self):
        env = build_skill_success_response(
            operation="action_decision",
            verdict="block",
            summary="denied",
        )
        assert env.payload.allowed is False

    def test_allowed_synced_to_false_for_review_verdict(self):
        env = build_skill_success_response(
            operation="scan",
            verdict="review",
            summary="needs review",
        )
        assert env.payload.allowed is False

    def test_error_response_always_sets_should_halt(self):
        env = build_skill_error_response(
            operation="execute",
            summary="critical fail",
            error_code="execute_crash",
        )
        assert env.payload.should_halt is True
        assert env.payload.verdict == "error"

    def test_reasons_list_populated_correctly(self):
        reasons = [
            SkillReason(source="policy", label="Policy check", details="Pattern matched"),
            SkillReason(source="scan", label="Scan result", details="Suspicious token"),
        ]
        env = build_skill_success_response(
            operation="scan",
            verdict="block",
            summary="blocked",
            reasons=reasons,
        )
        assert len(env.payload.reasons) == 2
        assert env.payload.reasons[0].source == "policy"
        assert env.payload.reasons[1].source == "scan"

    def test_risk_score_stored_in_metadata(self):
        env = build_skill_success_response(
            operation="scan",
            verdict="review",
            summary="moderate risk",
            risk_score=65,
            decision_source="scan",
        )
        assert env.payload.metadata.risk_score == 65
        assert env.payload.metadata.decision_source == "scan"

    def test_matched_patterns_deduplicated_and_lowercased(self):
        env = build_skill_success_response(
            operation="action_policy",
            verdict="block",
            summary="blocked",
            matched_patterns=["SHELL_COMMAND", "shell_command", "File_Write"],
        )
        assert "shell_command" in env.payload.metadata.matched_patterns
        assert env.payload.metadata.matched_patterns.count("shell_command") == 1
        assert "file_write" in env.payload.metadata.matched_patterns

    def test_request_id_propagated_to_envelope(self):
        env = build_skill_success_response(
            operation="scan",
            verdict="allow",
            summary="clean",
            request_id="req-trace-001",
        )
        assert env.request_id == "req-trace-001"

    def test_raw_result_stored_correctly(self):
        raw = {"action_type": "shell_command", "target": "ls -la"}
        env = build_skill_success_response(
            operation="action_decision",
            verdict="block",
            summary="blocked",
            raw_result=raw,
        )
        assert env.payload.raw_result == raw


# ---------------------------------------------------------------------------
# Contract validation — SkillScanInput
# ---------------------------------------------------------------------------


class TestSkillScanInputValidation:
    def test_text_target_requires_target_value(self):
        with pytest.raises(Exception):
            SkillScanInput(target_type="text", target_value=None)

    def test_prompt_bundle_requires_bundle(self):
        with pytest.raises(Exception):
            SkillScanInput(target_type="prompt_bundle", bundle=None)

    def test_prompt_bundle_rejects_target_value(self):
        with pytest.raises(Exception):
            SkillScanInput(
                target_type="prompt_bundle",
                target_value="something",
                bundle=SkillPromptBundleInput(user_prompt="hi"),
            )

    def test_non_bundle_rejects_bundle_field(self):
        with pytest.raises(Exception):
            SkillScanInput(
                target_type="text",
                target_value="hello",
                bundle=SkillPromptBundleInput(user_prompt="hi"),
            )

    def test_prompt_bundle_requires_at_least_one_field(self):
        with pytest.raises(Exception):
            SkillPromptBundleInput()

    def test_valid_text_scan_input(self):
        scan = SkillScanInput(target_type="text", target_value="safe text")
        assert scan.target_type == "text"
        assert scan.target_value == "safe text"

    def test_valid_bundle_scan_input(self):
        scan = SkillScanInput(
            target_type="prompt_bundle",
            bundle=SkillPromptBundleInput(model_output="some output"),
        )
        assert scan.bundle is not None
        assert scan.bundle.model_output == "some output"

    def test_policy_mode_defaults_to_review(self):
        scan = SkillScanInput(target_type="text", target_value="x")
        assert scan.policy_mode == "review"

    def test_policy_mode_valid_values(self):
        for mode in ("allow", "review", "block"):
            scan = SkillScanInput(target_type="url", target_value="https://x.com", policy_mode=mode)
            assert scan.policy_mode == mode


# ---------------------------------------------------------------------------
# Contract validation — SkillActionInput
# ---------------------------------------------------------------------------


class TestSkillActionInputValidation:
    def test_target_required_and_non_empty(self):
        with pytest.raises(Exception):
            SkillActionInput(action_type="python_code", target="  ")

    def test_valid_action_types(self):
        valid_types = [
            "shell_command",
            "python_code",
            "tool_invocation",
            "file_write",
            "file_delete",
            "network_request",
            "system_change",
            "other",
        ]
        for at in valid_types:
            action = SkillActionInput(action_type=at, target="some_target")
            assert action.action_type == at

    def test_invalid_action_type_raises(self):
        with pytest.raises(Exception):
            SkillActionInput(action_type="unknown_type", target="x")

    def test_extra_fields_forbidden(self):
        with pytest.raises(Exception):
            SkillActionInput(action_type="python_code", target="x", illegal_field="y")

    def test_content_optional(self):
        action = SkillActionInput(action_type="file_write", target="/tmp/test.txt")
        assert action.content is None

    def test_content_stored_when_provided(self):
        action = SkillActionInput(action_type="file_write", target="/tmp/test.txt", content="hello world")
        assert action.content == "hello world"

    def test_dry_run_defaults_false(self):
        action = SkillActionInput(action_type="python_code", target="x")
        assert action.dry_run is False


# ---------------------------------------------------------------------------
# Contract validation — SkillRequestContext
# ---------------------------------------------------------------------------


class TestSkillRequestContextValidation:
    def test_default_context_is_valid(self):
        ctx = SkillRequestContext()
        assert ctx.source_platform == "unknown"
        assert ctx.tags == []

    def test_source_platform_valid_values(self):
        for platform in ("claude", "openclaw", "unknown"):
            ctx = SkillRequestContext(source_platform=platform)
            assert ctx.source_platform == platform

    def test_invalid_source_platform_raises(self):
        with pytest.raises(Exception):
            SkillRequestContext(source_platform="openai")

    def test_tags_normalized_lowercase_deduplicated(self):
        ctx = SkillRequestContext(tags=["Security", "SECURITY", "scan", "  "])
        assert ctx.tags.count("security") == 1
        assert "scan" in ctx.tags
        assert "" not in ctx.tags

    def test_optional_fields_stripped_to_none(self):
        ctx = SkillRequestContext(request_id="  ", client_id="  ")
        assert ctx.request_id is None
        assert ctx.client_id is None

    def test_valid_optional_fields_preserved(self):
        ctx = SkillRequestContext(
            request_id="req-abc",
            tenant_id="tenant-123",
            client_id="client-xyz",
        )
        assert ctx.request_id == "req-abc"
        assert ctx.tenant_id == "tenant-123"


# ---------------------------------------------------------------------------
# SkillReason validation
# ---------------------------------------------------------------------------


class TestSkillReasonValidation:
    def test_valid_reason(self):
        r = SkillReason(source="policy", label="Matched rule", details="Pattern found in target.")
        assert r.source == "policy"
        assert r.score is None

    def test_score_range_valid(self):
        r = SkillReason(source="scan", label="Risk factor", details="High entropy.", score=0.87)
        assert r.score == pytest.approx(0.87)

    def test_score_out_of_range_raises(self):
        with pytest.raises(Exception):
            SkillReason(source="ai", label="test", details="detail", score=1.5)

    def test_empty_label_raises(self):
        with pytest.raises(Exception):
            SkillReason(source="runtime", label="", details="some detail")

    def test_empty_details_raises(self):
        with pytest.raises(Exception):
            SkillReason(source="runtime", label="label", details="")

    def test_valid_sources(self):
        for src in ("policy", "scan", "ai", "runtime", "installer", "skill"):
            r = SkillReason(source=src, label="ok", details="ok detail")
            assert r.source == src

    def test_invalid_source_raises(self):
        with pytest.raises(Exception):
            SkillReason(source="unknown_src", label="x", details="y")


# ---------------------------------------------------------------------------
# IronClawSkillError and error_to_response
# ---------------------------------------------------------------------------


class TestIronClawSkillErrors:
    def test_base_error_to_response_returns_envelope(self):
        err = IronClawSkillError(message="something broke", error_code="test_code", operation="scan")
        env = err.to_response()
        assert env.ok is False
        assert env.error_code == "test_code"
        assert env.operation == "scan"

    def test_base_error_to_reason(self):
        err = IronClawSkillError(message="detail msg", error_code="x", operation="scan")
        reason = err.to_reason()
        assert reason.source == "skill"
        assert reason.details == "detail msg"

    def test_skill_validation_error_maps_to_scan_operation(self):
        err = SkillValidationError(message="bad input")
        env = err.to_response()
        assert env.operation == "scan"
        assert env.error_code == "skill_validation_error"

    def test_skill_runtime_error_maps_to_execute_operation(self):
        err = SkillRuntimeError(message="runtime crash")
        env = err.to_response()
        assert env.operation == "execute"
        assert env.error_code == "skill_runtime_error"

    def test_skill_policy_error_maps_to_action_decision_operation(self):
        err = SkillPolicyError(message="policy denied")
        env = err.to_response()
        assert env.operation == "action_decision"
        assert env.error_code == "skill_policy_error"

    def test_skill_execution_error_maps_to_execute_operation(self):
        err = SkillExecutionError(message="exec failed")
        env = err.to_response()
        assert env.operation == "execute"
        assert env.error_code == "skill_execution_error"

    def test_unknown_operation_normalizes_to_scan(self):
        err = IronClawSkillError(message="err", error_code="x", operation="garbage_op")
        env = err.to_response()
        assert env.operation == "scan"

    def test_error_to_response_wraps_plain_exception(self):
        exc = ValueError("plain python error")
        env = error_to_response(exc)
        assert env.ok is False
        assert env.error_code == "unhandled_skill_error"
        assert env.operation == "scan"

    def test_error_to_response_passthrough_for_ironclaw_error(self):
        err = IronClawSkillError(message="known error", error_code="known_code", operation="execute")
        env = error_to_response(err)
        assert env.error_code == "known_code"
        assert env.operation == "execute"


# ---------------------------------------------------------------------------
# Middleware — SkillMiddleware execution
# ---------------------------------------------------------------------------


class TestSkillMiddleware:
    def test_sync_handler_executes_and_returns_result(self):
        def handler(req: SkillScanRequest) -> SkillResponseEnvelope:
            return build_skill_success_response(
                operation="scan",
                verdict="allow",
                summary="clean",
                request_id=req.context.request_id,
            )

        mw = create_middleware(
            operation="scan",
            handler=handler,
            config=MiddlewareConfig(enable_billing=False),
        )
        result = run_middleware(mw, _scan_request())
        assert isinstance(result, MiddlewareResult)
        assert result.response.operation == "scan"
        assert result.response.payload.verdict == "allow"

    def test_trace_populated_after_execution(self):
        def handler(req):
            return build_skill_success_response(
                operation="scan", verdict="allow", summary="ok", request_id=req.context.request_id
            )

        mw = create_middleware(
            operation="scan",
            handler=handler,
            config=MiddlewareConfig(enable_billing=False),
        )
        result = run_middleware(mw, _scan_request())
        assert result.trace.operation == "scan"
        assert result.trace.duration_ms >= 0
        assert result.trace.request_id == "req-001"
        assert result.trace.billed is False

    def test_trace_request_id_is_none_when_context_has_none(self):
        def handler(req):
            return build_skill_success_response(
                operation="action_policy", verdict="allow", summary="ok"
            )

        ctx = _make_context(request_id=None)
        mw = create_middleware(
            operation="action_policy",
            handler=handler,
            config=MiddlewareConfig(enable_billing=False),
        )
        result = run_middleware(mw, _action_policy_request(context=ctx))
        assert result.trace.request_id is None

    def test_stub_billing_hook_charges_without_rejection(self):
        def handler(req):
            return build_skill_success_response(
                operation="scan", verdict="allow", summary="ok", request_id=req.context.request_id
            )

        hook = StubBillingHook()
        mw = create_middleware(
            operation="scan",
            handler=handler,
            billing_hook=hook,
            config=MiddlewareConfig(enable_billing=True),
        )
        result = run_middleware(mw, _scan_request())
        assert result.trace.billed is True
        assert result.trace.billing_status == "noop"
        assert result.billing is not None
        assert result.billing.ok is True

    def test_memory_billing_hook_tracks_balance(self):
        def handler(req):
            return build_skill_success_response(
                operation="execute", verdict="allow", summary="ok", request_id=req.context.request_id
            )

        policy = BillingPolicy(
            provider="memory",
            units_per_execute=2,
            default_balance=10,
            block_on_exhausted=False,
        )
        hook = MemoryBillingHook(policy)
        hook.reset_balance(10)
        mw = create_middleware(
            operation="execute",
            handler=handler,
            billing_hook=hook,
            config=MiddlewareConfig(enable_billing=True),
        )
        run_middleware(mw, _execute_request())
        assert hook.balance == 8

    def test_memory_billing_hook_blocks_on_exhausted(self):
        def handler(req):
            return build_skill_success_response(
                operation="scan", verdict="allow", summary="ok"
            )

        policy = BillingPolicy(
            provider="memory",
            units_per_scan=5,
            default_balance=2,
            block_on_exhausted=True,
        )
        hook = MemoryBillingHook(policy)
        hook.reset_balance(2)
        mw = create_middleware(
            operation="scan",
            handler=handler,
            billing_hook=hook,
            config=MiddlewareConfig(enable_billing=True, fail_open_on_billing_error=False),
        )
        with pytest.raises(IronClawMiddlewareError):
            run_middleware(mw, _scan_request())

    def test_fail_open_on_billing_error_allows_handler_to_run(self):
        executed = []

        def handler(req):
            executed.append(True)
            return build_skill_success_response(
                operation="scan", verdict="allow", summary="ok"
            )

        class BrokenHook:
            def charge(self, *, operation, context=None, metadata=None, units=None):
                raise RuntimeError("billing unavailable")

        mw = create_middleware(
            operation="scan",
            handler=handler,
            billing_hook=BrokenHook(),
            config=MiddlewareConfig(enable_billing=True, fail_open_on_billing_error=True),
        )
        result = run_middleware(mw, _scan_request())
        assert executed
        assert result.response.operation == "scan"

    def test_fail_closed_on_billing_error_raises(self):
        def handler(req):
            return build_skill_success_response(
                operation="scan", verdict="allow", summary="ok"
            )

        class BrokenHook:
            def charge(self, *, operation, context=None, metadata=None, units=None):
                raise RuntimeError("billing unavailable")

        mw = create_middleware(
            operation="scan",
            handler=handler,
            billing_hook=BrokenHook(),
            config=MiddlewareConfig(enable_billing=True, fail_open_on_billing_error=False),
        )
        with pytest.raises(IronClawMiddlewareError, match="Billing middleware failed"):
            run_middleware(mw, _scan_request())

    def test_metadata_factory_enriches_trace(self):
        def handler(req):
            return build_skill_success_response(
                operation="scan", verdict="allow", summary="ok"
            )

        def meta_factory(req):
            return {"tenant": req.context.tenant_id, "custom_flag": True}

        mw = create_middleware(
            operation="scan",
            handler=handler,
            config=MiddlewareConfig(enable_billing=False, include_trace_metadata=True),
            metadata_factory=meta_factory,
        )
        result = run_middleware(mw, _scan_request())
        assert result.trace.metadata.get("tenant") == "tenant-abc"
        assert result.trace.metadata.get("custom_flag") is True

    def test_trace_metadata_excluded_when_flag_false(self):
        def handler(req):
            return build_skill_success_response(
                operation="scan", verdict="allow", summary="ok"
            )

        def meta_factory(req):
            return {"secret": "should_not_appear"}

        mw = create_middleware(
            operation="scan",
            handler=handler,
            config=MiddlewareConfig(enable_billing=False, include_trace_metadata=False),
            metadata_factory=meta_factory,
        )
        result = run_middleware(mw, _scan_request())
        assert result.trace.metadata == {}

    def test_middleware_result_to_dict_contains_trace_and_response(self):
        def handler(req):
            return build_skill_success_response(
                operation="action_decision", verdict="allow", summary="ok"
            )

        mw = create_middleware(
            operation="action_decision",
            handler=handler,
            config=MiddlewareConfig(enable_billing=False),
        )
        result = run_middleware(mw, _action_decision_request())
        d = result.to_dict()
        assert "trace" in d
        assert "response" in d
        assert d["trace"]["operation"] == "action_decision"


# ---------------------------------------------------------------------------
# attach_trace utility
# ---------------------------------------------------------------------------


class TestAttachTrace:
    def _make_trace(self) -> MiddlewareTrace:
        return MiddlewareTrace(
            operation="scan",
            duration_ms=10,
            request_id="req-x",
            billed=False,
            billing_status=None,
            units_charged=0,
            short_circuited=False,
            metadata={},
        )

    def test_attach_trace_to_dict(self):
        trace = self._make_trace()
        response = {"verdict": "allow"}
        enriched = attach_trace(response, trace)
        assert "trace" in enriched
        assert enriched["trace"]["operation"] == "scan"

    def test_attach_trace_to_none_returns_dict_with_trace(self):
        trace = self._make_trace()
        result = attach_trace(None, trace)
        assert isinstance(result, dict)
        assert "trace" in result

    def test_attach_trace_to_pydantic_model_returns_dict_with_trace(self):
        trace = self._make_trace()
        env = build_skill_success_response(
            operation="scan", verdict="allow", summary="ok"
        )
        enriched = attach_trace(env, trace)
        if isinstance(enriched, dict):
            assert "trace" in enriched
        else:
            assert hasattr(enriched, "trace") or isinstance(enriched, SkillResponseEnvelope)


# ---------------------------------------------------------------------------
# Billing — StubBillingHook
# ---------------------------------------------------------------------------


class TestStubBillingHook:
    def test_charge_always_succeeds(self):
        hook = StubBillingHook()
        result = hook.charge(operation="scan")
        assert result.ok is True
        assert result.status == "noop"
        assert result.provider == "stub"

    def test_charge_units_reflect_policy_for_execute(self):
        policy = BillingPolicy(provider="stub", units_per_execute=3)
        hook = StubBillingHook(policy)
        result = hook.charge(operation="execute")
        assert result.units_charged == 3

    def test_charge_with_context_stores_request_id(self):
        hook = StubBillingHook()
        ctx = BillingContext(request_id="bill-req-001")
        result = hook.charge(operation="action_policy", context=ctx)
        assert result.event is not None
        assert result.event.request_id == "bill-req-001"

    def test_override_units_respected(self):
        hook = StubBillingHook()
        result = hook.charge(operation="scan", units=99)
        assert result.units_charged == 99

    def test_negative_units_override_clamped_to_zero(self):
        hook = StubBillingHook()
        result = hook.charge(operation="scan", units=-5)
        assert result.units_charged == 0


# ---------------------------------------------------------------------------
# Billing — MemoryBillingHook
# ---------------------------------------------------------------------------


class TestMemoryBillingHook:
    def test_initial_balance_from_policy(self):
        policy = BillingPolicy(provider="memory", default_balance=50, block_on_exhausted=False)
        hook = MemoryBillingHook(policy)
        assert hook.balance == 50

    def test_balance_decremented_after_charge(self):
        policy = BillingPolicy(provider="memory", units_per_scan=1, default_balance=10)
        hook = MemoryBillingHook(policy)
        hook.reset_balance(10)
        hook.charge(operation="scan")
        assert hook.balance == 9

    def test_charge_accepted_when_sufficient_balance(self):
        policy = BillingPolicy(provider="memory", units_per_scan=1, default_balance=5, block_on_exhausted=True)
        hook = MemoryBillingHook(policy)
        hook.reset_balance(5)
        result = hook.charge(operation="scan")
        assert result.ok is True
        assert result.status == "accepted"

    def test_charge_rejected_when_exhausted_and_block_enabled(self):
        policy = BillingPolicy(provider="memory", units_per_scan=5, default_balance=2, block_on_exhausted=True)
        hook = MemoryBillingHook(policy)
        hook.reset_balance(2)
        result = hook.charge(operation="scan")
        assert result.ok is False
        assert result.status == "rejected"
        assert result.reason == "insufficient_units"
        assert hook.balance == 2

    def test_charge_allowed_when_block_on_exhausted_false(self):
        policy = BillingPolicy(provider="memory", units_per_scan=5, default_balance=1, block_on_exhausted=False)
        hook = MemoryBillingHook(policy)
        hook.reset_balance(1)
        result = hook.charge(operation="scan")
        assert result.ok is True
        assert hook.balance == -4

    def test_reset_balance_updates_balance(self):
        policy = BillingPolicy(provider="memory", default_balance=0)
        hook = MemoryBillingHook(policy)
        hook.reset_balance(100)
        assert hook.balance == 100

    def test_reset_balance_negative_raises(self):
        from ironclaw_skill.billing import IronClawBillingError

        policy = BillingPolicy(provider="memory")
        hook = MemoryBillingHook(policy)
        with pytest.raises(IronClawBillingError):
            hook.reset_balance(-1)

    def test_event_balance_before_after_recorded(self):
        policy = BillingPolicy(provider="memory", units_per_scan=3, default_balance=10, block_on_exhausted=False)
        hook = MemoryBillingHook(policy)
        hook.reset_balance(10)
        result = hook.charge(operation="scan")
        assert result.balance_before == 10
        assert result.balance_after == 7
        assert result.event is not None
        assert result.event.balance_before == 10
        assert result.event.balance_after == 7


# ---------------------------------------------------------------------------
# BillingPolicy — cost_for method
# ---------------------------------------------------------------------------


class TestBillingPolicyCostFor:
    def test_scan_cost(self):
        policy = BillingPolicy(units_per_scan=2)
        assert policy.cost_for("scan") == 2

    def test_action_policy_cost(self):
        policy = BillingPolicy(units_per_action_policy=1)
        assert policy.cost_for("action_policy") == 1

    def test_action_decision_cost(self):
        policy = BillingPolicy(units_per_action_decision=1)
        assert policy.cost_for("action_decision") == 1

    def test_execute_cost(self):
        policy = BillingPolicy(units_per_execute=4)
        assert policy.cost_for("execute") == 4

    def test_unknown_operation_returns_zero(self):
        policy = BillingPolicy()
        assert policy.cost_for("unknown") == 0

    def test_cost_for_is_case_insensitive(self):
        policy = BillingPolicy(units_per_scan=3)
        assert policy.cost_for("  SCAN  ") == 3


# ---------------------------------------------------------------------------
# Integration — router → middleware → billing pipeline
# ---------------------------------------------------------------------------


class TestRouterMiddlewareBillingPipeline:
    def test_full_scan_pipeline_allow(self):
        def scan_handler(req: SkillScanRequest) -> SkillResponseEnvelope:
            return build_skill_success_response(
                operation="scan",
                verdict="allow",
                summary="scan passed",
                request_id=req.context.request_id,
                decision_source="scan",
                risk_score=5,
            )

        policy = BillingPolicy(provider="memory", units_per_scan=1, default_balance=100, block_on_exhausted=True)
        hook = MemoryBillingHook(policy)
        hook.reset_balance(100)

        mw = create_middleware(
            operation="scan",
            handler=scan_handler,
            billing_hook=hook,
            config=MiddlewareConfig(enable_billing=True),
        )
        result = run_middleware(mw, _scan_request())

        assert result.response.payload.verdict == "allow"
        assert result.trace.billed is True
        assert result.trace.units_charged == 1
        assert hook.balance == 99

    def test_full_execute_pipeline_blocked_by_default(self):
        router = IronClawSkillRouter()
        req = _execute_request(action_type="shell_command", target="rm -rf /", require_confirmation=True)
        response = router.route(req)

        assert response.payload.verdict == "block"
        assert response.payload.should_halt is True
        assert response.payload.metadata.risk_score >= 80

    def test_full_action_decision_pipeline_custom_handler_with_billing(self):
        def decision_handler(req: SkillActionDecisionRequest) -> SkillResponseEnvelope:
            return build_skill_success_response(
                operation="action_decision",
                verdict="block",
                summary="blocked by custom policy",
                request_id=req.context.request_id,
                decision_source="policy",
                risk_score=95,
            )

        policy = BillingPolicy(
            provider="memory",
            units_per_action_decision=1,
            default_balance=10,
            block_on_exhausted=True,
        )
        hook = MemoryBillingHook(policy)
        hook.reset_balance(10)

        mw = create_middleware(
            operation="action_decision",
            handler=decision_handler,
            billing_hook=hook,
            config=MiddlewareConfig(enable_billing=True),
        )
        result = run_middleware(mw, _action_decision_request(action_type="system_change", target="modify kernel"))

        assert result.response.payload.verdict == "block"
        assert result.response.payload.metadata.risk_score == 95
        assert hook.balance == 9

    def test_billing_exhaustion_blocks_pipeline(self):
        def scan_handler(req):
            return build_skill_success_response(
                operation="scan", verdict="allow", summary="ok"
            )

        policy = BillingPolicy(
            provider="memory",
            units_per_scan=10,
            default_balance=3,
            block_on_exhausted=True,
        )
        hook = MemoryBillingHook(policy)
        hook.reset_balance(3)

        mw = create_middleware(
            operation="scan",
            handler=scan_handler,
            billing_hook=hook,
            config=MiddlewareConfig(enable_billing=True, fail_open_on_billing_error=False),
        )
        with pytest.raises(IronClawMiddlewareError):
            run_middleware(mw, _scan_request())

    def test_router_propagates_request_id_through_entire_stack(self):
        ctx = _make_context(request_id="full-stack-trace-id")

        def handler(req):
            return build_skill_success_response(
                operation="scan",
                verdict="review",
                summary="traced",
                request_id=req.context.request_id,
            )

        mw = create_middleware(
            operation="scan",
            handler=handler,
            config=MiddlewareConfig(enable_billing=False),
        )
        result = run_middleware(mw, _scan_request(context=ctx))
        assert result.response.request_id == "full-stack-trace-id"
        assert result.trace.request_id == "full-stack-trace-id"