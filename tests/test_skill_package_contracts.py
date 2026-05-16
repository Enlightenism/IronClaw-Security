from __future__ import annotations

import importlib

from pydantic import TypeAdapter, ValidationError
import pytest


def _contracts():
    return importlib.import_module("ironclawskill.contracts")


def test_contracts_module_exports_canonical_symbols():
    contracts = _contracts()

    expected_names = (
        "SkillProvider",
        "RiskLevel",
        "SkillBaseModel",
        "SkillReason",
        "SkillRequestContext",
        "SkillPromptBundleInput",
        "SkillScanInput",
        "SkillActionInput",
        "SkillExecutionInput",
        "SkillScanRequest",
        "SkillActionPolicyRequest",
        "SkillActionDecisionRequest",
        "SkillExecuteRequest",
        "SkillRequest",
        "SkillDecisionMetadata",
        "SkillResponsePayload",
        "SkillResponseEnvelope",
        "buildskillsuccessresponse",
        "buildskillerrorresponse",
    )

    for name in expected_names:
        assert hasattr(contracts, name), f"ironclawskill.contracts is missing export: {name}"


def test_skill_provider_and_risk_level_values_are_stable():
    contracts = _contracts()

    assert contracts.SkillProvider.OPENCLAW.value == "openclaw"
    assert contracts.SkillProvider.CLAUDE.value == "claude"
    assert contracts.SkillProvider.UNKNOWN.value == "unknown"

    assert contracts.RiskLevel.LOW.value == "low"
    assert contracts.RiskLevel.MEDIUM.value == "medium"
    assert contracts.RiskLevel.HIGH.value == "high"
    assert contracts.RiskLevel.CRITICAL.value == "critical"


def test_request_context_normalizes_optional_fields_and_tags():
    contracts = _contracts()

    context = contracts.SkillRequestContext(
        clientid="  cli_123  ",
        sessionid="  sess_123  ",
        userid="  user_123  ",
        tenantid="  tenant_123  ",
        organizationid="  org_123  ",
        requestid="  req_123  ",
        provider=contracts.SkillProvider.OPENCLAW,
        sourceplatform="  openclaw  ",
        sourceversion="  1.2.3  ",
        tags=[" Prompt-Injection ", "runtime", "runtime", "  "],
        metadata={"layer": "adapter"},
    )

    assert context.clientid == "cli_123"
    assert context.sessionid == "sess_123"
    assert context.userid == "user_123"
    assert context.tenantid == "tenant_123"
    assert context.organizationid == "org_123"
    assert context.requestid == "req_123"
    assert context.provider is contracts.SkillProvider.OPENCLAW
    assert context.sourceplatform == "openclaw"
    assert context.sourceversion == "1.2.3"
    assert context.tags == ["prompt-injection", "runtime"]
    assert dict(context.metadata) == {"layer": "adapter"}


def test_prompt_bundle_requires_at_least_one_field():
    contracts = _contracts()

    with pytest.raises(ValidationError):
        contracts.SkillPromptBundleInput()


def test_prompt_bundle_normalizes_present_fields():
    contracts = _contracts()

    bundle = contracts.SkillPromptBundleInput(
        userprompt="  summarize this  ",
        retrieveddoc="  retrieved context  ",
        tooloutput="  tool output  ",
        modeloutput="  model output  ",
    )

    assert bundle.userprompt == "summarize this"
    assert bundle.retrieveddoc == "retrieved context"
    assert bundle.tooloutput == "tool output"
    assert bundle.modeloutput == "model output"


def test_scan_input_for_promptbundle_requires_bundle_and_rejects_targetvalue():
    contracts = _contracts()

    with pytest.raises(ValidationError):
        contracts.SkillScanInput(
            targettype="promptbundle",
            policymode="review",
        )

    with pytest.raises(ValidationError):
        contracts.SkillScanInput(
            targettype="promptbundle",
            targetvalue="should-not-be-here",
            bundle=contracts.SkillPromptBundleInput(userprompt="hello"),
            policymode="review",
        )

    model = contracts.SkillScanInput(
        targettype="promptbundle",
        bundle=contracts.SkillPromptBundleInput(userprompt="hello"),
        policymode="review",
    )

    assert model.targettype == "promptbundle"
    assert model.targetvalue is None
    assert model.bundle is not None
    assert model.bundle.userprompt == "hello"


@pytest.mark.parametrize("targettype", ["text", "url", "filepath"])
def test_scan_input_for_non_bundle_targets_requires_targetvalue(targettype):
    contracts = _contracts()

    with pytest.raises(ValidationError):
        contracts.SkillScanInput(
            targettype=targettype,
            policymode="review",
        )

    model = contracts.SkillScanInput(
        targettype=targettype,
        targetvalue="  value  ",
        policymode="allow",
    )

    assert model.targettype == targettype
    assert model.targetvalue == "value"
    assert model.bundle is None
    assert model.policymode == "allow"


def test_action_input_normalizes_fields_and_defaults():
    contracts = _contracts()

    action = contracts.SkillActionInput(
        actiontype="shellcommand",
        target="  python -m pytest -q  ",
        content="  print('ok')  ",
        policymode="review",
        dryrun=True,
    )

    assert action.actiontype == "shellcommand"
    assert action.target == "python -m pytest -q"
    assert action.content == "print('ok')"
    assert action.policymode == "review"
    assert action.dryrun is True


def test_execution_input_wraps_action_and_flags():
    contracts = _contracts()

    execution = contracts.SkillExecutionInput(
        action=contracts.SkillActionInput(
            actiontype="pythoncode",
            target="runner.py",
            content="print('x')",
            policymode="block",
        ),
        requireconfirmation=True,
        allowsideeffects=False,
    )

    assert execution.action.actiontype == "pythoncode"
    assert execution.action.target == "runner.py"
    assert execution.requireconfirmation is True
    assert execution.allowsideeffects is False


def test_request_union_validates_each_supported_operation():
    contracts = _contracts()
    adapter = TypeAdapter(contracts.SkillRequest)

    scan_request = adapter.validate_python(
        {
            "operation": "scan",
            "input": {
                "targettype": "text",
                "targetvalue": "hello",
                "policymode": "review",
            },
            "context": {
                "requestid": "req_scan",
                "provider": "openclaw",
            },
        },
    )
    assert isinstance(scan_request, contracts.SkillScanRequest)
    assert scan_request.operation == "scan"

    action_policy_request = adapter.validate_python(
        {
            "operation": "actionpolicy",
            "input": {
                "actiontype": "toolinvocation",
                "target": "filesystem.read",
                "policymode": "review",
                "dryrun": True,
            },
            "context": {
                "requestid": "req_policy",
                "provider": "claude",
            },
        },
    )
    assert isinstance(action_policy_request, contracts.SkillActionPolicyRequest)
    assert action_policy_request.operation == "actionpolicy"

    action_decision_request = adapter.validate_python(
        {
            "operation": "actiondecision",
            "input": {
                "actiontype": "networkrequest",
                "target": "https://example.test/api",
                "policymode": "block",
            },
            "context": {
                "requestid": "req_decision",
                "provider": "unknown",
            },
        },
    )
    assert isinstance(action_decision_request, contracts.SkillActionDecisionRequest)
    assert action_decision_request.operation == "actiondecision"

    execute_request = adapter.validate_python(
        {
            "operation": "execute",
            "input": {
                "action": {
                    "actiontype": "shellcommand",
                    "target": "pytest -q",
                    "policymode": "review",
                },
                "requireconfirmation": True,
                "allowsideeffects": False,
            },
            "context": {
                "requestid": "req_execute",
                "provider": "openclaw",
            },
        },
    )
    assert isinstance(execute_request, contracts.SkillExecuteRequest)
    assert execute_request.operation == "execute"


def test_response_payload_defaults_allowed_from_verdict():
    contracts = _contracts()

    allow_payload = contracts.SkillResponsePayload(
        verdict="allow",
        summary="allowed",
    )
    assert allow_payload.allowed is True

    review_payload = contracts.SkillResponsePayload(
        verdict="review",
        summary="review required",
    )
    assert review_payload.allowed is False

    block_payload = contracts.SkillResponsePayload(
        verdict="block",
        summary="blocked",
    )
    assert block_payload.allowed is False

    error_payload = contracts.SkillResponsePayload(
        verdict="error",
        summary="errored",
    )
    assert error_payload.allowed is False


def test_buildskillsuccessresponse_shape_is_stable():
    contracts = _contracts()

    response = contracts.buildskillsuccessresponse(
        operation="scan",
        verdict="review",
        summary="Prompt injection indicators detected.",
        shouldhalt=False,
        shouldwarn=True,
        requestid="req_success",
        scanid="scan_123",
        decisionsource="scan",
        matchedpatterns=["prompt-injection", "data-exfiltration"],
        riskscore=84,
        reasons=[
            contracts.SkillReason(
                source="scan",
                label="Prompt injection",
                details="The prompt attempts to override system instructions.",
                score=0.84,
            ),
        ],
        rawresult={"engine": "ironclaw"},
    )

    assert isinstance(response, contracts.SkillResponseEnvelope)
    assert response.ok is True
    assert response.operation == "scan"
    assert response.requestid == "req_success"
    assert response.errorcode is None

    assert response.payload.verdict == "review"
    assert response.payload.summary == "Prompt injection indicators detected."
    assert response.payload.shouldhalt is False
    assert response.payload.shouldwarn is True
    assert response.payload.allowed is False

    assert response.payload.metadata.scanid == "scan_123"
    assert response.payload.metadata.decisionsource == "scan"
    assert response.payload.metadata.matchedpatterns == ["prompt-injection", "data-exfiltration"]
    assert response.payload.metadata.riskscore == 84

    assert len(response.payload.reasons) == 1
    assert response.payload.reasons[0].source == "scan"
    assert response.payload.reasons[0].label == "Prompt injection"
    assert response.payload.reasons[0].details == "The prompt attempts to override system instructions."
    assert response.payload.reasons[0].score == 0.84

    assert response.payload.rawresult == {"engine": "ironclaw"}


def test_buildskillerrorresponse_shape_is_stable():
    contracts = _contracts()

    response = contracts.buildskillerrorresponse(
        operation="execute",
        summary="Guarded execution failed.",
        errorcode="guardedexecutionfailed",
        requestid="req_error",
        reasons=[
            contracts.SkillReason(
                source="runtime",
                label="Execution failure",
                details="The sandbox runtime rejected the action.",
                score=0.91,
            ),
        ],
        rawresult={"phase": "dispatch"},
    )

    assert isinstance(response, contracts.SkillResponseEnvelope)
    assert response.ok is False
    assert response.operation == "execute"
    assert response.requestid == "req_error"
    assert response.errorcode == "guardedexecutionfailed"

    assert response.payload.verdict == "error"
    assert response.payload.summary == "Guarded execution failed."
    assert response.payload.shouldhalt is True
    assert response.payload.shouldwarn is True
    assert response.payload.allowed is False

    assert response.payload.metadata.scanid is None
    assert response.payload.metadata.decisionsource == "unknown"
    assert response.payload.metadata.matchedpatterns == []
    assert response.payload.metadata.riskscore is None

    assert len(response.payload.reasons) == 1
    assert response.payload.reasons[0].source == "runtime"
    assert response.payload.reasons[0].label == "Execution failure"
    assert response.payload.reasons[0].details == "The sandbox runtime rejected the action."
    assert response.payload.reasons[0].score == 0.91

    assert response.payload.rawresult == {"phase": "dispatch"}
