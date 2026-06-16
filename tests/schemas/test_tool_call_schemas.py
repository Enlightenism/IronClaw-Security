from __future__ import annotations

from datetime import UTC

from pydantic import ValidationError
import pytest

from app.schemas.tool_call import (
    ToolCallInspectRequest,
    ToolCallLog,
    ToolCallRequest,
    ToolCallRiskLevel,
    ToolCallVerdict,
    ToolCallVerdictResponse,
)

# ---------------------------------------------------------------------------
# Enums — complete value coverage
# ---------------------------------------------------------------------------


def test_tool_call_risk_level_values():
    assert set(ToolCallRiskLevel) == {
        ToolCallRiskLevel.critical,
        ToolCallRiskLevel.high,
        ToolCallRiskLevel.medium,
        ToolCallRiskLevel.low,
        ToolCallRiskLevel.info,
    }


@pytest.mark.parametrize("value", ["critical", "high", "medium", "low", "info"])
def test_tool_call_risk_level_from_string(value):
    assert ToolCallRiskLevel(value).value == value


def test_tool_call_risk_level_invalid():
    with pytest.raises(ValueError):
        ToolCallRiskLevel("extreme")


def test_tool_call_verdict_values():
    assert set(ToolCallVerdict) == {
        ToolCallVerdict.allow,
        ToolCallVerdict.warn,
        ToolCallVerdict.quarantine,
        ToolCallVerdict.block,
        ToolCallVerdict.audit,
    }


@pytest.mark.parametrize("value", ["allow", "warn", "quarantine", "block", "audit"])
def test_tool_call_verdict_from_string(value):
    assert ToolCallVerdict(value).value == value


def test_tool_call_verdict_invalid():
    with pytest.raises(ValueError):
        ToolCallVerdict("pass")


@pytest.mark.parametrize("member", list(ToolCallRiskLevel))
def test_tool_call_risk_level_round_trip(member):
    assert ToolCallRiskLevel(member.value) == member


@pytest.mark.parametrize("member", list(ToolCallVerdict))
def test_tool_call_verdict_round_trip(member):
    assert ToolCallVerdict(member.value) == member


# ---------------------------------------------------------------------------
# ToolCallRequest — tool_name validator + tool_args validator + optional fields
# ---------------------------------------------------------------------------

_BASE_REQUEST = dict(tool_name="read_file", tool_args={"path": "/etc/passwd"})


def test_tool_call_request_valid_minimal():
    req = ToolCallRequest(**_BASE_REQUEST)
    assert req.tool_name == "read_file"
    assert req.tool_args == {"path": "/etc/passwd"}


def test_tool_call_request_empty_tool_name_rejected():
    with pytest.raises(ValidationError):
        ToolCallRequest(tool_name="", tool_args={})


def test_tool_call_request_whitespace_only_tool_name_rejected():
    with pytest.raises(ValidationError):
        ToolCallRequest(tool_name="   ", tool_args={})


def test_tool_call_request_tool_name_stripped():
    req = ToolCallRequest(tool_name="  read_file  ", tool_args={})
    assert req.tool_name == "read_file"


def test_tool_call_request_non_dict_tool_args_rejected():
    with pytest.raises(ValidationError):
        ToolCallRequest(tool_name="read_file", tool_args=["not", "a", "dict"])


def test_tool_call_request_string_tool_args_rejected():
    with pytest.raises(ValidationError):
        ToolCallRequest(tool_name="read_file", tool_args="bad")


def test_tool_call_request_empty_dict_tool_args_accepted():
    req = ToolCallRequest(tool_name="ping", tool_args={})
    assert req.tool_args == {}


def test_tool_call_request_nested_dict_tool_args_accepted():
    req = ToolCallRequest(tool_name="call", tool_args={"nested": {"key": "val"}})
    assert req.tool_args["nested"]["key"] == "val"


def test_tool_call_request_calling_agent_id_defaults_none():
    req = ToolCallRequest(**_BASE_REQUEST)
    assert req.calling_agent_id is None


def test_tool_call_request_session_id_defaults_none():
    req = ToolCallRequest(**_BASE_REQUEST)
    assert req.session_id is None


def test_tool_call_request_calling_context_defaults_none():
    req = ToolCallRequest(**_BASE_REQUEST)
    assert req.calling_context is None


def test_tool_call_request_metadata_defaults_empty():
    req = ToolCallRequest(**_BASE_REQUEST)
    assert req.metadata == {}


def test_tool_call_request_optional_fields_set():
    req = ToolCallRequest(
        tool_name="exec",
        tool_args={"cmd": "ls"},
        calling_agent_id="agent-001",
        session_id="sess-abc",
        calling_context="pipeline-run",
        metadata={"source": "ironclaw"},
    )
    assert req.calling_agent_id == "agent-001"
    assert req.session_id == "sess-abc"
    assert req.calling_context == "pipeline-run"
    assert req.metadata["source"] == "ironclaw"


def test_tool_call_request_orm_compat():
    assert ToolCallRequest.model_config.get("from_attributes") is True


# ---------------------------------------------------------------------------
# ToolCallInspectRequest — same validators + enforce default
# ---------------------------------------------------------------------------

_BASE_INSPECT = dict(tool_name="write_file", tool_args={"path": "/tmp/out", "content": "data"})


def test_tool_call_inspect_request_valid_minimal():
    req = ToolCallInspectRequest(**_BASE_INSPECT)
    assert req.tool_name == "write_file"
    assert req.tool_args == {"path": "/tmp/out", "content": "data"}


def test_tool_call_inspect_request_empty_tool_name_rejected():
    with pytest.raises(ValidationError):
        ToolCallInspectRequest(tool_name="", tool_args={})


def test_tool_call_inspect_request_whitespace_tool_name_rejected():
    with pytest.raises(ValidationError):
        ToolCallInspectRequest(tool_name="   ", tool_args={})


def test_tool_call_inspect_request_tool_name_stripped():
    req = ToolCallInspectRequest(tool_name="  write_file  ", tool_args={})
    assert req.tool_name == "write_file"


def test_tool_call_inspect_request_non_dict_tool_args_rejected():
    with pytest.raises(ValidationError):
        ToolCallInspectRequest(tool_name="write_file", tool_args=123)


def test_tool_call_inspect_request_enforce_defaults_true():
    req = ToolCallInspectRequest(**_BASE_INSPECT)
    assert req.enforce is True


def test_tool_call_inspect_request_enforce_can_be_false():
    req = ToolCallInspectRequest(**{**_BASE_INSPECT, "enforce": False})
    assert req.enforce is False


def test_tool_call_inspect_request_calling_agent_id_defaults_none():
    req = ToolCallInspectRequest(**_BASE_INSPECT)
    assert req.calling_agent_id is None


def test_tool_call_inspect_request_session_id_defaults_none():
    req = ToolCallInspectRequest(**_BASE_INSPECT)
    assert req.session_id is None


def test_tool_call_inspect_request_policy_version_defaults_none():
    req = ToolCallInspectRequest(**_BASE_INSPECT)
    assert req.policy_version is None


def test_tool_call_inspect_request_calling_context_defaults_none():
    req = ToolCallInspectRequest(**_BASE_INSPECT)
    assert req.calling_context is None


def test_tool_call_inspect_request_metadata_defaults_empty():
    req = ToolCallInspectRequest(**_BASE_INSPECT)
    assert req.metadata == {}


def test_tool_call_inspect_request_orm_compat():
    assert ToolCallInspectRequest.model_config.get("from_attributes") is True


# ---------------------------------------------------------------------------
# ToolCallVerdictResponse — risk_score bounds + evaluated_at timezone
# ---------------------------------------------------------------------------

_BASE_VERDICT_RESP = dict(verdict=ToolCallVerdict.allow, tool_name="read_file")


def test_tool_call_verdict_response_minimal():
    r = ToolCallVerdictResponse(**_BASE_VERDICT_RESP)
    assert r.verdict == ToolCallVerdict.allow
    assert r.tool_name == "read_file"
    assert r.risk_level == ToolCallRiskLevel.info
    assert r.risk_score == 0
    assert r.matched_rules == []
    assert r.categories == []
    assert r.reasoning is None
    assert r.blocked is False
    assert r.policy_version is None


def test_tool_call_verdict_response_risk_score_zero():
    r = ToolCallVerdictResponse(**{**_BASE_VERDICT_RESP, "risk_score": 0})
    assert r.risk_score == 0


def test_tool_call_verdict_response_risk_score_max():
    r = ToolCallVerdictResponse(**{**_BASE_VERDICT_RESP, "risk_score": 100})
    assert r.risk_score == 100


def test_tool_call_verdict_response_risk_score_below_zero_rejected():
    with pytest.raises(ValidationError):
        ToolCallVerdictResponse(**{**_BASE_VERDICT_RESP, "risk_score": -1})


def test_tool_call_verdict_response_risk_score_above_100_rejected():
    with pytest.raises(ValidationError):
        ToolCallVerdictResponse(**{**_BASE_VERDICT_RESP, "risk_score": 101})


def test_tool_call_verdict_response_evaluated_at_timezone_aware():
    r = ToolCallVerdictResponse(**_BASE_VERDICT_RESP)
    assert r.evaluated_at.tzinfo is not None
    assert r.evaluated_at.tzinfo == UTC


def test_tool_call_verdict_response_evaluated_at_explicit_preserved():
    from datetime import datetime

    ts = datetime(2026, 6, 16, 10, 0, 0, tzinfo=UTC)
    r = ToolCallVerdictResponse(**{**_BASE_VERDICT_RESP, "evaluated_at": ts})
    assert r.evaluated_at == ts


@pytest.mark.parametrize("verdict", list(ToolCallVerdict))
def test_tool_call_verdict_response_all_verdicts(verdict):
    r = ToolCallVerdictResponse(verdict=verdict, tool_name="t")
    assert r.verdict == verdict


@pytest.mark.parametrize("risk_level", list(ToolCallRiskLevel))
def test_tool_call_verdict_response_all_risk_levels(risk_level):
    r = ToolCallVerdictResponse(**{**_BASE_VERDICT_RESP, "risk_level": risk_level})
    assert r.risk_level == risk_level


def test_tool_call_verdict_response_orm_compat():
    assert ToolCallVerdictResponse.model_config.get("from_attributes") is True


# ---------------------------------------------------------------------------
# ToolCallLog — risk_score bounds + logged_at timezone + optional field defaults
# ---------------------------------------------------------------------------

_BASE_LOG = dict(tool_name="delete_file", verdict=ToolCallVerdict.block)


def test_tool_call_log_minimal():
    log = ToolCallLog(**_BASE_LOG)
    assert log.tool_name == "delete_file"
    assert log.verdict == ToolCallVerdict.block
    assert log.tool_args == {}
    assert log.calling_agent_id is None
    assert log.session_id is None
    assert log.risk_level == ToolCallRiskLevel.info
    assert log.risk_score == 0
    assert log.matched_rules == []
    assert log.categories == []
    assert log.reasoning is None
    assert log.blocked is False
    assert log.policy_version is None
    assert log.calling_context is None
    assert log.metadata == {}
    assert log.log_id is None


def test_tool_call_log_risk_score_zero():
    log = ToolCallLog(**{**_BASE_LOG, "risk_score": 0})
    assert log.risk_score == 0


def test_tool_call_log_risk_score_max():
    log = ToolCallLog(**{**_BASE_LOG, "risk_score": 100})
    assert log.risk_score == 100


def test_tool_call_log_risk_score_below_zero_rejected():
    with pytest.raises(ValidationError):
        ToolCallLog(**{**_BASE_LOG, "risk_score": -1})


def test_tool_call_log_risk_score_above_100_rejected():
    with pytest.raises(ValidationError):
        ToolCallLog(**{**_BASE_LOG, "risk_score": 101})


def test_tool_call_log_logged_at_timezone_aware():
    log = ToolCallLog(**_BASE_LOG)
    assert log.logged_at.tzinfo is not None
    assert log.logged_at.tzinfo == UTC


def test_tool_call_log_logged_at_explicit_preserved():
    from datetime import datetime

    ts = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)
    log = ToolCallLog(**{**_BASE_LOG, "logged_at": ts})
    assert log.logged_at == ts


def test_tool_call_log_full_construction():
    from datetime import datetime

    now = datetime.now(UTC)
    log = ToolCallLog(
        log_id="log-001",
        tool_name="exec_code",
        tool_args={"code": "import os; os.system('rm -rf /')"},
        calling_agent_id="agent-007",
        session_id="sess-xyz",
        verdict=ToolCallVerdict.block,
        risk_level=ToolCallRiskLevel.critical,
        risk_score=99,
        matched_rules=["rule-001", "rule-002"],
        categories=["code_execution", "exfiltration"],
        reasoning="Detected destructive shell command",
        blocked=True,
        policy_version="2.0.0",
        calling_context="auto-run",
        metadata={"env": "prod"},
        logged_at=now,
    )
    assert log.log_id == "log-001"
    assert log.risk_level == ToolCallRiskLevel.critical
    assert log.risk_score == 99
    assert log.blocked is True
    assert "rule-001" in log.matched_rules
    assert log.policy_version == "2.0.0"
    assert log.metadata["env"] == "prod"


def test_tool_call_log_orm_compat():
    assert ToolCallLog.model_config.get("from_attributes") is True
