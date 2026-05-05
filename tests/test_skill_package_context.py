from __future__ import annotations

from dataclasses import is_dataclass

from ironclawskill.context import (
    IronClawSkillContext,
    IronClawSkillRequestContext,
    IronClawSkillSession,
)


def test_session_defaults_are_stable() -> None:
    session = IronClawSkillSession()

    assert is_dataclass(session)
    assert session.sessionid is None
    assert session.organizationid is None
    assert session.customerid is None
    assert session.actorid is None
    assert isinstance(session.metadata, dict)
    assert session.metadata == {}


def test_session_accepts_explicit_identity_fields() -> None:
    session = IronClawSkillSession(
        sessionid="sess_123",
        organizationid="org_123",
        customerid="cust_123",
        actorid="actor_123",
        metadata={"tier": "enterprise"},
    )

    assert session.sessionid == "sess_123"
    assert session.organizationid == "org_123"
    assert session.customerid == "cust_123"
    assert session.actorid == "actor_123"
    assert session.metadata == {"tier": "enterprise"}


def test_request_context_defaults_are_stable() -> None:
    context = IronClawSkillRequestContext()

    assert is_dataclass(context)
    assert context.requestid is None
    assert context.traceid is None
    assert context.sessionid is None
    assert context.organizationid is None
    assert context.customerid is None
    assert context.actorid is None
    assert isinstance(context.metadata, dict)
    assert context.metadata == {}


def test_request_context_accepts_explicit_request_and_identity_fields() -> None:
    context = IronClawSkillRequestContext(
        requestid="req_123",
        traceid="trace_123",
        sessionid="sess_123",
        organizationid="org_123",
        customerid="cust_123",
        actorid="actor_123",
        metadata={"source": "pytest"},
    )

    assert context.requestid == "req_123"
    assert context.traceid == "trace_123"
    assert context.sessionid == "sess_123"
    assert context.organizationid == "org_123"
    assert context.customerid == "cust_123"
    assert context.actorid == "actor_123"
    assert context.metadata == {"source": "pytest"}


def test_context_defaults_embed_request_and_session_objects() -> None:
    context = IronClawSkillContext()

    assert is_dataclass(context)
    assert isinstance(context.request, IronClawSkillRequestContext)
    assert isinstance(context.session, IronClawSkillSession)
    assert context.request.requestid is None
    assert context.request.traceid is None
    assert context.session.sessionid is None
    assert context.session.organizationid is None
    assert isinstance(context.metadata, dict)
    assert context.metadata == {}


def test_context_accepts_nested_request_and_session_objects() -> None:
    request = IronClawSkillRequestContext(
        requestid="req_nested",
        traceid="trace_nested",
        sessionid="sess_nested",
        organizationid="org_nested",
        customerid="cust_nested",
        actorid="actor_nested",
        metadata={"request_scope": "ingress"},
    )
    session = IronClawSkillSession(
        sessionid="sess_nested",
        organizationid="org_nested",
        customerid="cust_nested",
        actorid="actor_nested",
        metadata={"session_scope": "tenant"},
    )

    context = IronClawSkillContext(
        request=request,
        session=session,
        metadata={"pipeline": "middleware"},
    )

    assert context.request is request
    assert context.session is session
    assert context.metadata == {"pipeline": "middleware"}
    assert context.request.requestid == "req_nested"
    assert context.request.traceid == "trace_nested"
    assert context.session.sessionid == "sess_nested"
    assert context.session.organizationid == "org_nested"


def test_context_request_and_session_can_be_correlated_without_shape_drift() -> None:
    context = IronClawSkillContext(
        request=IronClawSkillRequestContext(
            requestid="req_corr",
            traceid="trace_corr",
            sessionid="sess_corr",
            organizationid="org_corr",
            customerid="cust_corr",
            actorid="actor_corr",
        ),
        session=IronClawSkillSession(
            sessionid="sess_corr",
            organizationid="org_corr",
            customerid="cust_corr",
            actorid="actor_corr",
        ),
    )

    assert context.request.sessionid == context.session.sessionid
    assert context.request.organizationid == context.session.organizationid
    assert context.request.customerid == context.session.customerid
    assert context.request.actorid == context.session.actorid