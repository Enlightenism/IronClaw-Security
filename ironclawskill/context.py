from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

JsonValue = Any


def utcnow() -> datetime:
    return datetime.now(UTC)


def newid(prefix: str) -> str:
    return f"{prefix}{uuid4().hex}"


@dataclass(slots=True, frozen=True)
class IronClawSkillSession:
    sessionid: str | None = None
    organizationid: str | None = None
    customerid: str | None = None
    actorid: str | None = None
    metadata: Mapping[str, JsonValue] = field(default_factory=dict)


@dataclass(slots=True, frozen=True)
class IronClawSkillRequestContext:
    requestid: str | None = None
    traceid: str | None = None
    sessionid: str | None = None
    organizationid: str | None = None
    customerid: str | None = None
    actorid: str | None = None
    metadata: Mapping[str, JsonValue] = field(default_factory=dict)


@dataclass(slots=True, frozen=True)
class IronClawSkillContext:
    request: IronClawSkillRequestContext = field(default_factory=IronClawSkillRequestContext)
    session: IronClawSkillSession = field(default_factory=IronClawSkillSession)
    metadata: Mapping[str, JsonValue] = field(default_factory=dict)


@dataclass(slots=True, frozen=True)
class SkillRequestContext:
    requestid: str = field(default_factory=lambda: newid("req"))
    traceid: str = field(default_factory=lambda: newid("trace"))
    correlationid: str = field(default_factory=lambda: newid("corr"))
    sessionid: str | None = None
    organizationid: str | None = None
    customerid: str | None = None
    actorid: str | None = None
    environment: str = "production"
    region: str | None = None
    sourceip: str | None = None
    useragent: str | None = None
    route: str | None = None
    method: str | None = None
    tags: tuple[str, ...] = ()
    labels: Mapping[str, str] = field(default_factory=dict)
    metadata: Mapping[str, JsonValue] = field(default_factory=dict)
    createdat: datetime = field(default_factory=utcnow)

    # Backwards-compatible aliases for tests or external callers
    @property
    def request_id(self) -> str:
        return self.requestid

    @property
    def trace_id(self) -> str:
        return self.traceid

    @property
    def correlation_id(self) -> str:
        return self.correlationid

    @property
    def session_id(self) -> str | None:
        return self.sessionid

    @property
    def organization_id(self) -> str | None:
        return self.organizationid

    @property
    def customer_id(self) -> str | None:
        return self.customerid

    @property
    def actor_id(self) -> str | None:
        return self.actorid

    @property
    def source_ip(self) -> str | None:
        return self.sourceip

    @property
    def user_agent(self) -> str | None:
        return self.useragent

    @property
    def created_at(self) -> datetime:
        return self.createdat

    def withmetadata(self, metadata: JsonValue) -> SkillRequestContext:
        merged = dict(self.metadata)
        if isinstance(metadata, Mapping):
            merged.update(metadata)
        return replace(self, metadata=merged)

    def with_metadata(self, **metadata: JsonValue) -> SkillRequestContext:
        merged = dict(self.metadata)
        merged.update(metadata)
        return replace(self, metadata=merged)

    def withlabel(self, **labels: str) -> SkillRequestContext:
        merged = dict(self.labels)
        merged.update(labels)
        return replace(self, labels=merged)

    def with_labels(self, **labels: str) -> SkillRequestContext:
        merged = dict(self.labels)
        merged.update(labels)
        return replace(self, labels=merged)

    def withtags(self, *tags: str) -> SkillRequestContext:
        combined = tuple(dict.fromkeys((*self.tags, *tags)))
        return replace(self, tags=combined)

    def with_tags(self, *tags: str) -> SkillRequestContext:
        combined = tuple(dict.fromkeys((*self.tags, *tags)))
        return replace(self, tags=combined)

    def child(
        self,
        *,
        requestid: str | None = None,
        traceid: str | None = None,
        correlationid: str | None = None,
        sessionid: str | None = None,
        metadata: Mapping[str, JsonValue] | None = None,
    ) -> SkillRequestContext:
        mergedmetadata = dict(self.metadata)
        if metadata:
            mergedmetadata.update(metadata)
        return SkillRequestContext(
            requestid=requestid or newid("req"),
            traceid=traceid or self.traceid,
            correlationid=correlationid or self.correlationid,
            sessionid=sessionid if sessionid is not None else self.sessionid,
            organizationid=self.organizationid,
            customerid=self.customerid,
            actorid=self.actorid,
            environment=self.environment,
            region=self.region,
            sourceip=self.sourceip,
            useragent=self.useragent,
            route=self.route,
            method=self.method,
            tags=self.tags,
            labels=dict(self.labels),
            metadata=mergedmetadata,
        )

    def toheaders(self) -> dict[str, str]:
        headers: dict[str, str] = {
            "x-request-id": self.requestid,
            "x-trace-id": self.traceid,
            "x-correlation-id": self.correlationid,
        }
        if self.sessionid:
            headers["x-session-id"] = self.sessionid
        if self.organizationid:
            headers["x-organization-id"] = self.organizationid
        if self.customerid:
            headers["x-customer-id"] = self.customerid
        if self.actorid:
            headers["x-actor-id"] = self.actorid
        if self.region:
            headers["x-region"] = self.region
        if self.environment:
            headers["x-environment"] = self.environment
        return headers

    def to_headers(self) -> dict[str, str]:
        return self.toheaders()


@dataclass(slots=True, frozen=True)
class SkillRuntimeContext:
    request: SkillRequestContext
    provider: str
    operation: str = "execute"
    capability: str | None = None
    policyid: str | None = None
    reviewrequired: bool = False
    sandboxenabled: bool = False
    networkallowed: bool = False
    filesystemwriteallowed: bool = False
    toolinvocationallowed: bool = False
    metadata: Mapping[str, JsonValue] = field(default_factory=dict)
    startedat: datetime = field(default_factory=utcnow)

    # Backwards-compatible aliases for tests/runtime callers
    @property
    def policy_id(self) -> str | None:
        return self.policyid

    @property
    def review_required(self) -> bool:
        return self.reviewrequired

    @property
    def sandbox_enabled(self) -> bool:
        return self.sandboxenabled

    @property
    def network_allowed(self) -> bool:
        return self.networkallowed

    @property
    def filesystem_write_allowed(self) -> bool:
        return self.filesystemwriteallowed

    @property
    def tool_invocation_allowed(self) -> bool:
        return self.toolinvocationallowed

    @property
    def started_at(self) -> datetime:
        return self.startedat

    def withmetadata(self, metadata: JsonValue) -> SkillRuntimeContext:
        merged = dict(self.metadata)
        if isinstance(metadata, Mapping):
            merged.update(metadata)
        return replace(self, metadata=merged)

    def with_metadata(self, **metadata: JsonValue) -> SkillRuntimeContext:
        merged = dict(self.metadata)
        merged.update(metadata)
        return replace(self, metadata=merged)

    def markreviewrequired(self, value: bool = True) -> SkillRuntimeContext:
        return replace(self, reviewrequired=value)

    def mark_review_required(self, value: bool = True) -> SkillRuntimeContext:
        return replace(self, reviewrequired=value)

    def enablesandbox(self, value: bool = True) -> SkillRuntimeContext:
        return replace(self, sandboxenabled=value)

    def enable_sandbox(self, value: bool = True) -> SkillRuntimeContext:
        return replace(self, sandboxenabled=value)

    def toauditrecord(self) -> dict[str, JsonValue]:
        return {
            "requestid": self.request.requestid,
            "traceid": self.request.traceid,
            "correlationid": self.request.correlationid,
            "sessionid": self.request.sessionid,
            "organizationid": self.request.organizationid,
            "customerid": self.request.customerid,
            "actorid": self.request.actorid,
            "provider": self.provider,
            "operation": self.operation,
            "capability": self.capability,
            "policyid": self.policyid,
            "reviewrequired": self.reviewrequired,
            "sandboxenabled": self.sandboxenabled,
            "networkallowed": self.networkallowed,
            "filesystemwriteallowed": self.filesystemwriteallowed,
            "toolinvocationallowed": self.toolinvocationallowed,
            "environment": self.request.environment,
            "region": self.request.region,
            "route": self.request.route,
            "method": self.request.method,
            "tags": list(self.request.tags),
            "labels": dict(self.request.labels),
            "requestmetadata": dict(self.request.metadata),
            "runtimemetadata": dict(self.metadata),
            "startedat": self.startedat.isoformat(),
            "createdat": self.request.createdat.isoformat(),
        }

    def to_audit_record(self) -> dict[str, JsonValue]:
        return self.toauditrecord()


def createrequestcontext(
    *,
    sessionid: str | None = None,
    organizationid: str | None = None,
    customerid: str | None = None,
    actorid: str | None = None,
    environment: str = "production",
    region: str | None = None,
    sourceip: str | None = None,
    useragent: str | None = None,
    route: str | None = None,
    method: str | None = None,
    tags: tuple[str, ...] = (),
    labels: Mapping[str, str] | None = None,
    metadata: Mapping[str, JsonValue] | None = None,
) -> SkillRequestContext:
    return SkillRequestContext(
        sessionid=sessionid,
        organizationid=organizationid,
        customerid=customerid,
        actorid=actorid,
        environment=environment,
        region=region,
        sourceip=sourceip,
        useragent=useragent,
        route=route,
        method=method,
        tags=tags,
        labels=dict(labels or {}),
        metadata=dict(metadata or {}),
    )


def createruntimecontext(
    *,
    provider: str,
    request: SkillRequestContext | None = None,
    operation: str = "execute",
    capability: str | None = None,
    policyid: str | None = None,
    reviewrequired: bool = False,
    sandboxenabled: bool = False,
    networkallowed: bool = False,
    filesystemwriteallowed: bool = False,
    toolinvocationallowed: bool = False,
    metadata: Mapping[str, JsonValue] | None = None,
) -> SkillRuntimeContext:
    return SkillRuntimeContext(
        request=request or SkillRequestContext(),
        provider=provider,
        operation=operation,
        capability=capability,
        policyid=policyid,
        reviewrequired=reviewrequired,
        sandboxenabled=sandboxenabled,
        networkallowed=networkallowed,
        filesystemwriteallowed=filesystemwriteallowed,
        toolinvocationallowed=toolinvocationallowed,
        metadata=dict(metadata or {}),
    )


# Backwards-compatible snake_case helpers used in some call sites/tests

def create_request_context(
    *,
    session_id: str | None = None,
    organization_id: str | None = None,
    customer_id: str | None = None,
    actor_id: str | None = None,
    environment: str = "production",
    region: str | None = None,
    source_ip: str | None = None,
    user_agent: str | None = None,
    route: str | None = None,
    method: str | None = None,
    tags: tuple[str, ...] = (),
    labels: Mapping[str, str] | None = None,
    metadata: Mapping[str, JsonValue] | None = None,
) -> SkillRequestContext:
    return createrequestcontext(
        sessionid=session_id,
        organizationid=organization_id,
        customerid=customer_id,
        actorid=actor_id,
        environment=environment,
        region=region,
        sourceip=source_ip,
        useragent=user_agent,
        route=route,
        method=method,
        tags=tags,
        labels=labels,
        metadata=metadata,
    )


def create_runtime_context(
    *,
    provider: str,
    request: SkillRequestContext | None = None,
    operation: str = "execute",
    capability: str | None = None,
    policy_id: str | None = None,
    review_required: bool = False,
    sandbox_enabled: bool = False,
    network_allowed: bool = False,
    filesystem_write_allowed: bool = False,
    tool_invocation_allowed: bool = False,
    metadata: Mapping[str, JsonValue] | None = None,
) -> SkillRuntimeContext:
    return createruntimecontext(
        provider=provider,
        request=request,
        operation=operation,
        capability=capability,
        policyid=policy_id,
        reviewrequired=review_required,
        sandboxenabled=sandbox_enabled,
        networkallowed=network_allowed,
        filesystemwriteallowed=filesystem_write_allowed,
        toolinvocationallowed=tool_invocation_allowed,
        metadata=metadata,
    )


__all__ = [
    "JsonValue",
    "IronClawSkillSession",
    "IronClawSkillRequestContext",
    "IronClawSkillContext",
    "SkillRequestContext",
    "SkillRuntimeContext",
    "create_request_context",
    "create_runtime_context",
    "createrequestcontext",
    "createruntimecontext",
    "newid",
    "utcnow",
]