from __future__ import annotations


from dataclasses import asdict, dataclass, field, replace
from datetime import UTC, datetime
from enum import Enum
from typing import Any, Literal, Mapping, Protocol, TypeAlias, runtime_checkable
from uuid import uuid4


from pydantic import BaseModel, Field



JsonPrimitive = str | int | float | bool | None
JsonValue: TypeAlias = JsonPrimitive | list["JsonValue"] | dict[str, "JsonValue"]



def utcnow() -> datetime:
    return datetime.now(UTC)



def newid(prefix: str = "") -> str:
    return f"{prefix}{uuid4().hex}"



class SkillProvider(str, Enum):
    CLAUDE = "claude"
    OPENCLAW = "openclaw"
    UNKNOWN = "unknown"



class SkillMode(str, Enum):
    SYNC = "sync"
    ASYNC = "async"
    STREAM = "stream"



class SkillDecision(str, Enum):
    ALLOW = "allow"
    REVIEW = "review"
    BLOCK = "block"
    ERROR = "error"



class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"



class EventKind(str, Enum):
    REQUEST = "request"
    GUARD = "guard"
    EXECUTION = "execution"
    RESPONSE = "response"
    TELEMETRY = "telemetry"
    ERROR = "error"



@dataclass(slots=True, frozen=True)
class SkillActor:
    actorid: str
    actortype: Literal["user", "system", "service", "operator"] = "user"
    displayname: str | None = None
    organizationid: str | None = None
    roles: tuple[str, ...] = ()



@dataclass(slots=True, frozen=True)
class SkillExecutionTarget:
    targetid: str
    targettype: Literal["agent", "tool", "runtime", "route", "workflow"] = "agent"
    name: str | None = None
    version: str | None = None



@dataclass(slots=True, frozen=True)
class SkillContextSnapshot:
    requestid: str
    sessionid: str | None = None
    traceid: str | None = None
    correlationid: str | None = None
    organizationid: str | None = None
    customerid: str | None = None
    environment: str = "production"
    region: str | None = None
    labels: Mapping[str, str] = field(default_factory=dict)
    metadata: Mapping[str, JsonValue] = field(default_factory=dict)



@dataclass(slots=True, frozen=True)
class SkillInputArtifact:
    artifactid: str
    kind: Literal["text", "json", "file", "url", "prompt", "toolresult"] = "text"
    name: str | None = None
    mimetype: str | None = None
    content: str | None = None
    uri: str | None = None
    sha256: str | None = None
    sizebytes: int | None = None
    metadata: Mapping[str, JsonValue] = field(default_factory=dict)



@dataclass(slots=True, frozen=True)
class SkillPolicyHint:
    allownetwork: bool = False
    allowfilesystemwrite: bool = False
    allowtoolinvocation: bool = False
    allowshellexecution: bool = False
    maxoutputbytes: int | None = None
    maxruntimeseconds: int | None = None
    classification: str | None = None
    requiredcontrols: tuple[str, ...] = ()
    metadata: Mapping[str, JsonValue] = field(default_factory=dict)



@dataclass(slots=True, frozen=True)
class SkillReason:
    source: Literal["policy", "scan", "ai", "guard", "runtime", "billing", "usage"] = "policy"
    label: str = ""
    details: str = ""
    score: int | float | None = None
    metadata: Mapping[str, JsonValue] = field(default_factory=dict)



@dataclass(slots=True, frozen=True)
class SkillDetection:
    detectionid: str
    category: str
    severity: RiskLevel
    summary: str
    detail: str | None = None
    source: str | None = None
    confidence: float | None = None
    matchedrule: str | None = None
    evidence: Mapping[str, JsonValue] = field(default_factory=dict)



@dataclass(slots=True, frozen=True)
class SkillUsage:
    inputtokens: int = 0
    outputtokens: int = 0
    totaltokens: int = 0
    computeunits: int = 0
    billableunits: int = 0
    estimatedcostusd: float = 0.0
    latencyms: int = 0



@dataclass(slots=True, frozen=True)
class SkillOutputArtifact:
    artifactid: str
    kind: Literal["text", "json", "file", "report", "telemetry"] = "text"
    name: str | None = None
    mimetype: str | None = None
    content: str | None = None
    uri: str | None = None
    sha256: str | None = None
    sizebytes: int | None = None
    metadata: Mapping[str, JsonValue] = field(default_factory=dict)



@dataclass(slots=True, frozen=True)
class SkillExecutionEvent:
    eventid: str
    kind: EventKind
    message: str
    createdat: datetime = field(default_factory=utcnow)
    metadata: Mapping[str, JsonValue] = field(default_factory=dict)



@dataclass(slots=True, frozen=True)
class SkillExecutionResult:
    requestid: str
    provider: SkillProvider
    decision: SkillDecision
    risk: RiskLevel = RiskLevel.LOW
    status: Literal["completed", "blocked", "review", "failed"] = "completed"
    summary: str | None = None
    message: str | None = None
    outputtext: str | None = None
    outputartifacts: tuple[SkillOutputArtifact, ...] = ()
    detections: tuple[SkillDetection, ...] = ()
    events: tuple[SkillExecutionEvent, ...] = ()
    usage: SkillUsage = field(default_factory=SkillUsage)
    error: Mapping[str, JsonValue] | None = None
    metadata: Mapping[str, JsonValue] = field(default_factory=dict)
    startedat: datetime | None = None
    finishedat: datetime = field(default_factory=utcnow)


    @property
    def isallowed(self) -> bool:
        return self.decision is SkillDecision.ALLOW


    @property
    def requiresreview(self) -> bool:
        return self.decision is SkillDecision.REVIEW


    @property
    def isblocked(self) -> bool:
        return self.decision is SkillDecision.BLOCK


    @property
    def iserror(self) -> bool:
        return self.decision is SkillDecision.ERROR


    def asdict(self) -> dict[str, Any]:
        return {
            "requestid": self.requestid,
            "provider": self.provider.value if isinstance(self.provider, SkillProvider) else self.provider,
            "decision": self.decision.value if isinstance(self.decision, SkillDecision) else self.decision,
            "risk": self.risk.value if isinstance(self.risk, RiskLevel) else self.risk,
            "status": self.status,
            "summary": self.summary,
            "message": self.message,
            "outputtext": self.outputtext,
            "outputartifacts": [asdict(a) for a in self.outputartifacts],
            "detections": [asdict(d) for d in self.detections],
            "events": [asdict(e) for e in self.events],
            "usage": asdict(self.usage),
            "error": dict(self.error) if self.error else None,
            "metadata": dict(self.metadata),
            "startedat": self.startedat.isoformat() if self.startedat else None,
            "finishedat": self.finishedat.isoformat() if self.finishedat else None,
            "result": {
                "risk": self.risk.value if isinstance(self.risk, RiskLevel) else self.risk,
                "error": dict(self.error) if self.error else {},
                "summary": self.summary,
                "message": self.message,
            },
        }



@dataclass(slots=True, frozen=True)
class SkillHealthStatus:
    name: str
    healthy: bool
    detail: str | None = None
    checkedat: datetime = field(default_factory=utcnow)
    metadata: Mapping[str, JsonValue] = field(default_factory=dict)



@dataclass(slots=True, frozen=True)
class SkillCapability:
    name: str
    enabled: bool = True
    description: str | None = None
    metadata: Mapping[str, JsonValue] = field(default_factory=dict)



@dataclass(slots=True, frozen=True)
class SkillProviderDecision:
    requestid: str
    provider: SkillProvider
    decision: SkillDecision
    risk: RiskLevel
    reasons: tuple[SkillReason, ...] = ()
    usage: SkillUsage = field(default_factory=SkillUsage)
    metadata: Mapping[str, JsonValue] = field(default_factory=dict)



@runtime_checkable
class SkillAdapter(Protocol):
    provider: SkillProvider


    def execute(self, request: "SkillExecutionRequest") -> SkillExecutionResult: ...



@runtime_checkable
class SkillRuntime(Protocol):
    def run(self, request: "SkillExecutionRequest") -> SkillExecutionResult: ...


    def health(self) -> SkillHealthStatus: ...



@runtime_checkable
class SkillBillingProvider(Protocol):
    def estimate(self, request: "SkillExecutionRequest") -> SkillUsage: ...



@dataclass(slots=True, frozen=True)
class SkillExecutionRequest:
    requestid: str
    provider: SkillProvider
    mode: SkillMode = SkillMode.SYNC
    operation: str = "execute"
    actor: SkillActor | None = None
    target: SkillExecutionTarget | None = None
    context: SkillContextSnapshot | None = None
    prompt: str | None = None
    systemprompt: str | None = None
    inputartifacts: tuple[SkillInputArtifact, ...] = ()
    policy: SkillPolicyHint | None = None
    capabilities: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    metadata: Mapping[str, JsonValue] = field(default_factory=dict)
    requestedat: datetime = field(default_factory=utcnow)



@dataclass(slots=True, frozen=True)
class SkillResponseEnvelopeRuntime:
    request: SkillExecutionRequest
    result: SkillExecutionResult
    metadata: Mapping[str, JsonValue] = field(default_factory=dict)



def buildblockedresult(
    request: SkillExecutionRequest,
    message: str,
    risk: RiskLevel = RiskLevel.HIGH,
    detections: tuple[SkillDetection, ...] = (),
    metadata: Mapping[str, JsonValue] | None = None,
    outputtext: str | None = None,
    rawresponse: Mapping[str, JsonValue] | None = None,
    reasons: tuple[SkillReason, ...] | None = None,
) -> SkillExecutionResult:
    meta = dict(metadata or {})
    if rawresponse is not None and "rawresponse" not in meta:
        meta["rawresponse"] = dict(rawresponse)
    if reasons is not None and "reasons" not in meta:
        meta["reasons"] = [
            {"source": r.source, "label": r.label, "details": r.details, "score": r.score, "metadata": dict(r.metadata)}
            for r in reasons
        ]
    return SkillExecutionResult(
        requestid=request.requestid,
        provider=request.provider,
        decision=SkillDecision.BLOCK,
        risk=risk,
        status="blocked",
        summary=message,
        message=message,
        detections=detections,
        outputtext=outputtext,
        metadata=meta,
    )



def buildreviewresult(
    request: SkillExecutionRequest,
    message: str,
    risk: RiskLevel = RiskLevel.MEDIUM,
    detections: tuple[SkillDetection, ...] = (),
    metadata: Mapping[str, JsonValue] | None = None,
    outputtext: str | None = None,
    rawresponse: Mapping[str, JsonValue] | None = None,
    reasons: tuple[SkillReason, ...] | None = None,
) -> SkillExecutionResult:
    meta = dict(metadata or {})
    if rawresponse is not None and "rawresponse" not in meta:
        meta["rawresponse"] = dict(rawresponse)
    if reasons is not None and "reasons" not in meta:
        meta["reasons"] = [
            {"source": r.source, "label": r.label, "details": r.details, "score": r.score, "metadata": dict(r.metadata)}
            for r in reasons
        ]
    return SkillExecutionResult(
        requestid=request.requestid,
        provider=request.provider,
        decision=SkillDecision.REVIEW,
        risk=risk,
        status="review",
        summary=message,
        message=message,
        detections=detections,
        outputtext=outputtext,
        metadata=meta,
    )



def buildallowedresult(
    request: SkillExecutionRequest,
    outputtext: str | None = None,
    outputartifacts: tuple[SkillOutputArtifact, ...] = (),
    usage: SkillUsage | None = None,
    metadata: Mapping[str, JsonValue] | None = None,
    summary: str | None = None,
    rawresponse: Mapping[str, JsonValue] | None = None,
    reasons: tuple[SkillReason, ...] | None = None,
    risk: RiskLevel = RiskLevel.LOW,
) -> SkillExecutionResult:
    meta = dict(metadata or {})
    if rawresponse is not None and "rawresponse" not in meta:
        meta["rawresponse"] = dict(rawresponse)
    if reasons is not None and "reasons" not in meta:
        meta["reasons"] = [
            {"source": r.source, "label": r.label, "details": r.details, "score": r.score, "metadata": dict(r.metadata)}
            for r in reasons
        ]
    return SkillExecutionResult(
        requestid=request.requestid,
        provider=request.provider,
        decision=SkillDecision.ALLOW,
        risk=risk,
        status="completed",
        summary=summary,
        message=summary,
        outputtext=outputtext,
        outputartifacts=outputartifacts,
        usage=usage or SkillUsage(),
        metadata=meta,
    )



def builderrorresult(
    request: SkillExecutionRequest,
    message: str,
    risk: RiskLevel = RiskLevel.HIGH,
    metadata: Mapping[str, JsonValue] | None = None,
    outputtext: str | None = None,
    rawresponse: Mapping[str, JsonValue] | None = None,
    reasons: tuple[SkillReason, ...] | None = None,
    traceid: str | None = None,
    error: Mapping[str, JsonValue] | None = None,
) -> SkillExecutionResult:
    meta = dict(metadata or {})
    if rawresponse is not None and "rawresponse" not in meta:
        meta["rawresponse"] = dict(rawresponse)
    if reasons is not None and "reasons" not in meta:
        meta["reasons"] = [
            {"source": r.source, "label": r.label, "details": r.details, "score": r.score, "metadata": dict(r.metadata)}
            for r in reasons
        ]
    if traceid is not None:
        meta.setdefault("traceid", traceid)

    error_payload: Mapping[str, JsonValue] | None = None
    if error is not None:
        error_payload = dict(error)
    elif meta.get("error") and isinstance(meta["error"], Mapping):
        error_payload = dict(meta["error"])  # type: ignore[arg-type]
    elif meta.get("errorcode"):
        error_payload = {"code": str(meta["errorcode"])}

    return SkillExecutionResult(
        requestid=request.requestid,
        provider=request.provider,
        decision=SkillDecision.ERROR,
        risk=risk,
        status="failed",
        summary=message,
        message=message,
        outputtext=outputtext,
        error=error_payload,
        metadata=meta,
    )



class SkillBaseModel(BaseModel):
    model_config = {"extra": "forbid", "populate_by_name": True}



class SkillRequestContext(SkillBaseModel):
    clientid: str | None = Field(default=None, min_length=1, max_length=200)
    sessionid: str | None = Field(default=None, min_length=1, max_length=200)
    userid: str | None = Field(default=None, min_length=1, max_length=200)
    tenantid: str | None = Field(default=None, min_length=1, max_length=200)
    organizationid: str | None = Field(default=None, min_length=1, max_length=200)
    requestid: str | None = Field(default=None, min_length=1, max_length=200)
    provider: SkillProvider = Field(default=SkillProvider.UNKNOWN)
    sourceplatform: str | None = Field(default=None, min_length=1, max_length=120)
    sourceversion: str | None = Field(default=None, min_length=1, max_length=120)
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


    def model_post_init(self, __context: Any) -> None:
        normalized = [t.strip().lower() for t in self.tags if t and t.strip()]
        deduped = list(dict.fromkeys(normalized))
        object.__setattr__(self, "tags", deduped)  # type: ignore[arg-type]
        if self.clientid:
            object.__setattr__(self, "clientid", self.clientid.strip())
        if self.sessionid:
            object.__setattr__(self, "sessionid", self.sessionid.strip())
        if self.userid:
            object.__setattr__(self, "userid", self.userid.strip())
        if self.tenantid:
            object.__setattr__(self, "tenantid", self.tenantid.strip())
        if self.organizationid:
            object.__setattr__(self, "organizationid", self.organizationid.strip())
        if self.requestid:
            object.__setattr__(self, "requestid", self.requestid.strip())
        if self.sourceplatform:
            object.__setattr__(self, "sourceplatform", self.sourceplatform.strip())
        if self.sourceversion:
            object.__setattr__(self, "sourceversion", self.sourceversion.strip())



class SkillPromptBundleInput(SkillBaseModel):
    userprompt: str | None = Field(default=None, min_length=1)
    retrieveddoc: str | None = Field(default=None, min_length=1)
    tooloutput: str | None = Field(default=None, min_length=1)
    modeloutput: str | None = Field(default=None, min_length=1)


    def model_post_init(self, __context: Any) -> None:
        for field_name in ("userprompt", "retrieveddoc", "tooloutput", "modeloutput"):
            value = getattr(self, field_name)
            if isinstance(value, str):
                object.__setattr__(self, field_name, value.strip())
        if not any(
            getattr(self, f) is not None
            for f in ("userprompt", "retrieveddoc", "tooloutput", "modeloutput")
        ):
            raise ValueError("At least one prompt bundle field must be provided")



class SkillScanInput(SkillBaseModel):
    targettype: Literal["promptbundle", "text", "url", "filepath"]
    targetvalue: str | None = Field(default=None, min_length=1)
    policymode: Literal["review", "block", "allow"] = "review"
    bundle: SkillPromptBundleInput | None = None


    def model_post_init(self, __context: Any) -> None:
        if self.targettype == "promptbundle":
            if self.bundle is None:
                raise ValueError("bundle is required when targettype='promptbundle'")
            if self.targetvalue is not None:
                raise ValueError("targetvalue must be omitted for targettype='promptbundle'")
        else:
            if not self.targetvalue:
                raise ValueError("targetvalue is required for non-bundle target types")
            object.__setattr__(self, "targetvalue", self.targetvalue.strip())



class SkillActionInput(SkillBaseModel):
    actiontype: Literal["shellcommand", "pythoncode", "toolinvocation", "networkrequest", "httpfetch"]
    target: str = Field(min_length=1, max_length=2000)
    content: str | None = Field(default=None, max_length=20000)
    policymode: Literal["review", "block", "allow"] = "review"
    dryrun: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


    def model_post_init(self, __context: Any) -> None:
        object.__setattr__(self, "target", self.target.strip())
        if self.content is not None:
            object.__setattr__(self, "content", self.content.strip())



class SkillExecutionInput(SkillBaseModel):
    action: SkillActionInput
    requireconfirmation: bool = False
    allowsideeffects: bool = False



class SkillScanRequest(SkillBaseModel):
    operation: Literal["scan"] = "scan"
    input: SkillScanInput
    context: SkillRequestContext



class SkillActionPolicyRequest(SkillBaseModel):
    operation: Literal["actionpolicy"] = "actionpolicy"
    input: SkillActionInput
    context: SkillRequestContext



class SkillActionDecisionRequest(SkillBaseModel):
    operation: Literal["actiondecision"] = "actiondecision"
    input: SkillActionInput
    context: SkillRequestContext
    decisionmetadata: dict[str, Any] = Field(default_factory=dict)



class SkillExecuteRequest(SkillBaseModel):
    operation: Literal["execute"] = "execute"
    input: SkillExecutionInput
    context: SkillRequestContext



class SkillDecisionMetadataModel(SkillBaseModel):
    scanid: str | None = None
    decisionsource: Literal["scan", "policy", "runtime", "billing", "usage", "unknown"] = "scan"
    matchedpatterns: list[str] = Field(default_factory=list)
    riskscore: int | float | None = None



class SkillDecisionMetadata(SkillBaseModel):
    shouldhalt: bool = False
    shouldwarn: bool = False
    matchedpatterns: list[str] = Field(default_factory=list)
    riskscore: int | float | None = None



class SkillReasonModel(SkillBaseModel):
    source: Literal["policy", "scan", "ai", "guard", "runtime", "billing", "usage"] = "policy"
    label: str = ""
    details: str = ""
    score: int | float | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)



class SkillResponsePayload(SkillBaseModel):
    verdict: Literal["allow", "review", "block", "error"]
    summary: str
    shouldhalt: bool = False
    shouldwarn: bool = False
    requestid: str | None = None
    scanid: str | None = None
    decisionsource: Literal["scan", "policy", "runtime", "billing", "usage", "unknown"] = "scan"
    matchedpatterns: list[str] = Field(default_factory=list)
    riskscore: int | float | None = None
    reasons: list[SkillReasonModel] = Field(default_factory=list)
    rawresult: dict[str, Any] = Field(default_factory=dict)


    @property
    def allowed(self) -> bool:
        return self.verdict == "allow"


    @property
    def metadata(self) -> SkillDecisionMetadataModel:
        return SkillDecisionMetadataModel(
            scanid=self.scanid,
            decisionsource=self.decisionsource,
            matchedpatterns=list(self.matchedpatterns),
            riskscore=self.riskscore,
        )


    def model_post_init(self, __context: Any) -> None:
        if self.verdict == "allow":
            if self.riskscore is None:
                object.__setattr__(self, "riskscore", 0)
            if not self.matchedpatterns:
                object.__setattr__(self, "matchedpatterns", [])



class SkillResponseEnvelope(SkillBaseModel):
    payload: SkillResponsePayload
    metadata: dict[str, Any] = Field(default_factory=dict)


    @property
    def ok(self) -> bool:
        return self.payload.verdict in {"allow", "review"}


    @property
    def operation(self) -> str | None:
        value = self.metadata.get("operation")
        return str(value) if value is not None else None


    @property
    def requestid(self) -> str | None:
        return self.payload.requestid


    @property
    def errorcode(self) -> str | None:
        code = self.metadata.get("errorcode")
        return str(code) if code is not None else None



SkillRequest: TypeAlias = (
    SkillScanRequest | SkillActionPolicyRequest | SkillActionDecisionRequest | SkillExecuteRequest
)


SkillRequestUnion: TypeAlias = SkillRequest



def buildskillsuccessresponse(
    *,
    operation: Literal["scan", "execute", "policy"],
    verdict: Literal["allow", "review", "block"],
    summary: str,
    shouldhalt: bool = False,
    shouldwarn: bool = False,
    requestid: str | None = None,
    scanid: str | None = None,
    decisionsource: Literal["scan", "policy", "runtime", "billing", "usage"] = "scan",
    matchedpatterns: list[str] | None = None,
    riskscore: int | float | None = None,
    reasons: list[SkillReason] | None = None,
    rawresult: dict[str, Any] | None = None,
) -> SkillResponseEnvelope:
    reasons_models = [
        SkillReasonModel(
            source=r.source,
            label=r.label,
            details=r.details,
            score=r.score,
            metadata=dict(r.metadata),
        )
        for r in (reasons or [])
    ]
    payload = SkillResponsePayload(
        verdict=verdict,
        summary=summary,
        shouldhalt=shouldhalt,
        shouldwarn=shouldwarn,
        requestid=requestid,
        scanid=scanid,
        decisionsource=decisionsource,
        matchedpatterns=matchedpatterns or [],
        riskscore=riskscore,
        reasons=reasons_models,
        rawresult=rawresult or {},
    )
    return SkillResponseEnvelope(
        payload=payload,
        metadata={"operation": operation},
    )



def buildskillerrorresponse(
    *,
    operation: Literal["scan", "execute", "policy"],
    summary: str,
    errorcode: str,
    requestid: str | None = None,
    reasons: list[SkillReason] | None = None,
    rawresult: dict[str, Any] | None = None,
) -> SkillResponseEnvelope:
    reasons_models = [
        SkillReasonModel(
            source=r.source,
            label=r.label,
            details=r.details,
            score=r.score,
            metadata=dict(r.metadata),
        )
        for r in (reasons or [])
    ]
    payload = SkillResponsePayload(
        verdict="error",
        summary=summary,
        shouldhalt=True,
        shouldwarn=True,
        requestid=requestid,
        scanid=None,
        decisionsource="unknown",
        matchedpatterns=[],
        riskscore=None,
        reasons=reasons_models,
        rawresult=rawresult or {},
    )
    return SkillResponseEnvelope(
        payload=payload,
        metadata={"operation": operation, "errorcode": errorcode},
    )



@dataclass(slots=True, frozen=True)
class SkillRequestContextRuntime:
    requestid: str = field(default_factory=lambda: newid("req_"))
    traceid: str = field(default_factory=lambda: newid("trace_"))
    correlationid: str = field(default_factory=lambda: newid("corr_"))
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


    def withmetadata(self, metadata: Mapping[str, JsonValue]) -> "SkillRequestContextRuntime":
        merged = dict(self.metadata)
        merged.update(metadata)
        return replace(self, metadata=merged)


    def withlabels(self, labels: Mapping[str, str]) -> "SkillRequestContextRuntime":
        merged = dict(self.labels)
        merged.update(labels)
        return replace(self, labels=merged)


    def withtags(self, tags: tuple[str, ...]) -> "SkillRequestContextRuntime":
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
    ) -> "SkillRequestContextRuntime":
        mergedmetadata = dict(self.metadata)
        if metadata:
            mergedmetadata.update(metadata)
        return SkillRequestContextRuntime(
            requestid=requestid or newid("req_"),
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



@dataclass(slots=True, frozen=True)
class SkillRuntimeContext:
    request: SkillRequestContextRuntime
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


    def withmetadata(self, metadata: Mapping[str, JsonValue]) -> "SkillRuntimeContext":
        merged = dict(self.metadata)
        merged.update(metadata)
        return replace(self, metadata=merged)


    def markreviewrequired(self, value: bool = True) -> "SkillRuntimeContext":
        return replace(self, reviewrequired=value)


    def enablesandbox(self, value: bool = True) -> "SkillRuntimeContext":
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



def createrequestcontext(
    *,
    session_id: str | None = None,
    sessionid: str | None = None,
    organization_id: str | None = None,
    organizationid: str | None = None,
    customer_id: str | None = None,
    customerid: str | None = None,
    actor_id: str | None = None,
    actorid: str | None = None,
    environment: str = "production",
    region: str | None = None,
    source_ip: str | None = None,
    sourceip: str | None = None,
    user_agent: str | None = None,
    useragent: str | None = None,
    route: str | None = None,
    method: str | None = None,
    tags: tuple[str, ...] = (),
    labels: Mapping[str, str] | None = None,
    metadata: Mapping[str, JsonValue] | None = None,
) -> SkillRequestContextRuntime:
    return SkillRequestContextRuntime(
        sessionid=sessionid or session_id,
        organizationid=organizationid or organization_id,
        customerid=customerid or customer_id,
        actorid=actorid or actor_id,
        environment=environment,
        region=region,
        sourceip=sourceip or source_ip,
        useragent=useragent or user_agent,
        route=route,
        method=method,
        tags=tags,
        labels=dict(labels or {}),
        metadata=dict(metadata or {}),
    )



def createruntimecontext(
    *,
    provider: str,
    request: SkillRequestContextRuntime | None = None,
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
        request=request or SkillRequestContextRuntime(),
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



__all__ = [
    "EventKind",
    "JsonPrimitive",
    "JsonValue",
    "RiskLevel",
    "SkillProvider",
    "SkillMode",
    "SkillDecision",
    "SkillActor",
    "SkillAdapter",
    "SkillBillingProvider",
    "SkillCapability",
    "SkillContextSnapshot",
    "SkillDetection",
    "SkillExecutionEvent",
    "SkillExecutionRequest",
    "SkillExecutionResult",
    "SkillExecutionTarget",
    "SkillHealthStatus",
    "SkillInputArtifact",
    "SkillOutputArtifact",
    "SkillPolicyHint",
    "SkillProviderDecision",
    "SkillReason",
    "SkillRequest",
    "SkillResponseEnvelopeRuntime",
    "SkillRuntime",
    "SkillRuntimeContext",
    "SkillUsage",
    "SkillBaseModel",
    "SkillRequestContext",
    "SkillPromptBundleInput",
    "SkillScanInput",
    "SkillActionInput",
    "SkillExecutionInput",
    "SkillScanRequest",
    "SkillActionPolicyRequest",
    "SkillActionDecisionRequest",
    "SkillExecuteRequest",
    "SkillDecisionMetadata",
    "SkillDecisionMetadataModel",
    "SkillReasonModel",
    "SkillResponsePayload",
    "SkillResponseEnvelope",
    "SkillRequestUnion",
    "buildskillsuccessresponse",
    "buildskillerrorresponse",
    "buildallowedresult",
    "buildblockedresult",
    "builderrorresult",
    "buildreviewresult",
    "createrequestcontext",
    "createruntimecontext",
    "newid",
    "utcnow",
    "SkillRequestContextRuntime",
]