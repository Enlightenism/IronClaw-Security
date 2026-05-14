from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from app.detection.downloadanalyzer import build_download_analyzer

ExecutorCallable = Callable[..., Any]


def _text(value: Any, default: str = "") -> str:
    if value is None:
        return default
    result = str(value).strip()
    return result or default


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _clamp_score(value: Any) -> int:
    return max(0, min(100, _int(value, default=0)))


def _as_dict(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, dict):
        return dict(value)
    if hasattr(value, "as_dict") and callable(value.as_dict):
        dumped = value.as_dict()
        if isinstance(dumped, dict):
            return dict(dumped)
    if hasattr(value, "model_dump") and callable(value.model_dump):
        dumped = value.model_dump()
        if isinstance(dumped, dict):
            return dict(dumped)
    if hasattr(value, "dict") and callable(value.dict):
        dumped = value.dict()
        if isinstance(dumped, dict):
            return dict(dumped)
    return {}


def _normalize_reason(
    reason: Any,
    *,
    default_source: str,
    default_label: str,
    default_details: str,
) -> dict[str, Any]:
    if isinstance(reason, dict):
        return {
            "source": _text(reason.get("source"), default_source),
            "label": _text(reason.get("label"), default_label),
            "details": _text(reason.get("details"), default_details),
            "score": _clamp_score(reason.get("score", 0)),
        }
    return {
        "source": default_source,
        "label": default_label,
        "details": _text(reason, default_details),
        "score": 0,
    }


def _safe_detector_result(
    detector_name: str,
    detector_callable: Callable[..., Any],
    /,
    **kwargs: Any,
) -> tuple[dict[str, Any], str | None]:
    try:
        result = detector_callable(**kwargs)
        normalized = _as_dict(result)
        normalized.setdefault("severity", "low")
        normalized.setdefault("riskdelta", 0)
        normalized.setdefault("reasons", [])
        normalized.setdefault("shouldreview", False)
        normalized.setdefault("shouldquarantine", False)
        normalized.setdefault("degraded", False)
        return normalized, None
    except Exception as exc:
        return (
            {
                "severity": "high",
                "riskdelta": 15,
                "reasons": [
                    {
                        "source": detector_name,
                        "label": "Detector failure",
                        "details": f"{detector_name} failed during runtime evaluation.",
                        "score": 15,
                    },
                ],
                "shouldreview": True,
                "shouldquarantine": False,
                "degraded": True,
                "error": {
                    "type": exc.__class__.__name__,
                    "message": _text(exc),
                },
            },
            detector_name,
        )


def _analyze_download_dict(
    *,
    actiontype: str,
    target: str,
    content: str,
    filepath: str,
    metadata: dict[str, Any],
) -> dict[str, Any]:
    analyzer = build_download_analyzer()
    result = analyzer.analyze(
        url=target if target.startswith(("http://", "https://")) else None,
        file_name=target if not target.startswith(("http://", "https://")) else None,
        context=f"action={actiontype}, filepath={filepath}",
    )
    return _as_dict(result)


def _merge_reasons(
    sandbox_decision: Any,
    tool_decision: Any,
) -> list[dict[str, Any]]:
    """Collect reasons from both decisions, deduplicated by (label, details)."""
    seen: set[tuple[str, str]] = set()
    merged: list[dict[str, Any]] = []
    for decision in (sandbox_decision, tool_decision):
        if decision is None:
            continue
        raw_reasons = getattr(decision, "reasons", None)
        if raw_reasons is None:
            d = _as_dict(decision)
            raw_reasons = d.get("reasons") or []
        for reason in raw_reasons or []:
            if isinstance(reason, dict):
                key = (_text(reason.get("label")), _text(reason.get("details")))
                if key not in seen:
                    seen.add(key)
                    merged.append(dict(reason))
    return merged


@dataclass(slots=True, frozen=True)
class SecureRuntimeDecision:
    executionstate: str
    policyverdict: str
    responseaction: str
    responsestatus: str
    shouldexecute: bool
    haltedbyboundary: bool
    reviewrequired: bool
    quarantine: bool
    degradedmode: bool
    adjustedriskscore: int
    normalizedriskscore: int
    reviewthresholdused: int
    blockthresholdused: int
    reasons: list[dict[str, Any]] = field(default_factory=list)
    degradationreasons: list[str] = field(default_factory=list)
    promptinjection: dict[str, Any] = field(default_factory=dict)
    hostilecontext: dict[str, Any] = field(default_factory=dict)
    downloadanalysis: dict[str, Any] = field(default_factory=dict)
    outputsanitization: dict[str, Any] = field(default_factory=dict)
    sessionrisk: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class SecureRuntimePipeline:
    reviewthreshold: int = 50
    blockthreshold: int = 85
    dryrunthreshold: int = 15
    toolreviewthreshold: int = 20
    toolblockthreshold: int = 60
    shellreviewthreshold: int = 10
    shellblockthreshold: int = 45
    defaultfilepath: str = "app/api/actionexecute.py"
    executor: ExecutorCallable | None = None
    name: str = "secureruntimepipeline"
    _sandbox_router: Any = field(default=None, repr=False, compare=False)
    _tool_call_guard: Any = field(default=None, repr=False, compare=False)
    _telemetry_sink: Any = field(default=None, repr=False, compare=False)
    _review_queue: Any = field(default=None, repr=False, compare=False)

    def _emit_telemetry(self, event: dict[str, Any]) -> None:
        sink = self._telemetry_sink
        if sink is None:
            return
        for method_name in ("record", "emit", "write"):
            method = getattr(sink, method_name, None)
            if callable(method):
                try:
                    method(event)
                except Exception:
                    pass
                return

    def _enqueue_review(self, item: dict[str, Any]) -> None:
        queue = self._review_queue
        if queue is None:
            return
        for method_name in ("enqueue", "submit"):
            method = getattr(queue, method_name, None)
            if callable(method):
                try:
                    method(item)
                except Exception:
                    pass
                return

    def _call_sandbox_router(self, *, session_id: str, tool_name: str, **kwargs: Any) -> Any | None:
        router = self._sandbox_router
        if router is None:
            return None
        evaluate = getattr(router, "evaluate", None)
        if not callable(evaluate):
            return None
        return evaluate(session_id=session_id, tool_name=tool_name, **kwargs)

    def _call_tool_guard(self, *, request: Any) -> Any | None:
        guard = self._tool_call_guard
        if guard is None:
            return None
        evaluate = getattr(guard, "evaluate", None)
        if not callable(evaluate):
            return None
        return evaluate(request=request)

    def _build_guarded_result(
        self,
        *,
        session_id: str,
        tool_name: str,
        verdict: str,
        allowed: bool,
        should_review: bool,
        should_block: bool,
        should_quarantine: bool,
        risk_delta: int,
        matched_rules: list[str],
        sandbox_decision: Any,
        tool_decision: Any,
    ) -> _GuardedRuntimeResult:
        reasons = _merge_reasons(sandbox_decision, tool_decision)
        return _GuardedRuntimeResult(
            session_id=session_id,
            tool_name=tool_name,
            verdict=verdict,
            allowed=allowed,
            should_review=should_review,
            should_block=should_block,
            should_quarantine=should_quarantine,
            risk_delta=risk_delta,
            matched_rules=matched_rules,
            reasons=reasons,
            sandbox_decision=_as_dict(sandbox_decision) if sandbox_decision is not None else {},
            tool_decision=_as_dict(tool_decision) if tool_decision is not None else {},
        )

    def evaluate(self, *, session_id: str = "", tool_name: str = "", **kwargs: Any) -> _GuardedRuntimeResult:  # type: ignore[override]
        session_id = (session_id or "").strip()
        tool_name = (tool_name or "").strip().lower()

        if not session_id:
            result = self._build_guarded_result(
                session_id=session_id,
                tool_name=tool_name,
                verdict="quarantine",
                allowed=False,
                should_review=False,
                should_block=True,
                should_quarantine=True,
                risk_delta=0,
                matched_rules=["secureruntimepipeline:missing_session_id"],
                sandbox_decision=None,
                tool_decision=None,
            )
            self._emit_telemetry({"event": "quarantine", "reason": "missing_session_id", "session_id": session_id})
            return result

        if not tool_name:
            result = self._build_guarded_result(
                session_id=session_id,
                tool_name=tool_name,
                verdict="quarantine",
                allowed=False,
                should_review=False,
                should_block=True,
                should_quarantine=True,
                risk_delta=0,
                matched_rules=["secureruntimepipeline:missing_tool_name"],
                sandbox_decision=None,
                tool_decision=None,
            )
            self._emit_telemetry({"event": "quarantine", "reason": "missing_tool_name", "session_id": session_id})
            return result

        cwd = kwargs.get("cwd")
        if isinstance(cwd, str):
            kwargs["cwd"] = cwd.strip()

        sandbox_decision = self._call_sandbox_router(session_id=session_id, tool_name=tool_name, **kwargs)
        sandbox_verdict = ""
        sandbox_allowed = True
        sandbox_rules: list[str] = []
        sandbox_risk_delta = 0
        if sandbox_decision is not None:
            sandbox_verdict = _text(getattr(sandbox_decision, "verdict", "")).lower()
            sandbox_allowed = bool(getattr(sandbox_decision, "allowed", True))
            sandbox_rules = list(getattr(sandbox_decision, "matched_rules", None) or [])
            sandbox_risk_delta = _int(getattr(sandbox_decision, "risk_delta", 0))

        if sandbox_verdict in ("block", "quarantine"):
            result = self._build_guarded_result(
                session_id=session_id,
                tool_name=tool_name,
                verdict=sandbox_verdict,
                allowed=False,
                should_review=False,
                should_block=True,
                should_quarantine=sandbox_verdict == "quarantine",
                risk_delta=sandbox_risk_delta,
                matched_rules=sandbox_rules,
                sandbox_decision=sandbox_decision,
                tool_decision=None,
            )
            self._emit_telemetry({"event": sandbox_verdict, "source": "sandbox_router", "session_id": session_id})
            return result

        class _Request:
            __slots__ = ("cwd", "kwargs", "session_id", "tool_name")

            def __init__(self, session_id: str, tool_name: str, **kw: Any) -> None:
                self.session_id = session_id
                self.tool_name = tool_name
                self.cwd = kw.get("cwd")
                self.kwargs = kw

        request = _Request(session_id=session_id, tool_name=tool_name, **kwargs)

        tool_decision = self._call_tool_guard(request=request)
        tool_verdict = ""
        tool_allowed = True
        tool_rules: list[str] = []
        tool_risk_delta = 0
        tool_should_review = False
        if tool_decision is not None:
            tool_verdict = _text(getattr(tool_decision, "verdict", "")).lower()
            tool_allowed = bool(getattr(tool_decision, "allowed", True))
            tool_rules = list(getattr(tool_decision, "matched_rules", None) or [])
            tool_risk_delta = _int(getattr(tool_decision, "risk_delta", 0))
            tool_should_review = bool(getattr(tool_decision, "should_review", False))

        # Deduplicate matched_rules, order-preserving
        seen_rules: set[str] = set()
        matched_rules: list[str] = []
        for rule in sandbox_rules + tool_rules:
            if rule not in seen_rules:
                seen_rules.add(rule)
                matched_rules.append(rule)

        total_risk_delta = sandbox_risk_delta + tool_risk_delta

        if tool_verdict in ("block", "quarantine"):
            verdict = tool_verdict
            allowed = False
            should_block = True
            should_quarantine = tool_verdict == "quarantine"
            should_review = False
            enqueue = False
        elif tool_verdict == "review" or tool_should_review:
            verdict = "review"
            allowed = tool_allowed
            should_block = False
            should_quarantine = False
            should_review = True
            enqueue = True
        else:
            verdict = sandbox_verdict if sandbox_verdict and sandbox_verdict != "allow" else (tool_verdict or "allow")
            if verdict == "":
                verdict = "allow"
            allowed = sandbox_allowed and tool_allowed
            should_block = not allowed and verdict == "block"
            should_quarantine = not allowed and verdict == "quarantine"
            should_review = False
            enqueue = False

        result = self._build_guarded_result(
            session_id=session_id,
            tool_name=tool_name,
            verdict=verdict,
            allowed=allowed,
            should_review=should_review,
            should_block=should_block,
            should_quarantine=should_quarantine,
            risk_delta=total_risk_delta,
            matched_rules=matched_rules,
            sandbox_decision=sandbox_decision,
            tool_decision=tool_decision,
        )

        self._emit_telemetry({"event": verdict, "session_id": session_id, "tool_name": tool_name})

        if enqueue:
            self._enqueue_review(
                {
                    "session_id": session_id,
                    "tool_name": tool_name,
                    "verdict": verdict,
                    "risk_delta": total_risk_delta,
                    "matched_rules": matched_rules,
                }
            )

        return result

    def allow(self, *, session_id: str = "", tool_name: str = "", **kwargs: Any) -> bool:
        return self.evaluate(session_id=session_id, tool_name=tool_name, **kwargs).allowed

    def _event_verdict_for_detectors(
        self,
        *,
        promptscan: dict[str, Any],
        hostilecontext: dict[str, Any],
        downloadanalysis: dict[str, Any],
        outputsanitization: dict[str, Any],
        degradedmode: bool = False,
    ) -> str:
        if outputsanitization.get("blocked"):
            return "block"
        if any(d.get("shouldquarantine") for d in (promptscan, hostilecontext, downloadanalysis)):
            return "block"
        if degradedmode:
            return "review"
        if any(d.get("shouldreview") for d in (promptscan, hostilecontext, downloadanalysis)):
            return "review"
        return "allow"

    def _event_severity_for_detectors(
        self,
        *,
        promptscan: dict[str, Any],
        hostilecontext: dict[str, Any],
        downloadanalysis: dict[str, Any],
        outputsanitization: dict[str, Any],
        degradedmode: bool = False,
    ) -> str:
        candidates: list[str] = []
        for detector in (promptscan, hostilecontext, downloadanalysis):
            severity = _text(detector.get("severity")).lower()
            if severity:
                candidates.append(severity)
        if outputsanitization.get("severity"):
            candidates.append(_text(outputsanitization.get("severity")).lower())
        if degradedmode:
            candidates.append("high")
        if "critical" in candidates:
            return "critical"
        if "high" in candidates:
            return "high"
        if "medium" in candidates:
            return "medium"
        if "low" in candidates:
            return "low"
        return "low"


@dataclass(slots=True)
class _GuardedRuntimeResult:
    session_id: str
    tool_name: str
    verdict: str
    allowed: bool
    should_review: bool
    should_block: bool
    should_quarantine: bool
    risk_delta: int
    matched_rules: list[str]
    reasons: list[dict[str, Any]]
    sandbox_decision: dict[str, Any]
    tool_decision: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "allowed": self.allowed,
            "sessionid": self.session_id,
            "toolname": self.tool_name,
            "shouldreview": self.should_review,
            "shouldblock": self.should_block,
            "shouldquarantine": self.should_quarantine,
            "riskdelta": self.risk_delta,
            "matchedrules": list(self.matched_rules),
            "reasons": list(self.reasons),
            "sandboxdecision": dict(self.sandbox_decision),
            "tooldecision": dict(self.tool_decision),
        }


def build_secure_runtime_pipeline(
    *,
    sandbox_router: Any = None,
    tool_call_guard: Any = None,
    telemetry_sink: Any = None,
    review_queue: Any = None,
    reviewthreshold: int = 50,
    blockthreshold: int = 85,
    dryrunthreshold: int = 15,
    toolreviewthreshold: int = 20,
    toolblockthreshold: int = 60,
    shellreviewthreshold: int = 10,
    shellblockthreshold: int = 45,
    defaultfilepath: str = "app/api/actionexecute.py",
    executor: ExecutorCallable | None = None,
) -> SecureRuntimePipeline:
    return SecureRuntimePipeline(
        reviewthreshold=reviewthreshold,
        blockthreshold=blockthreshold,
        dryrunthreshold=dryrunthreshold,
        toolreviewthreshold=toolreviewthreshold,
        toolblockthreshold=toolblockthreshold,
        shellreviewthreshold=shellreviewthreshold,
        shellblockthreshold=shellblockthreshold,
        defaultfilepath=defaultfilepath,
        executor=executor,
        _sandbox_router=sandbox_router,
        _tool_call_guard=tool_call_guard,
        _telemetry_sink=telemetry_sink,
        _review_queue=review_queue,
    )


def initialize_secureruntimepipeline(
    *,
    reviewthreshold: int = 50,
    blockthreshold: int = 85,
    dryrunthreshold: int = 15,
    toolreviewthreshold: int = 20,
    toolblockthreshold: int = 60,
    shellreviewthreshold: int = 10,
    shellblockthreshold: int = 45,
    defaultfilepath: str = "app/api/actionexecute.py",
    executor: ExecutorCallable | None = None,
) -> SecureRuntimePipeline:
    return SecureRuntimePipeline(
        reviewthreshold=reviewthreshold,
        blockthreshold=blockthreshold,
        dryrunthreshold=dryrunthreshold,
        toolreviewthreshold=toolreviewthreshold,
        toolblockthreshold=toolblockthreshold,
        shellreviewthreshold=shellreviewthreshold,
        shellblockthreshold=shellblockthreshold,
        defaultfilepath=defaultfilepath,
        executor=executor,
    )


def getactionexecutepipeline() -> SecureRuntimePipeline:
    return initialize_secureruntimepipeline()
