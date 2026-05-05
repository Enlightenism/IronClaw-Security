from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from app.detection.downloadanalyzer import analyze_download_dict
from app.detection.outputsanitizer import build_output_sanitizer
from app.detection.sessionrisk import SessionEvent, build_session_risk_analyzer
from app.security.hostilecontext import scanhostilecontextdict
from app.security.promptinjection import scanpromptinjectiondict


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
                    }
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
    executor: Optional[ExecutorCallable] = None
    name: str = "secureruntimepipeline"

    def evaluate(
        self,
        *,
        actorid: str,
        actiontype: str,
        target: str,
        content: str,
        riskscore: int,
        sessionid: str | None = None,
        filepath: str | None = None,
        metadata: dict[str, Any] | None = None,
        persistencedegraded: bool = False,
    ) -> SecureRuntimeDecision:
        effective_filepath = filepath or self.defaultfilepath
        effectivemetadata = dict(metadata or {})
        effectivemetadata.setdefault("filepath", effective_filepath)
        if sessionid:
            effectivemetadata.setdefault("sessionid", sessionid)
        if actorid:
            effectivemetadata.setdefault("actorid", actorid)

        normalized_risk = _clamp_score(riskscore)

        promptscan, prompt_failure = _safe_detector_result(
            "promptinjection",
            scanpromptinjectiondict,
            actiontype=actiontype,
            target=target,
            content=content,
            filepath=effective_filepath,
            metadata=effectivemetadata,
        )

        hostilecontext, hostile_failure = _safe_detector_result(
            "hostilecontext",
            scanhostilecontextdict,
            actiontype=actiontype,
            target=target,
            content=content,
            filepath=effective_filepath,
            metadata=effectivemetadata,
        )

        downloadanalysis, download_failure = _safe_detector_result(
            "downloadanalyzer",
            analyze_download_dict,
            actiontype=actiontype,
            target=target,
            content=content,
            filepath=effective_filepath,
            metadata=effectivemetadata,
        )

        output_sanitizer_failure: str | None = None
        try:
            outputsanitizer = build_output_sanitizer()
            outputsanitization_obj = outputsanitizer.sanitize(
                content,
                context=f"action={actiontype}, target={target}",
                redact_secrets=True,
                block_unsafe_commands=True,
            )
            outputsanitization = _as_dict(outputsanitization_obj)
            outputsanitization.setdefault("blocked", False)
            outputsanitization.setdefault("severity", "low")
            outputsanitization.setdefault("score", 0.0)
            outputsanitization.setdefault("reasons", [])
        except Exception as exc:
            output_sanitizer_failure = "outputsanitizer"
            outputsanitization = {
                "blocked": False,
                "severity": "high",
                "score": 0.5,
                "reasons": [
                    "Output sanitizer failed during runtime evaluation.",
                ],
                "degraded": True,
                "error": {
                    "type": exc.__class__.__name__,
                    "message": _text(exc),
                },
            }

        degraded_sources = [
            source
            for source in (
                prompt_failure,
                hostile_failure,
                download_failure,
                output_sanitizer_failure,
            )
            if source
        ]
        if persistencedegraded:
            degraded_sources.append("persistence")

        session_analyzer_failure = False
        try:
            session_analyzer = build_session_risk_analyzer()
            session_event = SessionEvent(
                source="secureruntimepipeline",
                verdict=self._event_verdict_for_detectors(
                    promptscan=promptscan,
                    hostilecontext=hostilecontext,
                    downloadanalysis=downloadanalysis,
                    outputsanitization=outputsanitization,
                    degradedmode=bool(degraded_sources),
                ),
                severity=self._event_severity_for_detectors(
                    promptscan=promptscan,
                    hostilecontext=hostilecontext,
                    downloadanalysis=downloadanalysis,
                    outputsanitization=outputsanitization,
                    degradedmode=bool(degraded_sources),
                ),
                score=float(normalized_risk) / 100.0,
                timestamp=effectivemetadata.get("timestamp") or None,
                detail=f"Aggregated runtime evaluation for action '{actiontype}' and target '{target}'.",
                metadata={
                    "actorid": actorid,
                    "sessionid": sessionid,
                    "filepath": effective_filepath,
                    "actiontype": actiontype,
                    "target": target,
                    "degradedmode": bool(degraded_sources),
                    "degradationsources": list(degraded_sources),
                },
            )
            sessionrisk_obj = session_analyzer.analyze(
                session_id=sessionid or "anonymous",
                events=[session_event],
                active_review=False,
            )
            sessionrisk = _as_dict(sessionrisk_obj)
            sessionrisk_score = float(getattr(sessionrisk_obj, "score", sessionrisk.get("score", 0.0)) or 0.0)
            sessionrisk_verdict = _text(getattr(sessionrisk_obj, "verdict", sessionrisk.get("verdict", "allow")), "allow").lower()
            sessionrisk_severity = _text(getattr(sessionrisk_obj, "severity", sessionrisk.get("severity", "low")), "low").lower()
            sessionrisk.setdefault("score", sessionrisk_score)
            sessionrisk.setdefault("verdict", sessionrisk_verdict)
            sessionrisk.setdefault("severity", sessionrisk_severity)
        except Exception as exc:
            session_analyzer_failure = True
            degraded_sources.append("sessionrisk")
            sessionrisk_score = 0.5
            sessionrisk_verdict = "review"
            sessionrisk_severity = "high"
            sessionrisk = {
                "score": sessionrisk_score,
                "verdict": sessionrisk_verdict,
                "severity": sessionrisk_severity,
                "degraded": True,
                "error": {
                    "type": exc.__class__.__name__,
                    "message": _text(exc),
                },
            }

        adjustedriskscore = _clamp_score(
            normalized_risk
            + _int(promptscan.get("riskdelta", 0))
            + _int(hostilecontext.get("riskdelta", 0))
            + _int(downloadanalysis.get("riskdelta", 0))
        )

        if sessionrisk_score >= 0.5:
            adjustedriskscore = min(100, adjustedriskscore + 10)

        if degraded_sources:
            adjustedriskscore = min(100, adjustedriskscore + 10)

        normalized_action = _text(actiontype).lower()
        normalized_target = _text(target).lower()

        reviewthreshold = self.reviewthreshold
        blockthreshold = self.blockthreshold

        tool_like_actions = {"toolcall", "shell", "command", "execute", "run"}
        shell_like_targets = {"shell", "powershell", "bash", "cmd", "terminal", "sh"}

        if normalized_action in tool_like_actions or normalized_target in shell_like_targets:
            reviewthreshold = min(reviewthreshold, self.toolreviewthreshold)
            blockthreshold = min(blockthreshold, self.toolblockthreshold)

        if normalized_target in shell_like_targets:
            reviewthreshold = min(reviewthreshold, self.shellreviewthreshold)
            blockthreshold = min(blockthreshold, self.shellblockthreshold)

        if sessionrisk_verdict in {"review", "block"}:
            reviewthreshold = min(reviewthreshold, 40)
            blockthreshold = min(blockthreshold, 75)

        if persistencedegraded:
            reviewthreshold = min(reviewthreshold, 25)
            blockthreshold = min(blockthreshold, 70)

        if degraded_sources:
            reviewthreshold = min(reviewthreshold, 35)

        reasons: list[dict[str, Any]] = [
            {
                "source": "pipeline",
                "label": "Risk evaluation",
                "details": (
                    f"Pipeline evaluated action '{actiontype}' for target '{target}' "
                    f"with base risk {normalized_risk} and adjusted risk {adjustedriskscore}."
                ),
                "score": adjustedriskscore,
            }
        ]

        if normalized_action in tool_like_actions or normalized_target in shell_like_targets:
            reasons.append(
                {
                    "source": "pipeline",
                    "label": "Tool-call hardening",
                    "details": (
                        f"Tool-call sensitive path detected for action '{actiontype}' and target "
                        f"'{target}', so stricter runtime thresholds were applied."
                    ),
                    "score": max(0, blockthreshold - reviewthreshold),
                }
            )

        if normalized_risk <= self.dryrunthreshold and not degraded_sources:
            reasons.append(
                {
                    "source": "pipeline",
                    "label": "Low-risk dry-run band",
                    "details": (
                        f"Base risk {normalized_risk} is within the configured dry-run threshold "
                        f"of {self.dryrunthreshold}."
                    ),
                    "score": normalized_risk,
                }
            )

        for reason in downloadanalysis.get("reasons", []):
            reasons.append(
                _normalize_reason(
                    reason,
                    default_source="downloadanalyzer",
                    default_label="Download risk indicator",
                    default_details="Download risk indicator detected.",
                )
            )

        for reason in promptscan.get("reasons", []):
            reasons.append(
                _normalize_reason(
                    reason,
                    default_source="promptinjection",
                    default_label="Prompt injection indicator",
                    default_details="Prompt injection indicator detected.",
                )
            )

        for reason in hostilecontext.get("reasons", []):
            reasons.append(
                _normalize_reason(
                    reason,
                    default_source="hostilecontext",
                    default_label="Hostile context indicator",
                    default_details="Hostile context indicator detected.",
                )
            )

        output_reasons = outputsanitization.get("reasons", [])
        if isinstance(output_reasons, list):
            output_reason_text = "; ".join(_text(item) for item in output_reasons if _text(item))
        else:
            output_reason_text = _text(output_reasons)

        reasons.append(
            {
                "source": "outputsanitizer",
                "label": "Output sanitization",
                "details": output_reason_text or "Output sanitization completed.",
                "score": _clamp_score(round(float(outputsanitization.get("score", 0.0) or 0.0) * 100)),
            }
        )

        reasons.append(
            {
                "source": "sessionrisk",
                "label": "Session risk aggregation",
                "details": (
                    f"Session risk resolved to {sessionrisk_verdict} with "
                    f"{sessionrisk_severity} severity and score {sessionrisk_score:.2f}."
                ),
                "score": _clamp_score(round(sessionrisk_score * 100)),
            }
        )

        degradationreasons: list[str] = []
        if degraded_sources:
            degradationreasons = [f"{source} unavailable or degraded during evaluation" for source in degraded_sources]
            reasons.append(
                {
                    "source": "pipeline",
                    "label": "Degraded mode",
                    "details": "; ".join(degradationreasons),
                    "score": 25,
                }
            )

        executionstate = "executed"
        policyverdict = "allow"
        responseaction = "allow"
        responsestatus = "completed"
        shouldexecute = True
        haltedbyboundary = False
        reviewrequired = False
        quarantine = False

        should_quarantine = bool(promptscan.get("shouldquarantine")) or bool(
            hostilecontext.get("shouldquarantine")
        ) or bool(downloadanalysis.get("shouldquarantine"))

        should_review = bool(promptscan.get("shouldreview")) or bool(
            hostilecontext.get("shouldreview")
        ) or bool(downloadanalysis.get("shouldreview")) or sessionrisk_verdict == "review"

        if outputsanitization.get("blocked"):
            executionstate = "denied"
            policyverdict = "block"
            responseaction = "deny"
            responsestatus = "denied"
            shouldexecute = False
            haltedbyboundary = True
        elif should_quarantine:
            executionstate = "denied"
            policyverdict = "quarantine"
            responseaction = "quarantine"
            responsestatus = "denied"
            shouldexecute = False
            haltedbyboundary = True
            reviewrequired = False
            quarantine = True
        elif persistencedegraded and (
            normalized_action in tool_like_actions or normalized_target in shell_like_targets
        ):
            executionstate = "queuedforreview"
            policyverdict = "warn"
            responseaction = "review"
            responsestatus = "queuedforreview"
            shouldexecute = False
            haltedbyboundary = True
            reviewrequired = True
        elif adjustedriskscore >= blockthreshold or sessionrisk_verdict == "block":
            executionstate = "denied"
            policyverdict = "block"
            responseaction = "deny"
            responsestatus = "denied"
            shouldexecute = False
            haltedbyboundary = True
        elif degraded_sources:
            executionstate = "queuedforreview"
            policyverdict = "warn"
            responseaction = "review"
            responsestatus = "queuedforreview"
            shouldexecute = False
            haltedbyboundary = True
            reviewrequired = True
        elif should_review or adjustedriskscore >= reviewthreshold:
            executionstate = "queuedforreview"
            policyverdict = "warn"
            responseaction = "review"
            responsestatus = "queuedforreview"
            shouldexecute = True
            haltedbyboundary = False
            reviewrequired = True
        elif normalized_risk <= self.dryrunthreshold:
            executionstate = "dryrun"
            policyverdict = "allow"
            responseaction = "dryrun"
            responsestatus = "dryrun"
            shouldexecute = True
            haltedbyboundary = False

        return SecureRuntimeDecision(
            executionstate=executionstate,
            policyverdict=policyverdict,
            responseaction=responseaction,
            responsestatus=responsestatus,
            shouldexecute=shouldexecute,
            haltedbyboundary=haltedbyboundary,
            reviewrequired=reviewrequired,
            quarantine=quarantine,
            degradedmode=bool(degraded_sources),
            adjustedriskscore=adjustedriskscore,
            normalizedriskscore=normalized_risk,
            reviewthresholdused=reviewthreshold,
            blockthresholdused=blockthreshold,
            reasons=reasons,
            degradationreasons=degradationreasons,
            promptinjection=promptscan,
            hostilecontext=hostilecontext,
            downloadanalysis=downloadanalysis,
            outputsanitization=outputsanitization,
            sessionrisk=sessionrisk,
        )

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
    executor: Optional[ExecutorCallable] = None,
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