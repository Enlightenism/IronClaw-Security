from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.orchestrator.secureruntimepipeline import (
    SecureRuntimeDecision,
    SecureRuntimePipeline,
    getactionexecutepipeline,
)


@dataclass(slots=True)
class SecurityTelemetryEvent:
    eventid: str
    eventtype: str
    occurredat: str
    actorid: str
    sessionid: str
    actiontype: str
    target: str
    filepath: str
    executionstate: str
    policyverdict: str
    responseaction: str
    responsestatus: str
    shouldexecute: bool
    haltedbyboundary: bool
    reviewrequired: bool
    quarantine: bool
    adjustedriskscore: int
    reasons: list[dict[str, Any]] = field(default_factory=list)
    promptinjection: dict[str, Any] = field(default_factory=dict)
    hostilecontext: dict[str, Any] = field(default_factory=dict)
    downloadanalysis: dict[str, Any] = field(default_factory=dict)
    outputsanitization: dict[str, Any] = field(default_factory=dict)
    sessionrisk: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class SecurityOrchestrationResult:
    decision: SecureRuntimeDecision
    telemetryevent: SecurityTelemetryEvent

    def as_dict(self) -> dict[str, Any]:
        return {
            "decision": asdict(self.decision),
            "telemetryevent": self.telemetryevent.as_dict(),
        }


@dataclass(slots=True)
class SecurityOrchestrator:
    pipeline: SecureRuntimePipeline = field(default_factory=getactionexecutepipeline)
    telemetrypath: str = "output/security-events.jsonl"
    eventprefix: str = "sec"

    def evaluate_and_record(
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
    ) -> SecurityOrchestrationResult:
        effectivemetadata = dict(metadata or {})
        occurredat = self._timestamp()
        effectivemetadata.setdefault("timestamp", occurredat)

        decision = self.pipeline.evaluate(
            actorid=actorid,
            actiontype=actiontype,
            target=target,
            content=content,
            riskscore=riskscore,
            sessionid=sessionid,
            filepath=filepath,
            metadata=effectivemetadata,
        )

        telemetryevent = self._build_event(
            actorid=actorid,
            sessionid=sessionid,
            actiontype=actiontype,
            target=target,
            filepath=filepath or self.pipeline.defaultfilepath,
            decision=decision,
            metadata=effectivemetadata,
            occurredat=occurredat,
        )

        self._append_event(telemetryevent)
        return SecurityOrchestrationResult(decision=decision, telemetryevent=telemetryevent)

    def replay_summary(self, limit: int = 100) -> dict[str, Any]:
        events = list(self.iter_events(limit=limit))
        reviewcount = sum(1 for item in events if item.reviewrequired)
        quarantinecount = sum(1 for item in events if item.quarantine)
        blockedcount = sum(1 for item in events if item.policyverdict in {"block", "quarantine"})
        allowcount = sum(1 for item in events if item.policyverdict == "allow")

        return {
            "telemetrypath": self.telemetrypath,
            "eventcount": len(events),
            "allowcount": allowcount,
            "reviewcount": reviewcount,
            "blockedcount": blockedcount,
            "quarantinecount": quarantinecount,
            "latesteventat": events[-1].occurredat if events else None,
        }

    def iter_events(self, limit: int | None = None) -> Iterable[SecurityTelemetryEvent]:
        path = Path(self.telemetrypath)
        if not path.exists():
            return []

        lines = path.read_text(encoding="utf-8").splitlines()
        if limit is not None and limit >= 0:
            lines = lines[-limit:]

        events: list[SecurityTelemetryEvent] = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            payload = json.loads(line)
            events.append(
                SecurityTelemetryEvent(
                    eventid=str(payload.get("eventid", "")),
                    eventtype=str(payload.get("eventtype", "security.runtime.decision")),
                    occurredat=str(payload.get("occurredat", "")),
                    actorid=str(payload.get("actorid", "")),
                    sessionid=str(payload.get("sessionid", "")),
                    actiontype=str(payload.get("actiontype", "")),
                    target=str(payload.get("target", "")),
                    filepath=str(payload.get("filepath", "")),
                    executionstate=str(payload.get("executionstate", "")),
                    policyverdict=str(payload.get("policyverdict", "")),
                    responseaction=str(payload.get("responseaction", "")),
                    responsestatus=str(payload.get("responsestatus", "")),
                    shouldexecute=bool(payload.get("shouldexecute", False)),
                    haltedbyboundary=bool(payload.get("haltedbyboundary", False)),
                    reviewrequired=bool(payload.get("reviewrequired", False)),
                    quarantine=bool(payload.get("quarantine", False)),
                    adjustedriskscore=int(payload.get("adjustedriskscore", 0)),
                    reasons=list(payload.get("reasons", [])),
                    promptinjection=dict(payload.get("promptinjection", {})),
                    hostilecontext=dict(payload.get("hostilecontext", {})),
                    downloadanalysis=dict(payload.get("downloadanalysis", {})),
                    outputsanitization=dict(payload.get("outputsanitization", {})),
                    sessionrisk=dict(payload.get("sessionrisk", {})),
                    metadata=dict(payload.get("metadata", {})),
                )
            )
        return events

    def _build_event(
        self,
        *,
        actorid: str,
        sessionid: str | None,
        actiontype: str,
        target: str,
        filepath: str,
        decision: SecureRuntimeDecision,
        metadata: dict[str, Any],
        occurredat: str,
    ) -> SecurityTelemetryEvent:
        eventid = self._event_id(
            actorid=actorid,
            sessionid=sessionid or "anonymous",
            actiontype=actiontype,
            occurredat=occurredat,
        )

        return SecurityTelemetryEvent(
            eventid=eventid,
            eventtype="security.runtime.decision",
            occurredat=occurredat,
            actorid=actorid,
            sessionid=sessionid or "anonymous",
            actiontype=actiontype,
            target=target,
            filepath=filepath,
            executionstate=decision.executionstate,
            policyverdict=decision.policyverdict,
            responseaction=decision.responseaction,
            responsestatus=decision.responsestatus,
            shouldexecute=decision.shouldexecute,
            haltedbyboundary=decision.haltedbyboundary,
            reviewrequired=decision.reviewrequired,
            quarantine=decision.quarantine,
            adjustedriskscore=decision.adjustedriskscore,
            reasons=list(decision.reasons),
            promptinjection=dict(decision.promptinjection),
            hostilecontext=dict(decision.hostilecontext),
            downloadanalysis=dict(getattr(decision, "downloadanalysis", {}) or {}),
            outputsanitization=dict(getattr(decision, "outputsanitization", {}) or {}),
            sessionrisk=dict(getattr(decision, "sessionrisk", {}) or {}),
            metadata=dict(metadata),
        )

    def _append_event(self, event: SecurityTelemetryEvent) -> None:
        path = Path(self.telemetrypath)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event.as_dict(), ensure_ascii=False) + "\n")

    def _event_id(
        self,
        *,
        actorid: str,
        sessionid: str,
        actiontype: str,
        occurredat: str,
    ) -> str:
        compact_ts = occurredat.replace("-", "").replace(":", "").replace(".", "").replace("+00:00", "Z")
        return f"{self.eventprefix}-{actorid or 'unknown'}-{sessionid}-{actiontype}-{compact_ts}"

    def _timestamp(self) -> str:
        return datetime.now(UTC).isoformat()


def initializesecurityorchestrator(
    *,
    pipeline: SecureRuntimePipeline | None = None,
    telemetrypath: str = "output/security-events.jsonl",
    eventprefix: str = "sec",
) -> SecurityOrchestrator:
    return SecurityOrchestrator(
        pipeline=pipeline or getactionexecutepipeline(),
        telemetrypath=telemetrypath,
        eventprefix=eventprefix,
    )


def getsecurityorchestrator() -> SecurityOrchestrator:
    return initializesecurityorchestrator()