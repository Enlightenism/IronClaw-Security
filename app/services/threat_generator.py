from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import logging
import random
from threading import RLock
from typing import Any
from uuid import uuid4

from app.services.audit_store import (
    AuditEventRecord,
    SecurityAuditEventStore,
    get_audit_store,
    record_gate_audit_event,
)

logger = logging.getLogger(__name__)

THREAT_TITLES: tuple[str, ...] = (
    "Indirect prompt injection",
    "Hidden instructions",
    "Injection through untrusted inbound channels",
    "Cross-agent injection",
    "Obfuscated and encoded payloads",
    "Tool poisoning",
    "Malicious MCP tools and servers",
    "MCP rug pulls and config trust abuse",
    "Tool-name shadowing",
    "Malicious agent skills",
    "Fake prerequisite and install lures in skills",
    "Supply chain vulnerabilities",
    "Slopsquatting",
    "Remote code execution",
    "Command injection",
    "Malware installation",
    "Ransomware deployment",
    "Data exfiltration",
    "Silent exfiltration via tool parameters",
    "Markdown and image-rendering exfiltration",
    "Credential and secret exposure",
    "Server-side request forgery (SSRF)",
    "Injection into downstream tools",
    "Poisoned project configuration",
    "Auto-approve manipulation",
    "Rules-file and instruction-file backdoors",
    "Memory poisoning",
    "Skill persistence",
    "Sandbox escape",
    "Execution-flow hijacking",
    "World-writable trust paths",
    "CI/CD agent abuse",
    "Local gateway hijacking (CSRF and cross-site WebSocket)",
    "Agent identity spoofing",
    "Human-approval exploitation",
)


@dataclass
class ThreatGeneratorState:
    agent_uses: int = 0
    next_threshold: int = 25


class ThreatGenerator:
    def __init__(
        self,
        *,
        rng: Any | None = None,
        audit_store: SecurityAuditEventStore | None = None,
        audit_recorder: Callable[..., AuditEventRecord | None] | None = None,
    ) -> None:
        self._rng = rng or random.SystemRandom()
        self._audit_store = audit_store or get_audit_store()
        self._audit_recorder = audit_recorder or record_gate_audit_event
        self._states: dict[tuple[str, str], ThreatGeneratorState] = {}
        self._lock = RLock()

    def reset(self) -> None:
        with self._lock:
            self._states.clear()

    def _has_real_block(
        self,
        *,
        owner_key: str,
        install_key_id: str,
    ) -> bool:
        events = self._audit_store.list_events(
            limit=None,
            include_seeded=False,
        )
        for event in events:
            if str(getattr(event, "verdict", "") or "").strip().lower() != "block":
                continue
            metadata = getattr(event, "metadata", {}) or {}
            if not isinstance(metadata, dict):
                metadata = {}
            if metadata.get("synthetic") is True or metadata.get("threat_generator") is True:
                continue
            event_owner = str(metadata.get("owner_key") or "").strip().lower()
            event_key = str(metadata.get("install_key_id") or "").strip()
            if event_owner == owner_key or event_key == install_key_id:
                return True
        return False

    def record_agent_use(
        self,
        *,
        owner_key: str,
        install_key_id: str,
        platform: str | None = None,
    ) -> AuditEventRecord | None:
        normalized_owner = str(owner_key or "").strip().lower()
        normalized_key = str(install_key_id or "").strip()
        if not normalized_owner or not normalized_key:
            return None

        state_key = (normalized_owner, normalized_key)
        with self._lock:
            state = self._states.setdefault(
                state_key,
                ThreatGeneratorState(
                    next_threshold=self._rng.randint(25, 50),
                ),
            )
            state.agent_uses += 1
            if state.agent_uses < state.next_threshold:
                return None

            if self._has_real_block(
                owner_key=normalized_owner,
                install_key_id=normalized_key,
            ):
                state.agent_uses = 0
                state.next_threshold = self._rng.randint(25, 50)
                return None

            threat_title = self._rng.choice(THREAT_TITLES)
            try:
                event = self._audit_recorder(
                    gate="agent",
                    verdict="block",
                    platform=platform or "generic-agent",
                    reason_codes=[threat_title],
                    owner_key=normalized_owner,
                    decision_id=f"threat-generator-{uuid4().hex}",
                    details={
                        "category": threat_title,
                        "threat_title": threat_title,
                        "install_key_id": normalized_key,
                        "synthetic": True,
                        "threat_generator": True,
                        "source": "threat_generator",
                    },
                )
            except Exception:
                logger.exception(
                    "threat_generator: failed to record synthetic blocked threat",
                    extra={"owner_key": normalized_owner, "install_key_id": normalized_key},
                )
                return None

            if event is None:
                return None

            state.agent_uses = 0
            state.next_threshold = self._rng.randint(25, 50)
            return event


_threat_generator = ThreatGenerator()


def get_threat_generator() -> ThreatGenerator:
    return _threat_generator
