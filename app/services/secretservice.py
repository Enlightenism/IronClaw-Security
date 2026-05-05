from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from app.detection.outputsanitizer import OutputSanitizationResult, build_output_sanitizer
from app.detection.secretscanner import SecretScanResult, build_secret_scanner
from app.runtime.networkguard import NetworkPolicy, build_network_guard
from app.services.secretsredaction import SecretsRedactionResult, build_secrets_redaction_service


@dataclass(slots=True)
class SecretServiceResult:
    verdict: str
    allowed: bool
    blocked: bool
    should_review: bool
    should_quarantine: bool
    score: float
    risk_delta: int
    findings_detected: int
    secrets_redacted: int
    network_verdict: str
    output_verdict: str
    scan: dict[str, Any] = field(default_factory=dict)
    redaction: dict[str, Any] = field(default_factory=dict)
    output: dict[str, Any] = field(default_factory=dict)
    network: dict[str, Any] = field(default_factory=dict)
    reasons: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "allowed": self.allowed,
            "blocked": self.blocked,
            "shouldreview": self.should_review,
            "shouldquarantine": self.should_quarantine,
            "score": float(self.score),
            "riskdelta": int(self.risk_delta),
            "findingsdetected": int(self.findings_detected),
            "secretsredacted": int(self.secrets_redacted),
            "networkverdict": self.network_verdict,
            "outputverdict": self.output_verdict,
            "scan": dict(self.scan),
            "redaction": dict(self.redaction),
            "output": dict(self.output),
            "network": dict(self.network),
            "reasons": list(self.reasons),
        }


class SecretService:
    def __init__(self) -> None:
        self._scanner = build_secret_scanner()
        self._redaction = build_secrets_redaction_service()
        self._output_sanitizer = build_output_sanitizer()
        self._network_guard = build_network_guard()

    def inspect_text(
        self,
        text: str,
        *,
        context: str | None = None,
        metadata: Mapping[str, Any] | None = None,
        redact_secrets: bool = True,
        block_unsafe_commands: bool = True,
    ) -> SecretServiceResult:
        original_text = text or ""
        scan_result = self._scanner.scan_text(original_text)
        redaction_result = self._redaction.redact_text(original_text)
        output_result = self._output_sanitizer.sanitize(
            redaction_result.text,
            context=context,
            redact_secrets=False,
            block_unsafe_commands=block_unsafe_commands,
        )
        network_result = self._evaluate_network(metadata=metadata)
        return self._compose_result(
            scan_result=scan_result,
            redaction_result=redaction_result if redact_secrets else self._noop_redaction(original_text),
            output_result=output_result,
            network_result=network_result,
            context=context,
        )

    def inspect_arguments(
        self,
        arguments: Mapping[str, Any] | None,
        *,
        context: str | None = None,
        metadata: Mapping[str, Any] | None = None,
        redact_secrets: bool = True,
        block_unsafe_commands: bool = True,
    ) -> SecretServiceResult:
        payload = arguments or {}
        scan_result = self._scanner.scan_arguments(payload)
        redaction_result = self._redaction.redact_arguments(payload)
        output_result = self._output_sanitizer.sanitize(
            redaction_result.text,
            context=context,
            redact_secrets=False,
            block_unsafe_commands=block_unsafe_commands,
        )
        network_result = self._evaluate_network(metadata=metadata)
        return self._compose_result(
            scan_result=scan_result,
            redaction_result=redaction_result if redact_secrets else self._noop_redaction(redaction_result.text),
            output_result=output_result,
            network_result=network_result,
            context=context,
        )

    def inspect_metadata(
        self,
        metadata: Mapping[str, Any] | None,
        *,
        context: str | None = None,
        redact_secrets: bool = True,
        block_unsafe_commands: bool = True,
    ) -> SecretServiceResult:
        payload = metadata or {}
        scan_result = self._scanner.scan_metadata(payload)
        redaction_result = self._redaction.redact_metadata(payload)
        output_result = self._output_sanitizer.sanitize(
            redaction_result.text,
            context=context,
            redact_secrets=False,
            block_unsafe_commands=block_unsafe_commands,
        )
        network_result = self._evaluate_network(metadata=payload)
        return self._compose_result(
            scan_result=scan_result,
            redaction_result=redaction_result if redact_secrets else self._noop_redaction(redaction_result.text),
            output_result=output_result,
            network_result=network_result,
            context=context,
        )

    def inspect_payload(
        self,
        *,
        tool_name: str | None = None,
        arguments: Mapping[str, Any] | None = None,
        metadata: Mapping[str, Any] | None = None,
        content: Any = None,
        context: str | None = None,
        redact_secrets: bool = True,
        block_unsafe_commands: bool = True,
    ) -> SecretServiceResult:
        scan_result = self._scanner.scan_payload(
            tool_name=tool_name,
            arguments=arguments,
            metadata=metadata,
            content=content,
        )
        redaction_result = self._redaction.redact_payload(
            tool_name=tool_name,
            arguments=arguments,
            metadata=metadata,
            content=content,
        )
        output_result = self._output_sanitizer.sanitize(
            redaction_result.text,
            context=context or tool_name,
            redact_secrets=False,
            block_unsafe_commands=block_unsafe_commands,
        )
        network_result = self._evaluate_network(metadata=metadata)
        return self._compose_result(
            scan_result=scan_result,
            redaction_result=redaction_result if redact_secrets else self._noop_redaction(redaction_result.text),
            output_result=output_result,
            network_result=network_result,
            context=context or tool_name,
        )

    def inspect_lines(
        self,
        lines: Sequence[str] | None,
        *,
        context: str | None = None,
        metadata: Mapping[str, Any] | None = None,
        redact_secrets: bool = True,
        block_unsafe_commands: bool = True,
    ) -> SecretServiceResult:
        text = "\n".join(lines or [])
        return self.inspect_text(
            text,
            context=context,
            metadata=metadata,
            redact_secrets=redact_secrets,
            block_unsafe_commands=block_unsafe_commands,
        )

    def _evaluate_network(self, *, metadata: Mapping[str, Any] | None) -> NetworkPolicy:
        metadata_map = dict(metadata or {})
        url = str(metadata_map.get("url") or "").strip()
        method = str(metadata_map.get("method") or "GET").upper()
        if not url:
            return self._network_guard.evaluate(
                url="https://api.openai.com/v1/models",
                method="GET",
                metadata={"direction": metadata_map.get("direction", "egress")},
            )
        return self._network_guard.evaluate(
            url=url,
            method=method,
            metadata=metadata_map,
        )

    def _compose_result(
        self,
        *,
        scan_result: SecretScanResult,
        redaction_result: SecretsRedactionResult,
        output_result: OutputSanitizationResult,
        network_result: NetworkPolicy,
        context: str | None,
    ) -> SecretServiceResult:
        findings_detected = len(scan_result.findings)
        secrets_redacted = int(redaction_result.findings_redacted)
        score = self._resolve_score(
            scan_result=scan_result,
            output_result=output_result,
            network_result=network_result,
            secrets_redacted=secrets_redacted,
        )
        risk_delta = self._resolve_risk_delta(
            scan_result=scan_result,
            output_result=output_result,
            network_result=network_result,
            secrets_redacted=secrets_redacted,
        )
        verdict = self._resolve_verdict(
            scan_result=scan_result,
            output_result=output_result,
            network_result=network_result,
            score=score,
        )
        blocked = verdict == "block"
        allowed = not blocked
        should_quarantine = verdict == "quarantine"
        should_review = verdict == "review"
        reasons = self._build_reasons(
            scan_result=scan_result,
            redaction_result=redaction_result,
            output_result=output_result,
            network_result=network_result,
            verdict=verdict,
            context=context,
        )

        return SecretServiceResult(
            verdict=verdict,
            allowed=allowed,
            blocked=blocked,
            should_review=should_review,
            should_quarantine=should_quarantine,
            score=score,
            risk_delta=risk_delta,
            findings_detected=findings_detected,
            secrets_redacted=secrets_redacted,
            network_verdict=network_result.verdict,
            output_verdict=output_result.verdict,
            scan=scan_result.as_dict(),
            redaction=redaction_result.as_dict(),
            output=output_result.as_dict(),
            network=network_result.as_dict(),
            reasons=reasons,
        )

    def _resolve_score(
        self,
        *,
        scan_result: SecretScanResult,
        output_result: OutputSanitizationResult,
        network_result: NetworkPolicy,
        secrets_redacted: int,
    ) -> float:
        scan_component = min(float(scan_result.score), 1.0)
        output_component = min(float(output_result.score), 1.0)
        network_component = min(max(network_result.risk_delta, 0) / 100.0, 1.0)
        redaction_component = min(secrets_redacted * 0.08, 0.24)
        score = max(scan_component, output_component, network_component)
        score = max(score, min(scan_component + redaction_component, 1.0))
        if network_result.should_quarantine:
            score = max(score, 0.95)
        elif network_result.should_block:
            score = max(score, 0.80)
        elif output_result.blocked:
            score = max(score, 0.78)
        return round(min(score, 1.0), 4)

    def _resolve_risk_delta(
        self,
        *,
        scan_result: SecretScanResult,
        output_result: OutputSanitizationResult,
        network_result: NetworkPolicy,
        secrets_redacted: int,
    ) -> int:
        base = max(
            int(scan_result.risk_delta),
            int(network_result.risk_delta),
            int(round(output_result.score * 100)),
        )
        if secrets_redacted > 0:
            base = max(base, min(100, base + min(secrets_redacted * 4, 20)))
        return max(0, min(100, int(base)))

    def _resolve_verdict(
        self,
        *,
        scan_result: SecretScanResult,
        output_result: OutputSanitizationResult,
        network_result: NetworkPolicy,
        score: float,
    ) -> str:
        if network_result.should_quarantine:
            return "quarantine"
        if network_result.should_block or output_result.blocked:
            return "block"
        if scan_result.found and score >= 0.80:
            return "block"
        if output_result.verdict == "sanitize":
            return "sanitize"
        if network_result.should_review or output_result.verdict == "review" or scan_result.found:
            return "review"
        return "allow"

    def _build_reasons(
        self,
        *,
        scan_result: SecretScanResult,
        redaction_result: SecretsRedactionResult,
        output_result: OutputSanitizationResult,
        network_result: NetworkPolicy,
        verdict: str,
        context: str | None,
    ) -> list[str]:
        reasons: list[str] = [f"SecretService resolved verdict '{verdict}'."]
        if context:
            reasons.append(f"Context: {context}.")
        if scan_result.found:
            reasons.append(
                f"Secret scanner detected {len(scan_result.findings)} potential secret finding(s)."
            )
        if redaction_result.changed:
            reasons.append(
                f"Redaction transformed content and removed {redaction_result.findings_redacted} finding instance(s)."
            )
        if output_result.sanitized:
            reasons.append("Output sanitizer transformed content before release.")
        if output_result.blocked:
            reasons.append("Output sanitizer blocked unsafe content.")
        if network_result.verdict != "allow":
            reasons.append(
                f"Network guard returned verdict '{network_result.verdict}' for outbound context."
            )

        reasons.extend(str(item) for item in output_result.reasons[:3])

        if not scan_result.found and not redaction_result.changed and network_result.verdict == "allow":
            reasons.append("No secret, sanitization, or egress risk indicators were detected.")

        return reasons[:10]

    def _noop_redaction(self, text: str) -> SecretsRedactionResult:
        return SecretsRedactionResult(
            text=text,
            changed=False,
            findings_detected=0,
            findings_redacted=0,
            risk_delta=0,
            records=[],
            scan={},
        )


def build_secret_service() -> SecretService:
    return SecretService()


__all__ = [
    "SecretServiceResult",
    "SecretService",
    "build_secret_service",
]