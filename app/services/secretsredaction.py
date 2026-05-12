from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from app.detection.secretscanner import SecretFinding, SecretScanResult, build_secret_scanner


@dataclass(frozen=True)
class RedactionRecord:
    label: str
    secret_type: str
    severity: str
    original_fingerprint: str
    replacement: str
    count: int
    details: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "secret_type": self.secret_type,
            "severity": self.severity,
            "original_fingerprint": self.original_fingerprint,
            "replacement": self.replacement,
            "count": self.count,
            "details": dict(self.details),
        }


@dataclass(frozen=True)
class SecretsRedactionResult:
    text: str
    changed: bool
    findings_detected: int
    findings_redacted: int
    risk_delta: int
    records: list[RedactionRecord]
    scan: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "text": self.text,
            "changed": self.changed,
            "findings_detected": self.findings_detected,
            "findings_redacted": self.findings_redacted,
            "risk_delta": self.risk_delta,
            "records": [record.as_dict() for record in self.records],
            "scan": dict(self.scan),
        }


class SecretsRedactionService:
    def __init__(self) -> None:
        self._scanner = build_secret_scanner()

    def redact_text(self, value: Any) -> SecretsRedactionResult:
        original_text = self._to_text(value)
        scan_result = self._scanner.scan_text(original_text)
        redacted_text, records = self._apply_redactions(original_text, scan_result)
        return SecretsRedactionResult(
            text=redacted_text,
            changed=redacted_text != original_text,
            findings_detected=len(scan_result.findings),
            findings_redacted=sum(record.count for record in records),
            risk_delta=scan_result.risk_delta,
            records=records,
            scan=scan_result.as_dict(),
        )

    def redact_arguments(self, arguments: Mapping[str, Any] | None) -> SecretsRedactionResult:
        payload = arguments or {}
        original_text = self._serialize_json(payload)
        scan_result = self._scanner.scan_arguments(payload)
        redacted_text, records = self._apply_redactions(original_text, scan_result)
        return SecretsRedactionResult(
            text=redacted_text,
            changed=redacted_text != original_text,
            findings_detected=len(scan_result.findings),
            findings_redacted=sum(record.count for record in records),
            risk_delta=scan_result.risk_delta,
            records=records,
            scan=scan_result.as_dict(),
        )

    def redact_metadata(self, metadata: Mapping[str, Any] | None) -> SecretsRedactionResult:
        payload = metadata or {}
        original_text = self._serialize_json(payload)
        scan_result = self._scanner.scan_metadata(payload)
        redacted_text, records = self._apply_redactions(original_text, scan_result)
        return SecretsRedactionResult(
            text=redacted_text,
            changed=redacted_text != original_text,
            findings_detected=len(scan_result.findings),
            findings_redacted=sum(record.count for record in records),
            risk_delta=scan_result.risk_delta,
            records=records,
            scan=scan_result.as_dict(),
        )

    def redact_payload(
        self,
        *,
        tool_name: str | None = None,
        arguments: Mapping[str, Any] | None = None,
        metadata: Mapping[str, Any] | None = None,
        content: Any = None,
    ) -> SecretsRedactionResult:
        payload = {
            "tool_name": tool_name,
            "arguments": arguments or {},
            "metadata": metadata or {},
            "content": content,
        }
        original_text = self._serialize_json(payload)
        scan_result = self._scanner.scan_payload(
            tool_name=tool_name,
            arguments=arguments,
            metadata=metadata,
            content=content,
        )
        redacted_text, records = self._apply_redactions(original_text, scan_result)
        return SecretsRedactionResult(
            text=redacted_text,
            changed=redacted_text != original_text,
            findings_detected=len(scan_result.findings),
            findings_redacted=sum(record.count for record in records),
            risk_delta=scan_result.risk_delta,
            records=records,
            scan=scan_result.as_dict(),
        )

    def redact_lines(self, lines: Sequence[str] | None) -> SecretsRedactionResult:
        return self.redact_text("\n".join(lines or []))

    def _apply_redactions(
        self,
        original_text: str,
        scan_result: SecretScanResult,
    ) -> tuple[str, list[RedactionRecord]]:
        if not scan_result.findings:
            return original_text, []

        redacted_text = original_text
        grouped: dict[tuple[str, str], dict[str, Any]] = {}

        ordered_findings = sorted(
            scan_result.findings,
            key=lambda item: (item.start, item.end - item.start),
            reverse=True,
        )

        for finding in ordered_findings:
            replacement = self._replacement_for(finding)
            redacted_text = self._replace_span(
                text=redacted_text,
                start=finding.start,
                end=finding.end,
                replacement=replacement,
            )

            group_key = (finding.secret_type, finding.details.get("fingerprint", ""))
            bucket = grouped.setdefault(
                group_key,
                {
                    "label": finding.label,
                    "secret_type": finding.secret_type,
                    "severity": finding.severity,
                    "original_fingerprint": finding.details.get("fingerprint", ""),
                    "replacement": replacement,
                    "count": 0,
                    "details": {
                        "length": finding.details.get("length"),
                    },
                },
            )
            bucket["count"] += 1

        records = [
            RedactionRecord(
                label=value["label"],
                secret_type=value["secret_type"],
                severity=value["severity"],
                original_fingerprint=value["original_fingerprint"],
                replacement=value["replacement"],
                count=value["count"],
                details=value["details"],
            )
            for value in grouped.values()
        ]
        records.sort(key=lambda item: (item.severity, item.secret_type, item.original_fingerprint))
        return redacted_text, records

    def _replacement_for(self, finding: SecretFinding) -> str:
        token = finding.match_text
        secret_type = finding.secret_type

        if secret_type in {"private_key", "pem_key_material"}:
            return f"[REDACTED:{secret_type.upper()}]"

        if secret_type == "database_credentials":
            return self._redact_database_url(token)

        return f"[REDACTED:{secret_type.upper()}:{finding.details.get('fingerprint', 'unknown')}]"

    def _redact_database_url(self, token: str) -> str:
        return re.sub(r"//([^:/@\s]+):([^@/\s]+)@", r"//\1:[REDACTED]@", token, count=1)

    def _replace_span(self, *, text: str, start: int, end: int, replacement: str) -> str:
        if start < 0 or end < start or end > len(text):
            snippet = text[max(0, start - 16) : min(len(text), end + 16)]
            escaped = re.escape(snippet)
            if escaped:
                return text.replace(snippet, replacement, 1)
            return text
        return f"{text[:start]}{replacement}{text[end:]}"

    def _to_text(self, value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, str):
            return value
        if isinstance(value, (bytes, bytearray)):
            return value.decode("utf-8", errors="ignore")
        if isinstance(value, Mapping):
            return self._serialize_json(value)
        if isinstance(value, (list, tuple, set)):
            return self._serialize_json(list(value))
        return str(value)

    def _serialize_json(self, value: Any) -> str:
        try:
            return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
        except Exception:
            return str(value)


def build_secrets_redaction_service() -> SecretsRedactionService:
    return SecretsRedactionService()