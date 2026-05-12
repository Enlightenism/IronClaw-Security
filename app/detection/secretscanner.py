from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class SecretFinding:
    label: str
    secret_type: str
    severity: str
    confidence: float
    start: int
    end: int
    match_text: str
    redacted_value: str
    risk_delta: int
    details: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "secret_type": self.secret_type,
            "severity": self.severity,
            "confidence": self.confidence,
            "start": self.start,
            "end": self.end,
            "match_text": self.match_text,
            "redacted_value": self.redacted_value,
            "risk_delta": self.risk_delta,
            "details": dict(self.details),
        }


@dataclass(frozen=True)
class SecretScanResult:
    found: bool
    findings: list[SecretFinding]
    risk_delta: int
    scanned_bytes: int
    truncated: bool
    summary: dict[str, int]

    def as_dict(self) -> dict[str, Any]:
        return {
            "found": self.found,
            "findings": [finding.as_dict() for finding in self.findings],
            "risk_delta": self.risk_delta,
            "scanned_bytes": self.scanned_bytes,
            "truncated": self.truncated,
            "summary": dict(self.summary),
        }


@dataclass(frozen=True)
class _SecretRule:
    label: str
    secret_type: str
    severity: str
    risk_delta: int
    confidence: float
    pattern: re.Pattern[str]
    min_match_length: int = 0


class SecretScanner:
    def __init__(
        self,
        *,
        max_scan_bytes: int = 512_000,
        max_findings: int = 100,
    ) -> None:
        self.max_scan_bytes = max_scan_bytes
        self.max_findings = max_findings
        self._rules = _build_rules()

    def scan_text(self, value: Any) -> SecretScanResult:
        text = self._to_text(value)
        scanned_text, truncated = self._truncate_text(text)
        findings = self._scan_string(scanned_text)
        return SecretScanResult(
            found=bool(findings),
            findings=findings,
            risk_delta=sum(finding.risk_delta for finding in findings),
            scanned_bytes=len(scanned_text.encode("utf-8", errors="ignore")),
            truncated=truncated,
            summary=self._summarize(findings),
        )

    def scan_arguments(self, arguments: Mapping[str, Any] | None) -> SecretScanResult:
        normalized = self._serialize_json(arguments or {})
        return self.scan_text(normalized)

    def scan_metadata(self, metadata: Mapping[str, Any] | None) -> SecretScanResult:
        normalized = self._serialize_json(metadata or {})
        return self.scan_text(normalized)

    def scan_payload(
        self,
        *,
        tool_name: str | None = None,
        arguments: Mapping[str, Any] | None = None,
        metadata: Mapping[str, Any] | None = None,
        content: Any = None,
    ) -> SecretScanResult:
        payload = {
            "tool_name": tool_name,
            "arguments": arguments or {},
            "metadata": metadata or {},
            "content": content,
        }
        return self.scan_text(self._serialize_json(payload))

    def scan_lines(self, lines: Sequence[str] | None) -> SecretScanResult:
        return self.scan_text("\n".join(lines or []))

    def scan_bytes(self, value: bytes | bytearray | None) -> SecretScanResult:
        if not value:
            return SecretScanResult(
                found=False,
                findings=[],
                risk_delta=0,
                scanned_bytes=0,
                truncated=False,
                summary={},
            )
        text = value.decode("utf-8", errors="ignore")
        return self.scan_text(text)

    def _scan_string(self, text: str) -> list[SecretFinding]:
        findings: list[SecretFinding] = []
        occupied: list[tuple[int, int, str]] = []

        for rule in self._rules:
            for match in rule.pattern.finditer(text):
                start, end = match.span()
                token = match.group(0)

                if len(token.strip()) < rule.min_match_length:
                    continue
                if self._should_skip_match(rule, token):
                    continue
                if self._overlaps_more_specific(occupied, start, end, rule.secret_type):
                    continue

                findings.append(
                    SecretFinding(
                        label=rule.label,
                        secret_type=rule.secret_type,
                        severity=rule.severity,
                        confidence=rule.confidence,
                        start=start,
                        end=end,
                        match_text=token,
                        redacted_value=self._redact_token(token),
                        risk_delta=rule.risk_delta,
                        details={
                            "fingerprint": self._fingerprint(token),
                            "length": len(token),
                        },
                    )
                )
                occupied.append((start, end, rule.secret_type))

                if len(findings) >= self.max_findings:
                    return findings

        return findings

    def _should_skip_match(self, rule: _SecretRule, token: str) -> bool:
        lowered = token.lower().strip()

        if "example" in lowered or "sample" in lowered or "test" in lowered:
            if rule.secret_type in {
                "aws_secret_key",
                "github_token",
                "slack_token",
                "private_key",
                "jwt",
                "bearer_token",
                "generic_api_key",
            }:
                return True

        if rule.secret_type == "generic_api_key":
            return self._looks_low_entropy(token)

        if rule.secret_type == "bearer_token":
            return self._looks_low_entropy(token.split(None, 1)[-1])

        if rule.secret_type == "jwt":
            return not self._looks_like_jwt(token)

        if rule.secret_type == "base64_blob":
            return self._looks_low_entropy(token)

        return False

    def _looks_low_entropy(self, token: str) -> bool:
        cleaned = re.sub(r"[^A-Za-z0-9+/=_-]", "", token)
        if len(cleaned) < 16:
            return True

        unique_ratio = len(set(cleaned)) / max(len(cleaned), 1)
        if unique_ratio < 0.22:
            return True

        entropy = self._shannon_entropy(cleaned)
        return entropy < 3.2

    def _looks_like_jwt(self, token: str) -> bool:
        parts = token.split(".")
        if len(parts) != 3:
            return False
        for part in parts[:2]:
            if not self._is_base64url_segment(part):
                return False
        return True

    def _is_base64url_segment(self, value: str) -> bool:
        if not re.fullmatch(r"[A-Za-z0-9_-]+", value):
            return False
        padding = "=" * ((4 - len(value) % 4) % 4)
        try:
            base64.urlsafe_b64decode(value + padding)
        except (binascii.Error, ValueError):
            return False
        return True

    def _shannon_entropy(self, value: str) -> float:
        if not value:
            return 0.0
        counts = {char: value.count(char) for char in set(value)}
        length = len(value)
        return -sum((count / length) * math.log2(count / length) for count in counts.values())

    def _overlaps_more_specific(
        self,
        occupied: Iterable[tuple[int, int, str]],
        start: int,
        end: int,
        secret_type: str,
    ) -> bool:
        for existing_start, existing_end, existing_type in occupied:
            overlap = not (end <= existing_start or start >= existing_end)
            if overlap and existing_type != secret_type:
                return True
        return False

    def _redact_token(self, token: str) -> str:
        stripped = token.strip()
        if len(stripped) <= 8:
            return "[REDACTED]"
        return f"{stripped[:4]}...[REDACTED]...{stripped[-4:]}"

    def _fingerprint(self, token: str) -> str:
        digest = hashlib.sha256(token.encode("utf-8", errors="ignore")).hexdigest()
        return digest[:16]

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

    def _truncate_text(self, text: str) -> tuple[str, bool]:
        raw = text.encode("utf-8", errors="ignore")
        if len(raw) <= self.max_scan_bytes:
            return text, False
        truncated = raw[: self.max_scan_bytes].decode("utf-8", errors="ignore")
        return truncated, True

    def _summarize(self, findings: Sequence[SecretFinding]) -> dict[str, int]:
        summary: dict[str, int] = {}
        for finding in findings:
            summary[finding.secret_type] = summary.get(finding.secret_type, 0) + 1
        return summary


def build_secret_scanner(
    *,
    max_scan_bytes: int = 512_000,
    max_findings: int = 100,
) -> SecretScanner:
    return SecretScanner(
        max_scan_bytes=max_scan_bytes,
        max_findings=max_findings,
    )


def _build_rules() -> list[_SecretRule]:
    return [
        _SecretRule(
            label="aws-access-key-id",
            secret_type="aws_access_key_id",
            severity="high",
            risk_delta=30,
            confidence=0.99,
            pattern=re.compile(r"\b(?:A3T|AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[A-Z0-9]{16}\b"),
            min_match_length=20,
        ),
        _SecretRule(
            label="aws-secret-access-key",
            secret_type="aws_secret_key",
            severity="critical",
            risk_delta=60,
            confidence=0.95,
            pattern=re.compile(
                r"(?i)(?:aws[\w\s._-]{0,24})?(?:secret|secret_access_key|secret-access-key)"
                r"[\s\"':=]{1,8}([A-Za-z0-9/+=]{40})"
            ),
            min_match_length=40,
        ),
        _SecretRule(
            label="github-token",
            secret_type="github_token",
            severity="critical",
            risk_delta=55,
            confidence=0.99,
            pattern=re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"),
            min_match_length=40,
        ),
        _SecretRule(
            label="slack-token",
            secret_type="slack_token",
            severity="critical",
            risk_delta=55,
            confidence=0.98,
            pattern=re.compile(r"\bxox(?:a|b|p|r|s)-[A-Za-z0-9-]{10,200}\b"),
            min_match_length=15,
        ),
        _SecretRule(
            label="stripe-secret-key",
            secret_type="stripe_secret_key",
            severity="critical",
            risk_delta=50,
            confidence=0.98,
            pattern=re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{16,128}\b"),
            min_match_length=20,
        ),
        _SecretRule(
            label="openai-api-key",
            secret_type="openai_api_key",
            severity="critical",
            risk_delta=55,
            confidence=0.99,
            pattern=re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
            min_match_length=24,
        ),
        _SecretRule(
            label="google-api-key",
            secret_type="google_api_key",
            severity="high",
            risk_delta=35,
            confidence=0.95,
            pattern=re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
            min_match_length=39,
        ),
        _SecretRule(
            label="jwt-token",
            secret_type="jwt",
            severity="high",
            risk_delta=35,
            confidence=0.92,
            pattern=re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
            min_match_length=24,
        ),
        _SecretRule(
            label="bearer-token",
            secret_type="bearer_token",
            severity="high",
            risk_delta=30,
            confidence=0.9,
            pattern=re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{16,}\b"),
            min_match_length=20,
        ),
        _SecretRule(
            label="private-key-block",
            secret_type="private_key",
            severity="critical",
            risk_delta=100,
            confidence=1.0,
            pattern=re.compile(
                r"-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PGP|PRIVATE)\s+PRIVATE\s+KEY-----[\s\S]{32,}"
                r"-----END\s+(?:RSA|DSA|EC|OPENSSH|PGP|PRIVATE)\s+PRIVATE\s+KEY-----"
            ),
            min_match_length=64,
        ),
        _SecretRule(
            label="pem-certificate-key-material",
            secret_type="pem_key_material",
            severity="high",
            risk_delta=45,
            confidence=0.93,
            pattern=re.compile(
                r"-----BEGIN\s+(?:OPENSSH PRIVATE KEY|ENCRYPTED PRIVATE KEY)-----[\s\S]{32,}"
                r"-----END\s+(?:OPENSSH PRIVATE KEY|ENCRYPTED PRIVATE KEY)-----"
            ),
            min_match_length=64,
        ),
        _SecretRule(
            label="database-url-with-credentials",
            secret_type="database_credentials",
            severity="critical",
            risk_delta=65,
            confidence=0.96,
            pattern=re.compile(
                r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis)://"
                r"[^/\s:@]+:[^/\s@]+@[^/\s]+"
            ),
            min_match_length=18,
        ),
        _SecretRule(
            label="generic-api-key-assignment",
            secret_type="generic_api_key",
            severity="medium",
            risk_delta=20,
            confidence=0.75,
            pattern=re.compile(
                r"(?i)\b(?:api[_-]?key|access[_-]?token|secret|token|client[_-]?secret)"
                r"\b[\s\"':=]{1,8}[\"']?([A-Za-z0-9_\-+/=]{16,})[\"']?"
            ),
            min_match_length=16,
        ),
        _SecretRule(
            label="high-entropy-base64-blob",
            secret_type="base64_blob",
            severity="medium",
            risk_delta=15,
            confidence=0.6,
            pattern=re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b"),
            min_match_length=40,
        ),
    ]