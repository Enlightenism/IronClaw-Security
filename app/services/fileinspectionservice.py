from __future__ import annotations

import base64
import binascii
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
import hashlib
import io
import re
from typing import Any
import zipfile

from app.services.secretservice import build_secret_service

_TEXT_EXTENSIONS = {
    ".env",
    ".ini",
    ".json",
    ".md",
    ".pem",
    ".properties",
    ".py",
    ".sh",
    ".sql",
    ".text",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}
_ARCHIVE_EXTENSIONS = {".zip", ".jar", ".whl"}
_EXECUTABLE_EXTENSIONS = {
    ".bat",
    ".cmd",
    ".com",
    ".dll",
    ".exe",
    ".js",
    ".msi",
    ".ps1",
    ".py",
    ".scr",
    ".sh",
}
_SUSPICIOUS_FILENAMES = {
    ".env",
    ".npmrc",
    ".pypirc",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_rsa",
    "known_hosts",
    "passwd",
    "shadow",
}
_SUSPICIOUS_PATH_PARTS = {
    ".aws",
    ".config",
    ".docker",
    ".git",
    ".gnupg",
    ".kube",
    ".ssh",
    "secrets",
}
_PRIVATE_KEY_MARKERS = (
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
)
_BINARY_MAGIC_LABELS: tuple[tuple[bytes, str], ...] = (
    (b"MZ", "windows-executable"),
    (b"\x7fELF", "elf-binary"),
    (b"\xca\xfe\xba\xbe", "java-class"),
    (b"\xfe\xed\xfa", "mach-o-binary"),
)
_DANGEROUS_MIME_PREFIXES = (
    "application/x-dosexec",
    "application/x-executable",
    "application/x-mach-binary",
    "application/x-msdownload",
)
_SUSPICIOUS_ARCHIVE_ENTRY_RE = re.compile(
    r"(^/)|(^[A-Za-z]:\\)|(^\\\\)|(?:^|/)\.\.(?:/|$)|(?:^|\\)\.\.(?:\\|$)",
)
_BASE64_RE = re.compile(r"\b(?:[A-Za-z0-9+/]{80,}={0,2})\b")
_HIGH_ENTROPY_RE = re.compile(r"\b[A-Za-z0-9_\-]{32,}\b")


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _coerce_mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return {str(k): v for k, v in value.items()}
    return {}


def _coerce_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8", errors="replace")
        except Exception:
            return ""
    return str(value)


def _extension_of(name: str) -> str:
    if "." not in name:
        return ""
    return "." + name.rsplit(".", 1)[-1].lower()


def _normalize_name(name: str) -> str:
    return name.replace("\\", "/").strip()


def _iter_path_parts(name: str) -> Iterable[str]:
    normalized = _normalize_name(name)
    for part in normalized.split("/"):
        part = part.strip()
        if part:
            yield part.lower()


def _looks_textual(data: bytes) -> bool:
    if not data:
        return True
    sample = data[:4096]
    if b"\x00" in sample:
        return False
    text_bytes = sum(1 for b in sample if 9 <= b <= 13 or 32 <= b <= 126)
    return (text_bytes / max(1, len(sample))) >= 0.85


def _truncate_text(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[:limit]


@dataclass(slots=True)
class FileInspectionDecision:
    verdict: str = "allow"
    allowed: bool = True
    blocked: bool = False
    should_review: bool = False
    should_quarantine: bool = False
    findings_detected: int = 0
    secrets_redacted: int = 0
    risk_delta: int = 0
    size_bytes: int = 0
    file_name: str = ""
    mime_type: str = "application/octet-stream"
    checksum_sha256: str = ""
    reasons: list[str] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    redaction: dict[str, Any] = field(default_factory=dict)
    content: dict[str, Any] = field(default_factory=dict)
    archive: dict[str, Any] = field(default_factory=dict)
    output: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "allowed": self.allowed,
            "blocked": self.blocked,
            "shouldreview": self.should_review,
            "shouldquarantine": self.should_quarantine,
            "findingsdetected": self.findings_detected,
            "secretsredacted": self.secrets_redacted,
            "riskdelta": self.risk_delta,
            "sizebytes": self.size_bytes,
            "filename": self.file_name,
            "mimetype": self.mime_type,
            "checksumsha256": self.checksum_sha256,
            "reasons": list(self.reasons),
            "findings": list(self.findings),
            "redaction": dict(self.redaction),
            "content": dict(self.content),
            "archive": dict(self.archive),
            "output": dict(self.output),
        }


class FileInspectionService:
    def __init__(
        self,
        *,
        secret_service: Any | None = None,
        max_inline_text_bytes: int = 65536,
        max_file_size_bytes: int = 25 * 1024 * 1024,
        max_archive_entries: int = 256,
        max_archive_total_uncompressed_bytes: int = 50 * 1024 * 1024,
    ) -> None:
        self._secret_service = secret_service or build_secret_service()
        self._max_inline_text_bytes = max_inline_text_bytes
        self._max_file_size_bytes = max_file_size_bytes
        self._max_archive_entries = max_archive_entries
        self._max_archive_total_uncompressed_bytes = max_archive_total_uncompressed_bytes

    def inspect_upload(
        self,
        *,
        file_name: str,
        content: bytes,
        mime_type: str | None = None,
        metadata: Mapping[str, Any] | None = None,
        context: str = "file_upload",
    ) -> FileInspectionDecision:
        return self._inspect_file(
            file_name=file_name,
            content=content,
            mime_type=mime_type,
            metadata=metadata,
            context=context,
            direction="ingress",
        )

    def inspect_download(
        self,
        *,
        file_name: str,
        content: bytes,
        mime_type: str | None = None,
        metadata: Mapping[str, Any] | None = None,
        context: str = "file_download",
    ) -> FileInspectionDecision:
        return self._inspect_file(
            file_name=file_name,
            content=content,
            mime_type=mime_type,
            metadata=metadata,
            context=context,
            direction="egress",
        )

    def inspect_artifact(
        self,
        *,
        file_name: str,
        content: bytes,
        mime_type: str | None = None,
        metadata: Mapping[str, Any] | None = None,
        context: str = "artifact_release",
    ) -> FileInspectionDecision:
        return self._inspect_file(
            file_name=file_name,
            content=content,
            mime_type=mime_type,
            metadata=metadata,
            context=context,
            direction="egress",
        )

    def inspect_batch(
        self,
        files: Sequence[Mapping[str, Any]],
        *,
        context: str = "file_batch",
        metadata: Mapping[str, Any] | None = None,
        direction: str = "ingress",
    ) -> dict[str, Any]:
        decisions: list[dict[str, Any]] = []
        highest_verdict = "allow"
        blocked = False
        should_review = False
        should_quarantine = False
        findings_detected = 0
        secrets_redacted = 0
        risk_delta = 0

        for item in files:
            mapping = _coerce_mapping(item)
            decision = self._inspect_file(
                file_name=_coerce_text(mapping.get("file_name") or mapping.get("name") or "unnamed"),
                content=mapping.get("content", b"") if isinstance(mapping.get("content"), bytes) else _coerce_text(mapping.get("content")).encode("utf-8", errors="replace"),
                mime_type=_coerce_text(mapping.get("mime_type") or mapping.get("content_type") or "application/octet-stream"),
                metadata={
                    **_coerce_mapping(metadata),
                    **_coerce_mapping(mapping.get("metadata")),
                    "direction": direction,
                },
                context=context,
                direction=direction,
            )
            decisions.append(decision.as_dict())
            highest_verdict = self._merge_verdict(highest_verdict, decision.verdict)
            blocked = blocked or decision.blocked
            should_review = should_review or decision.should_review
            should_quarantine = should_quarantine or decision.should_quarantine
            findings_detected += decision.findings_detected
            secrets_redacted += decision.secrets_redacted
            risk_delta += decision.risk_delta

        return {
            "verdict": highest_verdict,
            "allowed": not blocked,
            "blocked": blocked,
            "shouldreview": should_review,
            "shouldquarantine": should_quarantine,
            "findingsdetected": findings_detected,
            "secretsredacted": secrets_redacted,
            "riskdelta": risk_delta,
            "results": decisions,
        }

    def _inspect_file(
        self,
        *,
        file_name: str,
        content: bytes,
        mime_type: str | None,
        metadata: Mapping[str, Any] | None,
        context: str,
        direction: str,
    ) -> FileInspectionDecision:
        normalized_name = _normalize_name(file_name or "unnamed")
        effective_mime = (mime_type or "application/octet-stream").strip() or "application/octet-stream"
        metadata_map = _coerce_mapping(metadata)
        metadata_map.setdefault("direction", direction)
        size_bytes = len(content)
        extension = _extension_of(normalized_name)

        findings: list[dict[str, Any]] = []
        reasons: list[str] = []
        risk_delta = 0
        verdict = "allow"
        allowed = True
        blocked = False
        should_review = False
        should_quarantine = False

        checksum = _sha256_bytes(content)

        if size_bytes > self._max_file_size_bytes:
            findings.append(
                {
                    "label": "oversized-file",
                    "severity": "high",
                    "size_bytes": size_bytes,
                    "max_size_bytes": self._max_file_size_bytes,
                },
            )
            reasons.append("File exceeds maximum allowed size.")
            risk_delta += 35
            verdict = self._merge_verdict(verdict, "block")
            allowed = False
            blocked = True

        if any(part in _SUSPICIOUS_PATH_PARTS for part in _iter_path_parts(normalized_name)):
            findings.append(
                {
                    "label": "suspicious-path",
                    "severity": "medium",
                    "path": normalized_name,
                },
            )
            reasons.append("File path contains restricted or sensitive directory markers.")
            risk_delta += 18
            verdict = self._merge_verdict(verdict, "review")
            should_review = True

        basename = normalized_name.rsplit("/", 1)[-1].lower()
        if basename in _SUSPICIOUS_FILENAMES:
            findings.append(
                {
                    "label": "sensitive-filename",
                    "severity": "high",
                    "file_name": basename,
                },
            )
            reasons.append("File name matches a known sensitive credential or system artifact.")
            risk_delta += 30
            verdict = self._merge_verdict(verdict, "review")
            should_review = True

        if extension in _EXECUTABLE_EXTENSIONS:
            findings.append(
                {
                    "label": "executable-extension",
                    "severity": "high",
                    "extension": extension,
                },
            )
            reasons.append("Executable or script file detected.")
            risk_delta += 28
            verdict = self._merge_verdict(verdict, "review")
            should_review = True

        for magic, label in _BINARY_MAGIC_LABELS:
            if content.startswith(magic):
                findings.append(
                    {
                        "label": "dangerous-binary",
                        "severity": "high",
                        "magic": label,
                    },
                )
                reasons.append("Binary executable content detected.")
                risk_delta += 45
                verdict = self._merge_verdict(verdict, "block")
                allowed = False
                blocked = True
                break

        if any(effective_mime.startswith(prefix) for prefix in _DANGEROUS_MIME_PREFIXES):
            findings.append(
                {
                    "label": "dangerous-mime-type",
                    "severity": "high",
                    "mime_type": effective_mime,
                },
            )
            reasons.append("Dangerous executable MIME type detected.")
            risk_delta += 35
            verdict = self._merge_verdict(verdict, "block")
            allowed = False
            blocked = True

        archive_report: dict[str, Any] = {
            "is_archive": extension in _ARCHIVE_EXTENSIONS or zipfile.is_zipfile(io.BytesIO(content)),
            "entries": [],
            "entry_count": 0,
            "total_uncompressed_bytes": 0,
            "suspicious_entries": 0,
            "blocked": False,
        }
        if archive_report["is_archive"]:
            (
                archive_findings,
                archive_reasons,
                archive_risk,
                archive_verdict,
                archive_allowed,
                archive_blocked,
                archive_review,
                archive_quarantine,
                archive_payload,
            ) = self._inspect_archive(
                normalized_name=normalized_name,
                content=content,
            )
            findings.extend(archive_findings)
            reasons.extend(archive_reasons)
            risk_delta += archive_risk
            verdict = self._merge_verdict(verdict, archive_verdict)
            allowed = allowed and archive_allowed
            blocked = blocked or archive_blocked
            should_review = should_review or archive_review
            should_quarantine = should_quarantine or archive_quarantine
            archive_report = archive_payload

        extracted_text = ""
        decoded_from_binary = False
        if _looks_textual(content) or extension in _TEXT_EXTENSIONS:
            extracted_text = _truncate_text(content.decode("utf-8", errors="replace"), self._max_inline_text_bytes)
        else:
            decoded = self._attempt_base64_decode(content)
            if decoded:
                decoded_from_binary = True
                extracted_text = _truncate_text(decoded, self._max_inline_text_bytes)

        if extracted_text:
            secret_result = self._secret_service.inspect_text(
                extracted_text,
                context=context,
                metadata={
                    **metadata_map,
                    "file_name": normalized_name,
                    "mime_type": effective_mime,
                    "size_bytes": size_bytes,
                },
            )
            findings.append(
                {
                    "label": "secret-scan",
                    "severity": "medium" if secret_result.findings_detected else "info",
                    "findings_detected": secret_result.findings_detected,
                    "secrets_redacted": secret_result.secrets_redacted,
                    "verdict": secret_result.verdict,
                },
            )
            if secret_result.findings_detected:
                reasons.append("Sensitive content indicators were detected in file content.")
            risk_delta += _safe_int(getattr(secret_result, "risk_delta", 0))
            verdict = self._merge_verdict(verdict, getattr(secret_result, "verdict", "allow"))
            should_review = should_review or bool(getattr(secret_result, "should_review", False))
            should_quarantine = should_quarantine or bool(getattr(secret_result, "should_quarantine", False))
            if getattr(secret_result, "blocked", False):
                blocked = True
                allowed = False

            if any(marker in extracted_text for marker in _PRIVATE_KEY_MARKERS):
                findings.append(
                    {
                        "label": "private-key-material",
                        "severity": "critical",
                    },
                )
                reasons.append("Private key material detected in file content.")
                risk_delta += 50
                verdict = self._merge_verdict(verdict, "quarantine")
                blocked = True
                allowed = False
                should_quarantine = True

            if _BASE64_RE.search(extracted_text):
                findings.append(
                    {
                        "label": "encoded-payload",
                        "severity": "medium",
                    },
                )
                reasons.append("Large encoded payload detected.")
                risk_delta += 12
                verdict = self._merge_verdict(verdict, "review")
                should_review = True

            if "nc " in extracted_text or "curl " in extracted_text or "wget " in extracted_text:
                findings.append(
                    {
                        "label": "unsafe-command-content",
                        "severity": "high",
                    },
                )
                reasons.append("Command content may support outbound exfiltration or remote code execution.")
                risk_delta += 18
                verdict = self._merge_verdict(verdict, "review")
                should_review = True

            redaction = dict(getattr(secret_result, "redaction", {}))
            secrets_redacted = _safe_int(getattr(secret_result, "secrets_redacted", 0))
            findings_detected = len(findings) + _safe_int(getattr(secret_result, "findings_detected", 0))
            output = {
                "sanitized": bool(redaction.get("changed", False)),
                "sanitized_text": redaction.get("text", extracted_text),
                "blocked": blocked,
                "decodedfrombinary": decoded_from_binary,
            }
            content_report = {
                "is_text": True,
                "decodedfrombinary": decoded_from_binary,
                "sample": output["sanitized_text"][:512],
                "containsbase64": bool(_BASE64_RE.search(extracted_text)),
                "highentropytokens": len(_HIGH_ENTROPY_RE.findall(extracted_text)),
            }
        else:
            redaction = {"changed": False, "text": ""}
            secrets_redacted = 0
            findings_detected = len(findings)
            output = {
                "sanitized": False,
                "sanitized_text": "",
                "blocked": blocked,
                "decodedfrombinary": False,
            }
            content_report = {
                "is_text": False,
                "decodedfrombinary": False,
                "sample": "",
                "containsbase64": False,
                "highentropytokens": 0,
            }

        if not reasons:
            reasons.append("File cleared inspection checks.")

        if blocked and verdict == "allow":
            verdict = "block"
        if should_quarantine and verdict not in {"quarantine"}:
            verdict = self._merge_verdict(verdict, "quarantine")

        return FileInspectionDecision(
            verdict=verdict,
            allowed=allowed and not blocked,
            blocked=blocked,
            should_review=should_review,
            should_quarantine=should_quarantine,
            findings_detected=findings_detected,
            secrets_redacted=secrets_redacted,
            risk_delta=risk_delta,
            size_bytes=size_bytes,
            file_name=normalized_name,
            mime_type=effective_mime,
            checksum_sha256=checksum,
            reasons=self._dedupe_reasons(reasons),
            findings=findings,
            redaction=redaction,
            content=content_report,
            archive=archive_report,
            output=output,
        )

    def _inspect_archive(
        self,
        *,
        normalized_name: str,
        content: bytes,
    ) -> tuple[list[dict[str, Any]], list[str], int, str, bool, bool, bool, bool, dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        reasons: list[str] = []
        risk_delta = 0
        verdict = "allow"
        allowed = True
        blocked = False
        should_review = False
        should_quarantine = False
        payload: dict[str, Any] = {
            "is_archive": True,
            "entries": [],
            "entry_count": 0,
            "total_uncompressed_bytes": 0,
            "suspicious_entries": 0,
            "blocked": False,
        }

        try:
            with zipfile.ZipFile(io.BytesIO(content), "r") as archive:
                infos = archive.infolist()
                payload["entry_count"] = len(infos)

                if len(infos) > self._max_archive_entries:
                    findings.append(
                        {
                            "label": "archive-too-many-entries",
                            "severity": "high",
                            "entry_count": len(infos),
                            "max_entries": self._max_archive_entries,
                        },
                    )
                    reasons.append("Archive contains too many entries.")
                    risk_delta += 30
                    verdict = self._merge_verdict(verdict, "block")
                    allowed = False
                    blocked = True

                total_uncompressed = 0
                suspicious_entries = 0

                for info in infos[: self._max_archive_entries]:
                    entry_name = _normalize_name(info.filename)
                    entry_size = int(info.file_size)
                    total_uncompressed += entry_size
                    entry_flags: list[str] = []

                    if _SUSPICIOUS_ARCHIVE_ENTRY_RE.search(entry_name):
                        entry_flags.append("path-traversal")
                    if _extension_of(entry_name) in _EXECUTABLE_EXTENSIONS:
                        entry_flags.append("embedded-executable")
                    if entry_name.rsplit("/", 1)[-1].lower() in _SUSPICIOUS_FILENAMES:
                        entry_flags.append("embedded-sensitive-file")
                    if any(part in _SUSPICIOUS_PATH_PARTS for part in _iter_path_parts(entry_name)):
                        entry_flags.append("embedded-sensitive-path")

                    if entry_flags:
                        suspicious_entries += 1
                        findings.append(
                            {
                                "label": "suspicious-archive-entry",
                                "severity": "high",
                                "entry": entry_name,
                                "flags": list(entry_flags),
                            },
                        )
                        reasons.append(f"Archive entry flagged: {entry_name}.")
                        risk_delta += 14
                        verdict = self._merge_verdict(verdict, "review")
                        should_review = True

                    payload["entries"].append(
                        {
                            "name": entry_name,
                            "size_bytes": entry_size,
                            "flags": list(entry_flags),
                        },
                    )

                payload["total_uncompressed_bytes"] = total_uncompressed
                payload["suspicious_entries"] = suspicious_entries

                if total_uncompressed > self._max_archive_total_uncompressed_bytes:
                    findings.append(
                        {
                            "label": "archive-too-large-uncompressed",
                            "severity": "high",
                            "total_uncompressed_bytes": total_uncompressed,
                            "max_total_uncompressed_bytes": self._max_archive_total_uncompressed_bytes,
                        },
                    )
                    reasons.append("Archive expands beyond allowed uncompressed size.")
                    risk_delta += 35
                    verdict = self._merge_verdict(verdict, "block")
                    allowed = False
                    blocked = True

                if suspicious_entries > 0 and not blocked:
                    verdict = self._merge_verdict(verdict, "review")

                payload["blocked"] = blocked

        except zipfile.BadZipFile:
            findings.append(
                {
                    "label": "invalid-archive",
                    "severity": "high",
                    "file_name": normalized_name,
                },
            )
            reasons.append("Archive content is malformed or unreadable.")
            risk_delta += 25
            verdict = self._merge_verdict(verdict, "block")
            allowed = False
            blocked = True
            payload["blocked"] = True

        return (
            findings,
            reasons,
            risk_delta,
            verdict,
            allowed,
            blocked,
            should_review,
            should_quarantine,
            payload,
        )

    def _attempt_base64_decode(self, content: bytes) -> str:
        raw_text = _coerce_text(content)
        candidate = raw_text.strip()
        if len(candidate) < 80:
            return ""
        if not _BASE64_RE.search(candidate):
            return ""
        try:
            decoded = base64.b64decode(candidate, validate=True)
        except (binascii.Error, ValueError):
            return ""
        if not decoded:
            return ""
        if not _looks_textual(decoded):
            return ""
        return decoded.decode("utf-8", errors="replace")

    def _merge_verdict(self, left: str, right: str) -> str:
        rank = {
            "allow": 0,
            "sanitize": 1,
            "review": 2,
            "block": 3,
            "quarantine": 4,
        }
        return right if rank.get(right, 0) > rank.get(left, 0) else left

    def _dedupe_reasons(self, reasons: Sequence[str]) -> list[str]:
        seen: set[str] = set()
        ordered: list[str] = []
        for reason in reasons:
            normalized = reason.strip()
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            ordered.append(normalized)
        return ordered[:10]


def build_file_inspection_service(
    *,
    secret_service: Any | None = None,
    max_inline_text_bytes: int = 65536,
    max_file_size_bytes: int = 25 * 1024 * 1024,
    max_archive_entries: int = 256,
    max_archive_total_uncompressed_bytes: int = 50 * 1024 * 1024,
) -> FileInspectionService:
    return FileInspectionService(
        secret_service=secret_service,
        max_inline_text_bytes=max_inline_text_bytes,
        max_file_size_bytes=max_file_size_bytes,
        max_archive_entries=max_archive_entries,
        max_archive_total_uncompressed_bytes=max_archive_total_uncompressed_bytes,
    )
