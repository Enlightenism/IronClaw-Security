from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
import io
import mimetypes
import os
from pathlib import Path
import re
from typing import Any
import zipfile

from app.config import RISK_THRESHOLD_ALLOW_MAX, RISK_THRESHOLD_BLOCK_MIN
from app.detection.artifactanalyzer import analyze_artifact_dict
from app.detection.downloadanalyzer import analyze_download_dict
from app.detection.outputsanitizer import build_output_sanitizer
from app.services.fileinspectionservice import build_file_inspection_service

DEFAULT_ALLOWED_EXTENSIONS = {
    ".txt",
    ".md",
    ".json",
    ".yaml",
    ".yml",
    ".csv",
    ".tsv",
    ".log",
    ".xml",
    ".html",
    ".py",
    ".js",
    ".ts",
    ".css",
    ".png",
    ".jpg",
    ".jpeg",
    ".webp",
    ".gif",
    ".svg",
    ".pdf",
    ".zip",
}
DEFAULT_BLOCKED_EXTENSIONS = {
    ".exe",
    ".dll",
    ".bat",
    ".cmd",
    ".ps1",
    ".msi",
    ".scr",
    ".com",
    ".jar",
    ".apk",
    ".iso",
}
DEFAULT_BLOCKED_MIME_PREFIXES = (
    "application/x-dosexec",
    "application/x-msdownload",
    "application/x-sh",
    "application/x-bat",
    "application/x-executable",
)
DEFAULT_ALLOWED_ROOT_NAMES = {
    "artifacts",
    "reports",
    "output",
    "uploads",
    "quarantine",
    "samples",
}
DEFAULT_SENSITIVE_NAME_PATTERNS: tuple[tuple[str, str, int], ...] = (
    ("dotenv_file", r"(?i)(^|/)\.env(\.|$)?", 60),
    ("ssh_key", r"(?i)(id_rsa|id_dsa|authorized_keys|known_hosts)", 80),
    ("cloud_creds", r"(?i)(credentials|config)\.json$", 70),
    ("secret_material", r"(?i)(secret|token|apikey|api_key|password|passwd|private[_-]?key)", 45),
    ("shell_script", r"(?i)\.(sh|ps1|bat|cmd)$", 55),
)
_ALLOWED_MIME_OVERRIDES = {
    ".txt": {"text/plain"},
    ".md": {"text/markdown", "text/plain"},
    ".json": {"application/json", "text/plain"},
    ".yaml": {"application/x-yaml", "text/yaml", "text/plain"},
    ".yml": {"application/x-yaml", "text/yaml", "text/plain"},
    ".csv": {"text/csv", "text/plain"},
    ".tsv": {"text/tab-separated-values", "text/plain"},
    ".log": {"text/plain"},
    ".xml": {"application/xml", "text/xml", "text/plain"},
    ".html": {"text/html"},
    ".py": {"text/x-python", "text/plain"},
    ".js": {"application/javascript", "text/javascript", "text/plain"},
    ".ts": {"text/plain", "application/typescript"},
    ".css": {"text/css", "text/plain"},
    ".png": {"image/png"},
    ".jpg": {"image/jpeg"},
    ".jpeg": {"image/jpeg"},
    ".webp": {"image/webp"},
    ".gif": {"image/gif"},
    ".svg": {"image/svg+xml", "text/plain"},
    ".pdf": {"application/pdf"},
    ".zip": {"application/zip"},
}
_BINARY_MAGIC_LABELS: tuple[tuple[bytes, str, int], ...] = (
    (b"MZ", "windows-executable", 95),
    (b"\x7fELF", "elf-binary", 95),
    (b"\xca\xfe\xba\xbe", "java-class", 90),
    (b"\xfe\xed\xfa", "mach-o-binary", 95),
)
_SUSPICIOUS_ARCHIVE_ENTRY_RE = re.compile(
    r"(^/)|(^[A-Za-z]:\\)|(^\\\\)|(?:^|/)\.\.(?:/|$)|(?:^|\\)\.\.(?:\\|$)",
)


@dataclass(slots=True)
class FileReturnReason:
    source: str
    label: str
    details: str
    score: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "label": self.label,
            "details": self.details,
            "score": int(self.score),
        }


@dataclass(slots=True)
class FileReturnPolicy:
    verdict: str
    allowed: bool
    should_review: bool
    should_block: bool
    should_quarantine: bool
    risk_delta: int
    path: str
    filename: str
    extension: str
    mime_type: str
    size_bytes: int
    reasons: list[dict[str, Any]] = field(default_factory=list)
    matched_rules: list[str] = field(default_factory=list)
    artifact_analysis: dict[str, Any] = field(default_factory=dict)
    download_analysis: dict[str, Any] = field(default_factory=dict)
    output_sanitization: dict[str, Any] = field(default_factory=dict)
    file_inspection: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "allowed": self.allowed,
            "shouldreview": self.should_review,
            "shouldblock": self.should_block,
            "shouldquarantine": self.should_quarantine,
            "riskdelta": int(self.risk_delta),
            "path": self.path,
            "filename": self.filename,
            "extension": self.extension,
            "mimetype": self.mime_type,
            "sizebytes": int(self.size_bytes),
            "reasons": list(self.reasons),
            "matchedrules": list(self.matched_rules),
            "artifactanalysis": dict(self.artifact_analysis),
            "downloadanalysis": dict(self.download_analysis),
            "outputsanitization": dict(self.output_sanitization),
            "fileinspection": dict(self.file_inspection),
        }


@dataclass(slots=True)
class FileReturnGuard:
    review_threshold: int = RISK_THRESHOLD_ALLOW_MAX + 1
    block_threshold: int = RISK_THRESHOLD_BLOCK_MIN
    quarantine_threshold: int = RISK_THRESHOLD_BLOCK_MIN
    max_file_size_bytes: int = 10 * 1024 * 1024
    max_text_inspection_bytes: int = 256 * 1024
    allowed_extensions: set[str] = field(default_factory=lambda: set(DEFAULT_ALLOWED_EXTENSIONS))
    blocked_extensions: set[str] = field(default_factory=lambda: set(DEFAULT_BLOCKED_EXTENSIONS))
    blocked_mime_prefixes: tuple[str, ...] = DEFAULT_BLOCKED_MIME_PREFIXES
    allowed_root_names: set[str] = field(default_factory=lambda: set(DEFAULT_ALLOWED_ROOT_NAMES))
    sensitive_name_patterns: tuple[tuple[str, str, int], ...] = DEFAULT_SENSITIVE_NAME_PATTERNS
    file_inspection_service: Any | None = None

    def evaluate(
        self,
        *,
        path: str,
        content: str | bytes | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> FileReturnPolicy:
        normalized_path = str(path or "").strip()
        metadata_dict = dict(metadata or {})
        reasons: list[FileReturnReason] = []
        matched_rules: list[str] = []
        risk_delta = 0

        artifact_analysis: dict[str, Any] = {}
        download_analysis: dict[str, Any] = {}
        output_sanitization: dict[str, Any] = {}
        file_inspection: dict[str, Any] = {}

        if not normalized_path:
            reasons.append(
                FileReturnReason(
                    source="filereturnguard",
                    label="Missing path",
                    details="Artifact return was denied because no file path was provided.",
                    score=80,
                ),
            )
            return self._finalize(
                reasons=reasons,
                matched_rules=["missing_path"],
                risk_delta=80,
                path="",
                filename="",
                extension="",
                mime_type="application/octet-stream",
                size_bytes=0,
                artifact_analysis=artifact_analysis,
                download_analysis=download_analysis,
                output_sanitization=output_sanitization,
                file_inspection=file_inspection,
            )

        candidate = Path(normalized_path)
        normalized_posix = candidate.as_posix().replace("\\", "/")
        filename = candidate.name
        extension = candidate.suffix.lower()
        mime_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
        size_bytes = self._resolve_size_bytes(candidate=candidate, content=content)

        if self._has_parent_escape(normalized_posix):
            reasons.append(
                FileReturnReason(
                    source="filereturnguard",
                    label="Path escape attempt",
                    details="Artifact path references parent-directory traversal outside the return boundary.",
                    score=85,
                ),
            )
            matched_rules.append("path_escape")
            risk_delta += 85

        if self._has_absolute_path(normalized_posix):
            reasons.append(
                FileReturnReason(
                    source="filereturnguard",
                    label="Absolute path denied",
                    details="Artifact path must remain relative to an approved sandbox return directory.",
                    score=85,
                ),
            )
            matched_rules.append("absolute_path")
            risk_delta += 85

        root_name = self._resolve_root_name(candidate)
        allowed_roots = {item.lower() for item in self.allowed_root_names}
        if root_name and root_name not in allowed_roots:
            reasons.append(
                FileReturnReason(
                    source="filereturnguard",
                    label="Unapproved artifact root",
                    details=f"Artifact root '{root_name}' is outside the approved return directories.",
                    score=25,
                ),
            )
            matched_rules.append(f"unapproved_root:{root_name}")
            risk_delta += 25

        if extension in self.blocked_extensions:
            reasons.append(
                FileReturnReason(
                    source="filereturnguard",
                    label="Blocked file type",
                    details=f"Extension '{extension}' is blocked from leaving the sandbox.",
                    score=90,
                ),
            )
            matched_rules.append(f"blocked_extension:{extension}")
            risk_delta += 90
        elif extension and extension not in self.allowed_extensions:
            reasons.append(
                FileReturnReason(
                    source="filereturnguard",
                    label="Unapproved file type",
                    details=f"Extension '{extension}' is not in the approved artifact return set.",
                    score=25,
                ),
            )
            matched_rules.append(f"unapproved_extension:{extension}")
            risk_delta += 25
        elif not extension:
            reasons.append(
                FileReturnReason(
                    source="filereturnguard",
                    label="Missing extension",
                    details="Artifact has no extension and requires review before return.",
                    score=20,
                ),
            )
            matched_rules.append("missing_extension")
            risk_delta += 20

        for blocked_prefix in self.blocked_mime_prefixes:
            if mime_type.startswith(blocked_prefix):
                reasons.append(
                    FileReturnReason(
                        source="filereturnguard",
                        label="Blocked MIME type",
                        details=f"MIME type '{mime_type}' is blocked by artifact return policy.",
                        score=85,
                    ),
                )
                matched_rules.append(f"blocked_mime:{blocked_prefix}")
                risk_delta += 85

        allowed_mimes = _ALLOWED_MIME_OVERRIDES.get(extension)
        if allowed_mimes and mime_type not in allowed_mimes:
            reasons.append(
                FileReturnReason(
                    source="filereturnguard",
                    label="Unexpected MIME type",
                    details=f"MIME type '{mime_type}' does not match the expected type set for '{extension}'.",
                    score=35,
                ),
            )
            matched_rules.append(f"mime_mismatch:{extension}")
            risk_delta += 35

        if size_bytes > self.max_file_size_bytes:
            reasons.append(
                FileReturnReason(
                    source="filereturnguard",
                    label="Oversized artifact",
                    details=(f"Artifact size {size_bytes} bytes exceeded the allowed maximum of {self.max_file_size_bytes} bytes."),
                    score=55,
                ),
            )
            matched_rules.append("oversized_artifact")
            risk_delta += 55
        elif size_bytes == 0:
            reasons.append(
                FileReturnReason(
                    source="filereturnguard",
                    label="Empty artifact",
                    details="Artifact is empty and requires review before return.",
                    score=10,
                ),
            )
            matched_rules.append("empty_artifact")
            risk_delta += 10

        for rule_name, pattern, score in self.sensitive_name_patterns:
            if re.search(pattern, normalized_posix):
                reasons.append(
                    FileReturnReason(
                        source="filereturnguard",
                        label="Sensitive artifact name",
                        details=f"Artifact path matched sensitive rule '{rule_name}'.",
                        score=score,
                    ),
                )
                matched_rules.append(rule_name)
                risk_delta += int(score)

        payload_bytes = self._resolve_payload_bytes(candidate=candidate, content=content)
        payload_text = self._decode_payload_text(payload_bytes)

        binary_risk, binary_reasons, binary_rules = self._inspect_binary_signature(
            filename=filename or normalized_posix,
            extension=extension,
            payload_bytes=payload_bytes,
        )
        reasons.extend(binary_reasons)
        matched_rules.extend(binary_rules)
        risk_delta += binary_risk

        archive_risk, archive_reasons, archive_rules = self._inspect_archive_entries(
            filename=filename or normalized_posix,
            extension=extension,
            payload_bytes=payload_bytes,
        )
        reasons.extend(archive_reasons)
        matched_rules.extend(archive_rules)
        risk_delta += archive_risk

        artifact_analysis = analyze_artifact_dict(
            artifact_name=filename or normalized_posix,
            content=payload_text or normalized_posix,
            metadata={
                "path": normalized_posix,
                "mimetype": mime_type,
                "sizebytes": size_bytes,
                **metadata_dict,
            },
        )
        artifact_risk, artifact_reasons, artifact_rules = self._consume_analysis(
            source_default="artifactanalyzer",
            label_default="Artifact analysis",
            analysis=artifact_analysis,
        )
        reasons.extend(artifact_reasons)
        matched_rules.extend(artifact_rules)
        risk_delta += artifact_risk

        download_analysis = analyze_download_dict(
            actiontype="artifact_return",
            target=filename or normalized_posix,
            content=payload_text or normalized_posix,
            filepath=normalized_posix,
            metadata={
                "path": normalized_posix,
                "mimetype": mime_type,
                "sizebytes": size_bytes,
                **metadata_dict,
            },
        )
        download_risk, download_reasons, download_rules = self._consume_analysis(
            source_default="downloadanalyzer",
            label_default="Download analysis",
            analysis=download_analysis,
        )
        reasons.extend(download_reasons)
        matched_rules.extend(download_rules)
        risk_delta += download_risk

        inspection_service = self.file_inspection_service or build_file_inspection_service(
            max_file_size_bytes=self.max_file_size_bytes,
            max_inline_text_bytes=self.max_text_inspection_bytes,
        )
        inspection_result = inspection_service.inspect_artifact(
            file_name=filename or normalized_posix,
            content=payload_bytes,
            mime_type=mime_type,
            metadata={
                "path": normalized_posix,
                "sizebytes": size_bytes,
                **metadata_dict,
            },
            context="sandbox_return",
        )
        file_inspection = inspection_result.as_dict()
        file_inspection_risk = int(file_inspection.get("riskdelta", 0) or 0)
        risk_delta += file_inspection_risk
        if file_inspection.get("shouldquarantine") or file_inspection.get("shouldblock") or file_inspection.get("blocked") or file_inspection.get("shouldreview"):
            matched_rules.append("fileinspection:block")
        for item in file_inspection.get("reasons", []) or []:
            if isinstance(item, Mapping):
                reasons.append(
                    FileReturnReason(
                        source="fileinspectionservice",
                        label=str(item.get("label", "File inspection")),
                        details=str(item.get("details", item.get("label", "File inspection detected."))),
                        score=int(item.get("score", 0) or 0),
                    ),
                )
            else:
                reasons.append(
                    FileReturnReason(
                        source="fileinspectionservice",
                        label="File inspection",
                        details=str(item),
                        score=0,
                    ),
                )

        sanitizer = build_output_sanitizer()
        sanitized = sanitizer.sanitize(
            payload_text or filename or normalized_posix,
            context=f"artifact_return:{normalized_posix}",
            redact_secrets=True,
            block_unsafe_commands=True,
        )
        output_sanitization = sanitized.as_dict()
        if output_sanitization.get("blocked"):
            reasons.append(
                FileReturnReason(
                    source="filereturnguard",
                    label="Sanitized output blocked",
                    details="Artifact content triggered output sanitization blocking rules.",
                    score=70,
                ),
            )
            matched_rules.append("output_sanitizer_block")
            risk_delta += 70
        else:
            sanitizer_score = int(round(float(output_sanitization.get("score", 0.0)) * 100))
            if sanitizer_score > 0:
                reasons.append(
                    FileReturnReason(
                        source="filereturnguard",
                        label="Sanitized output risk",
                        details="Artifact content triggered output sanitization review signals.",
                        score=sanitizer_score,
                    ),
                )
                matched_rules.append("output_sanitizer_risk")
                risk_delta += sanitizer_score

        return self._finalize(
            reasons=reasons,
            matched_rules=matched_rules,
            risk_delta=risk_delta,
            path=normalized_posix,
            filename=filename,
            extension=extension,
            mime_type=mime_type,
            size_bytes=size_bytes,
            artifact_analysis=artifact_analysis,
            download_analysis=download_analysis,
            output_sanitization=output_sanitization,
            file_inspection=file_inspection,
        )

    def allow(
        self,
        *,
        path: str,
        content: str | bytes | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> bool:
        return self.evaluate(path=path, content=content, metadata=metadata).allowed

    def _resolve_size_bytes(self, *, candidate: Path, content: str | bytes | None) -> int:
        if content is not None:
            if isinstance(content, bytes):
                return len(content)
            return len(content.encode("utf-8", errors="ignore"))
        if candidate.exists() and candidate.is_file():
            try:
                return candidate.stat().st_size
            except OSError:
                return 0
        return 0

    def _resolve_payload_bytes(self, *, candidate: Path, content: str | bytes | None) -> bytes:
        if isinstance(content, bytes):
            return content[: self.max_text_inspection_bytes]
        if isinstance(content, str):
            return content.encode("utf-8", errors="ignore")[: self.max_text_inspection_bytes]
        if candidate.exists() and candidate.is_file():
            try:
                with candidate.open("rb") as handle:
                    return handle.read(self.max_text_inspection_bytes)
            except OSError:
                return b""
        return b""

    def _decode_payload_text(self, payload: bytes) -> str:
        if not payload:
            return ""
        return payload.decode("utf-8", errors="ignore")

    def _resolve_root_name(self, candidate: Path) -> str:
        parts = [part.lower() for part in candidate.parts if part not in {os.sep, ""}]
        if not parts:
            return ""
        if parts[0] == "." and len(parts) > 1:
            return parts[1]
        return parts[0]

    def _has_parent_escape(self, normalized_posix: str) -> bool:
        parts = [part for part in normalized_posix.replace("\\", "/").split("/") if part]
        return ".." in parts

    def _has_absolute_path(self, normalized_posix: str) -> bool:
        if normalized_posix.startswith("/"):
            return True
        return bool(re.match(r"^[A-Za-z]:/", normalized_posix))

    def _inspect_binary_signature(
        self,
        *,
        filename: str,
        extension: str,
        payload_bytes: bytes,
    ) -> tuple[int, list[FileReturnReason], list[str]]:
        reasons: list[FileReturnReason] = []
        matched_rules: list[str] = []
        risk_delta = 0

        for magic, label, score in _BINARY_MAGIC_LABELS:
            if payload_bytes.startswith(magic):
                reasons.append(
                    FileReturnReason(
                        source="filereturnguard",
                        label="Dangerous binary signature",
                        details=f"Artifact '{filename}' matched binary signature '{label}'.",
                        score=score,
                    ),
                )
                matched_rules.append(f"binary_signature:{label}")
                risk_delta += score

        if extension in {".zip", ".jar"} and payload_bytes.startswith(b"MZ"):
            reasons.append(
                FileReturnReason(
                    source="filereturnguard",
                    label="Extension/content mismatch",
                    details="Artifact extension indicates an archive but payload signature indicates an executable.",
                    score=90,
                ),
            )
            matched_rules.append("extension_content_mismatch")
            risk_delta += 90

        return risk_delta, reasons, matched_rules

    def _inspect_archive_entries(
        self,
        *,
        filename: str,
        extension: str,
        payload_bytes: bytes,
    ) -> tuple[int, list[FileReturnReason], list[str]]:
        reasons: list[FileReturnReason] = []
        matched_rules: list[str] = []
        risk_delta = 0

        if extension != ".zip" and not zipfile.is_zipfile(io.BytesIO(payload_bytes)):
            return risk_delta, reasons, matched_rules

        try:
            with zipfile.ZipFile(io.BytesIO(payload_bytes), "r") as archive:
                for info in archive.infolist():
                    entry_name = info.filename.replace("\\", "/")
                    if _SUSPICIOUS_ARCHIVE_ENTRY_RE.search(entry_name):
                        reasons.append(
                            FileReturnReason(
                                source="filereturnguard",
                                label="Archive path traversal",
                                details=f"Archive '{filename}' contains suspicious entry '{entry_name}'.",
                                score=85,
                            ),
                        )
                        matched_rules.append("archive_path_traversal")
                        risk_delta += 85
                    entry_extension = Path(entry_name).suffix.lower()
                    if entry_extension in self.blocked_extensions:
                        reasons.append(
                            FileReturnReason(
                                source="filereturnguard",
                                label="Archive contains blocked file",
                                details=f"Archive '{filename}' contains blocked entry '{entry_name}'.",
                                score=90,
                            ),
                        )
                        matched_rules.append(f"archive_blocked_extension:{entry_extension}")
                        risk_delta += 90
        except zipfile.BadZipFile:
            reasons.append(
                FileReturnReason(
                    source="filereturnguard",
                    label="Invalid archive",
                    details=f"Artifact '{filename}' claims to be an archive but could not be parsed.",
                    score=60,
                ),
            )
            matched_rules.append("invalid_archive")
            risk_delta += 60

        return risk_delta, reasons, matched_rules

    def _consume_analysis(
        self,
        *,
        source_default: str,
        label_default: str,
        analysis: Mapping[str, Any],
    ) -> tuple[int, list[FileReturnReason], list[str]]:
        reasons: list[FileReturnReason] = []
        matched_rules: list[str] = []
        risk_delta = int(analysis.get("riskdelta", 0) or 0)

        for item in analysis.get("reasons", []) or []:
            if isinstance(item, Mapping):
                reasons.append(
                    FileReturnReason(
                        source=str(item.get("source", source_default)),
                        label=str(item.get("label", label_default)),
                        details=str(item.get("details", f"{label_default} detected.")),
                        score=int(item.get("score", 0) or 0),
                    ),
                )
            else:
                reasons.append(
                    FileReturnReason(
                        source=source_default,
                        label=label_default,
                        details=str(item),
                        score=0,
                    ),
                )

        if analysis.get("shouldquarantine") or analysis.get("shouldblock") or analysis.get("blocked") or analysis.get("shouldreview") or analysis.get("matchedpatterns") or analysis.get("matched_patterns"):
            matched_rules.append(f"{source_default}:block")

        return risk_delta, reasons, matched_rules

    def _finalize(
        self,
        *,
        reasons: Iterable[FileReturnReason],
        matched_rules: list[str],
        risk_delta: int,
        path: str,
        filename: str,
        extension: str,
        mime_type: str,
        size_bytes: int,
        artifact_analysis: dict[str, Any],
        download_analysis: dict[str, Any],
        output_sanitization: dict[str, Any],
        file_inspection: dict[str, Any],
    ) -> FileReturnPolicy:
        normalized_risk = max(0, min(100, int(risk_delta)))
        deduped_rules = list(dict.fromkeys(item for item in matched_rules if item))
        should_review = bool(artifact_analysis.get("shouldreview")) or bool(download_analysis.get("shouldreview")) or bool(file_inspection.get("shouldreview")) or normalized_risk >= self.review_threshold
        should_block = (
            bool(deduped_rules)
            or normalized_risk > RISK_THRESHOLD_ALLOW_MAX
            or bool(output_sanitization.get("blocked"))
            or bool(artifact_analysis.get("shouldblock"))
            or bool(download_analysis.get("shouldblock"))
            or bool(download_analysis.get("blocked"))
            or bool(file_inspection.get("shouldquarantine"))
            or bool(file_inspection.get("shouldblock"))
            or bool(file_inspection.get("blocked"))
            or should_review
        )
        final_risk = max(normalized_risk, RISK_THRESHOLD_BLOCK_MIN) if should_block else normalized_risk

        materialized_reasons = self._dedupe_reasons(reasons)

        return FileReturnPolicy(
            verdict="block" if should_block else "allow",
            allowed=not should_block,
            should_review=should_review,
            should_block=should_block,
            should_quarantine=False,
            risk_delta=final_risk,
            path=path,
            filename=filename,
            extension=extension,
            mime_type=mime_type,
            size_bytes=size_bytes,
            reasons=[reason.as_dict() for reason in materialized_reasons],
            matched_rules=deduped_rules,
            artifact_analysis=artifact_analysis,
            download_analysis=download_analysis,
            output_sanitization=output_sanitization,
            file_inspection=file_inspection,
        )

    def _dedupe_reasons(self, reasons: Iterable[FileReturnReason]) -> list[FileReturnReason]:
        deduped: list[FileReturnReason] = []
        seen: set[tuple[str, str, str, int]] = set()
        for reason in reasons:
            key = (reason.source, reason.label, reason.details, int(reason.score))
            if key in seen:
                continue
            seen.add(key)
            deduped.append(reason)
        return deduped[:20]


def initialize_filereturnguard(
    *,
    review_threshold: int = RISK_THRESHOLD_ALLOW_MAX + 1,
    block_threshold: int = RISK_THRESHOLD_BLOCK_MIN,
    quarantine_threshold: int = RISK_THRESHOLD_BLOCK_MIN,
    max_file_size_bytes: int = 10 * 1024 * 1024,
    max_text_inspection_bytes: int = 256 * 1024,
    allowed_extensions: Iterable[str] | None = None,
    blocked_extensions: Iterable[str] | None = None,
    blocked_mime_prefixes: Iterable[str] | None = None,
    allowed_root_names: Iterable[str] | None = None,
    sensitive_name_patterns: Iterable[tuple[str, str, int]] | None = None,
    file_inspection_service: Any | None = None,
) -> FileReturnGuard:
    return FileReturnGuard(
        review_threshold=review_threshold,
        block_threshold=block_threshold,
        quarantine_threshold=quarantine_threshold,
        max_file_size_bytes=max_file_size_bytes,
        max_text_inspection_bytes=max_text_inspection_bytes,
        allowed_extensions=set(allowed_extensions or DEFAULT_ALLOWED_EXTENSIONS),
        blocked_extensions=set(blocked_extensions or DEFAULT_BLOCKED_EXTENSIONS),
        blocked_mime_prefixes=tuple(blocked_mime_prefixes or DEFAULT_BLOCKED_MIME_PREFIXES),
        allowed_root_names=set(allowed_root_names or DEFAULT_ALLOWED_ROOT_NAMES),
        sensitive_name_patterns=tuple(sensitive_name_patterns or DEFAULT_SENSITIVE_NAME_PATTERNS),
        file_inspection_service=file_inspection_service,
    )


def build_file_return_guard() -> FileReturnGuard:
    return initialize_filereturnguard()
