from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import ipaddress
import re
from urllib.parse import urlparse
from typing import Any

from app.detection.artifactanalyzer import ArtifactAnalyzer, build_artifact_analyzer
from app.services.threatintel import ThreatIntelService, build_default_threatintel_service


URL_SHORTENER_HOSTS = {
    "bit.ly",
    "t.co",
    "tinyurl.com",
    "goo.gl",
    "is.gd",
    "buff.ly",
    "ow.ly",
    "rebrand.ly",
    "cutt.ly",
    "tiny.one",
}

SUSPICIOUS_TLDS = {
    "zip",
    "mov",
    "top",
    "xyz",
    "click",
    "work",
    "country",
    "gq",
    "tk",
    "quest",
}

HIGH_RISK_EXTENSIONS = {
    ".exe",
    ".dll",
    ".scr",
    ".bat",
    ".cmd",
    ".ps1",
    ".js",
    ".jse",
    ".vbs",
    ".vbe",
    ".msi",
    ".iso",
    ".img",
    ".lnk",
    ".hta",
    ".jar",
}

ARCHIVE_EXTENSIONS = {
    ".zip",
    ".rar",
    ".7z",
    ".tar",
    ".gz",
    ".bz2",
    ".xz",
}

DOUBLE_EXTENSION_PATTERN = re.compile(
    r"\.(?:pdf|doc|docx|xls|xlsx|jpg|jpeg|png|txt|rtf)\.(?:exe|scr|bat|cmd|js|vbs|ps1)$",
    re.IGNORECASE,
)

IP_LITERAL_PATTERN = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
HEX_ESCAPE_PATTERN = re.compile(r"%[0-9a-fA-F]{2}")
REPEATED_SUBDOMAIN_PATTERN = re.compile(r"(?:[^.]+\.){4,}")
CREDENTIAL_STYLE_PATTERN = re.compile(r"^[^/@:]+:[^/@]+@")


@dataclass(slots=True)
class DownloadSignal:
    name: str
    weight: float
    evidence: str
    category: str = "download"


@dataclass(slots=True)
class DownloadAnalysisResult:
    download_id: str
    url: str | None
    file_name: str | None
    sha256: str | None
    verdict: str
    severity: str
    score: float
    confidence: float
    reasons: list[str]
    signals: list[DownloadSignal]
    metadata: dict[str, Any] = field(default_factory=dict)
    artifact_analysis: dict[str, Any] | None = None
    analyzed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def as_dict(self) -> dict[str, Any]:
        return {
            "download_id": self.download_id,
            "url": self.url,
            "file_name": self.file_name,
            "sha256": self.sha256,
            "verdict": self.verdict,
            "severity": self.severity,
            "score": self.score,
            "confidence": self.confidence,
            "reasons": list(self.reasons),
            "signals": [
                {
                    "name": signal.name,
                    "weight": signal.weight,
                    "evidence": signal.evidence,
                    "category": signal.category,
                }
                for signal in self.signals
            ],
            "metadata": dict(self.metadata),
            "artifact_analysis": self.artifact_analysis,
            "analyzed_at": self.analyzed_at,
        }


class DownloadAnalyzer:
    def __init__(
        self,
        *,
        artifact_analyzer: ArtifactAnalyzer | None = None,
        threatintel_service: ThreatIntelService | None = None,
    ) -> None:
        self._artifact_analyzer = artifact_analyzer or build_artifact_analyzer()
        self._threatintel = threatintel_service or build_default_threatintel_service()

    def analyze(
        self,
        *,
        url: str | None = None,
        payload: bytes | None = None,
        file_name: str | None = None,
        content_type: str | None = None,
        referrer: str | None = None,
        context: str | None = None,
    ) -> DownloadAnalysisResult:
        normalized_url = (url or "").strip() or None
        normalized_name = (file_name or "").strip() or None
        sha256 = hashlib.sha256(payload).hexdigest() if payload is not None else None
        download_id = self._build_download_id(
            url=normalized_url,
            file_name=normalized_name,
            sha256=sha256,
        )

        signals: list[DownloadSignal] = []
        metadata = {
            "content_type": content_type,
            "referrer": referrer,
            "has_payload": payload is not None,
            "payload_size": len(payload) if payload is not None else 0,
        }

        if normalized_url:
            signals.extend(self._analyze_url(normalized_url))
            threat = self._threatintel.assess_artifact(
                url=normalized_url,
                hashes=[sha256] if sha256 else [],
                text=normalized_name,
                context=context or "download-analysis",
            )
            signals.extend(self._signals_from_threatintel(threat))

        if normalized_name:
            signals.extend(self._analyze_file_name(normalized_name))

        if payload is not None:
            signals.extend(self._analyze_payload(payload, normalized_name, content_type))

        artifact_analysis = None
        if payload is not None:
            artifact_result = self._artifact_analyzer.analyze_bytes(
                payload,
                file_name=normalized_name,
                source_url=normalized_url,
                context=context or "download-analysis",
            )
            artifact_analysis = artifact_result.as_dict()
            signals.extend(self._signals_from_artifact(artifact_result))

        signals = self._dedupe_signals(signals)
        score = self._resolve_score(signals)
        severity = self._resolve_severity(score)
        verdict = self._resolve_verdict(score, signals)
        confidence = self._resolve_confidence(signals, payload_present=payload is not None, artifact_analysis=artifact_analysis)
        reasons = self._build_reasons(signals, verdict, severity, normalized_url, normalized_name, artifact_analysis)

        metadata["signal_count"] = len(signals)
        metadata["host"] = self._extract_host(normalized_url) if normalized_url else None

        return DownloadAnalysisResult(
            download_id=download_id,
            url=normalized_url,
            file_name=normalized_name,
            sha256=sha256,
            verdict=verdict,
            severity=severity,
            score=score,
            confidence=confidence,
            reasons=reasons,
            signals=signals,
            metadata=metadata,
            artifact_analysis=artifact_analysis,
        )

    def analyze_url(
        self,
        url: str,
        *,
        file_name: str | None = None,
        referrer: str | None = None,
        context: str | None = None,
    ) -> DownloadAnalysisResult:
        return self.analyze(
            url=url,
            file_name=file_name,
            referrer=referrer,
            context=context,
        )

    def analyze_bytes(
        self,
        payload: bytes,
        *,
        url: str | None = None,
        file_name: str | None = None,
        content_type: str | None = None,
        referrer: str | None = None,
        context: str | None = None,
    ) -> DownloadAnalysisResult:
        return self.analyze(
            url=url,
            payload=payload,
            file_name=file_name,
            content_type=content_type,
            referrer=referrer,
            context=context,
        )

    def _build_download_id(self, *, url: str | None, file_name: str | None, sha256: str | None) -> str:
        seed = "|".join(part for part in [url or "", file_name or "", sha256 or ""] if part)
        digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:12] if seed else "unknown"
        return f"download-{digest}"

    def _analyze_url(self, url: str) -> list[DownloadSignal]:
        signals: list[DownloadSignal] = []
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        path = parsed.path or ""
        query = parsed.query or ""

        if parsed.scheme and parsed.scheme.lower() not in {"http", "https"}:
            signals.append(
                DownloadSignal(
                    name="non_http_scheme",
                    weight=0.30,
                    evidence=f"Download URL uses {parsed.scheme} scheme.",
                )
            )

        if host in URL_SHORTENER_HOSTS:
            signals.append(
                DownloadSignal(
                    name="url_shortener",
                    weight=0.28,
                    evidence=f"Host {host} is a known shortening service.",
                )
            )

        tld = host.rsplit(".", 1)[-1] if "." in host else ""
        if tld in SUSPICIOUS_TLDS:
            signals.append(
                DownloadSignal(
                    name="suspicious_tld",
                    weight=0.26,
                    evidence=f"Host uses high-risk top-level domain .{tld}.",
                )
            )

        if IP_LITERAL_PATTERN.match(host):
            try:
                ip = ipaddress.ip_address(host)
                if not ip.is_private:
                    signals.append(
                        DownloadSignal(
                            name="ip_literal_host",
                            weight=0.24,
                            evidence=f"URL uses literal IP host {host}.",
                        )
                    )
            except ValueError:
                pass

        if REPEATED_SUBDOMAIN_PATTERN.search(host):
            signals.append(
                DownloadSignal(
                    name="deep_subdomain_chain",
                    weight=0.14,
                    evidence=f"Host {host} contains many chained subdomains.",
                )
            )

        if "@" in parsed.netloc and CREDENTIAL_STYLE_PATTERN.match(parsed.netloc):
            signals.append(
                DownloadSignal(
                    name="credential_style_url",
                    weight=0.32,
                    evidence="URL contains credential-style userinfo before host.",
                )
            )

        lowered_target = f"{path}?{query}".lower()
        if DOUBLE_EXTENSION_PATTERN.search(lowered_target):
            signals.append(
                DownloadSignal(
                    name="double_extension_url",
                    weight=0.42,
                    evidence=f"URL path suggests disguised executable: {path}",
                )
            )

        for ext in HIGH_RISK_EXTENSIONS:
            if lowered_target.endswith(ext):
                signals.append(
                    DownloadSignal(
                        name="executable_download_url",
                        weight=0.38,
                        evidence=f"URL path ends with executable extension {ext}.",
                    )
                )
                break

        if any(token in lowered_target for token in ("download=1", "export=1", "attachment=", "raw=1")) and HEX_ESCAPE_PATTERN.search(query):
            signals.append(
                DownloadSignal(
                    name="obfuscated_download_query",
                    weight=0.18,
                    evidence="Download query uses encoded characters alongside forced attachment semantics.",
                )
            )

        return signals

    def _analyze_file_name(self, file_name: str) -> list[DownloadSignal]:
        signals: list[DownloadSignal] = []
        lowered = file_name.lower()

        if DOUBLE_EXTENSION_PATTERN.search(lowered):
            signals.append(
                DownloadSignal(
                    name="double_extension_name",
                    weight=0.46,
                    evidence=f"Filename appears disguised with double extension: {file_name}",
                )
            )

        for ext in HIGH_RISK_EXTENSIONS:
            if lowered.endswith(ext):
                signals.append(
                    DownloadSignal(
                        name="high_risk_extension",
                        weight=0.34,
                        evidence=f"Filename uses high-risk extension {ext}.",
                    )
                )
                break

        archive_match = next((ext for ext in ARCHIVE_EXTENSIONS if lowered.endswith(ext)), None)
        if archive_match:
            signals.append(
                DownloadSignal(
                    name="archive_container",
                    weight=0.12,
                    evidence=f"Filename is an archive container {archive_match}.",
                )
            )

        if any(char in file_name for char in ("\u202e", "\u202d", "\u2066", "\u2067", "\u2068", "\u2069")):
            signals.append(
                DownloadSignal(
                    name="unicode_direction_override",
                    weight=0.54,
                    evidence="Filename contains Unicode direction override characters.",
                )
            )

        return signals

    def _analyze_payload(
        self,
        payload: bytes,
        file_name: str | None,
        content_type: str | None,
    ) -> list[DownloadSignal]:
        signals: list[DownloadSignal] = []
        prefix = payload[:32]
        lowered_name = (file_name or "").lower()

        if prefix.startswith(b"MZ"):
            signals.append(
                DownloadSignal(
                    name="portable_executable_header",
                    weight=0.48,
                    evidence="Payload starts with MZ executable header.",
                )
            )
        elif prefix.startswith(b"PK\x03\x04"):
            signals.append(
                DownloadSignal(
                    name="zip_container_header",
                    weight=0.12,
                    evidence="Payload starts with ZIP archive header.",
                )
            )
        elif prefix.startswith(b"%PDF"):
            if any(ext in lowered_name for ext in (".exe", ".scr", ".js", ".bat")):
                signals.append(
                    DownloadSignal(
                        name="extension_mime_mismatch",
                        weight=0.40,
                        evidence="Payload header appears to be PDF but filename extension is executable-like.",
                    )
                )

        if content_type:
            lowered_type = content_type.lower()
            if "octet-stream" in lowered_type and not any(lowered_name.endswith(ext) for ext in ARCHIVE_EXTENSIONS | HIGH_RISK_EXTENSIONS):
                signals.append(
                    DownloadSignal(
                        name="generic_binary_content_type",
                        weight=0.10,
                        evidence=f"Content-Type is generic binary: {content_type}",
                    )
                )
            if "text/html" in lowered_type and any(lowered_name.endswith(ext) for ext in HIGH_RISK_EXTENSIONS):
                signals.append(
                    DownloadSignal(
                        name="content_type_filename_mismatch",
                        weight=0.35,
                        evidence=f"Executable-like filename conflicts with content type {content_type}.",
                    )
                )

        if len(payload) < 180 and any(lowered_name.endswith(ext) for ext in HIGH_RISK_EXTENSIONS):
            signals.append(
                DownloadSignal(
                    name="tiny_executable_payload",
                    weight=0.14,
                    evidence="Executable-like payload is unusually small and may be a staged dropper or broken lure.",
                )
            )

        return signals

    def _signals_from_threatintel(self, assessment: Any) -> list[DownloadSignal]:
        signals: list[DownloadSignal] = []
        matches = list(getattr(assessment, "matches", []))
        if matches:
            signals.append(
                DownloadSignal(
                    name="threatintel_match",
                    weight=min(0.50, 0.16 + len(matches) * 0.08),
                    evidence=f"Threat intel matched {len(matches)} indicator(s).",
                    category="threatintel",
                )
            )

        for family in list(getattr(assessment, "risk_families", []))[:3]:
            signals.append(
                DownloadSignal(
                    name="threatintel_family",
                    weight=0.12,
                    evidence=f"Threat intel associated the target with {family}.",
                    category="threatintel",
                )
            )

        return signals

    def _signals_from_artifact(self, result: Any) -> list[DownloadSignal]:
        signals: list[DownloadSignal] = []
        score = float(getattr(result, "score", 0.0))
        verdict = str(getattr(result, "verdict", "allow"))
        severity = str(getattr(result, "severity", "low"))

        if score >= 0.20:
            signals.append(
                DownloadSignal(
                    name="artifact_risk_score",
                    weight=min(0.55, score * 0.50),
                    evidence=f"Artifact analysis returned score {score:.4f}, verdict {verdict}, severity {severity}.",
                    category="artifact",
                )
            )

        components = list(getattr(result, "components", []))
        for component in components:
            component_score = float(getattr(component, "score", 0.0))
            if component_score < 0.40:
                continue
            component_name = str(getattr(component, "name", "component"))
            signals.append(
                DownloadSignal(
                    name=f"artifact_component_{component_name}",
                    weight=min(0.22, component_score * 0.18),
                    evidence=f"{component_name} component contributed score {component_score:.4f}.",
                    category="artifact",
                )
            )

        return signals

    def _resolve_score(self, signals: list[DownloadSignal]) -> float:
        total = sum(signal.weight for signal in signals)
        return round(min(total, 1.0), 4)

    def _resolve_severity(self, score: float) -> str:
        if score >= 0.85:
            return "critical"
        if score >= 0.58:
            return "high"
        if score >= 0.28:
            return "medium"
        return "low"

    def _resolve_verdict(self, score: float, signals: list[DownloadSignal]) -> str:
        names = {signal.name for signal in signals}

        if score >= 0.82 or "unicode_direction_override" in names or "portable_executable_header" in names and "double_extension_name" in names:
            return "block"
        if score >= 0.52 or "threatintel_match" in names:
            return "review"
        if score >= 0.22:
            return "monitor"
        return "allow"

    def _resolve_confidence(
        self,
        signals: list[DownloadSignal],
        *,
        payload_present: bool,
        artifact_analysis: dict[str, Any] | None,
    ) -> float:
        base = 0.35
        if payload_present:
            base += 0.18
        if artifact_analysis:
            base += 0.18
        base += min(len(signals) * 0.04, 0.25)
        return round(min(base, 0.99), 4)

    def _build_reasons(
        self,
        signals: list[DownloadSignal],
        verdict: str,
        severity: str,
        url: str | None,
        file_name: str | None,
        artifact_analysis: dict[str, Any] | None,
    ) -> list[str]:
        reasons: list[str] = [
            f"Download risk classified as {verdict} with {severity} severity."
        ]

        if url:
            reasons.append(f"Evaluated download source {url}.")
        if file_name:
            reasons.append(f"Evaluated target filename {file_name}.")

        for signal in sorted(signals, key=lambda item: item.weight, reverse=True)[:5]:
            reasons.append(f"{signal.name}: {signal.evidence}")

        if artifact_analysis:
            reasons.append(
                f"Artifact analysis also returned verdict {artifact_analysis.get('verdict')} with score {artifact_analysis.get('score')}."
            )

        if len(reasons) == 1:
            reasons.append("No strong download-specific risk indicators were detected.")

        return reasons

    def _extract_host(self, url: str) -> str | None:
        try:
            return (urlparse(url).hostname or "").lower() or None
        except Exception:
            return None

    def _dedupe_signals(self, signals: list[DownloadSignal]) -> list[DownloadSignal]:
        deduped: list[DownloadSignal] = []
        seen: set[tuple[str, str]] = set()
        for signal in signals:
            key = (signal.name, signal.evidence)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(signal)
        return deduped


def build_download_analyzer(
    *,
    artifact_analyzer: ArtifactAnalyzer | None = None,
    threatintel_service: ThreatIntelService | None = None,
) -> DownloadAnalyzer:
    return DownloadAnalyzer(
        artifact_analyzer=artifact_analyzer,
        threatintel_service=threatintel_service,
    )


__all__ = [
    "DownloadSignal",
    "DownloadAnalysisResult",
    "DownloadAnalyzer",
    "build_download_analyzer",
]