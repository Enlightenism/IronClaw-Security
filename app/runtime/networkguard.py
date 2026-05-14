from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlparse

from app.detection.secretscanner import build_secret_scanner

DEFAULT_ALLOWED_SCHEMES = {"http", "https"}
DEFAULT_BLOCKED_SCHEMES = {
    "file",
    "ftp",
    "ftps",
    "gopher",
    "ldap",
    "ldaps",
    "dict",
    "smb",
    "ssh",
    "telnet",
    "ws",
    "wss",
}
DEFAULT_ALLOWED_HOSTS = {
    "api.openai.com",
    "api.groq.com",
    "github.com",
    "raw.githubusercontent.com",
    "pypi.org",
    "files.pythonhosted.org",
}
DEFAULT_BLOCKED_HOST_PATTERNS: tuple[tuple[str, str, int], ...] = (
    ("localhost", r"(?i)^localhost$", 80),
    ("loopback_name", r"(?i)^localhost\.localdomain$", 80),
    ("metadata_service", r"(?i)^169\.254\.169\.254$", 100),
    ("docker_internal", r"(?i)\b(host\.docker\.internal|gateway\.docker\.internal)\b", 90),
    ("local_domain", r"(?i)\.local$", 70),
    ("internal_domain", r"(?i)\.internal$", 70),
    ("lan_domain", r"(?i)\.lan$", 70),
    ("home_arpa", r"(?i)\.home\.arpa$", 70),
    ("private_tld", r"(?i)\.corp$", 70),
)
DEFAULT_BLOCKED_PATH_PATTERNS: tuple[tuple[str, str, int], ...] = (
    ("cloud_metadata", r"(?i)^/(latest|computeMetadata|metadata)(?:/|$)", 100),
    ("docker_socket_like", r"(?i)/var/run/docker\.sock", 100),
    ("sensitive_admin_path", r"(?i)/(admin|debug|actuator|internal)(?:/|$)", 30),
)
DEFAULT_SENSITIVE_FIELD_PATTERNS: tuple[tuple[str, str, int], ...] = (
    ("authorization_header", r"(?i)^authorization$", 60),
    ("cookie_header", r"(?i)^(cookie|set-cookie)$", 55),
    (
        "api_key_field",
        r"(?i)(api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|secret)$",
        45,
    ),
    ("password_field", r"(?i)(password|passwd|pwd)$", 50),
    ("private_key_field", r"(?i)(private[_-]?key|ssh[_-]?key|pem)$", 80),
)
DEFAULT_EXFIL_CONTENT_PATTERNS: tuple[tuple[str, str, int], ...] = (
    ("ssh_directory_reference", r"(?i)(^|[\\/])\.ssh([\\/]|$)", 45),
    ("shadow_file_reference", r"(?i)(^|[\\/])(etc[\\/])?(shadow|passwd)(\b|$)", 55),
    ("kubeconfig_reference", r"(?i)kubeconfig", 35),
    ("env_dump_reference", r"(?i)(^|[^a-z])env(?:ironment)?\s*(dump|export|vars?)", 25),
    ("archive_exfil_pattern", r"(?i)\b(tar|zip|gzip|base64)\b", 10),
)
DEFAULT_HIGH_RISK_PORTS = {
    21: 30,
    22: 40,
    23: 40,
    25: 35,
    53: 20,
    69: 35,
    110: 20,
    143: 20,
    445: 60,
    3306: 45,
    3389: 70,
    5432: 45,
    6379: 55,
    8080: 15,
}


@dataclass(slots=True)
class NetworkReason:
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
class NetworkPolicy:
    verdict: str
    allowed: bool
    should_review: bool
    should_block: bool
    should_quarantine: bool
    risk_delta: int
    scheme: str
    host: str
    port: int | None
    path: str
    normalized_url: str
    reasons: list[dict[str, Any]] = field(default_factory=list)
    matched_rules: list[str] = field(default_factory=list)
    direction: str = "egress"

    def as_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "allowed": self.allowed,
            "shouldreview": self.should_review,
            "shouldblock": self.should_block,
            "shouldquarantine": self.should_quarantine,
            "riskdelta": int(self.risk_delta),
            "scheme": self.scheme,
            "host": self.host,
            "port": self.port,
            "path": self.path,
            "normalizedurl": self.normalized_url,
            "reasons": list(self.reasons),
            "matchedrules": list(self.matched_rules),
            "direction": self.direction,
        }


@dataclass(slots=True)
class NetworkGuard:
    review_threshold: int = 20
    block_threshold: int = 50
    quarantine_threshold: int = 80
    allowed_schemes: set[str] = field(default_factory=lambda: set(DEFAULT_ALLOWED_SCHEMES))
    blocked_schemes: set[str] = field(default_factory=lambda: set(DEFAULT_BLOCKED_SCHEMES))
    allowed_hosts: set[str] = field(default_factory=lambda: set(DEFAULT_ALLOWED_HOSTS))
    blocked_host_patterns: tuple[tuple[str, str, int], ...] = DEFAULT_BLOCKED_HOST_PATTERNS
    blocked_path_patterns: tuple[tuple[str, str, int], ...] = DEFAULT_BLOCKED_PATH_PATTERNS
    sensitive_field_patterns: tuple[tuple[str, str, int], ...] = DEFAULT_SENSITIVE_FIELD_PATTERNS
    exfil_content_patterns: tuple[tuple[str, str, int], ...] = DEFAULT_EXFIL_CONTENT_PATTERNS
    high_risk_ports: dict[int, int] = field(default_factory=lambda: dict(DEFAULT_HIGH_RISK_PORTS))
    allow_private_hosts: bool = False

    def __post_init__(self) -> None:
        self.allowed_schemes = {item.strip().lower() for item in self.allowed_schemes if str(item).strip()}
        self.blocked_schemes = {item.strip().lower() for item in self.blocked_schemes if str(item).strip()}
        self.allowed_hosts = {item.strip().lower() for item in self.allowed_hosts if str(item).strip()}
        self._allowed_host_suffixes = self._expand_allowed_host_suffixes(self.allowed_hosts)
        self._secret_scanner = build_secret_scanner()

    def evaluate(
        self,
        *,
        url: str,
        method: str = "GET",
        metadata: Mapping[str, Any] | None = None,
    ) -> NetworkPolicy:
        normalized_url = str(url or "").strip()
        reasons: list[NetworkReason] = []
        matched_rules: list[str] = []
        risk_delta = 0
        metadata_map = dict(metadata or {})
        direction = str(metadata_map.get("direction") or "egress").strip().lower() or "egress"

        if not normalized_url:
            reasons.append(
                NetworkReason(
                    source="networkguard",
                    label="Missing URL",
                    details="Network request was denied because no URL was provided.",
                    score=80,
                ),
            )
            return self._finalize(
                reasons=reasons,
                matched_rules=["missing_url"],
                risk_delta=80,
                scheme="",
                host="",
                port=None,
                path="",
                normalized_url=normalized_url,
                direction=direction,
            )

        parsed = urlparse(normalized_url)
        scheme = (parsed.scheme or "").strip().lower()
        host = (parsed.hostname or "").strip().lower()
        port = parsed.port
        path = parsed.path or "/"
        normalized_method = str(method or "GET").upper()

        if not scheme:
            reasons.append(
                NetworkReason(
                    source="networkguard",
                    label="Missing scheme",
                    details="Network request must include an explicit scheme such as https.",
                    score=60,
                ),
            )
            matched_rules.append("missing_scheme")
            risk_delta += 60

        if scheme in self.blocked_schemes:
            reasons.append(
                NetworkReason(
                    source="networkguard",
                    label="Blocked scheme",
                    details=f"Scheme '{scheme}' is blocked by runtime network policy.",
                    score=85,
                ),
            )
            matched_rules.append(f"blocked_scheme:{scheme}")
            risk_delta += 85
        elif scheme and scheme not in self.allowed_schemes:
            reasons.append(
                NetworkReason(
                    source="networkguard",
                    label="Unapproved scheme",
                    details=f"Scheme '{scheme}' is outside the approved network policy set.",
                    score=35,
                ),
            )
            matched_rules.append(f"unapproved_scheme:{scheme}")
            risk_delta += 35

        if not host:
            reasons.append(
                NetworkReason(
                    source="networkguard",
                    label="Missing host",
                    details="Network request URL did not resolve to a host component.",
                    score=70,
                ),
            )
            matched_rules.append("missing_host")
            risk_delta += 70
        else:
            host_risk, host_reasons, host_rules = self._evaluate_host(host)
            reasons.extend(host_reasons)
            matched_rules.extend(host_rules)
            risk_delta += host_risk

        path_risk, path_reasons, path_rules = self._evaluate_path(path)
        reasons.extend(path_reasons)
        matched_rules.extend(path_rules)
        risk_delta += path_risk

        port_risk, port_reasons, port_rules = self._evaluate_port(port=port, scheme=scheme)
        reasons.extend(port_reasons)
        matched_rules.extend(port_rules)
        risk_delta += port_risk

        query_risk, query_reasons, query_rules = self._evaluate_query(parsed.query)
        reasons.extend(query_reasons)
        matched_rules.extend(query_rules)
        risk_delta += query_risk

        header_risk, header_reasons, header_rules = self._evaluate_headers(metadata_map.get("headers"))
        reasons.extend(header_reasons)
        matched_rules.extend(header_rules)
        risk_delta += header_risk

        body_risk, body_reasons, body_rules = self._evaluate_outbound_content(metadata_map)
        reasons.extend(body_reasons)
        matched_rules.extend(body_rules)
        risk_delta += body_risk

        if normalized_method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
            reasons.append(
                NetworkReason(
                    source="networkguard",
                    label="Unexpected method",
                    details=f"HTTP method '{normalized_method}' is non-standard for this runtime profile.",
                    score=10,
                ),
            )
            matched_rules.append(f"unexpected_method:{normalized_method}")
            risk_delta += 10

        if host and self._is_explicitly_allowed_host(host):
            reasons.append(
                NetworkReason(
                    source="networkguard",
                    label="Approved destination",
                    details=f"Host '{host}' is explicitly allowlisted for sandbox egress.",
                    score=0,
                ),
            )
            matched_rules.append(f"allowed_host:{host}")

        return self._finalize(
            reasons=reasons,
            matched_rules=matched_rules,
            risk_delta=risk_delta,
            scheme=scheme,
            host=host,
            port=port,
            path=path,
            normalized_url=normalized_url,
            direction=direction,
        )

    def allow(
        self,
        *,
        url: str,
        method: str = "GET",
        metadata: Mapping[str, Any] | None = None,
    ) -> bool:
        return self.evaluate(url=url, method=method, metadata=metadata).allowed

    def _evaluate_host(self, host: str) -> tuple[int, list[NetworkReason], list[str]]:
        reasons: list[NetworkReason] = []
        matched_rules: list[str] = []
        risk_delta = 0

        for rule_name, pattern, score in self.blocked_host_patterns:
            if re.search(pattern, host):
                reasons.append(
                    NetworkReason(
                        source="networkguard",
                        label="Blocked destination",
                        details=f"Destination host matched blocked rule '{rule_name}'.",
                        score=score,
                    ),
                )
                matched_rules.append(rule_name)
                risk_delta += int(score)

        ip_risk, ip_reasons, ip_rules = self._evaluate_ip_host(host)
        reasons.extend(ip_reasons)
        matched_rules.extend(ip_rules)
        risk_delta += ip_risk

        if "." not in host and host not in {"localhost"}:
            reasons.append(
                NetworkReason(
                    source="networkguard",
                    label="Single-label host",
                    details=f"Host '{host}' is a single-label destination and requires review.",
                    score=25,
                ),
            )
            matched_rules.append("single_label_host")
            risk_delta += 25

        if host and not self._is_explicitly_allowed_host(host):
            reasons.append(
                NetworkReason(
                    source="networkguard",
                    label="Unapproved destination",
                    details=f"Host '{host}' is not on the approved egress allowlist.",
                    score=20,
                ),
            )
            matched_rules.append("host_not_allowlisted")
            risk_delta += 20

        return risk_delta, reasons, matched_rules

    def _evaluate_ip_host(self, host: str) -> tuple[int, list[NetworkReason], list[str]]:
        reasons: list[NetworkReason] = []
        matched_rules: list[str] = []
        risk_delta = 0

        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return risk_delta, reasons, matched_rules

        if ip.is_loopback:
            reasons.append(
                NetworkReason(
                    source="networkguard",
                    label="Loopback destination",
                    details=f"Destination IP '{host}' is loopback and is blocked.",
                    score=95,
                ),
            )
            matched_rules.append("loopback_ip")
            risk_delta += 95

        if ip.is_link_local:
            reasons.append(
                NetworkReason(
                    source="networkguard",
                    label="Link-local destination",
                    details=f"Destination IP '{host}' is link-local and is blocked.",
                    score=95,
                ),
            )
            matched_rules.append("link_local_ip")
            risk_delta += 95

        if ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            reasons.append(
                NetworkReason(
                    source="networkguard",
                    label="Restricted IP range",
                    details=f"Destination IP '{host}' is in a restricted address range.",
                    score=85,
                ),
            )
            matched_rules.append("restricted_ip_range")
            risk_delta += 85

        if ip.is_private and not self.allow_private_hosts:
            reasons.append(
                NetworkReason(
                    source="networkguard",
                    label="Private network destination",
                    details=f"Destination IP '{host}' is private and blocked by sandbox egress policy.",
                    score=90,
                ),
            )
            matched_rules.append("private_ip")
            risk_delta += 90

        return risk_delta, reasons, matched_rules

    def _evaluate_path(self, path: str) -> tuple[int, list[NetworkReason], list[str]]:
        reasons: list[NetworkReason] = []
        matched_rules: list[str] = []
        risk_delta = 0

        for rule_name, pattern, score in self.blocked_path_patterns:
            if re.search(pattern, path):
                reasons.append(
                    NetworkReason(
                        source="networkguard",
                        label="Blocked path",
                        details=f"Request path matched blocked rule '{rule_name}'.",
                        score=score,
                    ),
                )
                matched_rules.append(rule_name)
                risk_delta += int(score)

        return risk_delta, reasons, matched_rules

    def _evaluate_port(self, *, port: int | None, scheme: str) -> tuple[int, list[NetworkReason], list[str]]:
        reasons: list[NetworkReason] = []
        matched_rules: list[str] = []
        risk_delta = 0

        if port is None:
            return risk_delta, reasons, matched_rules

        default_port = 443 if scheme == "https" else 80 if scheme == "http" else None
        if default_port is not None and port != default_port:
            reasons.append(
                NetworkReason(
                    source="networkguard",
                    label="Non-standard port",
                    details=f"Port '{port}' is non-standard for scheme '{scheme}'.",
                    score=15,
                ),
            )
            matched_rules.append(f"non_standard_port:{port}")
            risk_delta += 15

        if port in self.high_risk_ports:
            score = int(self.high_risk_ports[port])
            reasons.append(
                NetworkReason(
                    source="networkguard",
                    label="High-risk port",
                    details=f"Port '{port}' is high risk for sandbox egress.",
                    score=score,
                ),
            )
            matched_rules.append(f"high_risk_port:{port}")
            risk_delta += score

        return risk_delta, reasons, matched_rules

    def _evaluate_query(self, query: str) -> tuple[int, list[NetworkReason], list[str]]:
        reasons: list[NetworkReason] = []
        matched_rules: list[str] = []
        risk_delta = 0

        if not query:
            return risk_delta, reasons, matched_rules

        pairs = parse_qsl(query, keep_blank_values=True)

        for key, value in pairs:
            field_risk, field_reasons, field_rules = self._evaluate_sensitive_field_name(
                field_name=key,
                location="query parameter",
            )
            reasons.extend(field_reasons)
            matched_rules.extend(field_rules)
            risk_delta += field_risk

            combined = f"{key}={value}"
            secret_scan = self._secret_scanner.scan_text(combined)
            if secret_scan.found:
                reasons.append(
                    NetworkReason(
                        source="networkguard",
                        label="Secret in query string",
                        details=f"Query parameter '{key}' appears to contain credential or secret material.",
                        score=70,
                    ),
                )
                matched_rules.append(f"secret_query_param:{key.lower()}")
                risk_delta += 70

        return risk_delta, reasons, matched_rules

    def _evaluate_headers(self, headers: Any) -> tuple[int, list[NetworkReason], list[str]]:
        reasons: list[NetworkReason] = []
        matched_rules: list[str] = []
        risk_delta = 0

        if not isinstance(headers, Mapping):
            return risk_delta, reasons, matched_rules

        for key, value in headers.items():
            header_name = str(key)
            field_risk, field_reasons, field_rules = self._evaluate_sensitive_field_name(
                field_name=header_name,
                location="header",
            )
            reasons.extend(field_reasons)
            matched_rules.extend(field_rules)
            risk_delta += field_risk

            combined = f"{header_name}: {self._to_text(value)}"
            secret_scan = self._secret_scanner.scan_text(combined)
            if secret_scan.found:
                reasons.append(
                    NetworkReason(
                        source="networkguard",
                        label="Secret-bearing header",
                        details=f"Header '{header_name}' appears to carry secret or credential material.",
                        score=75,
                    ),
                )
                matched_rules.append(f"secret_header:{header_name.lower()}")
                risk_delta += 75

        return risk_delta, reasons, matched_rules

    def _evaluate_outbound_content(self, metadata: Mapping[str, Any]) -> tuple[int, list[NetworkReason], list[str]]:
        reasons: list[NetworkReason] = []
        matched_rules: list[str] = []
        risk_delta = 0

        content_candidates: list[tuple[str, Any]] = [
            ("body", metadata.get("body")),
            ("payload", metadata.get("payload")),
            ("content", metadata.get("content")),
            ("data", metadata.get("data")),
            ("json", metadata.get("json")),
            ("files", metadata.get("files")),
        ]

        for location, value in content_candidates:
            if value in {None, "", b"", bytearray()}:
                continue

            text = self._to_text(value)
            if not text:
                continue

            secret_scan = self._secret_scanner.scan_text(text)
            if secret_scan.found:
                reasons.append(
                    NetworkReason(
                        source="networkguard",
                        label="Secret-bearing outbound content",
                        details=f"Outbound {location} appears to contain secret or credential material.",
                        score=min(90, 35 + secret_scan.risk_delta),
                    ),
                )
                matched_rules.append(f"secret_outbound_content:{location}")
                risk_delta += min(90, 35 + secret_scan.risk_delta)

            pattern_risk, pattern_reasons, pattern_rules = self._evaluate_exfil_text_patterns(
                text=text,
                location=location,
            )
            reasons.extend(pattern_reasons)
            matched_rules.extend(pattern_rules)
            risk_delta += pattern_risk

        return risk_delta, reasons, matched_rules

    def _evaluate_sensitive_field_name(
        self,
        *,
        field_name: str,
        location: str,
    ) -> tuple[int, list[NetworkReason], list[str]]:
        reasons: list[NetworkReason] = []
        matched_rules: list[str] = []
        risk_delta = 0

        normalized = str(field_name or "").strip()
        if not normalized:
            return risk_delta, reasons, matched_rules

        for rule_name, pattern, score in self.sensitive_field_patterns:
            if re.search(pattern, normalized):
                reasons.append(
                    NetworkReason(
                        source="networkguard",
                        label="Sensitive outbound field",
                        details=f"{location.title()} '{normalized}' matched sensitive field rule '{rule_name}'.",
                        score=score,
                    ),
                )
                matched_rules.append(f"{location.replace(' ', '_')}:{rule_name}")
                risk_delta += int(score)

        return risk_delta, reasons, matched_rules

    def _evaluate_exfil_text_patterns(
        self,
        *,
        text: str,
        location: str,
    ) -> tuple[int, list[NetworkReason], list[str]]:
        reasons: list[NetworkReason] = []
        matched_rules: list[str] = []
        risk_delta = 0

        for rule_name, pattern, score in self.exfil_content_patterns:
            if re.search(pattern, text):
                reasons.append(
                    NetworkReason(
                        source="networkguard",
                        label="Exfiltration indicator",
                        details=f"Outbound {location} matched exfiltration rule '{rule_name}'.",
                        score=score,
                    ),
                )
                matched_rules.append(f"content:{rule_name}")
                risk_delta += int(score)

        return risk_delta, reasons, matched_rules

    def _expand_allowed_host_suffixes(self, hosts: Iterable[str]) -> set[str]:
        suffixes: set[str] = set()
        for host in hosts:
            normalized = host.strip().lower()
            if not normalized:
                continue
            suffixes.add(normalized)
            suffixes.add(f".{normalized}")
        return suffixes

    def _is_explicitly_allowed_host(self, host: str) -> bool:
        normalized = host.strip().lower()
        if normalized in self.allowed_hosts:
            return True
        return any(normalized.endswith(suffix) for suffix in self._allowed_host_suffixes if suffix.startswith("."))

    def _to_text(self, value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, str):
            return value
        if isinstance(value, bytes | bytearray):
            return value.decode("utf-8", errors="ignore")
        if isinstance(value, Mapping):
            return self._serialize_mapping(value)
        if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
            return "\n".join(self._to_text(item) for item in value)
        return str(value)

    def _serialize_mapping(self, value: Mapping[str, Any]) -> str:
        return "\n".join(f"{key}: {self._to_text(item)}" for key, item in value.items())

    def _dedupe_reasons(self, reasons: Iterable[NetworkReason]) -> list[NetworkReason]:
        deduped: list[NetworkReason] = []
        seen: set[tuple[str, str, str, int]] = set()
        for reason in reasons:
            key = (reason.source, reason.label, reason.details, int(reason.score))
            if key in seen:
                continue
            seen.add(key)
            deduped.append(reason)
        return deduped

    def _dedupe_rules(self, matched_rules: Iterable[str]) -> list[str]:
        deduped: list[str] = []
        seen: set[str] = set()
        for item in matched_rules:
            if item in seen:
                continue
            seen.add(item)
            deduped.append(item)
        return deduped

    def _finalize(
        self,
        *,
        reasons: Iterable[NetworkReason],
        matched_rules: list[str],
        risk_delta: int,
        scheme: str,
        host: str,
        port: int | None,
        path: str,
        normalized_url: str,
        direction: str,
    ) -> NetworkPolicy:
        deduped_reasons = self._dedupe_reasons(reasons)
        deduped_rules = self._dedupe_rules(matched_rules)
        normalized_risk = max(0, min(100, int(risk_delta)))

        verdict = "allow"
        allowed = True
        should_review = False
        should_block = False
        should_quarantine = False

        if normalized_risk >= self.quarantine_threshold:
            verdict = "quarantine"
            allowed = False
            should_block = True
            should_quarantine = True
        elif normalized_risk >= self.block_threshold:
            verdict = "block"
            allowed = False
            should_block = True
        elif normalized_risk >= self.review_threshold:
            verdict = "review"
            should_review = True

        return NetworkPolicy(
            verdict=verdict,
            allowed=allowed,
            should_review=should_review,
            should_block=should_block,
            should_quarantine=should_quarantine,
            risk_delta=normalized_risk,
            scheme=scheme,
            host=host,
            port=port,
            path=path,
            normalized_url=normalized_url,
            reasons=[reason.as_dict() for reason in deduped_reasons],
            matched_rules=deduped_rules,
            direction=direction,
        )


def initialize_networkguard(
    *,
    review_threshold: int = 20,
    block_threshold: int = 50,
    quarantine_threshold: int = 80,
    allowed_schemes: Iterable[str] | None = None,
    blocked_schemes: Iterable[str] | None = None,
    allowed_hosts: Iterable[str] | None = None,
    blocked_host_patterns: Iterable[tuple[str, str, int]] | None = None,
    blocked_path_patterns: Iterable[tuple[str, str, int]] | None = None,
    sensitive_field_patterns: Iterable[tuple[str, str, int]] | None = None,
    exfil_content_patterns: Iterable[tuple[str, str, int]] | None = None,
    high_risk_ports: Mapping[int, int] | None = None,
    allow_private_hosts: bool = False,
) -> NetworkGuard:
    return NetworkGuard(
        review_threshold=review_threshold,
        block_threshold=block_threshold,
        quarantine_threshold=quarantine_threshold,
        allowed_schemes=set(allowed_schemes or DEFAULT_ALLOWED_SCHEMES),
        blocked_schemes=set(blocked_schemes or DEFAULT_BLOCKED_SCHEMES),
        allowed_hosts=set(allowed_hosts or DEFAULT_ALLOWED_HOSTS),
        blocked_host_patterns=tuple(blocked_host_patterns or DEFAULT_BLOCKED_HOST_PATTERNS),
        blocked_path_patterns=tuple(blocked_path_patterns or DEFAULT_BLOCKED_PATH_PATTERNS),
        sensitive_field_patterns=tuple(sensitive_field_patterns or DEFAULT_SENSITIVE_FIELD_PATTERNS),
        exfil_content_patterns=tuple(exfil_content_patterns or DEFAULT_EXFIL_CONTENT_PATTERNS),
        high_risk_ports=dict(high_risk_ports or DEFAULT_HIGH_RISK_PORTS),
        allow_private_hosts=allow_private_hosts,
    )


def build_network_guard() -> NetworkGuard:
    return initialize_networkguard()
