from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Mapping
from urllib.parse import urlparse

from app.runtime.sandbox_router import SandboxLane, route_to_sandbox


LOCAL_HOSTS = {
    "localhost",
    "127.0.0.1",
    "::1",
    "0.0.0.0",
    "host.docker.internal",
}

HIGH_RISK_SCHEMES = {
    "file",
    "ftp",
    "smb",
    "ssh",
}

MEDIUM_RISK_KEYWORDS = {
    "download",
    "upload",
    "fetch",
    "webhook",
    "remote",
    "external",
    "redirect",
    "archive",
}

HIGH_RISK_KEYWORDS = {
    "metadata",
    "credential",
    "token",
    "cookie",
    "exfiltrate",
    "callback",
    "beacon",
    "command and control",
    "c2",
    "internal service",
    "169.254.169.254",
}


@dataclass(slots=True)
class NetworkGuardDecision:
    allowed: bool
    response_status: str
    policy_verdict: str
    sandbox_lane: str
    risk_score: int
    should_execute: bool
    halted_by_boundary: bool
    requires_review: bool
    url: str
    hostname: str
    scheme: str
    is_local_target: bool
    is_private_target: bool
    reason: str
    reasons: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _normalize_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip().lower()


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _get_value(payload: Mapping[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in payload:
            return payload[key]
    return None


def _extract_url(payload: Mapping[str, Any]) -> str:
    value = _get_value(payload, "url", "target", "target_value", "resource")
    return str(value or "")


def _collect_signal_text(payload: Mapping[str, Any], url: str) -> str:
    parts = [url]

    for key in (
        "summary",
        "reason",
        "content",
        "description",
        "action_type",
        "target_type",
    ):
        value = payload.get(key)
        if value is not None:
            parts.append(str(value))

    for key in ("reasons", "failed_checks", "matched_patterns", "tags", "alerts"):
        value = payload.get(key)
        if isinstance(value, list):
            parts.extend(str(item) for item in value if item is not None)
        elif value is not None:
            parts.append(str(value))

    return " | ".join(parts).lower()


def _is_private_target(hostname: str) -> bool:
    if not hostname:
        return False

    hostname = hostname.lower()

    if hostname in LOCAL_HOSTS:
        return True

    private_prefixes = (
        "10.",
        "192.168.",
        "172.16.",
        "172.17.",
        "172.18.",
        "172.19.",
        "172.20.",
        "172.21.",
        "172.22.",
        "172.23.",
        "172.24.",
        "172.25.",
        "172.26.",
        "172.27.",
        "172.28.",
        "172.29.",
        "172.30.",
        "172.31.",
    )

    return hostname.startswith(private_prefixes)


def _scheme_score(scheme: str) -> tuple[int, list[str]]:
    if scheme in HIGH_RISK_SCHEMES:
        return 50, [f"high-risk network scheme detected: {scheme}"]
    if scheme in {"http", "https"}:
        return 10, [f"external network request detected: {scheme}"]
    if scheme:
        return 20, [f"unrecognized network scheme detected: {scheme}"]
    return 0, []


def _target_score(hostname: str, is_private_target: bool) -> tuple[int, list[str]]:
    reasons: list[str] = []
    score = 0

    if not hostname:
        return 20, ["missing hostname in network request"]

    if hostname.lower() in LOCAL_HOSTS:
        score += 70
        reasons.append(f"local target detected: {hostname}")
    elif is_private_target:
        score += 60
        reasons.append(f"private-network target detected: {hostname}")

    if hostname.endswith(".local"):
        score += 40
        reasons.append(f"local-domain target detected: {hostname}")

    return score, reasons


def _keyword_score(signal_text: str) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []

    for keyword in HIGH_RISK_KEYWORDS:
        if keyword in signal_text:
            score += 30
            reasons.append(f"high-risk network keyword detected: {keyword}")

    for keyword in MEDIUM_RISK_KEYWORDS:
        if keyword in signal_text:
            score += 10
            reasons.append(f"network review keyword detected: {keyword}")

    return score, reasons


def evaluate_network_request(payload: Mapping[str, Any]) -> NetworkGuardDecision:
    url = _extract_url(payload)
    parsed = urlparse(url if "://" in url else f"https://{url}" if url else "")
    hostname = (parsed.hostname or "").lower()
    scheme = _normalize_text(parsed.scheme)
    is_private_target = _is_private_target(hostname)
    base_risk = _safe_int(_get_value(payload, "risk_score", "score"), 0)

    signal_text = _collect_signal_text(payload, url)
    scheme_score, scheme_reasons = _scheme_score(scheme)
    target_score, target_reasons = _target_score(hostname, is_private_target)
    keyword_score, keyword_reasons = _keyword_score(signal_text)

    total_risk = min(100, base_risk + scheme_score + target_score + keyword_score)
    reasons = [*scheme_reasons, *target_reasons, *keyword_reasons]

    route_payload = {
        "action_type": payload.get("action_type") or "network_request",
        "target": url,
        "content": signal_text,
        "risk_score": total_risk,
        "reasons": reasons,
        "policy_verdict": payload.get("policy_verdict") or payload.get("verdict"),
        "summary": payload.get("summary"),
        "reason": payload.get("reason"),
    }
    route_decision = route_to_sandbox(route_payload)

    if route_decision.lane == SandboxLane.HARD_BLOCK:
        response_status = "denied"
        policy_verdict = "deny"
        allowed = False
        halted_by_boundary = True
    elif route_decision.requires_review:
        response_status = "queued_for_review"
        policy_verdict = "warn"
        allowed = False
        halted_by_boundary = True
    else:
        response_status = "completed"
        policy_verdict = "allow"
        allowed = True
        halted_by_boundary = False

    if not reasons:
        reasons.append("network request accepted under current low-risk policy")

    return NetworkGuardDecision(
        allowed=allowed,
        response_status=response_status,
        policy_verdict=policy_verdict,
        sandbox_lane=route_decision.lane.value,
        risk_score=total_risk,
        should_execute=route_decision.should_execute and allowed,
        halted_by_boundary=halted_by_boundary,
        requires_review=route_decision.requires_review,
        url=url,
        hostname=hostname,
        scheme=scheme,
        is_local_target=hostname in LOCAL_HOSTS,
        is_private_target=is_private_target,
        reason=reasons[0],
        reasons=reasons,
        metadata={"source": "network_guard"},
    )


def summarize_network_guard(payload: Mapping[str, Any]) -> dict[str, Any]:
    return evaluate_network_request(payload).to_dict()


__all__ = [
    "LOCAL_HOSTS",
    "HIGH_RISK_SCHEMES",
    "MEDIUM_RISK_KEYWORDS",
    "HIGH_RISK_KEYWORDS",
    "NetworkGuardDecision",
    "evaluate_network_request",
    "summarize_network_guard",
]