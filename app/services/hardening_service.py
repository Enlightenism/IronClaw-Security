from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
import os
from typing import Any

# ---------------------------------------------------------------------------
# HardeningCheckStatus
# ---------------------------------------------------------------------------


class HardeningCheckStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    SKIP = "skip"


# ---------------------------------------------------------------------------
# HardeningRule
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HardeningRule:
    rule_id: str
    description: str
    severity: str
    enabled: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "description": self.description,
            "severity": self.severity,
            "enabled": self.enabled,
        }


# ---------------------------------------------------------------------------
# HardeningRuleSet
# ---------------------------------------------------------------------------


@dataclass
class HardeningRuleSet:
    rules: list[HardeningRule] = field(default_factory=list)

    def get(self, rule_id: str) -> HardeningRule | None:
        for r in self.rules:
            if r.rule_id == rule_id:
                return r
        return None

    def enabled_rules(self) -> list[HardeningRule]:
        return [r for r in self.rules if r.enabled]

    def by_severity(self, severity: str) -> list[HardeningRule]:
        return [r for r in self.rules if r.severity == severity]

    def to_dict(self) -> dict[str, Any]:
        return {"rules": [r.to_dict() for r in self.rules]}


# ---------------------------------------------------------------------------
# Default ruleset
# ---------------------------------------------------------------------------

_SEVERITY_WEIGHTS: dict[str, int] = {
    "critical": 30,
    "high": 20,
    "medium": 10,
    "low": 5,
    "info": 1,
}

_DEFAULT_RULES: list[HardeningRule] = [
    HardeningRule("TLS-001", "Host must use HTTPS (TLS)", "critical"),
    HardeningRule("HEADER-001", "X-Frame-Options must be present", "high"),
    HardeningRule("HEADER-002", "X-Content-Type-Options must be present", "high"),
    HardeningRule("HEADER-003", "Strict-Transport-Security must be present", "high"),
    HardeningRule("HEADER-004", "Content-Security-Policy must be present", "high"),
    HardeningRule("HEADER-005", "X-XSS-Protection must be present", "medium"),
    HardeningRule("HEADER-006", "Referrer-Policy must be present", "medium"),
    HardeningRule("HEADER-007", "Permissions-Policy must be present", "medium"),
    HardeningRule("SECRET-001", "No secret-pattern env vars with hardcoded values", "critical"),
    HardeningRule("ENV-001", "DEBUG must not be true in production", "high"),
    HardeningRule("ENV-002", "ENVIRONMENT variable must be set", "medium"),
    HardeningRule("RATELIMIT-001", "Rate limit must not be unreasonably high", "medium"),
]

_SECRET_KEY_PATTERNS: tuple[str, ...] = (
    "SECRET",
    "API_KEY",
    "PASSWORD",
    "TOKEN",
    "PRIVATE_KEY",
    "ACCESS_KEY",
    "AUTH_KEY",
    "CREDENTIALS",
    "PASSWD",
    "PWD",
)

_REQUIRED_SECURITY_HEADERS: tuple[str, ...] = (
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
)

_HIGH_RPM_THRESHOLD = 10_000
_HIGH_BURST_THRESHOLD = 5_000


def default_hardening_ruleset() -> HardeningRuleSet:
    return HardeningRuleSet(rules=list(_DEFAULT_RULES))


# ---------------------------------------------------------------------------
# RateLimitConfig
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RateLimitConfig:
    requests_per_minute: int = 60
    burst: int = 10

    def __post_init__(self) -> None:
        if self.requests_per_minute <= 0:
            raise ValueError("requests_per_minute must be > 0")
        if self.burst < 0:
            raise ValueError("burst must be >= 0")

    def to_dict(self) -> dict[str, Any]:
        return {
            "requests_per_minute": self.requests_per_minute,
            "burst": self.burst,
        }


# ---------------------------------------------------------------------------
# HardeningTarget
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HardeningTarget:
    name: str
    host: str
    headers: dict[str, str] = field(default_factory=dict)
    env: dict[str, str] = field(default_factory=dict)
    rate_limit: RateLimitConfig = field(default_factory=RateLimitConfig)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "host": self.host,
            "headers": dict(self.headers),
            # Expose only key names — never values
            "env": {k: "***" for k in self.env},
            "rate_limit": self.rate_limit.to_dict(),
        }


# ---------------------------------------------------------------------------
# HardeningCheckResult
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HardeningCheckResult:
    rule_id: str
    status: HardeningCheckStatus
    message: str
    detail: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "status": self.status,
            "message": self.message,
            "detail": self.detail,
        }


# ---------------------------------------------------------------------------
# PostureScore
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PostureScore:
    score: int
    max_score: int
    grade: str

    def __post_init__(self) -> None:
        if self.score < 0:
            raise ValueError("score must be >= 0")
        if self.score > self.max_score:
            raise ValueError("score must not exceed max_score")

    def pass_rate(self) -> float:
        if self.max_score == 0:
            return 1.0
        return self.score / self.max_score

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "max_score": self.max_score,
            "grade": self.grade,
            "pass_rate": self.pass_rate(),
        }


def _grade(pass_rate: float) -> str:
    if pass_rate >= 0.97:
        return "A"
    if pass_rate >= 0.80:
        return "B"
    if pass_rate >= 0.65:
        return "C"
    if pass_rate >= 0.50:
        return "D"
    return "F"


# ---------------------------------------------------------------------------
# Sub-reports
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TLSHardeningReport:
    host: str
    result: HardeningCheckResult

    def to_dict(self) -> dict[str, Any]:
        return {"host": self.host, "result": self.result.to_dict()}


@dataclass(frozen=True)
class HeaderHardeningReport:
    result: HardeningCheckResult
    present_headers: list[str]
    missing_headers: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "result": self.result.to_dict(),
            "present_headers": self.present_headers,
            "missing_headers": self.missing_headers,
        }


@dataclass(frozen=True)
class SecretExposureReport:
    result: HardeningCheckResult
    exposed_keys: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "result": self.result.to_dict(),
            "exposed_keys": self.exposed_keys,
        }


@dataclass(frozen=True)
class EnvHardeningReport:
    result: HardeningCheckResult
    findings: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "result": self.result.to_dict(),
            "findings": self.findings,
        }


@dataclass(frozen=True)
class RateLimitHardeningReport:
    result: HardeningCheckResult
    config: RateLimitConfig

    def to_dict(self) -> dict[str, Any]:
        return {
            "result": self.result.to_dict(),
            "config": self.config.to_dict(),
        }


# ---------------------------------------------------------------------------
# Composite HardeningReport
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HardeningReport:
    target_name: str
    posture_score: PostureScore
    tls: TLSHardeningReport
    headers: HeaderHardeningReport
    secret_exposure: SecretExposureReport
    env_hardening: EnvHardeningReport
    rate_limit: RateLimitHardeningReport
    checked_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_name": self.target_name,
            "posture_score": self.posture_score.to_dict(),
            "tls": self.tls.to_dict(),
            "headers": self.headers.to_dict(),
            "secret_exposure": self.secret_exposure.to_dict(),
            "env_hardening": self.env_hardening.to_dict(),
            "rate_limit": self.rate_limit.to_dict(),
            "checked_at": self.checked_at,
        }


# ---------------------------------------------------------------------------
# HardeningService
# ---------------------------------------------------------------------------


class HardeningService:
    def __init__(self, ruleset: HardeningRuleSet | None = None) -> None:
        self.ruleset = ruleset or default_hardening_ruleset()

    # ------------------------------------------------------------------
    # check_rule
    # ------------------------------------------------------------------

    def check_rule(self, rule_id: str, context: dict[str, Any]) -> HardeningCheckResult:
        rule = self.ruleset.get(rule_id)
        if rule is None:
            raise KeyError(f"Unknown hardening rule: {rule_id!r}")
        if not rule.enabled:
            return HardeningCheckResult(
                rule_id=rule_id,
                status=HardeningCheckStatus.SKIP,
                message="Rule disabled",
                detail={},
            )
        return HardeningCheckResult(
            rule_id=rule_id,
            status=HardeningCheckStatus.PASS,
            message="Rule check passed",
            detail=context,
        )

    # ------------------------------------------------------------------
    # Individual checks
    # ------------------------------------------------------------------

    def check_tls(self, target: HardeningTarget) -> TLSHardeningReport:
        rule_id = "TLS-001"
        if target.host.startswith("https://"):
            result = HardeningCheckResult(
                rule_id=rule_id,
                status=HardeningCheckStatus.PASS,
                message="Host uses HTTPS",
                detail={"host": target.host},
            )
        else:
            result = HardeningCheckResult(
                rule_id=rule_id,
                status=HardeningCheckStatus.FAIL,
                message="Host does not use HTTPS — TLS required",
                detail={"host": target.host},
            )
        return TLSHardeningReport(host=target.host, result=result)

    def check_headers(self, target: HardeningTarget) -> HeaderHardeningReport:
        rule_id = "HEADER-001"
        present = [h for h in _REQUIRED_SECURITY_HEADERS if h in target.headers]
        missing = [h for h in _REQUIRED_SECURITY_HEADERS if h not in target.headers]

        if not missing:
            status = HardeningCheckStatus.PASS
            message = "All required security headers present"
        elif len(missing) <= 2:
            status = HardeningCheckStatus.WARN
            message = f"{len(missing)} security header(s) missing"
        else:
            status = HardeningCheckStatus.FAIL
            message = f"{len(missing)} security headers missing"

        result = HardeningCheckResult(
            rule_id=rule_id,
            status=status,
            message=message,
            detail={"missing": missing, "present": present},
        )
        return HeaderHardeningReport(
            result=result,
            present_headers=present,
            missing_headers=missing,
        )

    def check_secret_exposure(self, target: HardeningTarget) -> SecretExposureReport:
        rule_id = "SECRET-001"
        exposed: list[str] = []
        for key in target.env:
            upper = key.upper()
            if any(pat in upper for pat in _SECRET_KEY_PATTERNS):
                exposed.append(key)

        if not exposed:
            status = HardeningCheckStatus.PASS
            message = "No secret-pattern env vars detected"
        else:
            status = HardeningCheckStatus.WARN
            message = f"{len(exposed)} potential secret env var(s) detected"

        result = HardeningCheckResult(
            rule_id=rule_id,
            status=status,
            message=message,
            detail={"exposed_key_count": len(exposed)},
        )
        return SecretExposureReport(result=result, exposed_keys=exposed)

    def check_env_hardening(self, target: HardeningTarget) -> EnvHardeningReport:
        rule_id = "ENV-001"
        findings: list[str] = []
        env = {k.upper(): v.lower() for k, v in target.env.items()}

        if "ENVIRONMENT" not in env:
            findings.append("ENVIRONMENT variable not set")

        debug_val = env.get("DEBUG", "false")
        if debug_val in ("true", "1", "yes", "on"):
            findings.append("DEBUG is enabled")

        if not findings:
            status = HardeningCheckStatus.PASS
            message = "Env hardening checks passed"
        elif len(findings) == 1 and "ENVIRONMENT" in findings[0]:
            status = HardeningCheckStatus.WARN
            message = "Env hardening warnings present"
        else:
            status = HardeningCheckStatus.FAIL
            message = "Env hardening failures detected"

        result = HardeningCheckResult(
            rule_id=rule_id,
            status=status,
            message=message,
            detail={"findings": findings},
        )
        return EnvHardeningReport(result=result, findings=findings)

    def check_rate_limit(self, target: HardeningTarget) -> RateLimitHardeningReport:
        rule_id = "RATELIMIT-001"
        cfg = target.rate_limit

        if cfg.requests_per_minute > _HIGH_RPM_THRESHOLD or cfg.burst > _HIGH_BURST_THRESHOLD:
            status = HardeningCheckStatus.WARN
            message = "Rate limit configuration is very permissive"
        else:
            status = HardeningCheckStatus.PASS
            message = "Rate limit configuration is acceptable"

        result = HardeningCheckResult(
            rule_id=rule_id,
            status=status,
            message=message,
            detail=cfg.to_dict(),
        )
        return RateLimitHardeningReport(result=result, config=cfg)

    # ------------------------------------------------------------------
    # summarize
    # ------------------------------------------------------------------

    def summarize(self, results: list[HardeningCheckResult]) -> dict[str, int]:
        summary: dict[str, int] = {
            HardeningCheckStatus.PASS: 0,
            HardeningCheckStatus.FAIL: 0,
            HardeningCheckStatus.WARN: 0,
            HardeningCheckStatus.SKIP: 0,
        }
        for r in results:
            summary[r.status] = summary.get(r.status, 0) + 1
        return summary

    # ------------------------------------------------------------------
    # compute_posture_score
    # ------------------------------------------------------------------

    def compute_posture_score(self, results: list[HardeningCheckResult]) -> PostureScore:
        if not results:
            return PostureScore(score=100, max_score=100, grade="A")

        total = len([r for r in results if r.status != HardeningCheckStatus.SKIP])
        if total == 0:
            return PostureScore(score=100, max_score=100, grade="A")

        passed = len([r for r in results if r.status == HardeningCheckStatus.PASS])
        warn_count = len([r for r in results if r.status == HardeningCheckStatus.WARN])

        raw_score = passed + (warn_count * 0.5)
        ratio = raw_score / total
        score = round(ratio * 100)
        score = max(0, min(score, 100))

        return PostureScore(score=score, max_score=100, grade=_grade(ratio))

    # ------------------------------------------------------------------
    # run_full_audit
    # ------------------------------------------------------------------

    def run_full_audit(self, target: HardeningTarget) -> HardeningReport:
        tls_report = self.check_tls(target)
        header_report = self.check_headers(target)
        secret_report = self.check_secret_exposure(target)
        env_report = self.check_env_hardening(target)
        rate_report = self.check_rate_limit(target)

        all_results = [
            tls_report.result,
            header_report.result,
            secret_report.result,
            env_report.result,
            rate_report.result,
        ]

        posture = self.compute_posture_score(all_results)
        checked_at = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

        return HardeningReport(
            target_name=target.name,
            posture_score=posture,
            tls=tls_report,
            headers=header_report,
            secret_exposure=secret_report,
            env_hardening=env_report,
            rate_limit=rate_report,
            checked_at=checked_at,
        )


# ---------------------------------------------------------------------------
# build_default_hardening_service
# ---------------------------------------------------------------------------


def build_default_hardening_service() -> HardeningService:
    strict = os.getenv("IRONCLAW_HARDENING_STRICT", "false").lower() in (
        "true",
        "1",
        "yes",
    )
    ruleset = default_hardening_ruleset()
    if strict:
        # In strict mode all rules remain enabled — future hook for custom overrides
        pass
    return HardeningService(ruleset=ruleset)
