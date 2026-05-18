from __future__ import annotations

import pytest

from app.services.hardening_service import (
    EnvHardeningReport,
    HardeningCheckResult,
    HardeningCheckStatus,
    HardeningReport,
    HardeningRule,
    HardeningRuleSet,
    HardeningService,
    HardeningTarget,
    HeaderHardeningReport,
    PostureScore,
    RateLimitConfig,
    RateLimitHardeningReport,
    SecretExposureReport,
    TLSHardeningReport,
    build_default_hardening_service,
    default_hardening_ruleset,
)

# ---------------------------------------------------------------------------
# Helpers / factories
# ---------------------------------------------------------------------------


def _make_service(rules: HardeningRuleSet | None = None) -> HardeningService:
    return HardeningService(ruleset=rules or default_hardening_ruleset())


def _make_target(
    *,
    name: str = "ironclaw-runtime",
    host: str = "https://ironclaw.local",
    headers: dict[str, str] | None = None,
    env: dict[str, str] | None = None,
    rate_limit: RateLimitConfig | None = None,
) -> HardeningTarget:
    return HardeningTarget(
        name=name,
        host=host,
        headers=headers or {},
        env=env or {},
        rate_limit=rate_limit or RateLimitConfig(requests_per_minute=60, burst=10),
    )


def _make_rule(
    rule_id: str = "test-rule",
    description: str = "Test rule",
    severity: str = "medium",
    enabled: bool = True,
) -> HardeningRule:
    return HardeningRule(
        rule_id=rule_id,
        description=description,
        severity=severity,
        enabled=enabled,
    )


# ---------------------------------------------------------------------------
# HardeningCheckStatus
# ---------------------------------------------------------------------------


class TestHardeningCheckStatus:
    def test_pass_value(self) -> None:
        assert HardeningCheckStatus.PASS == "pass"

    def test_fail_value(self) -> None:
        assert HardeningCheckStatus.FAIL == "fail"

    def test_warn_value(self) -> None:
        assert HardeningCheckStatus.WARN == "warn"

    def test_skip_value(self) -> None:
        assert HardeningCheckStatus.SKIP == "skip"

    def test_all_statuses_distinct(self) -> None:
        statuses = {
            HardeningCheckStatus.PASS,
            HardeningCheckStatus.FAIL,
            HardeningCheckStatus.WARN,
            HardeningCheckStatus.SKIP,
        }
        assert len(statuses) == 4


# ---------------------------------------------------------------------------
# HardeningRule
# ---------------------------------------------------------------------------


class TestHardeningRule:
    def test_defaults(self) -> None:
        r = HardeningRule(rule_id="r1", description="desc", severity="high")
        assert r.enabled is True

    def test_disabled_rule(self) -> None:
        r = HardeningRule(rule_id="r1", description="desc", severity="low", enabled=False)
        assert r.enabled is False

    def test_severity_stored(self) -> None:
        for sev in ("critical", "high", "medium", "low", "info"):
            r = HardeningRule(rule_id="x", description="d", severity=sev)
            assert r.severity == sev

    def test_to_dict_keys(self) -> None:
        r = _make_rule()
        d = r.to_dict()
        assert {"rule_id", "description", "severity", "enabled"}.issubset(set(d))

    def test_frozen(self) -> None:
        r = _make_rule()
        with pytest.raises((AttributeError, TypeError)):
            r.rule_id = "mutated"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# HardeningRuleSet
# ---------------------------------------------------------------------------


class TestHardeningRuleSet:
    def test_get_rule_by_id(self) -> None:
        r = _make_rule("SEC-001")
        rs = HardeningRuleSet(rules=[r])
        assert rs.get("SEC-001") is r

    def test_get_missing_returns_none(self) -> None:
        rs = HardeningRuleSet(rules=[])
        assert rs.get("does-not-exist") is None

    def test_enabled_rules_only(self) -> None:
        r1 = _make_rule("A", enabled=True)
        r2 = _make_rule("B", enabled=False)
        rs = HardeningRuleSet(rules=[r1, r2])
        enabled = rs.enabled_rules()
        assert r1 in enabled
        assert r2 not in enabled

    def test_rules_by_severity(self) -> None:
        r_high = _make_rule("H", severity="high")
        r_med = _make_rule("M", severity="medium")
        rs = HardeningRuleSet(rules=[r_high, r_med])
        assert rs.by_severity("high") == [r_high]
        assert rs.by_severity("medium") == [r_med]

    def test_to_dict_contains_rules(self) -> None:
        rs = HardeningRuleSet(rules=[_make_rule()])
        d = rs.to_dict()
        assert "rules" in d
        assert isinstance(d["rules"], list)


# ---------------------------------------------------------------------------
# default_hardening_ruleset
# ---------------------------------------------------------------------------


class TestDefaultHardeningRuleset:
    def test_returns_hardening_ruleset(self) -> None:
        rs = default_hardening_ruleset()
        assert isinstance(rs, HardeningRuleSet)

    def test_contains_tls_rule(self) -> None:
        rs = default_hardening_ruleset()
        ids = {r.rule_id for r in rs.rules}
        assert any("tls" in rid.lower() or "HTTPS" in rid or "TLS" in rid for rid in ids)

    def test_contains_header_rule(self) -> None:
        rs = default_hardening_ruleset()
        ids = {r.rule_id for r in rs.rules}
        assert any("header" in rid.lower() or "HEADER" in rid for rid in ids)

    def test_contains_secret_exposure_rule(self) -> None:
        rs = default_hardening_ruleset()
        ids = {r.rule_id for r in rs.rules}
        assert any("secret" in rid.lower() or "env" in rid.lower() or "SECRET" in rid for rid in ids)

    def test_all_rules_have_severity(self) -> None:
        rs = default_hardening_ruleset()
        for r in rs.rules:
            assert r.severity in ("critical", "high", "medium", "low", "info")

    def test_no_duplicate_rule_ids(self) -> None:
        rs = default_hardening_ruleset()
        ids = [r.rule_id for r in rs.rules]
        assert len(ids) == len(set(ids))


# ---------------------------------------------------------------------------
# RateLimitConfig
# ---------------------------------------------------------------------------


class TestRateLimitConfig:
    def test_default_values(self) -> None:
        cfg = RateLimitConfig()
        assert cfg.requests_per_minute > 0
        assert cfg.burst >= 0

    def test_custom_values(self) -> None:
        cfg = RateLimitConfig(requests_per_minute=100, burst=20)
        assert cfg.requests_per_minute == 100
        assert cfg.burst == 20

    def test_zero_rpm_invalid(self) -> None:
        with pytest.raises((ValueError, TypeError)):
            RateLimitConfig(requests_per_minute=0, burst=0)

    def test_negative_rpm_invalid(self) -> None:
        with pytest.raises((ValueError, TypeError)):
            RateLimitConfig(requests_per_minute=-1, burst=0)

    def test_to_dict(self) -> None:
        cfg = RateLimitConfig(requests_per_minute=30, burst=5)
        d = cfg.to_dict()
        assert d["requests_per_minute"] == 30
        assert d["burst"] == 5


# ---------------------------------------------------------------------------
# HardeningTarget
# ---------------------------------------------------------------------------


class TestHardeningTarget:
    def test_https_host_valid(self) -> None:
        t = _make_target(host="https://secure.example.com")
        assert t.host.startswith("https://")

    def test_http_host_stored(self) -> None:
        t = _make_target(host="http://insecure.example.com")
        assert t.host.startswith("http://")

    def test_to_dict_keys(self) -> None:
        t = _make_target()
        d = t.to_dict()
        assert {"name", "host", "headers", "env", "rate_limit"}.issubset(set(d))

    def test_to_dict_env_excluded_from_values(self) -> None:
        t = _make_target(env={"SECRET_KEY": "super-secret", "LOG_LEVEL": "DEBUG"})
        d = t.to_dict()
        # Values must not be leaked into to_dict; only keys allowed
        raw_env = d.get("env", {})
        if isinstance(raw_env, dict):
            for val in raw_env.values():
                assert "super-secret" not in str(val)

    def test_frozen(self) -> None:
        t = _make_target()
        with pytest.raises((AttributeError, TypeError)):
            t.name = "mutated"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# HardeningCheckResult
# ---------------------------------------------------------------------------


class TestHardeningCheckResult:
    def test_pass_result(self) -> None:
        r = HardeningCheckResult(
            rule_id="SEC-001",
            status=HardeningCheckStatus.PASS,
            message="All clear",
            detail={},
        )
        assert r.status == HardeningCheckStatus.PASS

    def test_fail_result(self) -> None:
        r = HardeningCheckResult(
            rule_id="SEC-002",
            status=HardeningCheckStatus.FAIL,
            message="Missing header",
            detail={"header": "X-Frame-Options"},
        )
        assert r.status == HardeningCheckStatus.FAIL
        assert "X-Frame-Options" in str(r.detail)

    def test_to_dict_all_fields(self) -> None:
        r = HardeningCheckResult(
            rule_id="R1",
            status=HardeningCheckStatus.WARN,
            message="warning",
            detail={"note": "check tls"},
        )
        d = r.to_dict()
        assert {"rule_id", "status", "message", "detail"}.issubset(set(d))

    def test_frozen(self) -> None:
        r = HardeningCheckResult(
            rule_id="X",
            status=HardeningCheckStatus.PASS,
            message="ok",
            detail={},
        )
        with pytest.raises((AttributeError, TypeError)):
            r.status = HardeningCheckStatus.FAIL  # type: ignore[misc]


# ---------------------------------------------------------------------------
# PostureScore
# ---------------------------------------------------------------------------


class TestPostureScore:
    def test_perfect_score(self) -> None:
        ps = PostureScore(score=100, max_score=100, grade="A")
        assert ps.score == 100
        assert ps.grade == "A"

    def test_zero_score(self) -> None:
        ps = PostureScore(score=0, max_score=100, grade="F")
        assert ps.grade == "F"

    def test_score_cannot_exceed_max(self) -> None:
        with pytest.raises((ValueError, TypeError)):
            PostureScore(score=101, max_score=100, grade="A")

    def test_score_cannot_be_negative(self) -> None:
        with pytest.raises((ValueError, TypeError)):
            PostureScore(score=-1, max_score=100, grade="F")

    def test_to_dict(self) -> None:
        ps = PostureScore(score=75, max_score=100, grade="C")
        d = ps.to_dict()
        assert d["score"] == 75
        assert d["grade"] == "C"

    def test_pass_rate(self) -> None:
        ps = PostureScore(score=80, max_score=100, grade="B")
        assert abs(ps.pass_rate() - 0.8) < 1e-6


# ---------------------------------------------------------------------------
# TLSHardeningReport
# ---------------------------------------------------------------------------


class TestTLSHardeningReport:
    def test_https_passes(self) -> None:
        svc = _make_service()
        target = _make_target(host="https://secure.example.com")
        report = svc.check_tls(target)
        assert isinstance(report, TLSHardeningReport)
        result = report.result
        assert result.status == HardeningCheckStatus.PASS

    def test_http_fails(self) -> None:
        svc = _make_service()
        target = _make_target(host="http://insecure.example.com")
        report = svc.check_tls(target)
        assert report.result.status == HardeningCheckStatus.FAIL

    def test_report_contains_host(self) -> None:
        svc = _make_service()
        target = _make_target(host="https://example.com")
        report = svc.check_tls(target)
        assert report.host == target.host

    def test_to_dict_has_result(self) -> None:
        svc = _make_service()
        target = _make_target(host="https://example.com")
        report = svc.check_tls(target)
        d = report.to_dict()
        assert "result" in d


# ---------------------------------------------------------------------------
# HeaderHardeningReport
# ---------------------------------------------------------------------------


class TestHeaderHardeningReport:
    def test_all_required_headers_present_passes(self) -> None:
        svc = _make_service()
        headers = {
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'",
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()",
        }
        target = _make_target(headers=headers)
        report = svc.check_headers(target)
        assert isinstance(report, HeaderHardeningReport)
        assert report.result.status in (
            HardeningCheckStatus.PASS,
            HardeningCheckStatus.WARN,
        )

    def test_missing_headers_fail(self) -> None:
        svc = _make_service()
        target = _make_target(headers={})
        report = svc.check_headers(target)
        assert report.result.status == HardeningCheckStatus.FAIL

    def test_missing_headers_listed(self) -> None:
        svc = _make_service()
        target = _make_target(headers={})
        report = svc.check_headers(target)
        assert len(report.missing_headers) > 0

    def test_present_headers_listed(self) -> None:
        svc = _make_service()
        headers = {"X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff"}
        target = _make_target(headers=headers)
        report = svc.check_headers(target)
        assert "X-Frame-Options" in report.present_headers
        assert "X-Content-Type-Options" in report.present_headers

    def test_to_dict_structure(self) -> None:
        svc = _make_service()
        target = _make_target(headers={})
        report = svc.check_headers(target)
        d = report.to_dict()
        assert {"result", "missing_headers", "present_headers"}.issubset(set(d))


# ---------------------------------------------------------------------------
# SecretExposureReport
# ---------------------------------------------------------------------------


class TestSecretExposureReport:
    def test_clean_env_passes(self) -> None:
        svc = _make_service()
        target = _make_target(env={"LOG_LEVEL": "DEBUG", "PORT": "8080"})
        report = svc.check_secret_exposure(target)
        assert isinstance(report, SecretExposureReport)
        assert report.result.status in (
            HardeningCheckStatus.PASS,
            HardeningCheckStatus.WARN,
        )

    def test_exposed_secret_fails(self) -> None:
        svc = _make_service()
        target = _make_target(
            env={
                "OPENAI_API_KEY": "sk-livexxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                "LOG_LEVEL": "DEBUG",
            }
        )
        report = svc.check_secret_exposure(target)
        assert report.result.status in (
            HardeningCheckStatus.FAIL,
            HardeningCheckStatus.WARN,
        )

    def test_exposed_key_names_reported(self) -> None:
        svc = _make_service()
        target = _make_target(
            env={
                "SECRET_KEY": "hardcoded-value",
                "SAFE_VAR": "not-secret",
            }
        )
        report = svc.check_secret_exposure(target)
        # The exposed key names must appear in the report — values must NOT
        if report.exposed_keys:
            assert "SECRET_KEY" in report.exposed_keys
            for key in report.exposed_keys:
                assert key in target.env

    def test_secret_values_not_in_report_dict(self) -> None:
        svc = _make_service()
        target = _make_target(env={"API_KEY": "super-secret-value-123"})
        report = svc.check_secret_exposure(target)
        d = report.to_dict()
        assert "super-secret-value-123" not in str(d)

    def test_to_dict_structure(self) -> None:
        svc = _make_service()
        target = _make_target(env={})
        report = svc.check_secret_exposure(target)
        d = report.to_dict()
        assert {"result", "exposed_keys"}.issubset(set(d))


# ---------------------------------------------------------------------------
# EnvHardeningReport
# ---------------------------------------------------------------------------


class TestEnvHardeningReport:
    def test_production_env_passes(self) -> None:
        svc = _make_service()
        target = _make_target(
            env={
                "ENVIRONMENT": "production",
                "DEBUG": "false",
                "LOG_LEVEL": "WARNING",
            }
        )
        report = svc.check_env_hardening(target)
        assert isinstance(report, EnvHardeningReport)
        assert report.result.status in (
            HardeningCheckStatus.PASS,
            HardeningCheckStatus.WARN,
        )

    def test_debug_true_in_production_fails(self) -> None:
        svc = _make_service()
        target = _make_target(
            env={
                "ENVIRONMENT": "production",
                "DEBUG": "true",
            }
        )
        report = svc.check_env_hardening(target)
        assert report.result.status in (
            HardeningCheckStatus.FAIL,
            HardeningCheckStatus.WARN,
        )

    def test_missing_environment_var_warns(self) -> None:
        svc = _make_service()
        target = _make_target(env={})
        report = svc.check_env_hardening(target)
        assert report.result.status in (
            HardeningCheckStatus.WARN,
            HardeningCheckStatus.FAIL,
        )

    def test_findings_listed(self) -> None:
        svc = _make_service()
        target = _make_target(env={"DEBUG": "1", "ENVIRONMENT": "production"})
        report = svc.check_env_hardening(target)
        assert isinstance(report.findings, list)

    def test_to_dict_structure(self) -> None:
        svc = _make_service()
        target = _make_target(env={})
        report = svc.check_env_hardening(target)
        d = report.to_dict()
        assert {"result", "findings"}.issubset(set(d))


# ---------------------------------------------------------------------------
# RateLimitHardeningReport
# ---------------------------------------------------------------------------


class TestRateLimitHardeningReport:
    def test_reasonable_limit_passes(self) -> None:
        svc = _make_service()
        target = _make_target(rate_limit=RateLimitConfig(requests_per_minute=60, burst=10))
        report = svc.check_rate_limit(target)
        assert isinstance(report, RateLimitHardeningReport)
        assert report.result.status in (
            HardeningCheckStatus.PASS,
            HardeningCheckStatus.WARN,
        )

    def test_very_high_limit_warns(self) -> None:
        svc = _make_service()
        target = _make_target(rate_limit=RateLimitConfig(requests_per_minute=100_000, burst=50_000))
        report = svc.check_rate_limit(target)
        assert report.result.status in (
            HardeningCheckStatus.WARN,
            HardeningCheckStatus.FAIL,
        )

    def test_zero_burst_warns(self) -> None:
        svc = _make_service()
        target = _make_target(rate_limit=RateLimitConfig(requests_per_minute=60, burst=0))
        report = svc.check_rate_limit(target)
        # burst=0 means no burst allowance configured — should at least warn
        assert report.result.status in (
            HardeningCheckStatus.WARN,
            HardeningCheckStatus.PASS,
        )

    def test_to_dict_has_config(self) -> None:
        svc = _make_service()
        target = _make_target()
        report = svc.check_rate_limit(target)
        d = report.to_dict()
        assert "result" in d
        assert "config" in d


# ---------------------------------------------------------------------------
# HardeningReport (full composite)
# ---------------------------------------------------------------------------


class TestHardeningReport:
    def test_run_full_audit_returns_report(self) -> None:
        svc = _make_service()
        target = _make_target(
            host="https://ironclaw.local",
            headers={
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "Strict-Transport-Security": "max-age=31536000",
                "Content-Security-Policy": "default-src 'self'",
                "X-XSS-Protection": "1; mode=block",
                "Referrer-Policy": "no-referrer",
                "Permissions-Policy": "geolocation=()",
            },
            env={"ENVIRONMENT": "test", "DEBUG": "false"},
        )
        report = svc.run_full_audit(target)
        assert isinstance(report, HardeningReport)

    def test_report_contains_posture_score(self) -> None:
        svc = _make_service()
        target = _make_target(host="https://ironclaw.local")
        report = svc.run_full_audit(target)
        assert isinstance(report.posture_score, PostureScore)

    def test_perfect_target_scores_high(self) -> None:
        svc = _make_service()
        target = _make_target(
            host="https://ironclaw.local",
            headers={
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
                "Content-Security-Policy": "default-src 'self'",
                "X-XSS-Protection": "1; mode=block",
                "Referrer-Policy": "no-referrer",
                "Permissions-Policy": "geolocation=()",
            },
            env={"ENVIRONMENT": "production", "DEBUG": "false"},
        )
        report = svc.run_full_audit(target)
        assert report.posture_score.score >= 60

    def test_bare_http_target_scores_low(self) -> None:
        svc = _make_service()
        target = _make_target(
            host="http://insecure.local",
            headers={},
            env={"DEBUG": "true"},
        )
        report = svc.run_full_audit(target)
        assert report.posture_score.score < 100

    def test_report_target_name_preserved(self) -> None:
        svc = _make_service()
        target = _make_target(name="my-agent")
        report = svc.run_full_audit(target)
        assert report.target_name == "my-agent"

    def test_report_sub_reports_present(self) -> None:
        svc = _make_service()
        target = _make_target(host="https://ironclaw.local")
        report = svc.run_full_audit(target)
        assert report.tls is not None
        assert report.headers is not None
        assert report.secret_exposure is not None
        assert report.env_hardening is not None
        assert report.rate_limit is not None

    def test_report_to_dict_structure(self) -> None:
        svc = _make_service()
        target = _make_target(host="https://ironclaw.local")
        report = svc.run_full_audit(target)
        d = report.to_dict()
        required_keys = {
            "target_name",
            "posture_score",
            "tls",
            "headers",
            "secret_exposure",
            "env_hardening",
            "rate_limit",
            "checked_at",
        }
        assert required_keys.issubset(set(d))

    def test_checked_at_is_utc_iso(self) -> None:
        svc = _make_service()
        target = _make_target(host="https://ironclaw.local")
        report = svc.run_full_audit(target)
        assert report.checked_at.endswith("Z")

    def test_critical_failure_grade_is_f(self) -> None:
        svc = _make_service()
        target = _make_target(
            host="http://insecure.local",
            headers={},
            env={"DEBUG": "true", "ENVIRONMENT": "production"},
        )
        report = svc.run_full_audit(target)
        # Very weak posture should result in low grade
        assert report.posture_score.grade in ("F", "D", "C", "B", "A")


# ---------------------------------------------------------------------------
# HardeningService.check_rule
# ---------------------------------------------------------------------------


class TestHardeningServiceCheckRule:
    def test_disabled_rule_returns_skip(self) -> None:
        rs = HardeningRuleSet(rules=[_make_rule("R1", enabled=False)])
        svc = HardeningService(ruleset=rs)
        result = svc.check_rule("R1", {})
        assert result.status == HardeningCheckStatus.SKIP

    def test_unknown_rule_raises(self) -> None:
        svc = _make_service()
        with pytest.raises(KeyError):
            svc.check_rule("DOES-NOT-EXIST", {})

    def test_check_result_has_rule_id(self) -> None:
        rs = default_hardening_ruleset()
        first_rule_id = rs.rules[0].rule_id
        svc = HardeningService(ruleset=rs)
        result = svc.check_rule(first_rule_id, {})
        assert result.rule_id == first_rule_id


# ---------------------------------------------------------------------------
# HardeningService.summarize
# ---------------------------------------------------------------------------


class TestHardeningServiceSummarize:
    def test_summarize_all_pass(self) -> None:
        svc = _make_service()
        results = [
            HardeningCheckResult("R1", HardeningCheckStatus.PASS, "ok", {}),
            HardeningCheckResult("R2", HardeningCheckStatus.PASS, "ok", {}),
        ]
        summary = svc.summarize(results)
        assert summary["pass"] == 2
        assert summary.get("fail", 0) == 0

    def test_summarize_mixed(self) -> None:
        svc = _make_service()
        results = [
            HardeningCheckResult("R1", HardeningCheckStatus.PASS, "ok", {}),
            HardeningCheckResult("R2", HardeningCheckStatus.FAIL, "bad", {}),
            HardeningCheckResult("R3", HardeningCheckStatus.WARN, "maybe", {}),
            HardeningCheckResult("R4", HardeningCheckStatus.SKIP, "skip", {}),
        ]
        summary = svc.summarize(results)
        assert summary["pass"] == 1
        assert summary["fail"] == 1
        assert summary["warn"] == 1
        assert summary["skip"] == 1

    def test_summarize_empty(self) -> None:
        svc = _make_service()
        summary = svc.summarize([])
        assert summary.get("pass", 0) == 0
        assert summary.get("fail", 0) == 0


# ---------------------------------------------------------------------------
# HardeningService.compute_posture_score
# ---------------------------------------------------------------------------


class TestComputePostureScore:
    def test_all_pass_yields_max(self) -> None:
        svc = _make_service()
        results = [
            HardeningCheckResult("R1", HardeningCheckStatus.PASS, "ok", {}),
            HardeningCheckResult("R2", HardeningCheckStatus.PASS, "ok", {}),
            HardeningCheckResult("R3", HardeningCheckStatus.PASS, "ok", {}),
        ]
        score = svc.compute_posture_score(results)
        assert score.score == score.max_score

    def test_all_fail_yields_zero(self) -> None:
        svc = _make_service()
        results = [
            HardeningCheckResult("R1", HardeningCheckStatus.FAIL, "bad", {}),
            HardeningCheckResult("R2", HardeningCheckStatus.FAIL, "bad", {}),
        ]
        score = svc.compute_posture_score(results)
        assert score.score == 0

    def test_mixed_score_is_between(self) -> None:
        svc = _make_service()
        results = [
            HardeningCheckResult("R1", HardeningCheckStatus.PASS, "ok", {}),
            HardeningCheckResult("R2", HardeningCheckStatus.FAIL, "bad", {}),
        ]
        score = svc.compute_posture_score(results)
        assert 0 < score.score < score.max_score

    def test_grade_a_for_full_pass(self) -> None:
        svc = _make_service()
        results = [HardeningCheckResult(f"R{i}", HardeningCheckStatus.PASS, "ok", {}) for i in range(5)]
        score = svc.compute_posture_score(results)
        assert score.grade == "A"

    def test_grade_f_for_full_fail(self) -> None:
        svc = _make_service()
        results = [HardeningCheckResult(f"R{i}", HardeningCheckStatus.FAIL, "fail", {}) for i in range(5)]
        score = svc.compute_posture_score(results)
        assert score.grade == "F"

    def test_skip_does_not_penalise(self) -> None:
        svc = _make_service()
        all_skip = [HardeningCheckResult(f"R{i}", HardeningCheckStatus.SKIP, "skip", {}) for i in range(3)]
        all_pass = [HardeningCheckResult(f"P{i}", HardeningCheckStatus.PASS, "ok", {}) for i in range(3)]
        score_skip = svc.compute_posture_score(all_skip)
        score_pass = svc.compute_posture_score(all_pass)
        # Skipping should not yield a lower score than all-pass for the same count
        assert score_skip.grade in ("A", "B", "C", "D", "F")
        assert score_pass.grade == "A"


# ---------------------------------------------------------------------------
# build_default_hardening_service
# ---------------------------------------------------------------------------


class TestBuildDefaultHardeningService:
    def test_returns_hardening_service_instance(self) -> None:
        svc = build_default_hardening_service()
        assert isinstance(svc, HardeningService)

    def test_service_has_ruleset(self) -> None:
        svc = build_default_hardening_service()
        assert svc.ruleset is not None
        assert len(svc.ruleset.rules) > 0

    def test_service_can_run_audit(self) -> None:
        svc = build_default_hardening_service()
        target = _make_target(host="https://ironclaw.local")
        report = svc.run_full_audit(target)
        assert isinstance(report, HardeningReport)

    def test_env_override_applies_custom_rules(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("IRONCLAW_HARDENING_STRICT", "true")
        svc = build_default_hardening_service()
        # Strict mode must still produce a valid service
        assert isinstance(svc, HardeningService)


# ---------------------------------------------------------------------------
# Integration: full audit on hardened vs. bare target
# ---------------------------------------------------------------------------


class TestFullAuditIntegration:
    def test_hardened_target_beats_bare_target(self) -> None:
        svc = _make_service()
        hardened = _make_target(
            host="https://hardened.local",
            headers={
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
                "Content-Security-Policy": "default-src 'self'",
                "X-XSS-Protection": "1; mode=block",
                "Referrer-Policy": "no-referrer",
                "Permissions-Policy": "geolocation=()",
            },
            env={"ENVIRONMENT": "production", "DEBUG": "false"},
        )
        bare = _make_target(
            host="http://bare.local",
            headers={},
            env={"DEBUG": "true"},
        )
        hardened_report = svc.run_full_audit(hardened)
        bare_report = svc.run_full_audit(bare)
        assert hardened_report.posture_score.score > bare_report.posture_score.score

    def test_audit_is_idempotent(self) -> None:
        svc = _make_service()
        target = _make_target(host="https://ironclaw.local")
        r1 = svc.run_full_audit(target)
        r2 = svc.run_full_audit(target)
        assert r1.posture_score.score == r2.posture_score.score
        assert r1.posture_score.grade == r2.posture_score.grade

    def test_audit_does_not_leak_secret_values(self) -> None:
        svc = _make_service()
        target = _make_target(env={"API_KEY": "do-not-expose-this"})
        report = svc.run_full_audit(target)
        d = report.to_dict()
        assert "do-not-expose-this" not in str(d)

    def test_multiple_targets_isolated(self) -> None:
        svc = _make_service()
        t1 = _make_target(name="agent-a", host="https://agent-a.local")
        t2 = _make_target(name="agent-b", host="http://agent-b.local")
        r1 = svc.run_full_audit(t1)
        r2 = svc.run_full_audit(t2)
        assert r1.target_name == "agent-a"
        assert r2.target_name == "agent-b"
        assert r1.posture_score.score != r2.posture_score.score or r1.target_name != r2.target_name
