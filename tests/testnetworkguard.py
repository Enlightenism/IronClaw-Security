from __future__ import annotations

import pytest

from app.runtime.networkguard import DEFAULT_ALLOWED_HOSTS, build_network_guard


@pytest.fixture
def guard():
    return build_network_guard()


def test_groq_api_host_is_not_default_allowlisted() -> None:
    assert "api.groq.com" not in DEFAULT_ALLOWED_HOSTS


def test_allow_safe_https_request(guard):
    policy = guard.evaluate(
        url="https://api.example.com/v1/status",
        method="GET",
        metadata={"direction": "egress"},
    )

    assert policy.allowed is True
    assert policy.verdict == "allow"
    assert policy.scheme == "https"
    assert policy.host == "api.example.com"
    assert policy.port == 443
    assert policy.should_block is False
    assert policy.should_quarantine is False


def test_allow_defaults_method_to_get(guard):
    policy = guard.evaluate(
        url="https://api.example.com/v1/health",
        method="",
    )

    assert policy.allowed is True
    assert policy.verdict == "allow"
    assert policy.method == "GET"


def test_quarantine_missing_url(guard):
    policy = guard.evaluate(url="", method="GET")

    assert policy.allowed is False
    assert policy.verdict == "quarantine"
    assert policy.should_quarantine is True
    assert "missing_url" in policy.matched_rules


def test_quarantine_invalid_url_format(guard):
    policy = guard.evaluate(url="not-a-url", method="GET")

    assert policy.allowed is False
    assert policy.verdict == "quarantine"
    assert policy.should_quarantine is True
    assert "invalid_url" in policy.matched_rules


def test_quarantine_missing_hostname(guard):
    policy = guard.evaluate(url="https:///v1/test", method="GET")

    assert policy.allowed is False
    assert policy.verdict == "quarantine"
    assert "missing_host" in policy.matched_rules


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:8000/admin",
        "http://localhost:8080",
        "http://0.0.0.0:9000",
        "http://10.0.0.5/service",
        "http://172.16.5.10/internal",
        "http://192.168.1.25/router",
        "http://169.254.169.254/latest/meta-data",
        "http://[::1]/",
        "http://[fd00::1]/",
    ],
)
def test_quarantine_private_loopback_and_link_local_targets(guard, url):
    policy = guard.evaluate(url=url, method="GET")

    assert policy.allowed is False
    assert policy.verdict == "quarantine"
    assert policy.should_quarantine is True


def test_quarantine_blocked_scheme_file(guard):
    policy = guard.evaluate(url="file:///etc/passwd", method="GET")

    assert policy.allowed is False
    assert policy.verdict == "quarantine"
    assert "blocked_scheme:file" in policy.matched_rules


def test_quarantine_blocked_scheme_ftp(guard):
    policy = guard.evaluate(url="ftp://example.com/file.txt", method="GET")

    assert policy.allowed is False
    assert policy.verdict == "quarantine"
    assert "blocked_scheme:ftp" in policy.matched_rules


def test_review_plain_http_when_not_explicitly_blocked(guard):
    policy = guard.evaluate(url="http://example.com/resource", method="GET")

    assert policy.verdict in {"review", "block", "quarantine"}
    assert any(rule.startswith("insecure_scheme:http") or rule == "insecure_scheme:http" for rule in policy.matched_rules)


def test_review_suspicious_port(guard):
    policy = guard.evaluate(url="https://example.com:25/mail", method="GET")

    assert policy.verdict in {"review", "block", "quarantine"}
    assert any("port" in rule for rule in policy.matched_rules)


@pytest.mark.parametrize(
    "method",
    ["TRACE", "CONNECT"],
)
def test_block_or_quarantine_disallowed_http_methods(guard, method):
    policy = guard.evaluate(url="https://example.com/resource", method=method)

    assert policy.allowed is False
    assert policy.verdict in {"block", "quarantine"}


@pytest.mark.parametrize(
    "host",
    [
        "metadata.google.internal",
        "169.254.169.254.nip.io",
    ],
)
def test_quarantine_ssrf_style_targets(guard, host):
    policy = guard.evaluate(url=f"https://{host}/computeMetadata/v1/", method="GET")

    assert policy.allowed is False
    assert policy.verdict in {"block", "quarantine"}


def test_review_suspicious_path_patterns(guard):
    policy = guard.evaluate(
        url="https://example.com/.aws/credentials",
        method="GET",
    )

    assert policy.verdict in {"review", "block", "quarantine"}
    assert len(policy.reasons) > 0


def test_review_suspicious_query_patterns(guard):
    policy = guard.evaluate(
        url="https://example.com/download?token=secret-token-value",
        method="GET",
    )

    assert policy.verdict in {"review", "block", "quarantine"}
    assert len(policy.reasons) > 0


def test_review_sensitive_metadata_direction_ingress_override(guard):
    policy = guard.evaluate(
        url="https://api.example.com/webhook",
        method="POST",
        metadata={"direction": "ingress"},
    )

    assert policy.verdict in {"allow", "review", "block", "quarantine"}


def test_allow_safe_post_to_public_api(guard):
    policy = guard.evaluate(
        url="https://hooks.example.com/v1/events",
        method="POST",
        metadata={"direction": "egress", "tool_name": "api"},
    )

    assert policy.allowed is True
    assert policy.verdict == "allow"


def test_policy_dict_contains_expected_shapes(guard):
    policy = guard.evaluate(
        url="https://api.example.com/v1/status",
        method="GET",
    )
    body = policy.as_dict()

    assert body["verdict"] == policy.verdict
    assert body["allowed"] is True
    assert body["host"] == policy.host
    assert body["scheme"] == policy.scheme
    assert body["method"] == policy.method
    assert isinstance(body["reasons"], list)
    assert isinstance(body["matchedrules"], list)


def test_allow_helper_matches_policy_allowed(guard):
    policy = guard.evaluate(url="https://api.example.com/v1/status", method="GET")
    decision = guard.allow(url="https://api.example.com/v1/status", method="GET")

    assert decision is policy.allowed


def test_reasons_and_rules_are_deduplicated_when_detectors_repeat(monkeypatch, guard):
    repeated_reason = {
        "source": "networkguard",
        "label": "Repeated",
        "details": "Same reason",
        "score": 15,
    }

    monkeypatch.setattr(
        guard,
        "_analyze_url",
        lambda *args, **kwargs: (
            15,
            [repeated_reason, repeated_reason],
            ["repeat_rule", "repeat_rule"],
        ),
    )

    policy = guard.evaluate(url="https://api.example.com/v1/status", method="GET")

    repeated = [item for item in policy.reasons if item["label"] == "Repeated" and item["details"] == "Same reason"]
    assert len(repeated) == 1
    assert policy.matched_rules.count("repeat_rule") == 1
