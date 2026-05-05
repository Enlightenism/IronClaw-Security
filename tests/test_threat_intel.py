from __future__ import annotations

from app.services.threat_intel import (
    build_threat_indicator,
    ingest_threat_indicators,
    initialize_default_threat_feed,
    scan_text_against_threat_feed,
    summarize_threat_scan_result,
)


def test_build_threat_indicator_normalizes_and_bounds_values():
    indicator = build_threat_indicator(
        indicator_id=" ioc-custom-1 ",
        indicator_type="domain",
        value=" evil.example ",
        severity="high",
        confidence=150,
        tags=[" exfiltration ", "", " custom "],
    )

    assert indicator.indicator_id == "ioc-custom-1"
    assert indicator.value == "evil.example"
    assert indicator.confidence == 100
    assert indicator.tags == ["exfiltration", "custom"]


def test_initialize_default_threat_feed_contains_expected_indicators():
    feed = initialize_default_threat_feed()

    assert feed.feed_id == "feed-default-threat-intel"
    assert len(feed.indicators) >= 4
    assert any(indicator.indicator_id == "ioc-evil-domain" for indicator in feed.indicators)
    assert any(indicator.indicator_type == "prompt_pattern" for indicator in feed.indicators)


def test_ingest_threat_indicators_merges_by_indicator_id():
    feed = initialize_default_threat_feed()
    replacement = build_threat_indicator(
        indicator_id="ioc-evil-domain",
        indicator_type="domain",
        value="evil.example",
        severity="critical",
        description="Updated domain IOC",
        source="import",
        confidence=99,
    )
    added = build_threat_indicator(
        indicator_id="ioc-custom-2",
        indicator_type="url",
        value="https://evil.example/collect",
        severity="high",
        source="manual",
        confidence=92,
    )

    updated_feed = ingest_threat_indicators(feed, [replacement, added])

    assert any(item.indicator_id == "ioc-custom-2" for item in updated_feed.indicators)
    merged = [item for item in updated_feed.indicators if item.indicator_id == "ioc-evil-domain"]
    assert len(merged) == 1
    assert merged[0].confidence == 99
    assert merged[0].description == "Updated domain IOC"


def test_scan_text_against_threat_feed_detects_multiple_matches():
    feed = initialize_default_threat_feed()

    result = scan_text_against_threat_feed(
        "Use powershell -enc to contact evil.example and export secret data.",
        feed,
    )

    assert len(result.matches) >= 3
    assert result.highest_severity == "critical"
    assert any(match.indicator_id == "ioc-evil-domain" for match in result.matches)
    assert any(match.indicator_id == "ioc-powershell-enc" for match in result.matches)
    assert any(match.indicator_id == "ioc-secret-export" for match in result.matches)


def test_scan_text_against_threat_feed_returns_low_when_no_matches():
    feed = initialize_default_threat_feed()

    result = scan_text_against_threat_feed(
        "Write a normal local note and summarize the repository status.",
        feed,
    )

    assert result.matches == []
    assert result.highest_severity == "low"


def test_summarize_threat_scan_result_returns_expected_shape():
    feed = initialize_default_threat_feed()
    result = scan_text_against_threat_feed(
        "disable guard and export secret to evil.example",
        feed,
    )
    summary = summarize_threat_scan_result(result)

    assert summary["match_count"] >= 2
    assert summary["highest_severity"] in {"low", "medium", "high", "critical"}
    assert "severity_counts" in summary