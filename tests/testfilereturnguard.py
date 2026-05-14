from __future__ import annotations

from pathlib import Path

import pytest

from app.runtime.filereturnguard import build_file_return_guard


@pytest.fixture
def guard():
    return build_file_return_guard()


def test_allow_safe_text_artifact_from_approved_root(guard):
    policy = guard.evaluate(
        path="artifacts/report.txt",
        content="safe report content",
        metadata={"source": "unit-test"},
    )

    assert policy.allowed is True
    assert policy.verdict == "allow"
    assert policy.path == "artifacts/report.txt"
    assert policy.extension == ".txt"
    assert policy.filename == "report.txt"
    assert policy.size_bytes == len(b"safe report content")
    assert policy.should_block is False
    assert policy.should_quarantine is False


def test_block_missing_path(guard):
    policy = guard.evaluate(path="", content="anything")

    assert policy.allowed is False
    assert policy.verdict == "quarantine"
    assert policy.should_quarantine is True
    assert "missing_path" in policy.matched_rules


def test_quarantine_parent_escape_path(guard):
    policy = guard.evaluate(path="../secrets.txt", content="secret")

    assert policy.allowed is False
    assert policy.verdict == "quarantine"
    assert policy.should_quarantine is True
    assert "path_escape" in policy.matched_rules


def test_quarantine_absolute_unix_path(guard):
    policy = guard.evaluate(path="/etc/passwd", content="root:x:0:0")

    assert policy.allowed is False
    assert policy.verdict == "quarantine"
    assert "absolute_path" in policy.matched_rules


def test_quarantine_absolute_windows_path(guard):
    policy = guard.evaluate(path="C:/windows/system32/cmd.exe", content=b"MZpayload")

    assert policy.allowed is False
    assert policy.verdict in {"block", "quarantine"}
    assert "absolute_path" in policy.matched_rules


def test_review_unapproved_root(guard):
    policy = guard.evaluate(path="tmp/report.txt", content="safe content")

    assert policy.verdict in {"review", "block", "quarantine"}
    assert any(rule.startswith("unapproved_root:tmp") for rule in policy.matched_rules)


def test_block_blocked_extension(guard):
    policy = guard.evaluate(path="artifacts/payload.exe", content=b"MZbinary")

    assert policy.allowed is False
    assert policy.verdict in {"block", "quarantine"}
    assert "blocked_extension:.exe" in policy.matched_rules


def test_review_unapproved_extension(guard):
    policy = guard.evaluate(path="artifacts/blob.bin", content=b"plain-bytes")

    assert policy.allowed is True
    assert policy.verdict == "review"
    assert "unapproved_extension:.bin" in policy.matched_rules


def test_review_missing_extension(guard):
    policy = guard.evaluate(path="artifacts/README", content="hello")

    assert policy.allowed is True
    assert policy.verdict == "review"
    assert "missing_extension" in policy.matched_rules


def test_review_empty_artifact(guard):
    policy = guard.evaluate(path="artifacts/empty.txt", content="")

    assert policy.allowed is True
    assert policy.verdict == "review"
    assert "empty_artifact" in policy.matched_rules


def test_block_oversized_artifact(guard):
    content = b"a" * (guard.max_file_size_bytes + 1)
    policy = guard.evaluate(path="artifacts/large.txt", content=content)

    assert policy.allowed is False
    assert policy.verdict in {"block", "quarantine"}
    assert "oversized_artifact" in policy.matched_rules


@pytest.mark.parametrize(
    ("path", "expected_rule"),
    [
        ("artifacts/.env", "dotenv_file"),
        ("artifacts/id_rsa.txt", "ssh_key"),
        ("artifacts/private_key_notes.md", "secret_material"),
        ("artifacts/config.json", "cloud_creds"),
    ],
)
def test_sensitive_name_rules_raise_risk(guard, path, expected_rule):
    policy = guard.evaluate(path=path, content="safe text")

    assert expected_rule in policy.matched_rules
    assert policy.verdict in {"review", "block", "quarantine"}


def test_quarantine_binary_magic_mz_under_safe_extension(guard):
    policy = guard.evaluate(path="artifacts/report.txt", content=b"MZfake-executable")

    assert policy.allowed is False
    assert policy.verdict == "quarantine"
    assert "binary_signature:windows-executable" in policy.matched_rules


def test_quarantine_binary_magic_elf_under_safe_extension(guard):
    policy = guard.evaluate(path="artifacts/report.txt", content=b"\x7fELFpayload")

    assert policy.allowed is False
    assert policy.verdict == "quarantine"
    assert "binary_signature:elf-binary" in policy.matched_rules


def test_zip_with_parent_traversal_entry_is_quarantined(guard):
    import io
    import zipfile

    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w") as archive:
        archive.writestr("../escape.txt", "bad")
        archive.writestr("nested/good.txt", "ok")

    policy = guard.evaluate(path="artifacts/archive.zip", content=payload.getvalue())

    assert policy.allowed is False
    assert policy.verdict == "quarantine"
    assert "archive_path_traversal" in policy.matched_rules


def test_zip_with_blocked_entry_is_quarantined(guard):
    import io
    import zipfile

    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w") as archive:
        archive.writestr("run.exe", b"MZbad")
        archive.writestr("notes.txt", "ok")

    policy = guard.evaluate(path="artifacts/bundle.zip", content=payload.getvalue())

    assert policy.allowed is False
    assert policy.verdict == "quarantine"
    assert "archive_blocked_extension:.exe" in policy.matched_rules


def test_invalid_zip_content_with_zip_extension_is_blocked(guard):
    policy = guard.evaluate(path="artifacts/fake.zip", content=b"not-a-real-zip")

    assert policy.allowed is False
    assert policy.verdict in {"block", "quarantine"}
    assert "invalid_archive" in policy.matched_rules


def test_allow_real_zip_with_safe_entries(guard):
    import io
    import zipfile

    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w") as archive:
        archive.writestr("docs/readme.txt", "safe")
        archive.writestr("images/logo.svg", "<svg></svg>")

    policy = guard.evaluate(path="artifacts/safe.zip", content=payload.getvalue())

    assert policy.allowed is True
    assert policy.verdict == "allow"


def test_allow_boolean_matches_policy_allowed(guard):
    policy = guard.evaluate(path="artifacts/file.txt", content="ok")
    decision = guard.allow(path="artifacts/file.txt", content="ok")

    assert decision is policy.allowed


def test_reads_existing_file_when_content_not_provided(tmp_path: Path, guard):
    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir()
    target = artifact_dir / "report.txt"
    target.write_text("from-disk", encoding="utf-8")

    policy = guard.evaluate(path=str(target))

    assert policy.filename == "report.txt"
    assert policy.size_bytes == len(b"from-disk")
    assert policy.verdict in {"review", "block", "quarantine"}


def test_policy_dict_contains_expected_shapes(guard):
    policy = guard.evaluate(path="artifacts/report.txt", content="safe content")
    body = policy.as_dict()

    assert body["verdict"] == policy.verdict
    assert body["allowed"] is True
    assert isinstance(body["reasons"], list)
    assert isinstance(body["matchedrules"], list)
    assert "artifactanalysis" in body
    assert "downloadanalysis" in body
    assert "outputsanitization" in body
    assert "fileinspection" in body


def test_reasons_and_rules_are_deduplicated_when_analyzers_repeat_signals(monkeypatch, guard):
    repeated_analysis = {
        "riskdelta": 25,
        "shouldreview": True,
        "reasons": [
            {
                "source": "artifactanalyzer",
                "label": "Repeated",
                "details": "Same reason",
                "score": 25,
            },
            {
                "source": "artifactanalyzer",
                "label": "Repeated",
                "details": "Same reason",
                "score": 25,
            },
        ],
    }

    monkeypatch.setattr(
        "app.runtime.filereturnguard.analyze_artifact_dict",
        lambda **kwargs: repeated_analysis,
    )
    monkeypatch.setattr(
        "app.runtime.filereturnguard.analyze_download_dict",
        lambda **kwargs: {"riskdelta": 0, "reasons": []},
    )

    class _Sanitized:
        def as_dict(self):
            return {"blocked": False, "score": 0.0}

    class _Sanitizer:
        def sanitize(self, *args, **kwargs):
            return _Sanitized()

    monkeypatch.setattr(
        "app.runtime.filereturnguard.build_output_sanitizer",
        lambda: _Sanitizer(),
    )

    class _InspectionResult:
        def as_dict(self):
            return {"riskdelta": 0, "reasons": [], "blocked": False, "shouldreview": False}

    class _InspectionService:
        def inspect_artifact(self, **kwargs):
            return _InspectionResult()

    monkeypatch.setattr(
        "app.runtime.filereturnguard.build_file_inspection_service",
        lambda **kwargs: _InspectionService(),
    )

    policy = guard.evaluate(path="artifacts/report.txt", content="safe")

    repeated = [item for item in policy.reasons if item["label"] == "Repeated" and item["details"] == "Same reason"]
    assert len(repeated) == 1
    assert policy.matched_rules.count("artifactanalyzer:review") == 1
