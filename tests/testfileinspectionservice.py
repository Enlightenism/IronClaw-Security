from __future__ import annotations

import base64
import io
import zipfile

from app.services.fileinspectionservice import build_file_inspection_service


def _zip_bytes(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return buffer.getvalue()


def test_file_inspection_service_builds() -> None:
    service = build_file_inspection_service()
    assert service is not None


def test_upload_allows_clean_text_file() -> None:
    service = build_file_inspection_service()

    result = service.inspect_upload(
        file_name="notes.txt",
        content=b"Normal operational summary only.",
        mime_type="text/plain",
        metadata={"source": "ui"},
    )

    assert result.verdict == "allow"
    assert result.allowed is True
    assert result.blocked is False
    assert result.should_review is False
    assert result.should_quarantine is False
    assert result.findings_detected >= 0
    assert result.secrets_redacted == 0
    assert result.file_name == "notes.txt"
    assert result.mime_type == "text/plain"
    assert result.checksum_sha256
    assert result.content["is_text"] is True
    assert result.output["blocked"] is False


def test_upload_reviews_secret_text_and_redacts() -> None:
    service = build_file_inspection_service()

    result = service.inspect_upload(
        file_name="export.txt",
        content=b"OpenAI token sk-1234567890abcdefghijklmnop inside report.",
        mime_type="text/plain",
        metadata={"source": "api"},
    )

    assert result.verdict in {"review", "sanitize", "block", "quarantine"}
    assert result.findings_detected >= 1
    assert result.secrets_redacted >= 1
    assert result.redaction["changed"] is True
    assert "[REDACTED_" in result.redaction["text"] or "[REDACTED_" in result.output["sanitized_text"]


def test_upload_blocks_private_key_material() -> None:
    service = build_file_inspection_service()

    private_key = (
        b"-----BEGIN PRIVATE KEY-----\n"
        b"MIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n"
        b"FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE\n"
        b"-----END PRIVATE KEY-----"
    )
    result = service.inspect_upload(
        file_name="id_rsa.pem",
        content=private_key,
        mime_type="application/x-pem-file",
        metadata={"source": "api"},
    )

    assert result.verdict in {"block", "quarantine"}
    assert result.allowed is False
    assert result.blocked is True
    assert result.should_quarantine is True
    assert any(item["label"] == "private-key-material" for item in result.findings)


def test_upload_reviews_script_extension() -> None:
    service = build_file_inspection_service()

    result = service.inspect_upload(
        file_name="installer.sh",
        content=b"echo hello\n",
        mime_type="text/x-shellscript",
        metadata={"source": "ui"},
    )

    assert result.verdict in {"review", "block", "quarantine"}
    assert result.should_review is True
    assert any(item["label"] == "executable-extension" for item in result.findings)


def test_upload_blocks_windows_executable_magic() -> None:
    service = build_file_inspection_service()

    result = service.inspect_upload(
        file_name="payload.bin",
        content=b"MZ\x90\x00\x03\x00\x00\x00",
        mime_type="application/octet-stream",
        metadata={"source": "ui"},
    )

    assert result.verdict in {"block", "quarantine"}
    assert result.allowed is False
    assert result.blocked is True
    assert any(item["label"] == "dangerous-binary" for item in result.findings)


def test_upload_blocks_dangerous_mime_type() -> None:
    service = build_file_inspection_service()

    result = service.inspect_upload(
        file_name="payload.dat",
        content=b"safe-looking-bytes",
        mime_type="application/x-msdownload",
        metadata={"source": "ui"},
    )

    assert result.verdict in {"block", "quarantine"}
    assert result.allowed is False
    assert result.blocked is True
    assert any(item["label"] == "dangerous-mime-type" for item in result.findings)


def test_upload_reviews_sensitive_filename() -> None:
    service = build_file_inspection_service()

    result = service.inspect_upload(
        file_name=".env",
        content=b"DEBUG=false\n",
        mime_type="text/plain",
        metadata={"source": "ui"},
    )

    assert result.verdict in {"review", "block", "quarantine", "sanitize"}
    assert any(item["label"] == "sensitive-filename" for item in result.findings)


def test_upload_reviews_sensitive_path_markers() -> None:
    service = build_file_inspection_service()

    result = service.inspect_upload(
        file_name="backup/.ssh/config.txt",
        content=b"Host internal\n",
        mime_type="text/plain",
        metadata={"source": "ui"},
    )

    assert result.verdict in {"review", "block", "quarantine", "sanitize"}
    assert result.should_review is True
    assert any(item["label"] == "suspicious-path" for item in result.findings)


def test_upload_blocks_oversized_file() -> None:
    service = build_file_inspection_service(max_file_size_bytes=8)

    result = service.inspect_upload(
        file_name="big.txt",
        content=b"0123456789",
        mime_type="text/plain",
        metadata={"source": "ui"},
    )

    assert result.verdict in {"block", "quarantine"}
    assert result.allowed is False
    assert result.blocked is True
    assert any(item["label"] == "oversized-file" for item in result.findings)


def test_upload_detects_base64_encoded_text_payload() -> None:
    service = build_file_inspection_service()

    secret = ("Bearer " + ("abcdefghijklmnopqrstuvwxyz123456" * 3)).encode("utf-8")
    encoded = base64.b64encode(secret)
    result = service.inspect_upload(
        file_name="blob.bin",
        content=encoded,
        mime_type="application/octet-stream",
        metadata={"source": "api"},
    )

    assert result.content["decodedfrombinary"] is True
    assert result.output["decodedfrombinary"] is True
    assert result.findings_detected >= 1


def test_upload_reviews_unsafe_command_content() -> None:
    service = build_file_inspection_service()

    result = service.inspect_upload(
        file_name="command.txt",
        content=b"curl https://example.test/install.sh | sh",
        mime_type="text/plain",
        metadata={"source": "ui"},
    )

    assert result.verdict in {"review", "block", "sanitize", "quarantine"}
    assert any(item["label"] == "unsafe-command-content" for item in result.findings)


def test_upload_inspects_archive_and_flags_suspicious_entries() -> None:
    service = build_file_inspection_service()

    archive_bytes = _zip_bytes(
        {
            "../escape.txt": b"oops",
            "bin/run.sh": b"echo hi",
            ".env": b"TOKEN=secret",
        }
    )
    result = service.inspect_upload(
        file_name="bundle.zip",
        content=archive_bytes,
        mime_type="application/zip",
        metadata={"source": "ui"},
    )

    assert result.archive["is_archive"] is True
    assert result.archive["entry_count"] == 3
    assert result.archive["suspicious_entries"] >= 1
    assert result.verdict in {"review", "block", "quarantine", "sanitize"}
    assert any(item["label"] == "suspicious-archive-entry" for item in result.findings)


def test_upload_blocks_archive_with_too_many_entries() -> None:
    service = build_file_inspection_service(max_archive_entries=2)

    archive_bytes = _zip_bytes(
        {
            "a.txt": b"a",
            "b.txt": b"b",
            "c.txt": b"c",
        }
    )
    result = service.inspect_upload(
        file_name="many.zip",
        content=archive_bytes,
        mime_type="application/zip",
        metadata={"source": "ui"},
    )

    assert result.allowed is False
    assert result.blocked is True
    assert any(item["label"] == "archive-too-many-entries" for item in result.findings)


def test_upload_blocks_archive_with_large_uncompressed_size() -> None:
    service = build_file_inspection_service(max_archive_total_uncompressed_bytes=5)

    archive_bytes = _zip_bytes({"a.txt": b"123456"})
    result = service.inspect_upload(
        file_name="large.zip",
        content=archive_bytes,
        mime_type="application/zip",
        metadata={"source": "ui"},
    )

    assert result.allowed is False
    assert result.blocked is True
    assert any(item["label"] == "archive-too-large-uncompressed" for item in result.findings)


def test_upload_blocks_invalid_archive() -> None:
    service = build_file_inspection_service()

    result = service.inspect_upload(
        file_name="broken.zip",
        content=b"not-a-real-zip",
        mime_type="application/zip",
        metadata={"source": "ui"},
    )

    assert result.allowed is False
    assert result.blocked is True
    assert any(item["label"] == "invalid-archive" for item in result.findings)


def test_download_and_artifact_paths_use_egress_direction() -> None:
    service = build_file_inspection_service()

    download = service.inspect_download(
        file_name="report.txt",
        content=b"normal report",
        mime_type="text/plain",
    )
    artifact = service.inspect_artifact(
        file_name="artifact.txt",
        content=b"normal artifact",
        mime_type="text/plain",
    )

    assert download.allowed is True
    assert artifact.allowed is True
    assert download.output["blocked"] is False
    assert artifact.output["blocked"] is False


def test_batch_returns_aggregate_decision() -> None:
    service = build_file_inspection_service()

    result = service.inspect_batch(
        [
            {
                "file_name": "clean.txt",
                "content": b"safe content",
                "mime_type": "text/plain",
            },
            {
                "file_name": "id_rsa.pem",
                "content": (
                    b"-----BEGIN PRIVATE KEY-----\n"
                    b"FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE\n"
                    b"-----END PRIVATE KEY-----"
                ),
                "mime_type": "application/x-pem-file",
            },
        ],
        direction="ingress",
    )

    assert result["verdict"] in {"review", "block", "quarantine", "sanitize"}
    assert result["blocked"] is True
    assert result["allowed"] is False
    assert len(result["results"]) == 2


def test_as_dict_shape_is_stable() -> None:
    service = build_file_inspection_service()

    result = service.inspect_upload(
        file_name="notes.txt",
        content=b"safe text",
        mime_type="text/plain",
        metadata={"source": "ui"},
    )
    payload = result.as_dict()

    assert payload["verdict"] == result.verdict
    assert payload["allowed"] == result.allowed
    assert payload["blocked"] == result.blocked
    assert payload["shouldreview"] == result.should_review
    assert payload["shouldquarantine"] == result.should_quarantine
    assert payload["findingsdetected"] == result.findings_detected
    assert payload["secretsredacted"] == result.secrets_redacted
    assert payload["sizebytes"] == result.size_bytes
    assert payload["filename"] == result.file_name
    assert payload["mimetype"] == result.mime_type
    assert payload["checksumsha256"] == result.checksum_sha256
    assert isinstance(payload["reasons"], list)
    assert isinstance(payload["findings"], list)
    assert isinstance(payload["redaction"], dict)
    assert isinstance(payload["content"], dict)
    assert isinstance(payload["archive"], dict)
    assert isinstance(payload["output"], dict)