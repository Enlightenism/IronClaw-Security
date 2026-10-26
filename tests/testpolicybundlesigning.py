from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any

import pytest

from app.services.policybundlesigning import build_policy_bundle_signing_service


def _canonical_bundle(
    *,
    bundle_id: str = "bundle-001",
    version: str = "2026.04.25",
    policy: dict[str, Any] | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "bundle_id": bundle_id,
        "version": version,
        "policy": policy
        or {
            "default_verdict": "allow",
            "rules": [
                {"id": "rule-safe-shell", "action": "allow", "match": {"tool": "bash"}},
                {"id": "rule-high-risk", "action": "review", "match": {"risk": "high"}},
            ],
        },
        "metadata": metadata
        or {
            "issuer": "ironclaw",
            "environment": "test",
            "targets": ["openclaw", "claude", "guard"],
        },
    }


def _stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256_hex(value: Any) -> str:
    if not isinstance(value, str):
        value = _stable_json(value)
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _hmac_b64(secret: str, message: str) -> str:
    digest = hmac.new(secret.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).digest()
    return base64.b64encode(digest).decode("utf-8")


@pytest.fixture
def service():
    return build_policy_bundle_signing_service()


def test_sign_bundle_returns_signed_bundle_and_manifest(service):
    bundle = _canonical_bundle()

    result = service.sign_bundle(bundle=bundle, secret="ironclaw-test-secret")

    assert result is not None
    assert result.bundle_id == "bundle-001"
    assert result.version == "2026.04.25"
    assert result.algorithm in {"hmac-sha256", "sha256-hmac"}
    assert isinstance(result.signature, str)
    assert result.signature
    assert isinstance(result.digest, str)
    assert len(result.digest) == 64
    assert isinstance(result.manifest, dict)
    assert result.manifest["bundleid"] == "bundle-001"
    assert result.manifest["version"] == "2026.04.25"


def test_verify_bundle_accepts_valid_signature(service):
    bundle = _canonical_bundle()
    signed = service.sign_bundle(bundle=bundle, secret="ironclaw-test-secret")

    verdict = service.verify_bundle(
        bundle=bundle,
        signature=signed.signature,
        secret="ironclaw-test-secret",
        manifest=signed.manifest,
    )

    assert verdict.valid is True
    assert verdict.allowed is True
    assert verdict.verdict == "allow"
    assert verdict.bundle_id == "bundle-001"
    assert verdict.version == "2026.04.25"


def test_verify_bundle_rejects_tampered_policy(service):
    bundle = _canonical_bundle()
    signed = service.sign_bundle(bundle=bundle, secret="ironclaw-test-secret")

    tampered = _canonical_bundle()
    tampered["policy"]["rules"].append(
        {"id": "rule-evil", "action": "allow", "match": {"tool": "python", "path": "/etc/shadow"}},
    )

    verdict = service.verify_bundle(
        bundle=tampered,
        signature=signed.signature,
        secret="ironclaw-test-secret",
        manifest=signed.manifest,
    )

    assert verdict.valid is False
    assert verdict.allowed is False
    assert verdict.verdict in {"block", "reject"}
    assert "digest_mismatch" in verdict.matched_rules or "signature_mismatch" in verdict.matched_rules


def test_verify_bundle_rejects_wrong_secret(service):
    bundle = _canonical_bundle()
    signed = service.sign_bundle(bundle=bundle, secret="ironclaw-test-secret")

    verdict = service.verify_bundle(
        bundle=bundle,
        signature=signed.signature,
        secret="wrong-secret",
        manifest=signed.manifest,
    )

    assert verdict.valid is False
    assert verdict.allowed is False
    assert verdict.verdict in {"block", "reject"}
    assert "signature_mismatch" in verdict.matched_rules


def test_verify_bundle_rejects_missing_signature(service):
    bundle = _canonical_bundle()

    verdict = service.verify_bundle(
        bundle=bundle,
        signature="",
        secret="ironclaw-test-secret",
        manifest={},
    )

    assert verdict.valid is False
    assert verdict.allowed is False
    assert verdict.verdict in {"block", "reject"}
    assert "missing_signature" in verdict.matched_rules


def test_verify_bundle_rejects_missing_secret(service):
    bundle = _canonical_bundle()
    signed = service.sign_bundle(bundle=bundle, secret="ironclaw-test-secret")

    verdict = service.verify_bundle(
        bundle=bundle,
        signature=signed.signature,
        secret="",
        manifest=signed.manifest,
    )

    assert verdict.valid is False
    assert verdict.allowed is False
    assert verdict.verdict in {"block", "reject"}
    assert "missing_secret" in verdict.matched_rules


def test_verify_bundle_rejects_manifest_bundle_id_mismatch(service):
    bundle = _canonical_bundle()
    signed = service.sign_bundle(bundle=bundle, secret="ironclaw-test-secret")
    manifest = dict(signed.manifest)
    manifest["bundleid"] = "bundle-xyz"

    verdict = service.verify_bundle(
        bundle=bundle,
        signature=signed.signature,
        secret="ironclaw-test-secret",
        manifest=manifest,
    )

    assert verdict.valid is False
    assert verdict.allowed is False
    assert verdict.verdict in {"block", "reject"}
    assert "bundle_id_mismatch" in verdict.matched_rules


def test_verify_bundle_rejects_manifest_version_mismatch(service):
    bundle = _canonical_bundle()
    signed = service.sign_bundle(bundle=bundle, secret="ironclaw-test-secret")
    manifest = dict(signed.manifest)
    manifest["version"] = "2026.04.26"

    verdict = service.verify_bundle(
        bundle=bundle,
        signature=signed.signature,
        secret="ironclaw-test-secret",
        manifest=manifest,
    )

    assert verdict.valid is False
    assert verdict.allowed is False
    assert verdict.verdict in {"block", "reject"}
    assert "version_mismatch" in verdict.matched_rules


def test_verify_bundle_rejects_manifest_digest_mismatch(service):
    bundle = _canonical_bundle()
    signed = service.sign_bundle(bundle=bundle, secret="ironclaw-test-secret")
    manifest = dict(signed.manifest)
    manifest["digest"] = "0" * 64

    verdict = service.verify_bundle(
        bundle=bundle,
        signature=signed.signature,
        secret="ironclaw-test-secret",
        manifest=manifest,
    )

    assert verdict.valid is False
    assert verdict.allowed is False
    assert verdict.verdict in {"block", "reject"}
    assert "manifest_digest_mismatch" in verdict.matched_rules or "digest_mismatch" in verdict.matched_rules


def test_build_signed_bundle_helper_contains_expected_shapes(service):
    bundle = _canonical_bundle()

    signed = service.sign_bundle(bundle=bundle, secret="ironclaw-test-secret")
    body = signed.as_dict()

    assert body["bundleid"] == "bundle-001"
    assert body["version"] == "2026.04.25"
    assert body["algorithm"] in {"hmac-sha256", "sha256-hmac"}
    assert isinstance(body["signature"], str)
    assert isinstance(body["digest"], str)
    assert isinstance(body["manifest"], dict)


def test_verification_result_contains_expected_shapes(service):
    bundle = _canonical_bundle()
    signed = service.sign_bundle(bundle=bundle, secret="ironclaw-test-secret")

    verdict = service.verify_bundle(
        bundle=bundle,
        signature=signed.signature,
        secret="ironclaw-test-secret",
        manifest=signed.manifest,
    )
    body = verdict.as_dict()

    assert body["valid"] is True
    assert body["allowed"] is True
    assert body["verdict"] == "allow"
    assert body["bundleid"] == "bundle-001"
    assert body["version"] == "2026.04.25"
    assert isinstance(body["matchedrules"], list)
    assert isinstance(body["reasons"], list)


def test_sign_bundle_is_stable_for_same_input(service):
    bundle = _canonical_bundle()

    first = service.sign_bundle(bundle=bundle, secret="ironclaw-test-secret")
    second = service.sign_bundle(bundle=bundle, secret="ironclaw-test-secret")

    assert first.digest == second.digest
    assert first.signature == second.signature


def test_sign_bundle_changes_when_bundle_changes(service):
    first_bundle = _canonical_bundle()
    second_bundle = _canonical_bundle(version="2026.04.26")

    first = service.sign_bundle(bundle=first_bundle, secret="ironclaw-test-secret")
    second = service.sign_bundle(bundle=second_bundle, secret="ironclaw-test-secret")

    assert first.digest != second.digest
    assert first.signature != second.signature


def test_sign_bundle_matches_expected_hmac_for_canonical_payload(service):
    bundle = _canonical_bundle()
    signed = service.sign_bundle(bundle=bundle, secret="ironclaw-test-secret")

    canonical = _stable_json(bundle)
    expected_digest = _sha256_hex(canonical)
    expected_signature = _hmac_b64("ironclaw-test-secret", canonical)

    assert signed.digest == expected_digest
    assert signed.signature == expected_signature


def test_verify_bundle_with_manual_signature_and_manifest(service):
    bundle = _canonical_bundle()
    canonical = _stable_json(bundle)
    digest = _sha256_hex(canonical)
    signature = _hmac_b64("ironclaw-test-secret", canonical)
    manifest = {
        "bundleid": "bundle-001",
        "version": "2026.04.25",
        "algorithm": "hmac-sha256",
        "digest": digest,
    }

    verdict = service.verify_bundle(
        bundle=bundle,
        signature=signature,
        secret="ironclaw-test-secret",
        manifest=manifest,
    )

    assert verdict.valid is True
    assert verdict.allowed is True
    assert verdict.verdict == "allow"


def test_rejects_invalid_base64_signature(service):
    bundle = _canonical_bundle()

    verdict = service.verify_bundle(
        bundle=bundle,
        signature="***not-base64***",
        secret="ironclaw-test-secret",
        manifest={"bundleid": "bundle-001", "version": "2026.04.25", "algorithm": "hmac-sha256"},
    )

    assert verdict.valid is False
    assert verdict.allowed is False
    assert verdict.verdict in {"block", "reject"}
    assert "invalid_signature_encoding" in verdict.matched_rules or "signature_mismatch" in verdict.matched_rules


def test_missing_bundle_id_is_rejected(service):
    bundle = _canonical_bundle()
    bundle["bundle_id"] = ""

    verdict = service.verify_bundle(
        bundle=bundle,
        signature="abc",
        secret="ironclaw-test-secret",
        manifest={"version": "2026.04.25"},
    )

    assert verdict.valid is False
    assert verdict.allowed is False
    assert verdict.verdict in {"block", "reject"}
    assert "missing_bundle_id" in verdict.matched_rules


def test_missing_version_is_rejected(service):
    bundle = _canonical_bundle()
    bundle["version"] = ""

    verdict = service.verify_bundle(
        bundle=bundle,
        signature="abc",
        secret="ironclaw-test-secret",
        manifest={"bundleid": "bundle-001"},
    )

    assert verdict.valid is False
    assert verdict.allowed is False
    assert verdict.verdict in {"block", "reject"}
    assert "missing_version" in verdict.matched_rules


def test_verify_latest_bundle_accepts_forward_progress(service):
    next_bundle = _canonical_bundle(version="2026.04.26")
    signed = service.sign_bundle(bundle=next_bundle, secret="ironclaw-test-secret")

    verdict = service.verify_bundle(
        bundle=next_bundle,
        signature=signed.signature,
        secret="ironclaw-test-secret",
        manifest=signed.manifest,
        current_version="2026.04.25",
    )

    assert verdict.valid is True
    assert verdict.allowed is True
    assert verdict.verdict == "allow"


def test_verify_bundle_rejects_rollback_version(service):
    rollback_bundle = _canonical_bundle(version="2026.04.24")
    signed = service.sign_bundle(bundle=rollback_bundle, secret="ironclaw-test-secret")

    verdict = service.verify_bundle(
        bundle=rollback_bundle,
        signature=signed.signature,
        secret="ironclaw-test-secret",
        manifest=signed.manifest,
        current_version="2026.04.25",
    )

    assert verdict.valid is False
    assert verdict.allowed is False
    assert verdict.verdict in {"block", "reject"}
    assert "rollback_detected" in verdict.matched_rules or "version_regression" in verdict.matched_rules


def test_rules_and_reasons_are_deduplicated(service):
    bundle = _canonical_bundle()
    signed = service.sign_bundle(bundle=bundle, secret="ironclaw-test-secret")

    verdict = service.verify_bundle(
        bundle=bundle,
        signature=signed.signature,
        secret="wrong-secret",
        manifest={
            "bundleid": "bundle-001",
            "version": "2026.04.26",
            "digest": "0" * 64,
            "algorithm": "hmac-sha256",
        },
    )

    assert len(verdict.matched_rules) == len(set(verdict.matched_rules))
    unique_reasons = {(r.get("label"), r.get("details")) for r in verdict.reasons}
    assert len(verdict.reasons) == len(unique_reasons)
