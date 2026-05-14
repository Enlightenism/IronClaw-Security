from __future__ import annotations

from app.services.policy_bundle_signing import (
    PolicyBundle,
    export_signed_bundle,
    import_signed_bundle,
    initialize_policy_signing_keys,
    sign_policy_bundle,
    summarize_signed_bundle,
    verify_policy_bundle_signature,
)


def test_sign_and_verify_policy_bundle_returns_valid_result():
    keyset = initialize_policy_signing_keys()
    bundle = PolicyBundle(
        bundle_id="bundle-gen1-default",
        version="1.0.0",
        created_at="2026-04-20T00:00:00+00:00",
        policies=[
            {
                "rule_id": "dangerous-shell-execution",
                "verdict": "block",
                "risk_level": "critical",
            },
            {
                "rule_id": "tool-credential-exfiltration",
                "verdict": "quarantine",
                "risk_level": "high",
            },
        ],
        metadata={
            "environment": "local-dev",
            "source": "pytest",
        },
    )

    signed = sign_policy_bundle(bundle, keyset)
    verification = verify_policy_bundle_signature(signed, keyset)

    assert signed.bundle.bundle_id == "bundle-gen1-default"
    assert signed.key_id == keyset.active_key_id
    assert signed.signature.startswith("hs256:")
    assert verification.status == "valid"
    assert verification.reason == "signature verified"


def test_verify_policy_bundle_signature_detects_tampering():
    keyset = initialize_policy_signing_keys()
    bundle = PolicyBundle(
        bundle_id="bundle-gen1-tamper",
        version="1.0.0",
        created_at="2026-04-20T00:00:00+00:00",
        policies=[
            {
                "rule_id": "pi-instruction-override",
                "verdict": "warn",
                "risk_level": "medium",
            },
        ],
        metadata={"source": "pytest"},
    )

    signed = sign_policy_bundle(bundle, keyset)
    signed.bundle.policies.append(
        {
            "rule_id": "network-high-risk-destination",
            "verdict": "block",
            "risk_level": "critical",
        },
    )

    verification = verify_policy_bundle_signature(signed, keyset)

    assert verification.status == "invalid"
    assert verification.reason == "signature mismatch"


def test_export_and_import_signed_bundle_round_trip():
    keyset = initialize_policy_signing_keys()
    bundle = PolicyBundle(
        bundle_id="bundle-gen1-roundtrip",
        version="1.0.0",
        created_at="2026-04-20T00:00:00+00:00",
        policies=[{"rule_id": "untrusted-external-write", "verdict": "quarantine"}],
        metadata={"format": "json"},
    )

    signed = sign_policy_bundle(bundle, keyset)
    exported = export_signed_bundle(signed)
    imported = import_signed_bundle(exported)
    verification = verify_policy_bundle_signature(imported, keyset)

    assert imported.bundle.bundle_id == signed.bundle.bundle_id
    assert imported.bundle.version == signed.bundle.version
    assert imported.key_id == signed.key_id
    assert imported.algorithm == "hs256"
    assert verification.status == "valid"


def test_summarize_signed_bundle_returns_expected_shape():
    keyset = initialize_policy_signing_keys()
    bundle = PolicyBundle(
        bundle_id="bundle-gen1-summary",
        version="1.0.1",
        created_at="2026-04-20T00:00:00+00:00",
        policies=[
            {"rule_id": "dangerous-shell-execution", "verdict": "block"},
            {"rule_id": "tool-credential-exfiltration", "verdict": "quarantine"},
        ],
        metadata={"source": "pytest"},
    )

    signed = sign_policy_bundle(bundle, keyset)
    verification = verify_policy_bundle_signature(signed, keyset)
    summary = summarize_signed_bundle(signed, verification)

    assert summary["bundle_id"] == "bundle-gen1-summary"
    assert summary["version"] == "1.0.1"
    assert summary["policy_count"] == 2
    assert summary["key_id"] == keyset.active_key_id
    assert summary["verification_status"] == "valid"
