from __future__ import annotations

import base64
from dataclasses import dataclass, field
from datetime import UTC, datetime
import hashlib
import hmac
import json
from typing import Any

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256_hex(value: Any) -> str:
    if not isinstance(value, str):
        value = _stable_json(value)
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _hmac_b64(secret: str, message: str) -> str:
    digest = hmac.new(
        secret.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    return base64.b64encode(digest).decode("utf-8")


def _normalize(value: str | None) -> str:
    return (value or "").strip()


def _require(value: str | None, label: str) -> str:
    v = _normalize(value)
    if not v:
        raise ValueError(f"{label} is required")
    return v


def _parse_semver(version: str) -> tuple[int, ...]:
    """Parse a version string of the form YYYY.MM.DD or N.N.N into a comparable
    tuple of integers. Returns an empty tuple on any parse failure so callers
    can decide whether to surface a specific error.
    """
    try:
        return tuple(int(p) for p in version.split("."))
    except (ValueError, AttributeError):
        return ()


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class SignedBundle:
    bundle_id: str
    version: str
    algorithm: str
    signature: str
    digest: str
    manifest: dict[str, Any]
    signed_at: str = field(default_factory=_utc_now)

    def as_dict(self) -> dict[str, Any]:
        return {
            "bundleid": self.bundle_id,
            "version": self.version,
            "algorithm": self.algorithm,
            "signature": self.signature,
            "digest": self.digest,
            "manifest": dict(self.manifest),
            "signedat": self.signed_at,
        }


@dataclass(slots=True)
class VerificationVerdict:
    valid: bool
    allowed: bool
    verdict: str  # "allow" | "block" | "reject"
    bundle_id: str
    version: str
    matched_rules: list[str] = field(default_factory=list)
    reasons: list[dict[str, Any]] = field(default_factory=list)
    verified_at: str = field(default_factory=_utc_now)

    def as_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "allowed": self.allowed,
            "verdict": self.verdict,
            "bundleid": self.bundle_id,
            "version": self.version,
            "matchedrules": list(self.matched_rules),
            "reasons": [dict(r) for r in self.reasons],
            "verifiedat": self.verified_at,
        }


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------


class PolicyBundleSigningService:
    """Service-pattern signing and verification for IronClaw policy bundles.

    Uses HMAC-SHA256 with base64-encoded signatures and SHA-256 content
    digests. All verification failures are accumulated into matched_rules
    so callers can inspect every violation in a single pass.
    """

    ALGORITHM = "hmac-sha256"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def sign_bundle(
        self,
        *,
        bundle: dict[str, Any],
        secret: str,
    ) -> SignedBundle:
        bundle_id = _require(bundle.get("bundle_id"), "bundle_id")
        version = _require(bundle.get("version"), "version")
        _require(secret, "secret")

        canonical = _stable_json(bundle)
        digest = _sha256_hex(canonical)
        signature = _hmac_b64(secret, canonical)

        manifest: dict[str, Any] = {
            "bundleid": bundle_id,
            "version": version,
            "algorithm": self.ALGORITHM,
            "digest": digest,
        }

        return SignedBundle(
            bundle_id=bundle_id,
            version=version,
            algorithm=self.ALGORITHM,
            signature=signature,
            digest=digest,
            manifest=manifest,
        )

    def verify_bundle(
        self,
        *,
        bundle: dict[str, Any],
        signature: str,
        secret: str,
        manifest: dict[str, Any],
        current_version: str | None = None,
    ) -> VerificationVerdict:
        bundle_id = _normalize(bundle.get("bundle_id"))
        version = _normalize(bundle.get("version"))
        matched_rules: list[str] = []
        reasons: list[dict[str, Any]] = []

        def _fail(rule: str, details: str) -> None:
            if rule not in matched_rules:
                matched_rules.append(rule)
                reasons.append({"label": rule, "details": details})

        # --- structural guards -------------------------------------------
        if not bundle_id:
            _fail("missing_bundle_id", "bundle_id is absent or empty")
        if not version:
            _fail("missing_version", "version is absent or empty")
        if not signature:
            _fail("missing_signature", "signature is absent or empty")
        if not secret:
            _fail("missing_secret", "secret is absent or empty")

        if matched_rules:
            return self._reject(bundle_id or "", version or "", matched_rules, reasons)

        # --- manifest cross-checks ----------------------------------------
        manifest_bundle_id = _normalize(manifest.get("bundleid"))
        manifest_version = _normalize(manifest.get("version"))
        manifest_digest = _normalize(manifest.get("digest"))

        if manifest_bundle_id and manifest_bundle_id != bundle_id:
            _fail(
                "bundle_id_mismatch",
                f"manifest bundleid={manifest_bundle_id!r} != bundle bundleid={bundle_id!r}",
            )

        if manifest_version and manifest_version != version:
            _fail(
                "version_mismatch",
                f"manifest version={manifest_version!r} != bundle version={version!r}",
            )

        # --- rollback check -----------------------------------------------
        if current_version:
            current_parts = _parse_semver(current_version)
            incoming_parts = _parse_semver(version)
            if current_parts and incoming_parts and incoming_parts < current_parts:
                _fail(
                    "rollback_detected",
                    f"incoming version {version!r} < current {current_version!r}",
                )

        if matched_rules:
            return self._reject(bundle_id, version, matched_rules, reasons)

        # --- cryptographic verification -----------------------------------
        canonical = _stable_json(bundle)
        expected_digest = _sha256_hex(canonical)

        if manifest_digest and manifest_digest != expected_digest:
            _fail("digest_mismatch", "bundle digest does not match manifest digest")

        try:
            expected_signature = _hmac_b64(secret, canonical)
        except Exception:
            _fail("signature_mismatch", "failed to compute expected signature")
            return self._reject(bundle_id, version, matched_rules, reasons)

        try:
            sig_bytes = base64.b64decode(signature)
            exp_bytes = base64.b64decode(expected_signature)
        except Exception:
            _fail("invalid_signature_encoding", "signature is not valid base64")
            return self._reject(bundle_id, version, matched_rules, reasons)

        if not hmac.compare_digest(sig_bytes, exp_bytes):
            _fail("signature_mismatch", "HMAC signature does not match")

        if matched_rules:
            return self._reject(bundle_id, version, matched_rules, reasons)

        return VerificationVerdict(
            valid=True,
            allowed=True,
            verdict="allow",
            bundle_id=bundle_id,
            version=version,
            matched_rules=[],
            reasons=[],
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _reject(
        bundle_id: str,
        version: str,
        matched_rules: list[str],
        reasons: list[dict[str, Any]],
    ) -> VerificationVerdict:
        return VerificationVerdict(
            valid=False,
            allowed=False,
            verdict="block",
            bundle_id=bundle_id,
            version=version,
            matched_rules=list(matched_rules),
            reasons=[dict(r) for r in reasons],
        )


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def build_policy_bundle_signing_service() -> PolicyBundleSigningService:
    return PolicyBundleSigningService()
