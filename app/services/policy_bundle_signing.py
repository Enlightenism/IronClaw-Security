from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
import hashlib
import hmac
import json
import secrets
from typing import Any, Literal

PolicyBundleFormat = Literal["json", "compact"]
PolicyBundleStatus = Literal["valid", "invalid", "expired", "unsigned"]


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _normalize_text(value: str | None) -> str:
    return (value or "").strip()


def _stable_json_dumps(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _clean_mapping(value: dict[str, Any] | None) -> dict[str, Any]:
    return dict(value or {})


def _clean_policy_list(value: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    if not value:
        return []
    return [dict(item) for item in value]


def _require_text(value: str | None, field_name: str) -> str:
    normalized = _normalize_text(value)
    if not normalized:
        raise ValueError(f"{field_name} is required")
    return normalized


@dataclass(slots=True)
class PolicyBundle:
    bundle_id: str
    version: str
    created_at: str
    policies: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.bundle_id = _require_text(self.bundle_id, "bundle_id")
        self.version = _require_text(self.version, "version")
        self.created_at = _require_text(self.created_at, "created_at")
        self.policies = _clean_policy_list(self.policies)
        self.metadata = _clean_mapping(self.metadata)

    def to_dict(self) -> dict[str, Any]:
        return {
            "bundle_id": self.bundle_id,
            "version": self.version,
            "created_at": self.created_at,
            "policies": [dict(item) for item in self.policies],
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class SignedPolicyBundle:
    bundle: PolicyBundle
    signature: str
    key_id: str
    algorithm: str = "hs256"
    signed_at: str = field(default_factory=_utc_now)

    def __post_init__(self) -> None:
        self.signature = _require_text(self.signature, "signature")
        self.key_id = _require_text(self.key_id, "key_id")
        self.algorithm = _normalize_text(self.algorithm or "hs256") or "hs256"
        self.signed_at = _require_text(self.signed_at, "signed_at")

    def to_dict(self) -> dict[str, Any]:
        return {
            "bundle": self.bundle.to_dict(),
            "signature": self.signature,
            "key_id": self.key_id,
            "algorithm": self.algorithm,
            "signed_at": self.signed_at,
        }


@dataclass(slots=True)
class PolicyBundleVerificationResult:
    bundle_id: str
    version: str
    status: PolicyBundleStatus
    reason: str
    key_id: str | None = None
    algorithm: str | None = None
    verified_at: str = field(default_factory=_utc_now)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "bundle_id": self.bundle_id,
            "version": self.version,
            "status": self.status,
            "reason": self.reason,
            "key_id": self.key_id,
            "algorithm": self.algorithm,
            "verified_at": self.verified_at,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class PolicySigningKey:
    key_id: str
    secret: str
    algorithm: str = "hs256"
    created_at: str = field(default_factory=_utc_now)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.key_id = _require_text(self.key_id, "key_id")
        self.secret = _require_text(self.secret, "secret")
        self.algorithm = _normalize_text(self.algorithm or "hs256") or "hs256"
        self.created_at = _require_text(self.created_at, "created_at")
        self.metadata = _clean_mapping(self.metadata)

    def to_dict(self) -> dict[str, Any]:
        return {
            "key_id": self.key_id,
            "algorithm": self.algorithm,
            "created_at": self.created_at,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class PolicySigningKeySet:
    active_key_id: str
    keys: dict[str, PolicySigningKey] = field(default_factory=dict)
    created_at: str = field(default_factory=_utc_now)
    updated_at: str = field(default_factory=_utc_now)

    def __post_init__(self) -> None:
        self.active_key_id = _require_text(self.active_key_id, "active_key_id")
        self.keys = dict(self.keys)
        self.created_at = _require_text(self.created_at, "created_at")
        self.updated_at = _require_text(self.updated_at, "updated_at")

    def to_dict(self) -> dict[str, Any]:
        return {
            "active_key_id": self.active_key_id,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "keys": {key_id: key.to_dict() for key_id, key in self.keys.items()},
        }


def create_policy_bundle(
    bundle_id: str,
    version: str,
    *,
    policies: list[dict[str, Any]] | None = None,
    metadata: dict[str, Any] | None = None,
    created_at: str | None = None,
) -> PolicyBundle:
    return PolicyBundle(
        bundle_id=bundle_id,
        version=version,
        created_at=_normalize_text(created_at) or _utc_now(),
        policies=_clean_policy_list(policies),
        metadata=_clean_mapping(metadata),
    )


def initialize_policy_signing_keys() -> PolicySigningKeySet:
    secret = secrets.token_hex(32)
    key_id = "ironclaw-local-default"
    now = _utc_now()

    key = PolicySigningKey(
        key_id=key_id,
        secret=secret,
        algorithm="hs256",
        created_at=now,
        metadata={"scope": "local", "purpose": "policy-bundle", "active": True},
    )
    return PolicySigningKeySet(
        active_key_id=key_id,
        keys={key_id: key},
        created_at=now,
        updated_at=now,
    )


def get_active_signing_key(keyset: PolicySigningKeySet) -> PolicySigningKey:
    key = keyset.keys.get(keyset.active_key_id)
    if key is None:
        raise KeyError(f"unknown active key_id: {keyset.active_key_id}")
    return key


def register_signing_key(
    keyset: PolicySigningKeySet,
    *,
    key_id: str,
    secret: str,
    algorithm: str = "hs256",
    metadata: dict[str, Any] | None = None,
    make_active: bool = False,
) -> PolicySigningKeySet:
    now = _utc_now()
    normalized_key_id = _require_text(key_id, "key_id")

    key = PolicySigningKey(
        key_id=normalized_key_id,
        secret=secret,
        algorithm=algorithm,
        created_at=now,
        metadata=_clean_mapping(metadata),
    )

    keys = dict(keyset.keys)
    keys[normalized_key_id] = key

    active_key_id = normalized_key_id if make_active else keyset.active_key_id
    if make_active:
        for existing_key in keys.values():
            existing_key.metadata = dict(existing_key.metadata)
            existing_key.metadata["active"] = existing_key.key_id == normalized_key_id

    return PolicySigningKeySet(
        active_key_id=active_key_id,
        keys=keys,
        created_at=keyset.created_at,
        updated_at=now,
    )


def rotate_active_signing_key(
    keyset: PolicySigningKeySet,
    *,
    key_id: str | None = None,
    secret: str | None = None,
    algorithm: str = "hs256",
    metadata: dict[str, Any] | None = None,
) -> PolicySigningKeySet:
    next_key_id = _normalize_text(key_id) or f"ironclaw-rotated-{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}"
    next_secret = _normalize_text(secret) or secrets.token_hex(32)
    next_metadata = dict(metadata or {})
    next_metadata.setdefault("scope", "local")
    next_metadata.setdefault("purpose", "policy-bundle")
    next_metadata["rotated"] = True
    next_metadata["active"] = True

    return register_signing_key(
        keyset,
        key_id=next_key_id,
        secret=next_secret,
        algorithm=algorithm,
        metadata=next_metadata,
        make_active=True,
    )


def _compute_hmac_signature(
    payload: dict[str, Any],
    *,
    secret: str,
    algorithm: str = "hs256",
) -> str:
    if algorithm != "hs256":
        raise ValueError(f"unsupported algorithm: {algorithm}")

    body = _stable_json_dumps(payload).encode("utf-8")
    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return f"{algorithm}:{digest}"


def _validate_bundle(bundle: PolicyBundle) -> None:
    _require_text(bundle.bundle_id, "bundle_id")
    _require_text(bundle.version, "version")
    _require_text(bundle.created_at, "created_at")


def sign_policy_bundle(
    bundle: PolicyBundle,
    keyset: PolicySigningKeySet,
) -> SignedPolicyBundle:
    _validate_bundle(bundle)
    key = get_active_signing_key(keyset)
    payload = bundle.to_dict()
    signature = _compute_hmac_signature(
        payload,
        secret=key.secret,
        algorithm=key.algorithm,
    )
    return SignedPolicyBundle(
        bundle=bundle,
        signature=signature,
        key_id=key.key_id,
        algorithm=key.algorithm,
    )


def verify_policy_bundle_signature(
    signed: SignedPolicyBundle,
    keyset: PolicySigningKeySet,
) -> PolicyBundleVerificationResult:
    bundle_dict = signed.bundle.to_dict()
    key = keyset.keys.get(signed.key_id)

    if key is None:
        return PolicyBundleVerificationResult(
            bundle_id=signed.bundle.bundle_id,
            version=signed.bundle.version,
            status="invalid",
            reason="signing key not found",
            key_id=signed.key_id,
            algorithm=signed.algorithm,
            metadata={"verification": "missing-key"},
        )

    if signed.algorithm != key.algorithm:
        return PolicyBundleVerificationResult(
            bundle_id=signed.bundle.bundle_id,
            version=signed.bundle.version,
            status="invalid",
            reason="algorithm mismatch",
            key_id=key.key_id,
            algorithm=signed.algorithm,
            metadata={"expected_algorithm": key.algorithm},
        )

    try:
        _validate_bundle(signed.bundle)
        expected_signature = _compute_hmac_signature(
            bundle_dict,
            secret=key.secret,
            algorithm=key.algorithm,
        )
    except ValueError as exc:
        return PolicyBundleVerificationResult(
            bundle_id=signed.bundle.bundle_id,
            version=signed.bundle.version,
            status="invalid",
            reason=str(exc),
            key_id=key.key_id,
            algorithm=key.algorithm,
            metadata={"verification": "validation-error"},
        )

    if not hmac.compare_digest(signed.signature, expected_signature):
        return PolicyBundleVerificationResult(
            bundle_id=signed.bundle.bundle_id,
            version=signed.bundle.version,
            status="invalid",
            reason="signature mismatch",
            key_id=key.key_id,
            algorithm=key.algorithm,
            metadata={"verification": "signature-mismatch"},
        )

    return PolicyBundleVerificationResult(
        bundle_id=signed.bundle.bundle_id,
        version=signed.bundle.version,
        status="valid",
        reason="signature verified",
        key_id=key.key_id,
        algorithm=key.algorithm,
        metadata={"verification": "verified"},
    )


def export_signed_bundle(
    signed: SignedPolicyBundle,
    *,
    format: PolicyBundleFormat = "json",
) -> str:
    payload = signed.to_dict()
    if format == "json":
        return json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=False)
    if format == "compact":
        return _stable_json_dumps(payload)
    raise ValueError(f"unsupported bundle export format: {format}")


def import_signed_bundle(serialized: str) -> SignedPolicyBundle:
    raw = json.loads(serialized)
    if not isinstance(raw, dict):
        raise ValueError("serialized bundle must decode to an object")

    bundle_data = raw.get("bundle")
    if not isinstance(bundle_data, dict):
        raise ValueError("serialized bundle is missing a valid 'bundle' object")

    bundle = PolicyBundle(
        bundle_id=_normalize_text(bundle_data.get("bundle_id")),
        version=_normalize_text(bundle_data.get("version")),
        created_at=_normalize_text(bundle_data.get("created_at")),
        policies=_clean_policy_list(bundle_data.get("policies")),
        metadata=_clean_mapping(bundle_data.get("metadata")),
    )

    return SignedPolicyBundle(
        bundle=bundle,
        signature=_normalize_text(raw.get("signature")),
        key_id=_normalize_text(raw.get("key_id")),
        algorithm=_normalize_text(raw.get("algorithm") or "hs256") or "hs256",
        signed_at=_normalize_text(raw.get("signed_at") or _utc_now()),
    )


def summarize_signed_bundle(
    signed: SignedPolicyBundle,
    verification: PolicyBundleVerificationResult | None = None,
) -> dict[str, Any]:
    verification_status = verification.status if verification else "unsigned"
    verification_reason = verification.reason if verification else "not verified"

    return {
        "bundle_id": signed.bundle.bundle_id,
        "version": signed.bundle.version,
        "policy_count": len(signed.bundle.policies),
        "key_id": signed.key_id,
        "algorithm": signed.algorithm,
        "signed_at": signed.signed_at,
        "verification_status": verification_status,
        "verification_reason": verification_reason,
    }


def summarize_signing_keyset(keyset: PolicySigningKeySet) -> dict[str, Any]:
    return {
        "active_key_id": keyset.active_key_id,
        "key_count": len(keyset.keys),
        "algorithms": sorted({key.algorithm for key in keyset.keys.values()}),
        "created_at": keyset.created_at,
        "updated_at": keyset.updated_at,
    }
