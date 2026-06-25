from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
import hashlib
import hmac
import os
import re
import secrets
import threading
from typing import Any
from uuid import uuid4

# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _utcnow_iso() -> str:
    return _utcnow().isoformat()


def _generate_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _validate_email(email: str) -> bool:
    pattern = r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(pattern, email))


def _safe_compare(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class InviteStatus(StrEnum):
    PENDING = "pending"
    ACCEPTED = "accepted"
    EXPIRED = "expired"
    REVOKED = "revoked"


class VerificationStatus(StrEnum):
    UNVERIFIED = "unverified"
    PENDING = "pending"
    VERIFIED = "verified"
    FAILED = "failed"
    EXPIRED = "expired"


class OnboardingStep(StrEnum):
    INVITE_SENT = "invite_sent"
    EMAIL_VERIFIED = "email_verified"
    PROFILE_COMPLETE = "profile_complete"
    TEAM_PROVISIONED = "team_provisioned"
    COMPLETED = "completed"


class TeamProvisionStatus(StrEnum):
    PENDING = "pending"
    PROVISIONING = "provisioning"
    ACTIVE = "active"
    FAILED = "failed"


class MemberRole(StrEnum):
    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"
    VIEWER = "viewer"


# ---------------------------------------------------------------------------
# Default role-to-permissions mapping
# ---------------------------------------------------------------------------

_ROLE_PERMISSIONS: dict[str, list[str]] = {
    MemberRole.OWNER: [
        "org:manage",
        "org:delete",
        "team:manage",
        "member:invite",
        "member:remove",
        "policy:write",
        "policy:read",
        "audit:read",
        "audit:export",
        "guard:evaluate",
        "webhook:manage",
        "integration:manage",
        "session:manage",
    ],
    MemberRole.ADMIN: [
        "team:manage",
        "member:invite",
        "member:remove",
        "policy:write",
        "policy:read",
        "audit:read",
        "audit:export",
        "guard:evaluate",
        "webhook:manage",
        "integration:manage",
        "session:manage",
    ],
    MemberRole.MEMBER: [
        "policy:read",
        "audit:read",
        "guard:evaluate",
        "webhook:read",
        "integration:read",
        "session:read",
    ],
    MemberRole.VIEWER: [
        "policy:read",
        "audit:read",
        "session:read",
    ],
}

# Invite TTL
_INVITE_TTL_HOURS: int = int(os.environ.get("IRONCLAW_INVITE_TTL_HOURS", "48"))
_VERIFY_TTL_HOURS: int = int(os.environ.get("IRONCLAW_VERIFY_TTL_HOURS", "24"))
_MAX_PENDING_INVITES_PER_ORG: int = int(os.environ.get("IRONCLAW_MAX_PENDING_INVITES", "200"))


# ---------------------------------------------------------------------------
# Internal data records (in-memory store)
# ---------------------------------------------------------------------------


@dataclass
class _InviteRecord:
    invite_id: str
    org_id: str
    email: str
    role: str
    invited_by: str
    token_hash: str
    status: str
    created_at: str
    expires_at: str
    accepted_at: str | None
    revoked_at: str | None
    revoked_by: str | None
    principal_id: str | None
    metadata: dict[str, Any]


@dataclass
class _VerificationRecord:
    verification_id: str
    principal_id: str
    email: str
    org_id: str | None
    token_hash: str
    status: str
    attempt_count: int
    created_at: str
    expires_at: str
    verified_at: str | None
    failed_reason: str | None
    metadata: dict[str, Any]


@dataclass
class _OnboardingRecord:
    onboarding_id: str
    principal_id: str
    org_id: str
    invite_id: str | None
    current_step: str
    completed_steps: list[str]
    email_verified: bool
    profile_complete: bool
    team_provisioned: bool
    created_at: str
    updated_at: str
    completed_at: str | None
    metadata: dict[str, Any]


@dataclass
class _TeamRecord:
    team_id: str
    org_id: str
    name: str
    description: str
    created_by: str
    provision_status: str
    members: list[dict[str, Any]]
    created_at: str
    updated_at: str
    provisioned_at: str | None
    failed_reason: str | None
    metadata: dict[str, Any]


@dataclass
class _OrgRecord:
    org_id: str
    name: str
    slug: str
    owner_principal_id: str
    plan: str
    active: bool
    member_count: int
    created_at: str
    updated_at: str
    metadata: dict[str, Any]


# ---------------------------------------------------------------------------
# Response shapes
# ---------------------------------------------------------------------------


class InviteResponse:
    __slots__ = (
        "invite_id",
        "org_id",
        "email",
        "role",
        "invited_by",
        "status",
        "created_at",
        "expires_at",
        "accepted_at",
        "revoked_at",
        "principal_id",
        "metadata",
    )

    def __init__(self, record: _InviteRecord) -> None:
        self.invite_id = record.invite_id
        self.org_id = record.org_id
        self.email = record.email
        self.role = record.role
        self.invited_by = record.invited_by
        self.status = record.status
        self.created_at = record.created_at
        self.expires_at = record.expires_at
        self.accepted_at = record.accepted_at
        self.revoked_at = record.revoked_at
        self.principal_id = record.principal_id
        self.metadata = dict(record.metadata)

    def to_dict(self) -> dict[str, Any]:
        return {
            "invite_id": self.invite_id,
            "org_id": self.org_id,
            "email": self.email,
            "role": self.role,
            "invited_by": self.invited_by,
            "status": self.status,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "accepted_at": self.accepted_at,
            "revoked_at": self.revoked_at,
            "principal_id": self.principal_id,
            "metadata": self.metadata,
        }


class InviteCreateResponse:
    __slots__ = ("invite_id", "org_id", "email", "role", "status", "invite_token", "expires_at", "created_at")

    def __init__(self, record: _InviteRecord, invite_token: str) -> None:
        self.invite_id = record.invite_id
        self.org_id = record.org_id
        self.email = record.email
        self.role = record.role
        self.status = record.status
        self.invite_token = invite_token
        self.expires_at = record.expires_at
        self.created_at = record.created_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "invite_id": self.invite_id,
            "org_id": self.org_id,
            "email": self.email,
            "role": self.role,
            "status": self.status,
            "invite_token": self.invite_token,
            "expires_at": self.expires_at,
            "created_at": self.created_at,
        }


class VerificationResponse:
    __slots__ = (
        "verification_id",
        "principal_id",
        "email",
        "status",
        "attempt_count",
        "created_at",
        "expires_at",
        "verified_at",
        "failed_reason",
    )

    def __init__(self, record: _VerificationRecord) -> None:
        self.verification_id = record.verification_id
        self.principal_id = record.principal_id
        self.email = record.email
        self.status = record.status
        self.attempt_count = record.attempt_count
        self.created_at = record.created_at
        self.expires_at = record.expires_at
        self.verified_at = record.verified_at
        self.failed_reason = record.failed_reason

    def to_dict(self) -> dict[str, Any]:
        return {
            "verification_id": self.verification_id,
            "principal_id": self.principal_id,
            "email": self.email,
            "status": self.status,
            "attempt_count": self.attempt_count,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "verified_at": self.verified_at,
            "failed_reason": self.failed_reason,
        }


class OnboardingResponse:
    __slots__ = (
        "onboarding_id",
        "principal_id",
        "org_id",
        "invite_id",
        "current_step",
        "completed_steps",
        "email_verified",
        "profile_complete",
        "team_provisioned",
        "created_at",
        "updated_at",
        "completed_at",
        "metadata",
    )

    def __init__(self, record: _OnboardingRecord) -> None:
        self.onboarding_id = record.onboarding_id
        self.principal_id = record.principal_id
        self.org_id = record.org_id
        self.invite_id = record.invite_id
        self.current_step = record.current_step
        self.completed_steps = list(record.completed_steps)
        self.email_verified = record.email_verified
        self.profile_complete = record.profile_complete
        self.team_provisioned = record.team_provisioned
        self.created_at = record.created_at
        self.updated_at = record.updated_at
        self.completed_at = record.completed_at
        self.metadata = dict(record.metadata)

    def to_dict(self) -> dict[str, Any]:
        return {
            "onboarding_id": self.onboarding_id,
            "principal_id": self.principal_id,
            "org_id": self.org_id,
            "invite_id": self.invite_id,
            "current_step": self.current_step,
            "completed_steps": self.completed_steps,
            "email_verified": self.email_verified,
            "profile_complete": self.profile_complete,
            "team_provisioned": self.team_provisioned,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "completed_at": self.completed_at,
            "metadata": self.metadata,
        }


class TeamResponse:
    __slots__ = (
        "team_id",
        "org_id",
        "name",
        "description",
        "created_by",
        "provision_status",
        "members",
        "created_at",
        "updated_at",
        "provisioned_at",
        "failed_reason",
        "metadata",
    )

    def __init__(self, record: _TeamRecord) -> None:
        self.team_id = record.team_id
        self.org_id = record.org_id
        self.name = record.name
        self.description = record.description
        self.created_by = record.created_by
        self.provision_status = record.provision_status
        self.members = [dict(m) for m in record.members]
        self.created_at = record.created_at
        self.updated_at = record.updated_at
        self.provisioned_at = record.provisioned_at
        self.failed_reason = record.failed_reason
        self.metadata = dict(record.metadata)

    def to_dict(self) -> dict[str, Any]:
        return {
            "team_id": self.team_id,
            "org_id": self.org_id,
            "name": self.name,
            "description": self.description,
            "created_by": self.created_by,
            "provision_status": self.provision_status,
            "members": self.members,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "provisioned_at": self.provisioned_at,
            "failed_reason": self.failed_reason,
            "metadata": self.metadata,
        }


class OrgResponse:
    __slots__ = (
        "org_id",
        "name",
        "slug",
        "owner_principal_id",
        "plan",
        "active",
        "member_count",
        "created_at",
        "updated_at",
        "metadata",
    )

    def __init__(self, record: _OrgRecord) -> None:
        self.org_id = record.org_id
        self.name = record.name
        self.slug = record.slug
        self.owner_principal_id = record.owner_principal_id
        self.plan = record.plan
        self.active = record.active
        self.member_count = record.member_count
        self.created_at = record.created_at
        self.updated_at = record.updated_at
        self.metadata = dict(record.metadata)

    def to_dict(self) -> dict[str, Any]:
        return {
            "org_id": self.org_id,
            "name": self.name,
            "slug": self.slug,
            "owner_principal_id": self.owner_principal_id,
            "plan": self.plan,
            "active": self.active,
            "member_count": self.member_count,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "metadata": self.metadata,
        }


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class OnboardingError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message

    def to_dict(self) -> dict[str, str]:
        return {"error_code": self.code, "message": self.message}


class InviteNotFoundError(OnboardingError):
    def __init__(self, invite_id: str) -> None:
        super().__init__("INVITE_NOT_FOUND", f"Invite not found: {invite_id}")


class InviteExpiredError(OnboardingError):
    def __init__(self) -> None:
        super().__init__("INVITE_EXPIRED", "Invite has expired.")


class InviteAlreadyAcceptedError(OnboardingError):
    def __init__(self) -> None:
        super().__init__("INVITE_ALREADY_ACCEPTED", "Invite has already been accepted.")


class InviteRevokedError(OnboardingError):
    def __init__(self) -> None:
        super().__init__("INVITE_REVOKED", "Invite has been revoked.")


class InviteLimitExceededError(OnboardingError):
    def __init__(self) -> None:
        super().__init__("INVITE_LIMIT_EXCEEDED", "Organization pending invite limit reached.")


class DuplicateInviteError(OnboardingError):
    def __init__(self, email: str) -> None:
        super().__init__("DUPLICATE_INVITE", f"A pending invite already exists for: {email}")


class InvalidTokenError(OnboardingError):
    def __init__(self) -> None:
        super().__init__("INVALID_TOKEN", "Token is invalid or does not match.")


class VerificationNotFoundError(OnboardingError):
    def __init__(self, verification_id: str) -> None:
        super().__init__("VERIFICATION_NOT_FOUND", f"Verification not found: {verification_id}")


class VerificationExpiredError(OnboardingError):
    def __init__(self) -> None:
        super().__init__("VERIFICATION_EXPIRED", "Verification token has expired.")


class VerificationAlreadyCompleteError(OnboardingError):
    def __init__(self) -> None:
        super().__init__("VERIFICATION_ALREADY_COMPLETE", "Email already verified.")


class MaxVerificationAttemptsError(OnboardingError):
    def __init__(self) -> None:
        super().__init__("MAX_VERIFICATION_ATTEMPTS", "Maximum verification attempts exceeded.")


class InvalidEmailError(OnboardingError):
    def __init__(self, email: str) -> None:
        super().__init__("INVALID_EMAIL", f"Email address is invalid: {email}")


class InvalidRoleError(OnboardingError):
    def __init__(self, role: str) -> None:
        super().__init__("INVALID_ROLE", f"Role is not recognized: {role}")


class OrgNotFoundError(OnboardingError):
    def __init__(self, org_id: str) -> None:
        super().__init__("ORG_NOT_FOUND", f"Organization not found: {org_id}")


class TeamNotFoundError(OnboardingError):
    def __init__(self, team_id: str) -> None:
        super().__init__("TEAM_NOT_FOUND", f"Team not found: {team_id}")


class OnboardingNotFoundError(OnboardingError):
    def __init__(self, principal_id: str) -> None:
        super().__init__("ONBOARDING_NOT_FOUND", f"Onboarding record not found for: {principal_id}")


class TeamNameConflictError(OnboardingError):
    def __init__(self, name: str) -> None:
        super().__init__("TEAM_NAME_CONFLICT", f"Team name already exists in this org: {name}")


# ---------------------------------------------------------------------------
# Core Service
# ---------------------------------------------------------------------------

_MAX_VERIFY_ATTEMPTS: int = 5


class OnboardingService:
    """
    Manages the full IronClaw onboarding lifecycle:
      - invite creation, validation, acceptance, revocation
      - email verification token issuance and confirmation
      - onboarding state machine tracking per principal
      - team provisioning with member role assignment
      - org provisioning and membership management

    Thread-safe. All state is in-memory; swap _store calls for
    Supabase adapters without changing the public contract.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()

        # invite_id -> _InviteRecord
        self._invites: dict[str, _InviteRecord] = {}
        # (org_id, email) -> invite_id  (pending index)
        self._invite_index: dict[tuple[str, str], str] = {}

        # verification_id -> _VerificationRecord
        self._verifications: dict[str, _VerificationRecord] = {}
        # principal_id -> verification_id (latest)
        self._verification_by_principal: dict[str, str] = {}

        # principal_id -> _OnboardingRecord
        self._onboarding: dict[str, _OnboardingRecord] = {}

        # team_id -> _TeamRecord
        self._teams: dict[str, _TeamRecord] = {}
        # (org_id, team_name_lower) -> team_id
        self._team_name_index: dict[tuple[str, str], str] = {}

        # org_id -> _OrgRecord
        self._orgs: dict[str, _OrgRecord] = {}
        # slug -> org_id
        self._org_slug_index: dict[str, str] = {}

    # -----------------------------------------------------------------------
    # Org management
    # -----------------------------------------------------------------------

    def create_org(
        self,
        name: str,
        owner_principal_id: str,
        plan: str = "free",
        metadata: dict[str, Any] | None = None,
    ) -> OrgResponse:
        slug = re.sub(r"[^a-z0-9\-]", "-", name.lower().strip())
        slug = re.sub(r"-{2,}", "-", slug).strip("-")
        if not slug:
            raise OnboardingError("INVALID_ORG_NAME", "Org name produced an empty slug.")

        with self._lock:
            # make slug unique
            base_slug = slug
            counter = 1
            while slug in self._org_slug_index:
                slug = f"{base_slug}-{counter}"
                counter += 1

            org_id = f"org-{uuid4().hex[:16]}"
            now = _utcnow_iso()
            record = _OrgRecord(
                org_id=org_id,
                name=name.strip(),
                slug=slug,
                owner_principal_id=owner_principal_id,
                plan=plan,
                active=True,
                member_count=1,
                created_at=now,
                updated_at=now,
                metadata=metadata or {},
            )
            self._orgs[org_id] = record
            self._org_slug_index[slug] = org_id

        return OrgResponse(record)

    def get_org(self, org_id: str) -> OrgResponse | None:
        with self._lock:
            record = self._orgs.get(org_id)
        return OrgResponse(record) if record else None

    def get_org_by_slug(self, slug: str) -> OrgResponse | None:
        with self._lock:
            org_id = self._org_slug_index.get(slug)
            if not org_id:
                return None
            record = self._orgs.get(org_id)
        return OrgResponse(record) if record else None

    def list_orgs(self) -> list[OrgResponse]:
        with self._lock:
            records = list(self._orgs.values())
        return [OrgResponse(r) for r in records]

    # -----------------------------------------------------------------------
    # Invite flow
    # -----------------------------------------------------------------------

    def create_invite(
        self,
        org_id: str,
        email: str,
        role: str,
        invited_by: str,
        metadata: dict[str, Any] | None = None,
    ) -> InviteCreateResponse:
        email = email.strip().lower()
        if not _validate_email(email):
            raise InvalidEmailError(email)
        if role not in _ROLE_PERMISSIONS:
            raise InvalidRoleError(role)

        with self._lock:
            if org_id not in self._orgs:
                raise OrgNotFoundError(org_id)

            # enforce pending invite limit
            pending_count = sum(1 for r in self._invites.values() if r.org_id == org_id and r.status == InviteStatus.PENDING)
            if pending_count >= _MAX_PENDING_INVITES_PER_ORG:
                raise InviteLimitExceededError()

            # check for duplicate pending
            key = (org_id, email)
            existing_id = self._invite_index.get(key)
            if existing_id:
                existing = self._invites.get(existing_id)
                if existing and existing.status == InviteStatus.PENDING:
                    # expire stale if past TTL, otherwise raise
                    expires = datetime.fromisoformat(existing.expires_at)
                    if _utcnow() < expires:
                        raise DuplicateInviteError(email)
                    else:
                        existing.status = InviteStatus.EXPIRED
                        del self._invite_index[key]

            token = _generate_token(48)
            token_h = _token_hash(token)
            invite_id = f"inv-{uuid4().hex[:16]}"
            now = _utcnow()
            expires_at = now + timedelta(hours=_INVITE_TTL_HOURS)

            record = _InviteRecord(
                invite_id=invite_id,
                org_id=org_id,
                email=email,
                role=role,
                invited_by=invited_by,
                token_hash=token_h,
                status=InviteStatus.PENDING,
                created_at=now.isoformat(),
                expires_at=expires_at.isoformat(),
                accepted_at=None,
                revoked_at=None,
                revoked_by=None,
                principal_id=None,
                metadata=metadata or {},
            )
            self._invites[invite_id] = record
            self._invite_index[key] = invite_id

        return InviteCreateResponse(record, invite_token=token)

    def get_invite(self, invite_id: str) -> InviteResponse | None:
        with self._lock:
            record = self._invites.get(invite_id)
        return InviteResponse(record) if record else None

    def list_invites(
        self,
        org_id: str,
        status: str | None = None,
    ) -> list[InviteResponse]:
        with self._lock:
            records = [r for r in self._invites.values() if r.org_id == org_id and (status is None or r.status == status)]
        return [InviteResponse(r) for r in records]

    def validate_invite_token(
        self,
        invite_id: str,
        token: str,
    ) -> InviteResponse:
        with self._lock:
            record = self._invites.get(invite_id)
            if not record:
                raise InviteNotFoundError(invite_id)

            if record.status == InviteStatus.REVOKED:
                raise InviteRevokedError()
            if record.status == InviteStatus.ACCEPTED:
                raise InviteAlreadyAcceptedError()

            if _utcnow() > datetime.fromisoformat(record.expires_at):
                record.status = InviteStatus.EXPIRED
                raise InviteExpiredError()

            if record.status == InviteStatus.EXPIRED:
                raise InviteExpiredError()

            if not _safe_compare(_token_hash(token), record.token_hash):
                raise InvalidTokenError()

        return InviteResponse(record)

    def accept_invite(
        self,
        invite_id: str,
        token: str,
        principal_id: str,
    ) -> InviteResponse:
        with self._lock:
            record = self._invites.get(invite_id)
            if not record:
                raise InviteNotFoundError(invite_id)
            if record.status == InviteStatus.REVOKED:
                raise InviteRevokedError()
            if record.status == InviteStatus.ACCEPTED:
                raise InviteAlreadyAcceptedError()
            if _utcnow() > datetime.fromisoformat(record.expires_at):
                record.status = InviteStatus.EXPIRED
                raise InviteExpiredError()
            if record.status == InviteStatus.EXPIRED:
                raise InviteExpiredError()
            if not _safe_compare(_token_hash(token), record.token_hash):
                raise InvalidTokenError()

            now = _utcnow_iso()
            record.status = InviteStatus.ACCEPTED
            record.accepted_at = now
            record.principal_id = principal_id

            # remove from pending index
            self._invite_index.pop((record.org_id, record.email), None)

            # increment org member count
            org = self._orgs.get(record.org_id)
            if org:
                org.member_count += 1
                org.updated_at = now

        return InviteResponse(record)

    def revoke_invite(
        self,
        invite_id: str,
        revoked_by: str,
    ) -> InviteResponse:
        with self._lock:
            record = self._invites.get(invite_id)
            if not record:
                raise InviteNotFoundError(invite_id)
            if record.status == InviteStatus.ACCEPTED:
                raise InviteAlreadyAcceptedError()
            if record.status == InviteStatus.REVOKED:
                return InviteResponse(record)

            now = _utcnow_iso()
            record.status = InviteStatus.REVOKED
            record.revoked_at = now
            record.revoked_by = revoked_by

            self._invite_index.pop((record.org_id, record.email), None)

        return InviteResponse(record)

    def expire_stale_invites(self) -> int:
        """Sweep and mark expired pending invites. Returns count expired."""
        count = 0
        now = _utcnow()
        with self._lock:
            for record in self._invites.values():
                if record.status == InviteStatus.PENDING:
                    if now > datetime.fromisoformat(record.expires_at):
                        record.status = InviteStatus.EXPIRED
                        self._invite_index.pop((record.org_id, record.email), None)
                        count += 1
        return count

    # -----------------------------------------------------------------------
    # Email verification
    # -----------------------------------------------------------------------

    def issue_verification(
        self,
        principal_id: str,
        email: str,
        org_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> tuple[VerificationResponse, str]:
        """
        Issues a new email verification token.
        Returns (VerificationResponse, raw_token).
        The raw_token must be delivered out-of-band (email).
        Only the hash is stored.
        """
        email = email.strip().lower()
        if not _validate_email(email):
            raise InvalidEmailError(email)

        with self._lock:
            # invalidate any existing pending for this principal
            existing_id = self._verification_by_principal.get(principal_id)
            if existing_id:
                existing = self._verifications.get(existing_id)
                if existing and existing.status in (
                    VerificationStatus.PENDING,
                    VerificationStatus.UNVERIFIED,
                ):
                    existing.status = VerificationStatus.EXPIRED

            token = _generate_token(32)
            token_h = _token_hash(token)
            verification_id = f"ver-{uuid4().hex[:16]}"
            now = _utcnow()
            expires_at = now + timedelta(hours=_VERIFY_TTL_HOURS)

            record = _VerificationRecord(
                verification_id=verification_id,
                principal_id=principal_id,
                email=email,
                org_id=org_id,
                token_hash=token_h,
                status=VerificationStatus.PENDING,
                attempt_count=0,
                created_at=now.isoformat(),
                expires_at=expires_at.isoformat(),
                verified_at=None,
                failed_reason=None,
                metadata=metadata or {},
            )
            self._verifications[verification_id] = record
            self._verification_by_principal[principal_id] = verification_id

        return VerificationResponse(record), token

    def confirm_verification(
        self,
        verification_id: str,
        token: str,
    ) -> VerificationResponse:
        with self._lock:
            record = self._verifications.get(verification_id)
            if not record:
                raise VerificationNotFoundError(verification_id)
            if record.status == VerificationStatus.VERIFIED:
                raise VerificationAlreadyCompleteError()
            if record.status == VerificationStatus.EXPIRED:
                raise VerificationExpiredError()

            if _utcnow() > datetime.fromisoformat(record.expires_at):
                record.status = VerificationStatus.EXPIRED
                raise VerificationExpiredError()

            record.attempt_count += 1

            if record.attempt_count > _MAX_VERIFY_ATTEMPTS:
                record.status = VerificationStatus.FAILED
                record.failed_reason = "max_attempts_exceeded"
                raise MaxVerificationAttemptsError()

            if not _safe_compare(_token_hash(token), record.token_hash):
                record.status = VerificationStatus.FAILED
                record.failed_reason = "invalid_token"
                raise InvalidTokenError()

            now = _utcnow_iso()
            record.status = VerificationStatus.VERIFIED
            record.verified_at = now

            # advance onboarding if linked
            onboarding = self._onboarding.get(record.principal_id)
            if onboarding and not onboarding.email_verified:
                onboarding.email_verified = True
                onboarding.updated_at = now
                self._advance_onboarding_step(onboarding)

        return VerificationResponse(record)

    def get_verification(self, verification_id: str) -> VerificationResponse | None:
        with self._lock:
            record = self._verifications.get(verification_id)
        return VerificationResponse(record) if record else None

    def get_verification_for_principal(self, principal_id: str) -> VerificationResponse | None:
        with self._lock:
            vid = self._verification_by_principal.get(principal_id)
            if not vid:
                return None
            record = self._verifications.get(vid)
        return VerificationResponse(record) if record else None

    def is_email_verified(self, principal_id: str) -> bool:
        with self._lock:
            vid = self._verification_by_principal.get(principal_id)
            if not vid:
                return False
            record = self._verifications.get(vid)
            return bool(record and record.status == VerificationStatus.VERIFIED)

    # -----------------------------------------------------------------------
    # Onboarding state machine
    # -----------------------------------------------------------------------

    def start_onboarding(
        self,
        principal_id: str,
        org_id: str,
        invite_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> OnboardingResponse:
        with self._lock:
            if org_id not in self._orgs:
                raise OrgNotFoundError(org_id)

            existing = self._onboarding.get(principal_id)
            if existing:
                return OnboardingResponse(existing)

            onboarding_id = f"onb-{uuid4().hex[:16]}"
            now = _utcnow_iso()
            record = _OnboardingRecord(
                onboarding_id=onboarding_id,
                principal_id=principal_id,
                org_id=org_id,
                invite_id=invite_id,
                current_step=OnboardingStep.INVITE_SENT,
                completed_steps=[OnboardingStep.INVITE_SENT],
                email_verified=False,
                profile_complete=False,
                team_provisioned=False,
                created_at=now,
                updated_at=now,
                completed_at=None,
                metadata=metadata or {},
            )
            self._onboarding[principal_id] = record

        return OnboardingResponse(record)

    def get_onboarding(self, principal_id: str) -> OnboardingResponse | None:
        with self._lock:
            record = self._onboarding.get(principal_id)
        return OnboardingResponse(record) if record else None

    def mark_profile_complete(self, principal_id: str) -> OnboardingResponse:
        with self._lock:
            record = self._onboarding.get(principal_id)
            if not record:
                raise OnboardingNotFoundError(principal_id)
            now = _utcnow_iso()
            record.profile_complete = True
            record.updated_at = now
            self._advance_onboarding_step(record)
        return OnboardingResponse(record)

    def complete_onboarding(self, principal_id: str) -> OnboardingResponse:
        with self._lock:
            record = self._onboarding.get(principal_id)
            if not record:
                raise OnboardingNotFoundError(principal_id)
            now = _utcnow_iso()
            record.current_step = OnboardingStep.COMPLETED
            if OnboardingStep.COMPLETED not in record.completed_steps:
                record.completed_steps.append(OnboardingStep.COMPLETED)
            record.completed_at = now
            record.updated_at = now
        return OnboardingResponse(record)

    def _advance_onboarding_step(self, record: _OnboardingRecord) -> None:
        """
        Internal: evaluate current flags and advance current_step.
        Must be called under self._lock.
        """
        if not record.email_verified:
            return
        if record.current_step == OnboardingStep.INVITE_SENT:
            record.current_step = OnboardingStep.EMAIL_VERIFIED
            if OnboardingStep.EMAIL_VERIFIED not in record.completed_steps:
                record.completed_steps.append(OnboardingStep.EMAIL_VERIFIED)

        if record.email_verified and record.profile_complete:
            if record.current_step in (
                OnboardingStep.INVITE_SENT,
                OnboardingStep.EMAIL_VERIFIED,
            ):
                record.current_step = OnboardingStep.PROFILE_COMPLETE
                if OnboardingStep.PROFILE_COMPLETE not in record.completed_steps:
                    record.completed_steps.append(OnboardingStep.PROFILE_COMPLETE)

        if record.email_verified and record.profile_complete and record.team_provisioned:
            if record.current_step in (
                OnboardingStep.INVITE_SENT,
                OnboardingStep.EMAIL_VERIFIED,
                OnboardingStep.PROFILE_COMPLETE,
            ):
                record.current_step = OnboardingStep.TEAM_PROVISIONED
                if OnboardingStep.TEAM_PROVISIONED not in record.completed_steps:
                    record.completed_steps.append(OnboardingStep.TEAM_PROVISIONED)

    # -----------------------------------------------------------------------
    # Team provisioning
    # -----------------------------------------------------------------------

    def provision_team(
        self,
        org_id: str,
        name: str,
        created_by: str,
        description: str = "",
        initial_members: list[dict[str, Any]] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> TeamResponse:
        """
        Provisions a team within an org.
        initial_members: list of {"principal_id": str, "role": str}
        """
        name = name.strip()
        if not name:
            raise OnboardingError("INVALID_TEAM_NAME", "Team name cannot be empty.")

        with self._lock:
            if org_id not in self._orgs:
                raise OrgNotFoundError(org_id)

            name_key = (org_id, name.lower())
            if name_key in self._team_name_index:
                raise TeamNameConflictError(name)

            team_id = f"team-{uuid4().hex[:16]}"
            now = _utcnow_iso()

            validated_members: list[dict[str, Any]] = []
            for m in initial_members or []:
                m_role = m.get("role", MemberRole.MEMBER)
                if m_role not in _ROLE_PERMISSIONS:
                    raise InvalidRoleError(m_role)
                validated_members.append(
                    {
                        "principal_id": m["principal_id"],
                        "role": m_role,
                        "permissions": list(_ROLE_PERMISSIONS[m_role]),
                        "added_at": now,
                    }
                )

            record = _TeamRecord(
                team_id=team_id,
                org_id=org_id,
                name=name,
                description=description,
                created_by=created_by,
                provision_status=TeamProvisionStatus.PROVISIONING,
                members=validated_members,
                created_at=now,
                updated_at=now,
                provisioned_at=None,
                failed_reason=None,
                metadata=metadata or {},
            )
            self._teams[team_id] = record
            self._team_name_index[name_key] = team_id

            # finalize provisioning
            record.provision_status = TeamProvisionStatus.ACTIVE
            record.provisioned_at = now

            # mark team_provisioned on any linked onboarding records
            for principal_id in [m["principal_id"] for m in validated_members]:
                onboarding = self._onboarding.get(principal_id)
                if onboarding and onboarding.org_id == org_id:
                    onboarding.team_provisioned = True
                    onboarding.updated_at = now
                    self._advance_onboarding_step(onboarding)

        return TeamResponse(record)

    def get_team(self, team_id: str) -> TeamResponse | None:
        with self._lock:
            record = self._teams.get(team_id)
        return TeamResponse(record) if record else None

    def list_teams(self, org_id: str) -> list[TeamResponse]:
        with self._lock:
            records = [r for r in self._teams.values() if r.org_id == org_id]
        return [TeamResponse(r) for r in records]

    def add_team_member(
        self,
        team_id: str,
        principal_id: str,
        role: str,
    ) -> TeamResponse:
        if role not in _ROLE_PERMISSIONS:
            raise InvalidRoleError(role)
        with self._lock:
            record = self._teams.get(team_id)
            if not record:
                raise TeamNotFoundError(team_id)
            # deduplicate
            for m in record.members:
                if m["principal_id"] == principal_id:
                    m["role"] = role
                    m["permissions"] = list(_ROLE_PERMISSIONS[role])
                    m["updated_at"] = _utcnow_iso()
                    record.updated_at = _utcnow_iso()
                    return TeamResponse(record)
            now = _utcnow_iso()
            record.members.append(
                {
                    "principal_id": principal_id,
                    "role": role,
                    "permissions": list(_ROLE_PERMISSIONS[role]),
                    "added_at": now,
                }
            )
            record.updated_at = now
        return TeamResponse(record)

    def remove_team_member(
        self,
        team_id: str,
        principal_id: str,
    ) -> TeamResponse:
        with self._lock:
            record = self._teams.get(team_id)
            if not record:
                raise TeamNotFoundError(team_id)
            record.members = [m for m in record.members if m["principal_id"] != principal_id]
            record.updated_at = _utcnow_iso()
        return TeamResponse(record)

    def delete_team(self, team_id: str) -> bool:
        with self._lock:
            record = self._teams.pop(team_id, None)
            if not record:
                return False
            self._team_name_index.pop((record.org_id, record.name.lower()), None)
        return True

    # -----------------------------------------------------------------------
    # Role + permission helpers
    # -----------------------------------------------------------------------

    def get_permissions_for_role(self, role: str) -> list[str]:
        if role not in _ROLE_PERMISSIONS:
            raise InvalidRoleError(role)
        return list(_ROLE_PERMISSIONS[role])

    def get_all_roles(self) -> list[str]:
        return list(_ROLE_PERMISSIONS.keys())

    # -----------------------------------------------------------------------
    # Reset (test / memory mode)
    # -----------------------------------------------------------------------

    def reset(self) -> None:
        with self._lock:
            self._invites.clear()
            self._invite_index.clear()
            self._verifications.clear()
            self._verification_by_principal.clear()
            self._onboarding.clear()
            self._teams.clear()
            self._team_name_index.clear()
            self._orgs.clear()
            self._org_slug_index.clear()


# ---------------------------------------------------------------------------
# Singleton accessor
# ---------------------------------------------------------------------------

_onboarding_service_instance: OnboardingService | None = None
_onboarding_service_lock = threading.Lock()


def get_onboarding_service() -> OnboardingService:
    global _onboarding_service_instance
    if _onboarding_service_instance is None:
        with _onboarding_service_lock:
            if _onboarding_service_instance is None:
                _onboarding_service_instance = OnboardingService()
    return _onboarding_service_instance


def reset_onboarding_service() -> None:
    global _onboarding_service_instance
    with _onboarding_service_lock:
        if _onboarding_service_instance is not None:
            _onboarding_service_instance.reset()
        _onboarding_service_instance = None
