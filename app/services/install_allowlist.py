"""IronClaw-pinned install blocks matched by SHA-256 fingerprint and source URL. Default-deny for everything else."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re
from typing import Final

from app.core.install_key_formats import IRONCLAW_INSTALLER_SOURCE_URL, SECURITY_GUARDIAN_SKILL_URL

CLAIM_TOKEN_PATTERN: Final[re.Pattern[str]] = re.compile(r"ic_claim_[A-Za-z0-9_-]{20,128}")
CLAIM_TOKEN_PLACEHOLDER: Final[str] = "<claim_token>"

_INSTALLER_SOURCE_URLS: Final[tuple[str, ...]] = (IRONCLAW_INSTALLER_SOURCE_URL,)
_INSTALLER_AND_SKILL_SOURCE_URLS: Final[tuple[str, ...]] = (IRONCLAW_INSTALLER_SOURCE_URL, SECURITY_GUARDIAN_SKILL_URL)


@dataclass(frozen=True, slots=True)
class PinnedInstallBlock:
    program: str
    fingerprint: str
    source_urls: tuple[str, ...]


def normalize_install_block(command: str) -> str:
    lines = command.replace("\r\n", "\n").strip().split("\n")
    normalized = "\n".join(line.rstrip() for line in lines)
    return CLAIM_TOKEN_PATTERN.sub(CLAIM_TOKEN_PLACEHOLDER, normalized)


def fingerprint_install_block(command: str) -> str:
    return hashlib.sha256(normalize_install_block(command).encode("utf-8")).hexdigest()


PINNED_INSTALL_BLOCKS: Final[tuple[PinnedInstallBlock, ...]] = (
    PinnedInstallBlock(program="openclaw", fingerprint="5cbe9f59fcb08d4f7670a91bc7b2b3ddc9ac6a8215efbfa19045c0b76d0dd5d6", source_urls=_INSTALLER_SOURCE_URLS),
    PinnedInstallBlock(program="claude_code", fingerprint="6665447aad8aebcaa9b6bc95f2b2b8b6ed9f90a2f81f6cab9582f07e9c8fcd5a", source_urls=_INSTALLER_SOURCE_URLS),
    PinnedInstallBlock(program="cursor", fingerprint="4020f4ecafd2b258950ae8201db559a0d351d543305331f3e3ce536527a8b904", source_urls=_INSTALLER_SOURCE_URLS),
    PinnedInstallBlock(program="goose", fingerprint="3c2c5faabf881946da5dec56f9eabbc8d429efae76b59f6483af23b878ec5a61", source_urls=_INSTALLER_SOURCE_URLS),
    PinnedInstallBlock(program="gemini_cli", fingerprint="17bda4da7b2a867fe9bd0a5076d695fe64c114f745ba14a6c4274452b36f48d9", source_urls=_INSTALLER_SOURCE_URLS),
    PinnedInstallBlock(program="copilot", fingerprint="4f4ed48bb0bf83dbb9b7604f78a5d9679d264d94c2df8e5bea6fe5c27811d0d1", source_urls=_INSTALLER_SOURCE_URLS),
    PinnedInstallBlock(program="hermes", fingerprint="a6aa2f913d157df405a6113e6a3559a68baeb9eed3ff299e934a169a921d7c83", source_urls=_INSTALLER_AND_SKILL_SOURCE_URLS),
)


def find_pinned_install_block(command: str) -> PinnedInstallBlock | None:
    fingerprint = fingerprint_install_block(command)
    for pin in PINNED_INSTALL_BLOCKS:
        if pin.fingerprint == fingerprint:
            return pin
    return None
