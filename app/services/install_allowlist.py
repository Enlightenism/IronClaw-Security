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
    PinnedInstallBlock(program="openclaw", fingerprint="b9ae25b21bea168c43a2c30ae012f5c1985e370f20e3523b9b0eec5b0a3f3eb3", source_urls=_INSTALLER_SOURCE_URLS),
    PinnedInstallBlock(program="claude_code", fingerprint="b3f41de829707675bfa50e4beb14c6410e79a64e17cdd2f01239c7e66b8d3c90", source_urls=_INSTALLER_SOURCE_URLS),
    PinnedInstallBlock(program="cursor", fingerprint="0890192c1961267460c501ce84a1e3cf96b82689c14b1eb3826408ef2b792254", source_urls=_INSTALLER_SOURCE_URLS),
    PinnedInstallBlock(program="goose", fingerprint="0bcbc7a119695e2e9171bce9f0a37218182b2f94b0b7bb7b4f7d2d479e88db08", source_urls=_INSTALLER_SOURCE_URLS),
    PinnedInstallBlock(program="gemini_cli", fingerprint="ed7d729a2b1630c6b3dfc3a93f9a4efffe98fc1541ff1f816008d2d4b41432a7", source_urls=_INSTALLER_SOURCE_URLS),
    PinnedInstallBlock(program="copilot", fingerprint="0f54a9c32ec6e52d18405cf90c05fc50a4aa092dd57fb16320a30dd6bf14a461", source_urls=_INSTALLER_SOURCE_URLS),
    PinnedInstallBlock(program="hermes", fingerprint="0bc0f6944b9bd8b9499a3f61423bd241b8bcf9c1a9db9d488de3ce5ae26816b9", source_urls=_INSTALLER_AND_SKILL_SOURCE_URLS),
)


def find_pinned_install_block(command: str) -> PinnedInstallBlock | None:
    fingerprint = fingerprint_install_block(command)
    for pin in PINNED_INSTALL_BLOCKS:
        if pin.fingerprint == fingerprint:
            return pin
    return None
