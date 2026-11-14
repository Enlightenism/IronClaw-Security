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
    PinnedInstallBlock(program="openclaw", fingerprint="5c6ae6d0db128f47a0c336e4af65cb3ae3674f6baccc2c9c14b95822cbb84c6e", source_urls=_INSTALLER_SOURCE_URLS),
    PinnedInstallBlock(program="claude_code", fingerprint="57e72b37bb0df3c7381e363bd50ab0d91cb9609cd818b5ad2bb680cde0505534", source_urls=_INSTALLER_SOURCE_URLS),
    PinnedInstallBlock(program="cursor", fingerprint="b4d7c9a36b2801cc725403c1433c34a093648bcd70e44057e8d8b68bcaeaedc8", source_urls=_INSTALLER_SOURCE_URLS),
    PinnedInstallBlock(program="goose", fingerprint="1235904b43a79418d88870986789e158485cf5dcd2771a8bb292d3797aafd2c7", source_urls=_INSTALLER_SOURCE_URLS),
    PinnedInstallBlock(program="gemini_cli", fingerprint="10d95a2b02dbd3b57544af00cb8f731d48a2ee5e3eb58d9aca8121c660870086", source_urls=_INSTALLER_SOURCE_URLS),
    PinnedInstallBlock(program="copilot", fingerprint="c6386f0a47385828b42b20211cf715727af4b15920f45f6b735b1ca6a96a4341", source_urls=_INSTALLER_SOURCE_URLS),
    PinnedInstallBlock(program="hermes", fingerprint="3da33cf6a833d32bd2a8d2c935fd76215fba464b3aba25f1085724d9b92ccd5b", source_urls=_INSTALLER_AND_SKILL_SOURCE_URLS),
)


def find_pinned_install_block(command: str) -> PinnedInstallBlock | None:
    fingerprint = fingerprint_install_block(command)
    for pin in PINNED_INSTALL_BLOCKS:
        if pin.fingerprint == fingerprint:
            return pin
    return None
