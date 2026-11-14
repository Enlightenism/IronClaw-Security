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
    PinnedInstallBlock(program="openclaw", fingerprint="a1fabecf39894b72ab96ef04f333d51da3fee652598fed345bee8ef9c4ecb09f", source_urls=_INSTALLER_SOURCE_URLS),
    PinnedInstallBlock(program="claude_code", fingerprint="c9fa0e389b9ca77b689f4b5926d77804e7d7b16136ad91bbefaaca9a49fa3677", source_urls=_INSTALLER_SOURCE_URLS),
    PinnedInstallBlock(program="cursor", fingerprint="021e3522063e318d4202c0df6b79a054c14e500ef93983712349d323f9a47b39", source_urls=_INSTALLER_SOURCE_URLS),
    PinnedInstallBlock(program="goose", fingerprint="146d2d8c76b1047dbc24a7ff7e8fc7f8a44df51b97e9839f852ad99e95a91aae", source_urls=_INSTALLER_SOURCE_URLS),
    PinnedInstallBlock(program="gemini_cli", fingerprint="4a15a6636ab3dcb5d497e02d4e45219adf6785f6f156db5516d483e609b54c37", source_urls=_INSTALLER_SOURCE_URLS),
    PinnedInstallBlock(program="copilot", fingerprint="8502df8128cc86ab2e398b50cfd973515b69159a8c03fb194be7d98429f4d976", source_urls=_INSTALLER_SOURCE_URLS),
    PinnedInstallBlock(program="hermes", fingerprint="00a54cf66a4f68ad874a784b1253b7a0ef04d4bd6dbd21c36dac87dcf8c2f64d", source_urls=_INSTALLER_AND_SKILL_SOURCE_URLS),
)


def find_pinned_install_block(command: str) -> PinnedInstallBlock | None:
    fingerprint = fingerprint_install_block(command)
    for pin in PINNED_INSTALL_BLOCKS:
        if pin.fingerprint == fingerprint:
            return pin
    return None
