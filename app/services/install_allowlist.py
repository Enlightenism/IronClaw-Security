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
    PinnedInstallBlock(program="openclaw", fingerprint="b67aa82b1a8168049c35a5df5736ed3324a2c3d9cf363c245114fd5f2a349e66", source_urls=_INSTALLER_SOURCE_URLS),
    PinnedInstallBlock(program="claude_code", fingerprint="11d1f701949fe7c717bf5112c893ae97ed24040eff8b71a9b7d88172797a24b5", source_urls=_INSTALLER_SOURCE_URLS),
    PinnedInstallBlock(program="cursor", fingerprint="5bdd3e0293950a0f71d401f9f5cebe6dc566be1842df80251d51278f97b2feee", source_urls=_INSTALLER_SOURCE_URLS),
    PinnedInstallBlock(program="goose", fingerprint="31a90ce4d3534f7ca10e888b04e3bca99c0187dacacf1e86f826cea3cb954963", source_urls=_INSTALLER_SOURCE_URLS),
    PinnedInstallBlock(program="gemini_cli", fingerprint="f80cc652a395fd25a8632be65d99f2c7ff4711dd59760dc56ea9286b8dad50a2", source_urls=_INSTALLER_SOURCE_URLS),
    PinnedInstallBlock(program="copilot", fingerprint="f3eff9e27b992278a86360d2c6a393daf13d4d4d4ce9f9ba34145b9370d06520", source_urls=_INSTALLER_SOURCE_URLS),
    PinnedInstallBlock(program="hermes", fingerprint="641f55017d4bd0e41a654b39efce07e26f9dbc76d3e5c1d12c00b2edfa518225", source_urls=_INSTALLER_AND_SKILL_SOURCE_URLS),
)


def find_pinned_install_block(command: str) -> PinnedInstallBlock | None:
    fingerprint = fingerprint_install_block(command)
    for pin in PINNED_INSTALL_BLOCKS:
        if pin.fingerprint == fingerprint:
            return pin
    return None
