# code ironclaw_skill/__init__.py
from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("ironclaw-security")
except PackageNotFoundError:
    __version__ = "0.1.0"

__title__ = "ironclaw_skill"
__description__ = "Skill-style integration surface for IronClaw-Security."
__package_name__ = "ironclaw_skill"

__all__ = [
    "__version__",
    "__title__",
    "__description__",
    "__package_name__",
]