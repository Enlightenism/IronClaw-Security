from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.services.groq_security_brain import GroqMode

router = APIRouter(
    prefix="/ui/groq",
    tags=["groq-control-panel"],
)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


# ---------- core state (temporary in-memory store) ----------


@dataclass(slots=True)
class GroqControlFlags:
    """Centralized, mutable control flags for the Groq security brain.

    This is intentionally kept in memory so you can later swap it with
    a config service, database, or environment-backed settings without
    changing the UI contract.
    """

    mode: GroqMode = "assist"
    allow_shell_commands: bool = False
    allow_network: bool = True
    allow_file_write: bool = True
    allow_prompt_injection_testing: bool = False
    log_only_mode: bool = False
    maintenance_mode: bool = False
    updated_at: str = Field(default_factory=_utc_now)  # type: ignore[assignment]
    updated_by: str = "system"

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        # Pydantic-compatible structure
        return {
            "mode": data["mode"],
            "allow_shell_commands": data["allow_shell_commands"],
            "allow_network": data["allow_network"],
            "allow_file_write": data["allow_file_write"],
            "allow_prompt_injection_testing": data["allow_prompt_injection_testing"],
            "log_only_mode": data["log_only_mode"],
            "maintenance_mode": data["maintenance_mode"],
            "updated_at": data["updated_at"],
            "updated_by": data["updated_by"],
        }


# Global in-memory instance (safe enough for your single-process control panel)
CONTROL_FLAGS = GroqControlFlags()


# ---------- Pydantic models (API schema) ----------


class GroqControlFlagsView(BaseModel):
    mode: GroqMode
    allow_shell_commands: bool
    allow_network: bool
    allow_file_write: bool
    allow_prompt_injection_testing: bool
    log_only_mode: bool
    maintenance_mode: bool
    updated_at: str
    updated_by: str


class GroqControlPanelResponse(BaseModel):
    flags: GroqControlFlagsView
    generated_at: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class GroqControlPanelPatch(BaseModel):
    """Partial update body for the control panel.

    All fields are optional; only provided fields are changed.
    """

    mode: GroqMode | None = Field(
        default=None,
        description="Groq security brain mode: disabled, observe, assist, or enforce.",
    )
    allow_shell_commands: bool | None = Field(
        default=None,
        description="If false, shellcommand actions are hard-blocked before evaluation.",
    )
    allow_network: bool | None = Field(
        default=None,
        description="If false, network actions are blocked.",
    )
    allow_file_write: bool | None = Field(
        default=None,
        description="If false, filewrite actions are blocked.",
    )
    allow_prompt_injection_testing: bool | None = Field(
        default=None,
        description="If true, allows explicit prompt-injection test flows in non-prod.",
    )
    log_only_mode: bool | None = Field(
        default=None,
        description="If true, actions are logged but not enforced (soft-eval).",
    )
    maintenance_mode: bool | None = Field(
        default=None,
        description="If true, system may short-circuit some decisions for safety.",
    )
    updated_by: str | None = Field(
        default=None,
        description="Identifier for who performed the update (user, system, API key).",
    )


# ---------- internal helpers ----------


def _apply_patch(
    patch: GroqControlPanelPatch,
    *,
    flags: GroqControlFlags,
) -> GroqControlFlags:
    # Mode
    if patch.mode is not None:
        flags.mode = patch.mode

    # Toggles
    if patch.allow_shell_commands is not None:
        flags.allow_shell_commands = patch.allow_shell_commands

    if patch.allow_network is not None:
        flags.allow_network = patch.allow_network

    if patch.allow_file_write is not None:
        flags.allow_file_write = patch.allow_file_write

    if patch.allow_prompt_injection_testing is not None:
        flags.allow_prompt_injection_testing = patch.allow_prompt_injection_testing

    if patch.log_only_mode is not None:
        flags.log_only_mode = patch.log_only_mode

    if patch.maintenance_mode is not None:
        flags.maintenance_mode = patch.maintenance_mode

    # Metadata
    if patch.updated_by is not None:
        flags.updated_by = patch.updated_by
    else:
        # preserve last actor if not overwritten
        flags.updated_by = flags.updated_by or "system"

    flags.updated_at = _utc_now()
    return flags


def _make_response_metadata() -> dict[str, Any]:
    return {
        "version": "v1",
        "source": "ui-groq-control-panel",
    }


# ---------- HTTP endpoints ----------


@router.get("/control", response_model=GroqControlPanelResponse)
def get_groq_control_panel() -> GroqControlPanelResponse:
    """Read the current Groq security brain mode and safety toggles.

    This endpoint is designed for a control panel UI that needs to
    render switches and radio-buttons based on central brain state.
    """
    flags_view = GroqControlFlagsView(**CONTROL_FLAGS.to_dict())
    return GroqControlPanelResponse(
        flags=flags_view,
        generated_at=_utc_now(),
        metadata=_make_response_metadata(),
    )


@router.patch("/control", response_model=GroqControlPanelResponse)
def patch_groq_control_panel(patch: GroqControlPanelPatch) -> GroqControlPanelResponse:
    """Partially update Groq security brain control flags.

    This is safe for UI forms that send only changed fields. It keeps
    the contract stable as you later wire flags into real policy logic.
    """
    global CONTROL_FLAGS
    CONTROL_FLAGS = _apply_patch(patch, flags=CONTROL_FLAGS)

    flags_view = GroqControlFlagsView(**CONTROL_FLAGS.to_dict())
    return GroqControlPanelResponse(
        flags=flags_view,
        generated_at=_utc_now(),
        metadata=_make_response_metadata(),
    )
