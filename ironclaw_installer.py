from __future__ import annotations

import argparse
import csv
from dataclasses import asdict, dataclass, field
from importlib import resources
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
from typing import Any, Final
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from app.core.install_key_formats import (
    IRONCLAW_GITHUB_REPOSITORY,
    IRONCLAW_PUBLIC_BASE_URL,
    SECURITY_GUARDIAN_SKILL_NAME,
    SECURITY_GUARDIAN_SKILL_REPOSITORY_PATH,
    SECURITY_GUARDIAN_SKILL_URL,
    InstallKeyFormatRegistry,
    normalize_install_key_program,
)

DEFAULT_BASE_URL: Final[str] = "http://127.0.0.1:8000"
DEFAULT_BOOTSTRAP_BASE_URL: Final[str] = IRONCLAW_PUBLIC_BASE_URL
DEFAULT_CONFIG_DIRNAME: Final[str] = ".ironclaw"
DEFAULT_CONFIG_FILENAME: Final[str] = "config.json"
DEFAULT_SKILL_CONFIG_FILENAME: Final[str] = "skill.json"
OPENCLAW_PLUGIN_ID: Final[str] = "ironclaw-security"
_OPENCLAW_PLUGIN_FILES: Final[tuple[str, ...]] = (
    "package.json",
    "openclaw.plugin.json",
    "index.js",
    "policy.js",
)
HERMES_PLUGIN_ID: Final[str] = "ironclaw-security"
_HERMES_PLUGIN_FILES: Final[tuple[str, ...]] = (
    "__init__.py",
    "plugin.yaml",
)
DEFAULT_ENV_FILENAME: Final[str] = ".env"
DEFAULT_TIMEOUT_SECONDS: Final[float] = 20.0
DEFAULT_BACKUP_TARGET: Final[str] = "primary"
DEFAULT_RESTORE_TARGET: Final[str] = "primary"
DEFAULT_RETENTION_DAYS: Final[int] = 30
DEFAULT_PROVIDER_TARGETS: Final[tuple[str, ...]] = tuple(InstallKeyFormatRegistry.list_programs())
_CANONICAL_RUNTIME_TARGETS: Final[tuple[str, ...]] = DEFAULT_PROVIDER_TARGETS
_INSTALL_CLAIM_PATTERN: Final[re.Pattern[str]] = re.compile(r"ic_claim_[A-Za-z0-9_-]{20,128}\Z")
_MAX_CLAIM_RESPONSE_BYTES: Final[int] = 16_384
_MAX_USER_CONFIG_BYTES: Final[int] = 1_048_576
_GENERIC_INSTALL_KEY_PREFIXES: Final[tuple[str, ...]] = (
    "sk_",
    "ghp_",
    "gho_",
    "github_pat_",
    "token_",
    "secret_",
    "api_",
    "api-key",
    "api_key",
    "platform-api-key",
    "platform_api_key",
    "internal-platform-api-key",
    "internal_platform_api_key",
    "system-api-key",
    "system_api_key",
    "bearer ",
    "x-api-key",
)
_SUBPROCESS_TIMEOUT: Final[int] = 300


class IronClawInstallerError(RuntimeError):
    """Base installer error."""


@dataclass(frozen=True, slots=True)
class InstallConfig:
    project_root: Path
    config_dir: Path
    config_file: Path
    env_file: Path
    base_url: str
    backup_target: str
    restore_target: str
    retention_days: int
    install_vscode_settings: bool
    install_skill_config: bool
    write_env_file: bool
    overwrite: bool
    provider_targets: tuple[str, ...]
    install_claims: dict[str, str] = field(default_factory=dict, repr=False)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["project_root"] = str(self.project_root)
        payload["config_dir"] = str(self.config_dir)
        payload["config_file"] = str(self.config_file)
        payload["env_file"] = str(self.env_file)
        payload["provider_targets"] = list(self.provider_targets)
        payload["install_claims"] = {program: "[REDACTED]" for program in self.install_claims}
        return payload


@dataclass(frozen=True, slots=True)
class InstallResult:
    ok: bool
    config_file: Path
    env_file: Path | None
    vscode_settings_file: Path | None
    skill_config_file: Path | None
    created_paths: tuple[str, ...]
    updated_paths: tuple[str, ...]
    skipped_paths: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "config_file": str(self.config_file),
            "env_file": str(self.env_file) if self.env_file else None,
            "vscode_settings_file": str(self.vscode_settings_file) if self.vscode_settings_file else None,
            "skill_config_file": str(self.skill_config_file) if self.skill_config_file else None,
            "created_paths": list(self.created_paths),
            "updated_paths": list(self.updated_paths),
            "skipped_paths": list(self.skipped_paths),
        }


@dataclass(frozen=True, slots=True)
class BootstrapResult:
    program: str
    config_file: Path
    skill_name: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": True,
            "program": self.program,
            "config_file": str(self.config_file),
            "skill_name": self.skill_name,
        }


def _project_root() -> Path:
    return Path(__file__).resolve().parent


def _default_config_dir() -> Path:
    return Path.home() / DEFAULT_CONFIG_DIRNAME


def _strong_secret(length: int = 32) -> str:
    return secrets.token_urlsafe(length)


def _ensure_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def _restrict_private_file_permissions(path: Path) -> None:
    if path.is_symlink():
        raise IronClawInstallerError(f"Refusing to write a credential file through a symbolic link: {path}")

    if os.name != "nt":
        try:
            path.chmod(0o600)
        except OSError as exc:
            raise IronClawInstallerError(f"Could not restrict permissions for credential file: {path}") from exc
        return

    system_root = os.environ.get("SystemRoot")
    if not system_root:
        raise IronClawInstallerError("Could not restrict permissions for a credential file on Windows.")

    system_directory = Path(system_root) / "System32"
    whoami = system_directory / "whoami.exe"
    icacls = system_directory / "icacls.exe"
    try:
        identity = subprocess.run(
            [str(whoami), "/user", "/fo", "csv", "/nh"],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=DEFAULT_TIMEOUT_SECONDS,
        )
        user_sid = next(
            (row[1].strip() for row in csv.reader(identity.stdout.splitlines()) if len(row) > 1 and row[1].strip().startswith("S-1-")),
            None,
        )
        if user_sid is None:
            raise IronClawInstallerError("Could not determine the current Windows user for credential protection.")
        subprocess.run(
            [
                str(icacls),
                str(path),
                "/reset",
                "/inheritance:r",
                "/grant:r",
                f"*{user_sid}:(F)",
                "/grant",
                "*S-1-5-18:(F)",
            ],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=DEFAULT_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError, csv.Error) as exc:
        raise IronClawInstallerError(f"Could not restrict permissions for credential file: {path}") from exc


class _RejectRedirectHandler(HTTPRedirectHandler):
    def redirect_request(
        self,
        request: Request,
        file: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> None:
        return None


def _open_install_claim_request(request: Request, *, timeout: float) -> Any:
    return build_opener(_RejectRedirectHandler()).open(request, timeout=timeout)


def _write_file(
    path: Path,
    contents: str,
    *,
    overwrite: bool,
    private: bool,
) -> tuple[bool, bool]:
    if path.is_symlink():
        raise IronClawInstallerError(f"Refusing to write through a symbolic link: {path}")

    existed_before = path.exists()
    if existed_before and not overwrite:
        if private:
            _restrict_private_file_permissions(path)
        return False, True

    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT
    flags |= os.O_TRUNC if overwrite else os.O_EXCL
    if private:
        flags |= getattr(os, "O_NOFOLLOW", 0)

    try:
        descriptor = os.open(path, flags, 0o600 if private else 0o666)
    except FileExistsError:
        if not overwrite:
            if private:
                _restrict_private_file_permissions(path)
            return False, True
        raise
    except OSError as exc:
        raise IronClawInstallerError(f"Unable to write file: {path}") from exc

    try:
        if private:
            _restrict_private_file_permissions(path)
        stream = os.fdopen(descriptor, "w", encoding="utf-8")
        descriptor = -1
        with stream:
            stream.write(contents)
    except OSError as exc:
        raise IronClawInstallerError(f"Unable to write file: {path}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)

    return True, existed_before


def _normalize_base_url(value: str) -> str:
    normalized = str(value).strip().rstrip("/")
    if not normalized:
        raise IronClawInstallerError("--base-url must not be empty")
    try:
        parsed = urlsplit(normalized)
        hostname = parsed.hostname
        _ = parsed.port
    except ValueError as exc:
        raise IronClawInstallerError("--base-url must be a valid HTTP or HTTPS URL") from exc
    if parsed.scheme not in {"http", "https"} or not hostname or parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment:
        raise IronClawInstallerError(
            "--base-url must be a valid HTTP or HTTPS URL without user info, query, or fragment.",
        )
    if parsed.scheme == "http" and hostname.lower() not in {"localhost", "127.0.0.1", "::1"}:
        raise IronClawInstallerError("--base-url must use HTTPS except for localhost.")
    return normalized


def _normalize_target(value: str, *, flag_name: str, default: str) -> str:
    normalized = str(value).strip()
    if normalized:
        return normalized
    if default:
        return default
    raise IronClawInstallerError(f"{flag_name} must not be empty")


def _normalize_provider_targets(values: tuple[str, ...] | list[str] | None) -> tuple[str, ...]:
    if not values:
        return DEFAULT_PROVIDER_TARGETS

    normalized: list[str] = []
    seen: set[str] = set()

    for value in values:
        item = str(value).strip()
        if not item:
            continue
        canonical = InstallKeyFormatRegistry.normalize_program(item) or normalize_install_key_program(item)
        if canonical is None or canonical in {"security_guardian"}:
            raise IronClawInstallerError(f"Unsupported provider target: {value!r}")
        if canonical not in seen:
            normalized.append(canonical)
            seen.add(canonical)

    if not normalized:
        raise IronClawInstallerError("--provider-target must include at least one non-empty value")

    return tuple(normalized)


def _classify_write(
    path: Path,
    wrote: bool,
    existed_before: bool,
    created: list[str],
    updated: list[str],
    skipped: list[str],
) -> None:
    path_text = str(path)
    if not wrote:
        skipped.append(path_text)
        return
    if existed_before:
        updated.append(path_text)
    else:
        created.append(path_text)


def _write_json_file(
    path: Path,
    payload: dict[str, Any],
    *,
    overwrite: bool,
    private: bool = False,
) -> tuple[bool, bool]:
    return _write_file(
        path,
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        overwrite=overwrite,
        private=private,
    )


def _write_text_file(
    path: Path,
    content: str,
    *,
    overwrite: bool,
    private: bool = False,
) -> tuple[bool, bool]:
    return _write_file(path, content, overwrite=overwrite, private=private)


def _canonical_program_name(value: str | None) -> str | None:
    if value is None:
        return None
    program = InstallKeyFormatRegistry.normalize_program(value)
    if program is not None:
        return program
    normalized = str(value).strip().lower().replace("-", "_")
    return normalize_install_key_program(normalized)


def _is_placeholder_or_masked_install_key(candidate: str) -> bool:
    value = str(candidate).strip()
    if not value:
        return True
    lowered = value.lower()
    placeholder_tokens = (
        "placeholder",
        "fake",
        "faker",
        "stale",
        "dummy",
        "example",
        "demo",
        "test",
        "mask",
        "masked",
        "none",
        "null",
        "undefined",
        "missing",
        "not_set",
        "your_key",
    )
    if lowered in placeholder_tokens:
        return True
    if any(token in lowered for token in placeholder_tokens):
        return True
    if "..." in value or "***" in value or "*" in value and len(value) <= 24:
        return True
    return False


def _validate_install_key_for_runtime(program: str | None, install_key: str | None) -> str:
    runtime_program = _canonical_program_name(program)
    if runtime_program is None or runtime_program not in _CANONICAL_RUNTIME_TARGETS:
        raise IronClawInstallerError(f"Unsupported runtime target for install-key injection: {program!r}")

    candidate = str(install_key).strip() if install_key is not None else ""
    if not candidate:
        raise IronClawInstallerError(f"A valid paid install key is required for {runtime_program}; blank values are rejected.")

    if _is_placeholder_or_masked_install_key(candidate):
        raise IronClawInstallerError(f"A valid paid install key is required for {runtime_program}; placeholder, masked, or stale values are rejected.")

    lower = candidate.lower()
    if any(lower.startswith(prefix) for prefix in _GENERIC_INSTALL_KEY_PREFIXES):
        raise IronClawInstallerError(f"A valid paid install key is required for {runtime_program}; generic platform auth values are rejected.")
    if candidate.startswith("ic_org_"):
        raise IronClawInstallerError(f"A valid paid install key is required for {runtime_program}; organization keys are not runtime install keys.")

    expected_prefix = InstallKeyFormatRegistry.get_spec(runtime_program).prefix
    if candidate.startswith("ic_") and not candidate.startswith(expected_prefix):
        raise IronClawInstallerError(f"A valid paid install key is required for {runtime_program}; key prefix mismatch for canonical runtime family.")
    if not candidate.startswith(expected_prefix):
        raise IronClawInstallerError(f"A valid paid install key is required for {runtime_program}; expected prefix {expected_prefix!r}.")

    return candidate


def _validate_install_claim_for_runtime(program: str | None, claim_token: str | None) -> str:
    runtime_program = _canonical_program_name(program)
    if runtime_program is None or runtime_program not in _CANONICAL_RUNTIME_TARGETS:
        raise IronClawInstallerError(f"Unsupported runtime target for install-claim redemption: {program!r}")

    candidate = str(claim_token).strip() if claim_token is not None else ""
    if not _INSTALL_CLAIM_PATTERN.fullmatch(candidate):
        raise IronClawInstallerError(f"A valid one-time install claim is required for {runtime_program}.")
    return candidate


def _build_platform_install_claim_command(program: str | None, claim_token: str | None) -> str:
    runtime_program = _canonical_program_name(program)
    if runtime_program is None or runtime_program not in _CANONICAL_RUNTIME_TARGETS:
        raise IronClawInstallerError(f"Unsupported runtime target for install-claim redemption: {program!r}")
    validated_claim = _validate_install_claim_for_runtime(runtime_program, claim_token)
    return InstallKeyFormatRegistry.get_spec(runtime_program).format_command(validated_claim)


def build_install_claim_commands(install_claims: dict[str, str] | None) -> dict[str, str]:
    if not install_claims:
        return {}

    commands: dict[str, str] = {}
    for program, claim_token in install_claims.items():
        runtime_program = _canonical_program_name(program)
        if runtime_program is None or runtime_program not in _CANONICAL_RUNTIME_TARGETS:
            raise IronClawInstallerError(f"Unsupported runtime target for install-claim redemption: {program!r}")
        if runtime_program in commands:
            raise IronClawInstallerError(f"Only one install claim may be provided for {runtime_program}.")
        commands[runtime_program] = _build_platform_install_claim_command(runtime_program, claim_token)
    return dict(sorted(commands.items(), key=lambda pair: _CANONICAL_RUNTIME_TARGETS.index(pair[0])))


def _normalize_install_claim_map(values: list[str] | tuple[str, ...] | None) -> dict[str, str]:
    if not values:
        return {}

    normalized: dict[str, str] = {}
    for item in values:
        text = str(item).strip()
        if not text:
            continue
        if "=" not in text:
            raise IronClawInstallerError(
                "Install claims must be provided as PROGRAM=VALUE entries; blank or malformed values are rejected.",
            )
        program_text, claim_text = text.split("=", 1)
        runtime_program = _canonical_program_name(program_text)
        if runtime_program is None or runtime_program not in _CANONICAL_RUNTIME_TARGETS:
            raise IronClawInstallerError(f"Unsupported runtime target for install-claim redemption: {program_text!r}")
        if runtime_program in normalized:
            raise IronClawInstallerError(f"Only one install claim may be provided for {runtime_program}.")
        validated_claim = _validate_install_claim_for_runtime(runtime_program, claim_text)
        if validated_claim in normalized.values():
            raise IronClawInstallerError("An install claim may only be assigned to one runtime.")
        normalized[runtime_program] = validated_claim
    return dict(sorted(normalized.items(), key=lambda pair: _CANONICAL_RUNTIME_TARGETS.index(pair[0])))


def _redeem_install_claim(base_url: str, program: str, claim_token: str) -> str:
    validated_claim = _validate_install_claim_for_runtime(program, claim_token)
    endpoint = urljoin(f"{base_url.rstrip('/')}/", "integrations/install-claims/redeem")
    request = Request(
        endpoint,
        data=json.dumps({"claim_token": validated_claim}).encode("utf-8"),
        headers={"Accept": "application/json", "Cache-Control": "no-store", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with _open_install_claim_request(request, timeout=DEFAULT_TIMEOUT_SECONDS) as response:
            response_body = response.read(_MAX_CLAIM_RESPONSE_BYTES + 1)
    except HTTPError as exc:
        exc.close()
        raise IronClawInstallerError(
            f"Install claim redemption failed for {program} (HTTP {exc.code}).",
        ) from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise IronClawInstallerError(f"Unable to reach the install-claim service for {program}.") from exc

    if len(response_body) > _MAX_CLAIM_RESPONSE_BYTES:
        raise IronClawInstallerError(f"Install-claim response for {program} exceeded the size limit.")
    try:
        payload = json.loads(response_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IronClawInstallerError(f"Install-claim response for {program} was not valid JSON.") from exc
    if not isinstance(payload, dict):
        raise IronClawInstallerError(f"Install-claim response for {program} was not an object.")

    response_program = InstallKeyFormatRegistry.normalize_program(str(payload.get("program", "")))
    key_id = str(payload.get("key_id", "")).strip()
    if response_program != program or not key_id:
        raise IronClawInstallerError(f"Install-claim response did not match the requested runtime {program}.")
    return _validate_install_key_for_runtime(program, str(payload.get("install_key", "")))


def _read_bootstrap_config(config_file: Path) -> dict[str, Any]:
    if config_file.is_symlink():
        raise IronClawInstallerError(f"Refusing to read a credential file through a symbolic link: {config_file}")
    if not config_file.exists():
        return {}
    if not config_file.is_file():
        raise IronClawInstallerError(f"User configuration is not a regular file: {config_file}")

    try:
        if config_file.stat().st_size > _MAX_USER_CONFIG_BYTES:
            raise IronClawInstallerError("User configuration exceeds the maximum supported size.")
        payload = json.loads(config_file.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IronClawInstallerError(f"Unable to read valid user configuration: {config_file}") from exc
    if not isinstance(payload, dict):
        raise IronClawInstallerError("User configuration must contain a JSON object.")
    return payload


def _build_bootstrap_config_payload(
    existing: dict[str, Any],
    *,
    program: str,
    install_key: str,
    base_url: str,
) -> dict[str, Any]:
    install_keys_value = existing.get("install_keys", {})
    if not isinstance(install_keys_value, dict) or any(not isinstance(key, str) or not isinstance(value, str) for key, value in install_keys_value.items()):
        raise IronClawInstallerError("User configuration contains an invalid install-key map.")
    install_keys = dict(install_keys_value)
    install_keys[program] = install_key

    runtime_commands_value = existing.get("runtime_commands", {})
    if not isinstance(runtime_commands_value, dict) or any(not isinstance(key, str) or not isinstance(value, str) for key, value in runtime_commands_value.items()):
        raise IronClawInstallerError("User configuration contains an invalid runtime-command map.")
    runtime_commands = dict(runtime_commands_value)
    runtime_commands[program] = InstallKeyFormatRegistry.get_spec(program).generic_command

    existing_targets = existing.get("provider_targets", [])
    if not isinstance(existing_targets, list) or any(not isinstance(value, str) for value in existing_targets):
        raise IronClawInstallerError("User configuration contains an invalid provider-target list.")
    provider_targets = _normalize_provider_targets([*existing_targets, program])

    existing_features = existing.get("features", {})
    if not isinstance(existing_features, dict):
        raise IronClawInstallerError("User configuration contains an invalid feature map.")
    features = _build_runtime_features(set(provider_targets), bool(install_keys))
    features.update({key: value for key, value in existing_features.items() if key not in features})

    installed_skills_value = existing.get("installed_skills", {})
    if not isinstance(installed_skills_value, dict) or any(not isinstance(key, str) or not isinstance(value, str) for key, value in installed_skills_value.items()):
        raise IronClawInstallerError("User configuration contains an invalid installed-skill map.")
    installed_skills = dict(installed_skills_value)
    installed_skills[program] = SECURITY_GUARDIAN_SKILL_NAME

    payload = dict(existing)
    payload.update(
        {
            "schema_version": 1,
            "product": "IronClaw-Security",
            "install_mode": "local-bootstrap",
            "skill_mode": True,
            "base_url": base_url,
            "backup_target": existing.get("backup_target", DEFAULT_BACKUP_TARGET),
            "restore_target": existing.get("restore_target", DEFAULT_RESTORE_TARGET),
            "retention_days": existing.get("retention_days", DEFAULT_RETENTION_DAYS),
            "provider_targets": list(provider_targets),
            "install_keys": install_keys,
            "runtime_commands": runtime_commands,
            "installed_skills": installed_skills,
            "features": features,
        },
    )
    return payload


def _runtime_skill_install_command(program: str) -> list[str]:
    spec = InstallKeyFormatRegistry.get_spec(program)
    if program == "hermes":
        return ["hermes", "skills", "install", SECURITY_GUARDIAN_SKILL_URL, "--name", SECURITY_GUARDIAN_SKILL_NAME]
    if spec.agent_cli_id is None:
        raise IronClawInstallerError(f"No supported skill installer is configured for {program}.")
    return [
        "gh",
        "skill",
        "install",
        IRONCLAW_GITHUB_REPOSITORY,
        SECURITY_GUARDIAN_SKILL_REPOSITORY_PATH,
        "--agent",
        spec.agent_cli_id,
        "--scope",
        "user",
    ]


def _stage_openclaw_plugin(config_dir: Path) -> Path:
    plugin_dir = config_dir / "openclaw-plugin"
    if plugin_dir.is_symlink():
        raise IronClawInstallerError(
            f"Refusing to install the OpenClaw plugin through a symbolic-link directory: {plugin_dir}",
        )
    try:
        _ensure_directory(plugin_dir)
        packaged_plugin = resources.files("ironclaw_sdk").joinpath("openclaw_plugin")
        for filename in _OPENCLAW_PLUGIN_FILES:
            source = packaged_plugin.joinpath(filename)
            if not source.is_file():
                raise FileNotFoundError(filename)
            _write_text_file(
                plugin_dir / filename,
                source.read_text(encoding="utf-8"),
                overwrite=True,
            )
    except (ModuleNotFoundError, OSError, UnicodeDecodeError) as exc:
        raise IronClawInstallerError(
            "The OpenClaw enforcement plugin is missing from the installed IronClaw package.",
        ) from exc
    return plugin_dir


def _install_openclaw_plugin(plugin_dir: Path, config_file: Path) -> None:
    config_path = str(config_file.resolve())
    config_path_setting = f"plugins.entries.{OPENCLAW_PLUGIN_ID}.config.configFile"
    python_path_setting = f"plugins.entries.{OPENCLAW_PLUGIN_ID}.config.pythonPath"
    commands = (
        ["openclaw", "plugins", "install", "--link", str(plugin_dir), "--force"],
        ["openclaw", "config", "set", config_path_setting, config_path],
        ["openclaw", "config", "set", python_path_setting, sys.executable],
        ["openclaw", "plugins", "enable", OPENCLAW_PLUGIN_ID],
    )
    try:
        for command in commands:
            subprocess.run(command, check=True, timeout=_SUBPROCESS_TIMEOUT)
    except FileNotFoundError as exc:
        raise IronClawInstallerError("The OpenClaw CLI was not found.") from exc
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise IronClawInstallerError("The OpenClaw enforcement plugin could not be installed or enabled.") from exc


def _configure_openclaw_plugin(target_config_dir: Path, config_file: Path) -> None:
    plugin_dir = target_config_dir / "openclaw-plugin"
    try:
        plugin_dir = _stage_openclaw_plugin(target_config_dir)
        _install_openclaw_plugin(plugin_dir, config_file)
    except IronClawInstallerError as exc:
        config_path_setting = f"plugins.entries.{OPENCLAW_PLUGIN_ID}.config.configFile"
        python_path_setting = f"plugins.entries.{OPENCLAW_PLUGIN_ID}.config.pythonPath"
        raise IronClawInstallerError(
            f"OpenClaw enforcement setup failed: {exc} The paid key was securely saved to {config_file}. "
            f'Complete setup with `openclaw plugins install --link "{plugin_dir}" --force`, '
            f'`openclaw config set {config_path_setting} "{config_file.resolve()}"`, '
            f'`openclaw config set {python_path_setting} "{sys.executable}"`, and '
            f"`openclaw plugins enable {OPENCLAW_PLUGIN_ID}`.",
        ) from exc


def _install_hermes_plugin() -> Path:
    plugin_dir = Path.home() / ".hermes" / "plugins" / HERMES_PLUGIN_ID
    if plugin_dir.is_symlink():
        raise IronClawInstallerError(f"Refusing to install the Hermes plugin through a symbolic-link directory: {plugin_dir}")
    try:
        _ensure_directory(plugin_dir)
        packaged_plugin = resources.files("ironclaw_sdk").joinpath("hermes_plugin")
        for filename in _HERMES_PLUGIN_FILES:
            source = packaged_plugin.joinpath(filename)
            if not source.is_file():
                raise FileNotFoundError(filename)
            _write_text_file(
                plugin_dir / filename,
                source.read_text(encoding="utf-8"),
                overwrite=True,
            )
    except (ModuleNotFoundError, OSError, UnicodeDecodeError) as exc:
        raise IronClawInstallerError("The Hermes enforcement plugin is missing from the installed IronClaw package.") from exc
    try:
        subprocess.run(["hermes", "plugins", "enable", HERMES_PLUGIN_ID], check=True, timeout=_SUBPROCESS_TIMEOUT)
    except FileNotFoundError as exc:
        raise IronClawInstallerError(f"The Hermes CLI was not found. The plugin was copied to {plugin_dir}; run `hermes plugins enable {HERMES_PLUGIN_ID}` after installing Hermes.") from exc
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise IronClawInstallerError(f"The Hermes enforcement plugin could not be enabled. Run `hermes plugins enable {HERMES_PLUGIN_ID}`.") from exc
    return plugin_dir


def _prepare_config_dir(config_dir: Path | None) -> Path:
    target_config_dir = (config_dir or _default_config_dir()).expanduser()
    if target_config_dir.is_symlink():
        raise IronClawInstallerError(f"Refusing to write credentials into a symbolic-link directory: {target_config_dir}")
    try:
        _ensure_directory(target_config_dir)
    except OSError as exc:
        raise IronClawInstallerError(f"Unable to create user configuration directory: {target_config_dir}") from exc
    return target_config_dir


def _store_install_key(
    *,
    target_config_dir: Path,
    program: str,
    install_key: str,
    base_url: str,
) -> Path:
    config_file = target_config_dir / DEFAULT_CONFIG_FILENAME
    existing_config = _read_bootstrap_config(config_file)
    payload = _build_bootstrap_config_payload(
        existing_config,
        program=program,
        install_key=install_key,
        base_url=base_url,
    )
    _write_json_file(config_file, payload, overwrite=True, private=True)
    return config_file


def _redeem_claim_into_config(
    *,
    program: str,
    claim_token: str,
    config_dir: Path | None,
    base_url: str,
) -> tuple[str, Path, Path]:
    runtime_program = _canonical_program_name(program)
    if runtime_program is None or runtime_program not in _CANONICAL_RUNTIME_TARGETS:
        raise IronClawInstallerError(f"Unsupported runtime target for install-claim redemption: {program!r}")

    validated_claim = _validate_install_claim_for_runtime(runtime_program, claim_token)
    normalized_base_url = _normalize_base_url(base_url)
    target_config_dir = _prepare_config_dir(config_dir)
    install_key = _redeem_install_claim(normalized_base_url, runtime_program, validated_claim)
    config_file = _store_install_key(
        target_config_dir=target_config_dir,
        program=runtime_program,
        install_key=install_key,
        base_url=normalized_base_url,
    )
    return runtime_program, target_config_dir, config_file


def run_bootstrap(
    *,
    program: str,
    claim_token: str,
    config_dir: Path | None = None,
    base_url: str = DEFAULT_BOOTSTRAP_BASE_URL,
) -> BootstrapResult:
    runtime_program, target_config_dir, config_file = _redeem_claim_into_config(
        program=program,
        claim_token=claim_token,
        config_dir=config_dir,
        base_url=base_url,
    )

    command = _runtime_skill_install_command(runtime_program)
    try:
        subprocess.run(command, check=True, timeout=_SUBPROCESS_TIMEOUT)
    except FileNotFoundError as exc:
        raise IronClawInstallerError(
            f"Required installer '{command[0]}' was not found. The paid key was securely saved to {config_file}.",
        ) from exc
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise IronClawInstallerError(
            f"Shared skill installation failed for {runtime_program}. The paid key was securely saved to {config_file}.",
        ) from exc

    if runtime_program == "openclaw":
        _configure_openclaw_plugin(target_config_dir, config_file)

    return BootstrapResult(
        program=runtime_program,
        config_file=config_file,
        skill_name=SECURITY_GUARDIAN_SKILL_NAME,
    )


def run_redeem(
    *,
    program: str,
    claim_token: str,
    config_dir: Path | None = None,
    base_url: str = DEFAULT_BOOTSTRAP_BASE_URL,
) -> BootstrapResult:
    """Redeem a claim and store the key. The generic skill-install command shown next to it installs the skill."""
    runtime_program, target_config_dir, config_file = _redeem_claim_into_config(
        program=program,
        claim_token=claim_token,
        config_dir=config_dir,
        base_url=base_url,
    )

    if runtime_program == "openclaw":
        _configure_openclaw_plugin(target_config_dir, config_file)

    return BootstrapResult(
        program=runtime_program,
        config_file=config_file,
        skill_name=SECURITY_GUARDIAN_SKILL_NAME,
    )


def save_install_key(
    *,
    program: str,
    install_key: str,
    config_dir: Path | None = None,
    base_url: str = DEFAULT_BOOTSTRAP_BASE_URL,
) -> BootstrapResult:
    """Store an install key that was already redeemed from a claim. Never redeems a claim."""
    runtime_program = _canonical_program_name(program)
    if runtime_program is None or runtime_program not in _CANONICAL_RUNTIME_TARGETS:
        raise IronClawInstallerError(f"Unsupported runtime target for install-key storage: {program!r}")
    if not InstallKeyFormatRegistry.get_spec(runtime_program).matches_key(install_key):
        raise IronClawInstallerError(f"Install key does not match the {runtime_program} key format.")

    normalized_base_url = _normalize_base_url(base_url)
    target_config_dir = _prepare_config_dir(config_dir)
    config_file = _store_install_key(
        target_config_dir=target_config_dir,
        program=runtime_program,
        install_key=install_key,
        base_url=normalized_base_url,
    )
    if runtime_program == "openclaw":
        _configure_openclaw_plugin(target_config_dir, config_file)

    return BootstrapResult(
        program=runtime_program,
        config_file=config_file,
        skill_name=SECURITY_GUARDIAN_SKILL_NAME,
    )


def _build_runtime_features(provider_set: set[str], has_install_keys: bool) -> dict[str, bool]:
    return {
        "health": True,
        "ui": True,
        "backup": True,
        "restore": True,
        "guarded_execution": True,
        "skill_integration": True,
        "shared_skill_package": bool(provider_set),
        "claude_integration": "claude_code" in provider_set,
        "openclaw_integration": "openclaw" in provider_set,
        "cursor_integration": "cursor" in provider_set,
        "goose_integration": "goose" in provider_set,
        "gemini_cli_integration": "gemini_cli" in provider_set,
        "copilot_integration": "copilot" in provider_set,
        "hermes_integration": "hermes" in provider_set,
        "embedded_install_keys": has_install_keys,
    }


def _build_runtime_config(config: InstallConfig, install_keys: dict[str, str] | None = None) -> dict[str, Any]:
    provider_set = set(config.provider_targets)
    redeemed_install_keys = install_keys or {}
    features = _build_runtime_features(provider_set, bool(redeemed_install_keys))
    runtime_commands = {program: InstallKeyFormatRegistry.get_spec(program).generic_command for program in redeemed_install_keys}
    return {
        "schema_version": 1,
        "product": "IronClaw-Security",
        "install_mode": "local-bootstrap",
        "skill_mode": True,
        "base_url": config.base_url,
        "backup_target": config.backup_target,
        "restore_target": config.restore_target,
        "retention_days": config.retention_days,
        "provider_targets": list(config.provider_targets),
        "install_keys": dict(redeemed_install_keys),
        "runtime_commands": runtime_commands,
        "paths": {
            "project_root": str(config.project_root),
            "env_file": str(config.env_file),
        },
        "features": features,
    }


def _build_env_contents(config: InstallConfig) -> str:
    shared_skill_package = bool(config.provider_targets)
    values = {
        "ENVIRONMENT": "production",
        "IRONCLAW_BASE_URL": config.base_url,
        "IRONCLAW_PERSISTENCE_MODE": "supabase",
        "IRONCLAW_API_KEY": _strong_secret(24),
        "AUTH_REQUIRED": "true",
        "IRONCLAW_BACKUP_TARGET_NAME": config.backup_target,
        "IRONCLAW_RESTORE_TARGET_NAME": config.restore_target,
        "IRONCLAW_BACKUP_RETENTION_DAYS": str(config.retention_days),
        "IRONCLAW_BACKUP_ENCRYPTION": "true",
        "IRONCLAW_BACKUP_CHECKSUM": "true",
        "IRONCLAW_PROVIDER_TARGETS": ",".join(config.provider_targets),
        "IRONCLAW_SHARED_SKILL_PACKAGE": "true" if shared_skill_package else "false",
        "SECRET_KEY": _strong_secret(),
        "JWT_SECRET": _strong_secret(),
        "API_SECRET": _strong_secret(),
        "SUPABASE_URL": "",
        "SUPABASE_SERVICE_ROLE_KEY": "",
        "SUPABASE_KEY": "",
        "SUPABASE_ANON_KEY": "",
    }

    lines = [
        "# IronClaw-Security local installer environment",
        "# Review and replace placeholder values before production use.",
        "# IRONCLAW_API_KEY is auto-generated — save it before sharing with clients.",
        "",
    ]
    lines.extend(f"{key}={value}" for key, value in values.items())
    lines.append("")
    return "\n".join(lines)


def _build_vscode_settings() -> dict[str, Any]:
    return {
        "python.defaultInterpreterPath": "${workspaceFolder}\\.venv\\Scripts\\python.exe",
        "python.analysis.extraPaths": ["${workspaceFolder}"],
        "python.analysis.autoSearchPaths": True,
        "python.analysis.diagnosticMode": "workspace",
        "python.analysis.typeCheckingMode": "basic",
        "python.testing.pytestEnabled": True,
        "python.testing.unittestEnabled": False,
        "python.testing.pytestArgs": ["tests"],
        "python.envFile": "${workspaceFolder}\\.env",
        "python.terminal.activateEnvironment": True,
        "[python]": {
            "editor.defaultFormatter": "ms-python.black-formatter",
            "editor.formatOnSave": True,
            "editor.codeActionsOnSave": {
                "source.organizeImports": "explicit",
                "source.fixAll": "explicit",
            },
        },
        "editor.formatOnSave": True,
        "files.trimTrailingWhitespace": True,
        "files.insertFinalNewline": True,
        "files.trimFinalNewlines": True,
        "files.eol": "\n",
        "ruff.nativeServer": "on",
        "ruff.organizeImports": True,
        "ruff.lint.run": "onType",
    }


def _build_skill_config(config: InstallConfig) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "enabled": True,
        "product": "IronClaw-Security",
        "provider_targets": list(config.provider_targets),
        "base_url": config.base_url,
        "default_policy_mode": "review",
        "default_timeout_seconds": DEFAULT_TIMEOUT_SECONDS,
    }


def _venv_python(project_root: Path) -> Path:
    if os.name == "nt":
        return project_root / ".venv" / "Scripts" / "python.exe"
    return project_root / ".venv" / "bin" / "python"


def _validate_project_root(project_root: Path) -> None:
    if not project_root.exists():
        raise IronClawInstallerError(f"Project root does not exist: {project_root}")
    if not project_root.is_dir():
        raise IronClawInstallerError(f"Project root is not a directory: {project_root}")
    if not (project_root / "pyproject.toml").exists():
        raise IronClawInstallerError(f"pyproject.toml was not found under project root: {project_root}")


def _create_virtualenv(project_root: Path) -> None:
    venv_python = _venv_python(project_root)
    if venv_python.exists():
        return

    subprocess.run(
        [sys.executable, "-m", "venv", str(project_root / ".venv")],
        cwd=str(project_root),
        check=True,
        capture_output=True,
        text=True,
        timeout=_SUBPROCESS_TIMEOUT,
    )


def _install_project_editable(project_root: Path) -> None:
    venv_python = _venv_python(project_root)
    if not venv_python.exists():
        raise IronClawInstallerError("Virtual environment python executable was not created.")

    subprocess.run(
        [str(venv_python), "-m", "pip", "install", "--upgrade", "pip"],
        cwd=str(project_root),
        check=True,
        capture_output=True,
        text=True,
        timeout=_SUBPROCESS_TIMEOUT,
    )
    subprocess.run(
        [str(venv_python), "-m", "pip", "install", "-e", ".[dev]"],
        cwd=str(project_root),
        check=True,
        capture_output=True,
        text=True,
        timeout=_SUBPROCESS_TIMEOUT,
    )


def run_install(config: InstallConfig) -> InstallResult:
    created_paths: list[str] = []
    updated_paths: list[str] = []
    skipped_paths: list[str] = []

    _validate_project_root(config.project_root)
    _ensure_directory(config.config_dir)

    install_keys = {program: _redeem_install_claim(config.base_url, program, claim_token) for program, claim_token in config.install_claims.items()}
    config_payload = _build_runtime_config(config, install_keys)
    wrote_config, config_existed_before = _write_json_file(
        config.config_file,
        config_payload,
        overwrite=config.overwrite,
        private=True,
    )
    _classify_write(
        config.config_file,
        wrote_config,
        config_existed_before,
        created_paths,
        updated_paths,
        skipped_paths,
    )

    env_path: Path | None = None
    if config.write_env_file:
        env_contents = _build_env_contents(config)
        wrote_env, env_existed_before = _write_text_file(
            config.env_file,
            env_contents,
            overwrite=config.overwrite,
            private=True,
        )
        env_path = config.env_file
        _classify_write(
            config.env_file,
            wrote_env,
            env_existed_before,
            created_paths,
            updated_paths,
            skipped_paths,
        )

    vscode_settings_path: Path | None = None
    if config.install_vscode_settings:
        vscode_dir = config.project_root / ".vscode"
        vscode_settings_path = vscode_dir / "settings.json"
        wrote_vscode, vscode_existed_before = _write_json_file(
            vscode_settings_path,
            _build_vscode_settings(),
            overwrite=config.overwrite,
        )
        _classify_write(
            vscode_settings_path,
            wrote_vscode,
            vscode_existed_before,
            created_paths,
            updated_paths,
            skipped_paths,
        )

    skill_config_path: Path | None = None
    if config.install_skill_config:
        skill_config_path = config.config_dir / DEFAULT_SKILL_CONFIG_FILENAME
        wrote_skill, skill_existed_before = _write_json_file(
            skill_config_path,
            _build_skill_config(config),
            overwrite=config.overwrite,
        )
        _classify_write(
            skill_config_path,
            wrote_skill,
            skill_existed_before,
            created_paths,
            updated_paths,
            skipped_paths,
        )

    _create_virtualenv(config.project_root)
    _install_project_editable(config.project_root)

    return InstallResult(
        ok=True,
        config_file=config.config_file,
        env_file=env_path,
        vscode_settings_file=vscode_settings_path,
        skill_config_file=skill_config_path,
        created_paths=tuple(created_paths),
        updated_paths=tuple(updated_paths),
        skipped_paths=tuple(skipped_paths),
    )


def build_bootstrap_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Install the shared IronClaw security skill and securely provision one paid runtime key.",
    )
    parser.add_argument(
        "--program",
        required=True,
        choices=_CANONICAL_RUNTIME_TARGETS,
        help="Canonical runtime target for this one-time install claim.",
    )
    parser.add_argument(
        "--claim-token",
        required=True,
        help="Single-use install claim generated by the IronClaw dashboard. Claims do not expire.",
    )
    parser.add_argument(
        "--config-dir",
        type=Path,
        default=_default_config_dir(),
        help="Directory for private IronClaw user configuration.",
    )
    parser.add_argument(
        "--enable-runtime-hooks",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Write the fail-closed tool-call enforcement hook into the runtime's user-global config (claude_code, gemini_cli, cursor, copilot, goose), or install and enable the IronClaw plugin for hermes. On by default; pass --no-enable-runtime-hooks to skip.",
    )
    parser.add_argument(
        "--base-url",
        default=os.getenv("IRONCLAW_BASE_URL", DEFAULT_BOOTSTRAP_BASE_URL),
        help=f"Base URL for the claim service, default: {DEFAULT_BOOTSTRAP_BASE_URL}",
    )
    return parser


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Install and bootstrap IronClaw-Security for local skill-style use.",
    )
    parser.add_argument(
        "--project-root",
        type=Path,
        default=_project_root(),
        help="Project root directory containing pyproject.toml.",
    )
    parser.add_argument(
        "--config-dir",
        type=Path,
        default=_default_config_dir(),
        help="Directory for persistent IronClaw user configuration.",
    )
    parser.add_argument(
        "--base-url",
        default=os.getenv("IRONCLAW_BASE_URL", DEFAULT_BASE_URL),
        help=f"Base URL for IronClaw runtime, default: {DEFAULT_BASE_URL}",
    )
    parser.add_argument(
        "--backup-target",
        default=os.getenv("IRONCLAW_BACKUP_TARGET_NAME", DEFAULT_BACKUP_TARGET),
        help=f"Default backup target, default: {DEFAULT_BACKUP_TARGET}",
    )
    parser.add_argument(
        "--restore-target",
        default=os.getenv("IRONCLAW_RESTORE_TARGET_NAME", DEFAULT_RESTORE_TARGET),
        help=f"Default restore target, default: {DEFAULT_RESTORE_TARGET}",
    )
    parser.add_argument(
        "--retention-days",
        type=int,
        default=DEFAULT_RETENTION_DAYS,
        help=f"Backup retention days, default: {DEFAULT_RETENTION_DAYS}",
    )
    parser.add_argument(
        "--provider-target",
        action="append",
        default=[],
        help="Provider target to enable, repeatable, e.g. --provider-target claude_code --provider-target openclaw --provider-target hermes",
    )
    parser.add_argument(
        "--install-claim",
        action="append",
        default=[],
        help="One-time install claim to redeem for a runtime target, e.g. --install-claim openclaw=ic_claim_...",
    )
    parser.add_argument(
        "--no-vscode",
        action="store_true",
        help="Do not write .vscode/settings.json.",
    )
    parser.add_argument(
        "--no-skill-config",
        action="store_true",
        help="Do not write skill.json into the user IronClaw config directory.",
    )
    parser.add_argument(
        "--no-env",
        action="store_true",
        help="Do not write the project .env file.",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite existing generated files.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the install result as JSON.",
    )
    return parser


def build_install_config(args: argparse.Namespace) -> InstallConfig:
    project_root = args.project_root.expanduser().resolve()
    config_dir = args.config_dir.expanduser().resolve()

    if args.retention_days <= 0:
        raise IronClawInstallerError("--retention-days must be greater than 0")

    install_claims = _normalize_install_claim_map(getattr(args, "install_claim", None) or [])

    return InstallConfig(
        project_root=project_root,
        config_dir=config_dir,
        config_file=config_dir / DEFAULT_CONFIG_FILENAME,
        env_file=project_root / DEFAULT_ENV_FILENAME,
        base_url=_normalize_base_url(args.base_url),
        backup_target=_normalize_target(
            args.backup_target,
            flag_name="--backup-target",
            default=DEFAULT_BACKUP_TARGET,
        ),
        restore_target=_normalize_target(
            args.restore_target,
            flag_name="--restore-target",
            default=DEFAULT_RESTORE_TARGET,
        ),
        retention_days=args.retention_days,
        install_vscode_settings=not args.no_vscode,
        install_skill_config=not args.no_skill_config,
        write_env_file=not args.no_env,
        overwrite=bool(args.overwrite),
        provider_targets=_normalize_provider_targets(args.provider_target),
        install_claims=install_claims,
    )


def _runtime_hook_plan(program: str, enable: bool) -> list[tuple[Path, dict[str, Any]]] | None:
    from ironclaw_sdk import goose_hooks, runtime_hooks

    if not enable or program not in runtime_hooks.SUPPORTED_PROGRAMS:
        return None
    if program == "goose":
        return goose_hooks.plan_goose_hook()
    if program == "hermes":
        # Hermes loads a Python plugin directory, so there is no JSON config to validate before redeeming.
        return []
    plan = runtime_hooks.plan_runtime_hook(program)
    return None if plan is None else [plan]


def _report_runtime_hook(program: str, enable: bool, plan: list[tuple[Path, dict[str, Any]]] | None) -> int:
    from ironclaw_sdk import runtime_hooks

    if program == "openclaw":
        print("[ironclaw-installer] enforcement: the OpenClaw plugin registered during setup enforces tool calls; no runtime hook is written here.")
        return 0
    if program not in runtime_hooks.SUPPORTED_PROGRAMS:
        print(f"[ironclaw-installer] enforcement: no tool-call hook applies to {program}; its skill is guidance-only.")
        return 0
    if not enable or plan is None:
        if program in runtime_hooks.ADAPTER_PROGRAMS:
            print(f"[ironclaw-installer] enforcement hook not written. Re-run without --no-enable-runtime-hooks to install the {program} enforcement hook.")
            return 0
        target = runtime_hooks.runtime_hook_config_path(program)
        print(f"[ironclaw-installer] enforcement hook not written. Re-run without --no-enable-runtime-hooks, or add this to {target}:")
        print(json.dumps(runtime_hooks.merge_hook_config(program, {}), indent=2))
        return 0
    try:
        if program == "hermes":
            plugin_dir = _install_hermes_plugin()
            print(f"[ironclaw-installer] enforcement hook written: {plugin_dir}")
            return 0
        written_paths = [runtime_hooks.write_runtime_hook(target, merged) for target, merged in plan]
    except (OSError, IronClawInstallerError) as exc:
        print(f"[ironclaw-installer] install key saved, but the enforcement hook could not be written: {exc}", file=sys.stderr)
        return 1
    for written in written_paths:
        print(f"[ironclaw-installer] enforcement hook written: {written}")
    if program == "cursor":
        print("[ironclaw-installer] cursor: local MCP tool output is replaced when withheld; built-in and HTTP MCP output is audited but not replaced, and unparseable events are withheld.")
    return 0


def _bootstrap_main(argv: list[str]) -> int:
    args = build_bootstrap_parser().parse_args(argv)
    try:
        hook_plan = _runtime_hook_plan(args.program, args.enable_runtime_hooks)
    except (OSError, ValueError) as exc:
        print(f"[ironclaw-installer] failed: existing runtime hook configuration is invalid; no claim was redeemed: {exc}", file=sys.stderr)
        return 1
    try:
        result = run_bootstrap(
            program=args.program,
            claim_token=args.claim_token,
            config_dir=args.config_dir,
            base_url=args.base_url,
        )
    except IronClawInstallerError as exc:
        print(f"[ironclaw-installer] failed: {exc}", file=sys.stderr)
        return 1

    print("[ironclaw-installer] shared skill installed")
    print(f"[ironclaw-installer] program: {result.program}")
    print(f"[ironclaw-installer] config: {result.config_file}")
    return _report_runtime_hook(args.program, args.enable_runtime_hooks, hook_plan)


def _redeem_main(argv: list[str]) -> int:
    args = build_bootstrap_parser().parse_args(argv)
    try:
        hook_plan = _runtime_hook_plan(args.program, args.enable_runtime_hooks)
    except (OSError, ValueError) as exc:
        print(f"[ironclaw-installer] failed: existing runtime hook configuration is invalid; no claim was redeemed: {exc}", file=sys.stderr)
        return 1
    try:
        result = run_redeem(
            program=args.program,
            claim_token=args.claim_token,
            config_dir=args.config_dir,
            base_url=args.base_url,
        )
    except IronClawInstallerError as exc:
        print(f"[ironclaw-installer] failed: {exc}", file=sys.stderr)
        return 1

    print("[ironclaw-installer] install key redeemed")
    print(f"[ironclaw-installer] program: {result.program}")
    print(f"[ironclaw-installer] config: {result.config_file}")
    return _report_runtime_hook(args.program, args.enable_runtime_hooks, hook_plan)


def main(argv: list[str] | None = None) -> int:
    command_line = list(sys.argv[1:] if argv is None else argv)
    if command_line and command_line[0] == "bootstrap":
        return _bootstrap_main(command_line[1:])
    if command_line and command_line[0] == "redeem":
        return _redeem_main(command_line[1:])

    parser = build_parser()
    args = parser.parse_args(command_line)

    try:
        config = build_install_config(args)
        result = run_install(config)
    except (IronClawInstallerError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        print(f"[ironclaw-installer] failed: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print("[ironclaw-installer] install completed")
        print(f"[ironclaw-installer] config: {result.config_file}")
        if result.skill_config_file is not None:
            print(f"[ironclaw-installer] skill-config: {result.skill_config_file}")
        if result.env_file is not None:
            print(f"[ironclaw-installer] env: {result.env_file}")
        if result.vscode_settings_file is not None:
            print(f"[ironclaw-installer] vscode: {result.vscode_settings_file}")
        if result.created_paths:
            print(f"[ironclaw-installer] created: {len(result.created_paths)}")
        if result.updated_paths:
            print(f"[ironclaw-installer] updated: {len(result.updated_paths)}")
        if result.skipped_paths:
            print(f"[ironclaw-installer] skipped: {len(result.skipped_paths)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
