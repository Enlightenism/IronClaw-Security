from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import time
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Final

DEFAULT_TIMEOUT_SECONDS: Final[float] = 10.0
DEFAULT_MAX_OUTPUT_CHARS: Final[int] = 12000
DEFAULT_AUDIT_FILE: Final[Path] = Path(__file__).resolve().with_name(".ironclawshellguard-audit.json")

SAFE_ENV_ALLOWLIST: Final[set[str]] = {
    "PATH",
    "PYTHONPATH",
    "SYSTEMROOT",
    "WINDIR",
    "TEMP",
    "TMP",
    "HOME",
    "USERPROFILE",
    "IRONCLAW_ENV",
    "IRONCLAW_MODE",
}

DEFAULT_ALLOWED_COMMANDS: Final[dict[str, tuple[str, ...]]] = {
    "python": ("python", "python3", "py"),
    "pip": ("pip", "pip3"),
    "pytest": ("pytest",),
    "uvicorn": ("uvicorn",),
    "ruff": ("ruff",),
    "mypy": ("mypy",),
    "bandit": ("bandit",),
    "npm": ("npm",),
    "node": ("node",),
    "git": ("git",),
}

DANGEROUS_TOKENS: Final[tuple[str, ...]] = (
    ";",
    "&&",
    "||",
    "|",
    ">",
    ">>",
    "<",
    "$(",
    "`",
    "\n",
    "\r",
)

WINDOWS_ABSOLUTE_PATH_RE: Final[re.Pattern[str]] = re.compile(r"^[a-zA-Z]:\\")
SAFE_TOKEN_RE: Final[re.Pattern[str]] = re.compile(r"^[a-zA-Z0-9._:/=,@%+\-\\]+$")


class ShellGuardError(RuntimeError):
    """Base error for shell guard failures."""


class ShellGuardPolicyError(ShellGuardError):
    """Raised when a command violates IronClaw shell policy."""


class ShellGuardExecutionError(ShellGuardError):
    """Raised when a guarded command execution fails."""


@dataclass(frozen=True, slots=True)
class GuardedCommandResult:
    ok: bool
    returncode: int | None
    command: tuple[str, ...]
    duration_ms: int
    stdout: str
    stderr: str
    policy: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class IronClawShellGuard:
    """IronClaw shell command policy guard.

    Security goals:
    - never uses shell=True
    - enforces command allowlisting
    - blocks shell metacharacter usage
    - constrains environment exposure
    - captures output safely with timeout support
    """

    def __init__(
        self,
        *,
        allowed_commands: dict[str, tuple[str, ...]] | None = None,
        default_timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        max_output_chars: int = DEFAULT_MAX_OUTPUT_CHARS,
        audit_file: Path | None = None,
    ) -> None:
        self._allowed_commands = allowed_commands or DEFAULT_ALLOWED_COMMANDS
        self._default_timeout_seconds = default_timeout_seconds if default_timeout_seconds > 0 else DEFAULT_TIMEOUT_SECONDS
        self._max_output_chars = max_output_chars if max_output_chars > 0 else DEFAULT_MAX_OUTPUT_CHARS
        self._audit_file = (audit_file or DEFAULT_AUDIT_FILE).resolve()

    @property
    def audit_file(self) -> Path:
        return self._audit_file

    def run(
        self,
        command: str | Sequence[str],
        *,
        timeout_seconds: float | None = None,
        cwd: str | Path | None = None,
        env: dict[str, str] | None = None,
        check: bool = True,
    ) -> GuardedCommandResult:
        argv = self._normalize_command(command)
        self._validate_command(argv)

        effective_timeout = timeout_seconds if timeout_seconds and timeout_seconds > 0 else self._default_timeout_seconds
        effective_cwd = self._normalize_cwd(cwd)
        effective_env = self._build_env(env)

        started = time.perf_counter()
        try:
            completed = subprocess.run(
                argv,
                check=False,
                cwd=str(effective_cwd) if effective_cwd else None,
                env=effective_env,
                shell=False,
                capture_output=True,
                text=True,
                timeout=effective_timeout,
                encoding="utf-8",
                errors="replace",
            )
            duration_ms = round((time.perf_counter() - started) * 1000)
        except subprocess.TimeoutExpired as exc:
            duration_ms = round((time.perf_counter() - started) * 1000)
            stdout = self._truncate_output(exc.stdout or "")
            stderr = self._truncate_output(exc.stderr or "")
            result = GuardedCommandResult(
                ok=False,
                returncode=None,
                command=tuple(argv),
                duration_ms=duration_ms,
                stdout=stdout,
                stderr=stderr,
                policy="timeout",
            )
            self._append_audit(result)
            raise ShellGuardExecutionError(
                f"Command timed out after {effective_timeout} seconds: {self._render_command(argv)}",
            ) from exc
        except OSError as exc:
            raise ShellGuardExecutionError(
                f"Command execution failed for {self._render_command(argv)}: {exc}",
            ) from exc

        result = GuardedCommandResult(
            ok=(completed.returncode == 0),
            returncode=completed.returncode,
            command=tuple(argv),
            duration_ms=duration_ms,
            stdout=self._truncate_output(completed.stdout),
            stderr=self._truncate_output(completed.stderr),
            policy="allowed",
        )
        self._append_audit(result)

        if check and completed.returncode != 0:
            raise ShellGuardExecutionError(
                f"Command failed with exit code {completed.returncode}: {self._render_command(argv)}",
            )

        return result

    def dry_validate(self, command: str | Sequence[str]) -> tuple[str, ...]:
        argv = self._normalize_command(command)
        self._validate_command(argv)
        return tuple(argv)

    def _normalize_command(self, command: str | Sequence[str]) -> list[str]:
        if isinstance(command, str):
            stripped = command.strip()
            if not stripped:
                raise ShellGuardPolicyError("Empty command is not allowed.")
            try:
                argv = shlex.split(stripped, posix=os.name != "nt")
            except ValueError as exc:
                raise ShellGuardPolicyError(f"Invalid command syntax: {exc}") from exc
        else:
            argv = [str(part).strip() for part in command if str(part).strip()]

        if not argv:
            raise ShellGuardPolicyError("Command produced no executable tokens.")
        return argv

    def _validate_command(self, argv: Sequence[str]) -> None:
        executable = argv[0]
        normalized_executable = Path(executable).name.lower()

        if not self._is_allowed_executable(normalized_executable):
            raise ShellGuardPolicyError(f"Executable is not allowlisted: {executable}")

        for token in argv:
            self._validate_token(token)

    def _validate_token(self, token: str) -> None:
        if not token:
            raise ShellGuardPolicyError("Empty command token is not allowed.")

        if any(marker in token for marker in DANGEROUS_TOKENS):
            raise ShellGuardPolicyError(f"Dangerous shell token rejected: {token!r}")

        if token.startswith(("~", "*", "?", "!")):
            raise ShellGuardPolicyError(f"Unsafe shell-expansion token rejected: {token!r}")

        if token.startswith("-") and len(token) > 128:
            raise ShellGuardPolicyError(f"Suspicious oversized flag rejected: {token!r}")

        if token.startswith("/"):
            return

        if WINDOWS_ABSOLUTE_PATH_RE.match(token):
            return

        if SAFE_TOKEN_RE.fullmatch(token):
            return

        raise ShellGuardPolicyError(f"Unsafe command token rejected: {token!r}")

    def _is_allowed_executable(self, executable_name: str) -> bool:
        for aliases in self._allowed_commands.values():
            if executable_name in {item.lower() for item in aliases}:
                return True
        return False

    def _normalize_cwd(self, cwd: str | Path | None) -> Path | None:
        if cwd is None:
            return None

        resolved = Path(cwd).expanduser().resolve()
        workspace_root = Path.cwd().resolve()

        if not self._is_relative_to(resolved, workspace_root):
            raise ShellGuardPolicyError(f"Working directory escapes workspace root: {resolved}")

        if not resolved.exists() or not resolved.is_dir():
            raise ShellGuardPolicyError(f"Working directory does not exist: {resolved}")

        return resolved

    def _build_env(self, env: dict[str, str] | None) -> dict[str, str]:
        safe_env = {key: value for key, value in os.environ.items() if key in SAFE_ENV_ALLOWLIST}

        if not env:
            return safe_env

        for key, value in env.items():
            if key not in SAFE_ENV_ALLOWLIST:
                raise ShellGuardPolicyError(f"Environment variable is not allowlisted: {key}")
            safe_env[key] = value

        return safe_env

    def _append_audit(self, result: GuardedCommandResult) -> None:
        self._audit_file.parent.mkdir(parents=True, exist_ok=True)
        record = result.to_dict()
        record["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        with self._audit_file.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")

    def _truncate_output(self, value: str | bytes | None) -> str:
        if value is None:
            return ""
        if isinstance(value, bytes):
            value = value.decode("utf-8", errors="replace")
        if len(value) <= self._max_output_chars:
            return value
        return value[: self._max_output_chars] + "\n...[truncated]"

    @staticmethod
    def _render_command(argv: Sequence[str]) -> str:
        return " ".join(shlex.quote(part) for part in argv)

    @staticmethod
    def _is_relative_to(path: Path, base: Path) -> bool:
        try:
            path.relative_to(base)
            return True
        except ValueError:
            return False


_default_guard = IronClawShellGuard()


def run_guarded_command(
    command: str | Sequence[str],
    *,
    timeout_seconds: float | None = None,
    cwd: str | Path | None = None,
    env: dict[str, str] | None = None,
    check: bool = True,
) -> GuardedCommandResult:
    return _default_guard.run(
        command,
        timeout_seconds=timeout_seconds,
        cwd=cwd,
        env=env,
        check=check,
    )


def validate_guarded_command(command: str | Sequence[str]) -> tuple[str, ...]:
    return _default_guard.dry_validate(command)
