from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence


SHELL_LIKE_TARGETS = {
    "shell",
    "bash",
    "sh",
    "zsh",
    "powershell",
    "pwsh",
    "cmd",
    "terminal",
}

COMMAND_LIKE_ACTIONS = {
    "shell",
    "command",
    "toolcall",
    "execute",
    "run",
}

DEFAULT_ALLOWED_BINARIES = {
    "python",
    "python3",
    "py",
    "pip",
    "pip3",
    "pytest",
    "uvicorn",
    "fastapi",
    "bash",
    "sh",
    "pwsh",
    "powershell",
    "cmd",
    "echo",
    "cat",
    "type",
    "ls",
    "dir",
    "pwd",
    "cd",
    "find",
    "grep",
    "rg",
    "sed",
    "awk",
    "head",
    "tail",
    "curl",
    "wget",
    "git",
    "node",
    "npm",
    "npx",
}

DEFAULT_BLOCKED_PATTERNS: tuple[tuple[str, str, int], ...] = (
    ("credential_dumping", r"(?i)\b(mimikatz|sekurlsa|procdump|lsass)\b", 45),
    ("destructive_delete", r"(?i)\b(rm\s+-rf|del\s+/[sqf]+\s|format\s+[a-z]:)\b", 55),
    ("persistence_cron", r"(?i)\b(crontab|schtasks|at\.exe|systemctl\s+enable)\b", 35),
    ("privilege_escalation", r"(?i)\b(sudo|runas|chmod\s+\+s|setcap)\b", 35),
    ("reverse_shell", r"(?i)\b(nc\s+-e|bash\s+-i|powershell.+tcpclient|socat\s+.*exec:)\b", 60),
    ("sensitive_file_access", r"(?i)(/etc/shadow|/etc/passwd|id_rsa|authorized_keys|\.aws/credentials)", 40),
    ("system_recon", r"(?i)\b(whoami|net\s+user|ipconfig|ifconfig|route\s+print|arp\s+-a)\b", 20),
    ("download_and_execute", r"(?i)\b(curl|wget).*(\||&&|;).*\b(sh|bash|pwsh|powershell|python)\b", 60),
    ("encoded_powershell", r"(?i)\bpowershell(?:\.exe)?\b.*(?:-enc|-encodedcommand)\b", 55),
    ("environment_secret_access", r"(?i)\b(printenv|env|set)\b.*\b(key|token|secret|password)\b", 35),
)

DEFAULT_BLOCKED_BASENAMES = {
    "mimikatz",
    "nc",
    "netcat",
    "ncat",
    "socat",
    "procdump",
    "certutil",
    "bitsadmin",
    "regsvr32",
    "mshta",
    "rundll32",
}


@dataclass(slots=True)
class CommandReason:
    source: str
    label: str
    details: str
    score: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "label": self.label,
            "details": self.details,
            "score": int(self.score),
        }


@dataclass(slots=True)
class CommandPolicy:
    verdict: str
    allowed: bool
    should_review: bool
    should_block: bool
    should_quarantine: bool
    risk_delta: int
    normalized_command: str
    executable: str
    reasons: list[dict[str, Any]] = field(default_factory=list)
    matched_rules: list[str] = field(default_factory=list)
    cwd: str | None = None
    environment_scope: str = "sandbox"
    command_kind: str = "shell"

    def as_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "allowed": self.allowed,
            "shouldreview": self.should_review,
            "shouldblock": self.should_block,
            "shouldquarantine": self.should_quarantine,
            "riskdelta": int(self.risk_delta),
            "normalizedcommand": self.normalized_command,
            "executable": self.executable,
            "reasons": list(self.reasons),
            "matchedrules": list(self.matched_rules),
            "cwd": self.cwd,
            "environmentscope": self.environment_scope,
            "commandkind": self.command_kind,
        }


@dataclass(slots=True)
class CommandSupervisor:
    review_threshold: int = 20
    block_threshold: int = 50
    quarantine_threshold: int = 80
    max_command_length: int = 4000
    allowed_binaries: set[str] = field(default_factory=lambda: set(DEFAULT_ALLOWED_BINARIES))
    blocked_basenames: set[str] = field(default_factory=lambda: set(DEFAULT_BLOCKED_BASENAMES))
    blocked_patterns: tuple[tuple[str, str, int], ...] = DEFAULT_BLOCKED_PATTERNS

    def evaluate(
        self,
        *,
        command: str | Sequence[str],
        actiontype: str = "command",
        target: str = "shell",
        cwd: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> CommandPolicy:
        normalized_command = self._normalize_command(command)
        executable = self._extract_executable(command)
        normalized_action = str(actiontype or "").strip().lower()
        normalized_target = str(target or "").strip().lower()
        command_kind = "shell" if normalized_target in SHELL_LIKE_TARGETS else "subprocess"
        environment_scope = str((metadata or {}).get("environment_scope") or "sandbox")

        reasons: list[CommandReason] = []
        matched_rules: list[str] = []
        risk_delta = 0

        if not normalized_command:
            reasons.append(
                CommandReason(
                    source="commandsupervisor",
                    label="Empty command",
                    details="Command execution was denied because no command content was provided.",
                    score=60,
                )
            )
            return self._finalize(
                reasons=reasons,
                matched_rules=["empty_command"],
                risk_delta=60,
                normalized_command=normalized_command,
                executable=executable,
                cwd=cwd,
                environment_scope=environment_scope,
                command_kind=command_kind,
            )

        if len(normalized_command) > self.max_command_length:
            reasons.append(
                CommandReason(
                    source="commandsupervisor",
                    label="Command too large",
                    details=(
                        f"Command length {len(normalized_command)} exceeded the allowed maximum "
                        f"of {self.max_command_length} characters."
                    ),
                    score=35,
                )
            )
            matched_rules.append("oversized_command")
            risk_delta += 35

        if normalized_action in COMMAND_LIKE_ACTIONS or normalized_target in SHELL_LIKE_TARGETS:
            reasons.append(
                CommandReason(
                    source="commandsupervisor",
                    label="Execution boundary",
                    details=(
                        f"Command supervision applied hardened policy for action '{actiontype}' "
                        f"targeting '{target}'."
                    ),
                    score=10,
                )
            )
            matched_rules.append("execution_boundary")
            risk_delta += 10

        if executable:
            basename = executable.rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()
            if basename in self.blocked_basenames:
                reasons.append(
                    CommandReason(
                        source="commandsupervisor",
                        label="Blocked executable",
                        details=f"Executable '{basename}' is explicitly blocked by command policy.",
                        score=70,
                    )
                )
                matched_rules.append(f"blocked_basename:{basename}")
                risk_delta += 70
            elif basename not in {item.lower() for item in self.allowed_binaries}:
                reasons.append(
                    CommandReason(
                        source="commandsupervisor",
                        label="Unapproved executable",
                        details=(
                            f"Executable '{basename}' is outside the approved sandbox command set "
                            "and requires review."
                        ),
                        score=20,
                    )
                )
                matched_rules.append(f"unapproved_basename:{basename}")
                risk_delta += 20
        else:
            reasons.append(
                CommandReason(
                    source="commandsupervisor",
                    label="Unknown executable",
                    details="Unable to determine the executable from the provided command payload.",
                    score=15,
                )
            )
            matched_rules.append("unknown_executable")
            risk_delta += 15

        for rule_name, pattern, score in self.blocked_patterns:
            if re.search(pattern, normalized_command):
                reasons.append(
                    CommandReason(
                        source="commandsupervisor",
                        label="Command policy match",
                        details=f"Command matched supervised rule '{rule_name}'.",
                        score=score,
                    )
                )
                matched_rules.append(rule_name)
                risk_delta += int(score)

        if self._looks_like_chained_execution(normalized_command):
            reasons.append(
                CommandReason(
                    source="commandsupervisor",
                    label="Chained execution",
                    details="Command contains chained execution operators and needs stricter review.",
                    score=15,
                )
            )
            matched_rules.append("chained_execution")
            risk_delta += 15

        if self._references_parent_escape(cwd=cwd, command=normalized_command):
            reasons.append(
                CommandReason(
                    source="commandsupervisor",
                    label="Path escape attempt",
                    details="Command appears to reference parent-directory traversal outside the sandbox.",
                    score=40,
                )
            )
            matched_rules.append("path_escape")
            risk_delta += 40

        if self._requests_interactive_session(normalized_command):
            reasons.append(
                CommandReason(
                    source="commandsupervisor",
                    label="Interactive session request",
                    details="Interactive or long-lived shell behavior was detected.",
                    score=25,
                )
            )
            matched_rules.append("interactive_session")
            risk_delta += 25

        if environment_scope.lower() != "sandbox":
            reasons.append(
                CommandReason(
                    source="commandsupervisor",
                    label="Non-sandbox environment",
                    details=(
                        f"Environment scope '{environment_scope}' is outside the default sandbox "
                        "boundary and requires escalation."
                    ),
                    score=45,
                )
            )
            matched_rules.append("non_sandbox_environment")
            risk_delta += 45

        return self._finalize(
            reasons=reasons,
            matched_rules=matched_rules,
            risk_delta=risk_delta,
            normalized_command=normalized_command,
            executable=executable,
            cwd=cwd,
            environment_scope=environment_scope,
            command_kind=command_kind,
        )

    def allow(
        self,
        *,
        command: str | Sequence[str],
        actiontype: str = "command",
        target: str = "shell",
        cwd: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> bool:
        return self.evaluate(
            command=command,
            actiontype=actiontype,
            target=target,
            cwd=cwd,
            metadata=metadata,
        ).allowed

    def _finalize(
        self,
        *,
        reasons: Iterable[CommandReason],
        matched_rules: list[str],
        risk_delta: int,
        normalized_command: str,
        executable: str,
        cwd: str | None,
        environment_scope: str,
        command_kind: str,
    ) -> CommandPolicy:
        normalized_risk = max(0, min(100, int(risk_delta)))

        verdict = "allow"
        allowed = True
        should_review = False
        should_block = False
        should_quarantine = False

        if normalized_risk >= self.quarantine_threshold:
            verdict = "quarantine"
            allowed = False
            should_block = True
            should_quarantine = True
        elif normalized_risk >= self.block_threshold:
            verdict = "block"
            allowed = False
            should_block = True
        elif normalized_risk >= self.review_threshold:
            verdict = "review"
            should_review = True

        return CommandPolicy(
            verdict=verdict,
            allowed=allowed,
            should_review=should_review,
            should_block=should_block,
            should_quarantine=should_quarantine,
            risk_delta=normalized_risk,
            normalized_command=normalized_command,
            executable=executable,
            reasons=[reason.as_dict() for reason in reasons],
            matched_rules=matched_rules,
            cwd=cwd,
            environment_scope=environment_scope,
            command_kind=command_kind,
        )

    def _normalize_command(self, command: str | Sequence[str]) -> str:
        if isinstance(command, str):
            return command.strip()
        parts = [str(part).strip() for part in command if str(part).strip()]
        return " ".join(parts).strip()

    def _extract_executable(self, command: str | Sequence[str]) -> str:
        if isinstance(command, str):
            try:
                parts = shlex.split(command, posix=False)
            except ValueError:
                parts = command.strip().split()
        else:
            parts = [str(part).strip() for part in command if str(part).strip()]
        return parts[0] if parts else ""

    def _looks_like_chained_execution(self, command: str) -> bool:
        return any(token in command for token in ("&&", "||", "|", ";"))

    def _references_parent_escape(self, *, cwd: str | None, command: str) -> bool:
        if ".." in command.replace("\\", "/"):
            return True
        if cwd and ".." in str(cwd).replace("\\", "/"):
            return True
        return False

    def _requests_interactive_session(self, command: str) -> bool:
        patterns = (
            r"(?i)\bssh\b",
            r"(?i)\btelnet\b",
            r"(?i)\bftp\b",
            r"(?i)\bpython\b.*\s-i\b",
            r"(?i)\bbash\b.*\s-i\b",
            r"(?i)\bpowershell(?:\.exe)?\b.*\s-noexit\b",
        )
        return any(re.search(pattern, command) for pattern in patterns)


def initialize_commandsupervisor(
    *,
    review_threshold: int = 20,
    block_threshold: int = 50,
    quarantine_threshold: int = 80,
    max_command_length: int = 4000,
    allowed_binaries: Iterable[str] | None = None,
    blocked_basenames: Iterable[str] | None = None,
    blocked_patterns: Sequence[tuple[str, str, int]] | None = None,
) -> CommandSupervisor:
    return CommandSupervisor(
        review_threshold=review_threshold,
        block_threshold=block_threshold,
        quarantine_threshold=quarantine_threshold,
        max_command_length=max_command_length,
        allowed_binaries=set(allowed_binaries or DEFAULT_ALLOWED_BINARIES),
        blocked_basenames=set(blocked_basenames or DEFAULT_BLOCKED_BASENAMES),
        blocked_patterns=tuple(blocked_patterns or DEFAULT_BLOCKED_PATTERNS),
    )


def build_command_supervisor() -> CommandSupervisor:
    return initialize_commandsupervisor()