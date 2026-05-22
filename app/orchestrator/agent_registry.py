from __future__ import annotations

from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
import hashlib
import json
import logging
from pathlib import Path
from typing import Any, Literal

AgentLanguage = Literal[
    "python",
    "javascript",
    "typescript",
    "json",
    "yaml",
    "markdown",
    "html",
    "css",
    "shell",
    "powershell",
    "unknown",
]


ThreatProfile = Literal[
    "low_risk",
    "standard",
    "sensitive",
    "execution_capable",
    "security_critical",
]


ProtectedAction = Literal[
    "file_write",
    "file_edit",
    "shell_command",
    "network_request",
    "git_operation",
    "tool_call",
]


DEFAULT_INCLUDE_EXTENSIONS = {
    ".py",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".json",
    ".yml",
    ".yaml",
    ".md",
    ".html",
    ".css",
    ".sh",
    ".ps1",
}


DEFAULT_EXCLUDED_DIRS = {
    ".git",
    ".pytest_cache",
    ".mypy_cache",
    ".venv",
    "venv",
    "__pycache__",
    "node_modules",
    "dist",
    "build",
    ".next",
    ".idea",
    ".vscode",
}


def _get_logger() -> logging.Logger:
    try:
        from app.core.logging import get_logger  # noqa: PLC0415

        return get_logger("ironclaw.agent_registry")
    except Exception:  # noqa: BLE001
        return logging.getLogger("ironclaw.agent_registry")


_logger: logging.Logger = _get_logger()


# ---------------------------------------------------------------------------
# Module-level re-export so tests can patch
# 'app.orchestrator.agent_registry.get_behavioral_baseline_store'
# ---------------------------------------------------------------------------
try:
    from app.services.behavioral_baseline import (  # noqa: PLC0415
        get_behavioral_baseline_store,
    )
except Exception:  # noqa: BLE001

    def get_behavioral_baseline_store():  # type: ignore[misc]
        raise RuntimeError("behavioral_baseline service is not available")


@dataclass
class AgentDescriptor:
    agent_id: str
    relative_path: str
    absolute_path: str
    language: AgentLanguage
    threat_profile: ThreatProfile
    protected_actions: list[ProtectedAction] = field(default_factory=list)
    exists: bool = True
    size_bytes: int = 0
    file_hash: str | None = None
    last_modified_ts: float | None = None
    tags: list[str] = field(default_factory=list)
    baseline_status: str = "unknown"


@dataclass
class AgentRegistry:
    project_root: str
    count: int
    items: list[AgentDescriptor] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_root": self.project_root,
            "count": self.count,
            "items": [asdict(item) for item in self.items],
        }


def _normalize_root(project_root: str | Path) -> Path:
    return Path(project_root).expanduser().resolve()


def _infer_language(path: Path) -> AgentLanguage:
    suffix = path.suffix.lower()

    if suffix == ".py":
        return "python"
    if suffix in {".js", ".jsx"}:
        return "javascript"
    if suffix in {".ts", ".tsx"}:
        return "typescript"
    if suffix == ".json":
        return "json"
    if suffix in {".yml", ".yaml"}:
        return "yaml"
    if suffix == ".md":
        return "markdown"
    if suffix == ".html":
        return "html"
    if suffix == ".css":
        return "css"
    if suffix == ".sh":
        return "shell"
    if suffix == ".ps1":
        return "powershell"
    return "unknown"


def _read_text_safe(path: Path, max_chars: int = 5000) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")[:max_chars]
    except OSError:
        return ""


def _hash_file(path: Path) -> str | None:
    try:
        digest = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def _stable_agent_id(relative_path: str) -> str:
    digest = hashlib.sha256(relative_path.encode("utf-8")).hexdigest()
    return f"ic-agent-{digest[:16]}"


def _protected_actions_for(language: AgentLanguage, path: Path, content: str) -> list[ProtectedAction]:
    actions: set[ProtectedAction] = {"file_edit"}

    lowered_path = str(path).lower()
    lowered = content.lower()

    if language in {"python", "javascript", "typescript", "shell", "powershell"}:
        actions.add("tool_call")

    if language in {"shell", "powershell"}:
        actions.add("shell_command")
        actions.add("file_write")

    if any(token in lowered for token in ["subprocess", "os.system", "invoke-webrequest", "start-process", "iex "]):
        actions.add("shell_command")

    if any(token in lowered for token in ["requests.", "httpx.", "fetch(", "curl", "wget", "invoke-webrequest"]):
        actions.add("network_request")

    if any(token in lowered for token in ["git", "github", "gitlab"]):
        actions.add("git_operation")

    if any(token in lowered for token in ["write_text(", "open(", "path.write", "outfile", "set-content", "add-content"]):
        actions.add("file_write")

    if "docker" in lowered or "kubectl" in lowered or "terraform" in lowered:
        actions.add("shell_command")

    if "api" in lowered_path or "service" in lowered_path or "guard" in lowered_path or "scanner" in lowered_path:
        actions.add("tool_call")

    return sorted(actions)


def _threat_profile_for(path: Path, language: AgentLanguage, content: str) -> ThreatProfile:
    lowered_path = str(path).lower()
    lowered = content.lower()

    if any(
        part in lowered_path
        for part in [
            "security",
            "guard",
            "scanner",
            "policy",
            "telemetry",
            "orchestrator",
            "behavioral_baseline",
        ]
    ):
        return "security_critical"

    if any(
        token in lowered
        for token in [
            "subprocess",
            "os.system",
            "invoke-webrequest",
            "start-process",
            "curl",
            "wget",
            "requests.",
            "httpx.",
            "socket",
            "ssh",
            "token",
            "secret",
            "credential",
        ]
    ):
        return "execution_capable"

    if any(part in lowered_path for part in ["auth", "history", "client", "api", "service"]):
        return "sensitive"

    if language in {"python", "javascript", "typescript", "shell", "powershell"}:
        return "standard"

    return "low_risk"


def _tags_for(path: Path, language: AgentLanguage, content: str) -> list[str]:
    tags: set[str] = {language}

    lowered_path = str(path).lower()
    lowered = content.lower()

    keyword_map = {
        "security": ["security", "scanner", "guard", "policy"],
        "network": ["requests.", "httpx.", "fetch(", "curl", "wget", "invoke-webrequest"],
        "execution": ["subprocess", "os.system", "start-process", "iex "],
        "history": ["history", "scan_id"],
        "telemetry": ["telemetry", "event"],
        "orchestrator": ["orchestrator", "agent_registry", "agent"],
        "api": ["apirouter", "fastapi", "router"],
        "behavioral_baseline": ["behavioral_baseline", "drift", "baseline"],
    }

    for tag, needles in keyword_map.items():
        if tag in lowered_path or any(needle in lowered for needle in needles):
            tags.add(tag)

    return sorted(tags)


def _fetch_baseline_status(agent_id: str) -> str:
    """Return the current baseline status string for an agent.

    Falls back to 'unknown' on any failure so descriptor construction
    is never blocked by baseline availability.
    """
    try:
        baseline = get_behavioral_baseline_store().get_baseline(agent_id)
        if baseline is None:
            return "learning"
        return baseline.status
    except Exception as exc:  # noqa: BLE001
        _logger.warning(
            "agent_registry_baseline_fetch_failed",
            extra={
                "event": "agent_registry_baseline_fetch_failed",
                "agent_id": agent_id,
                "error": str(exc),
            },
        )
        return "unknown"


def _iter_candidate_files(
    project_root: Path,
    include_extensions: set[str] | None = None,
    excluded_dirs: set[str] | None = None,
) -> Iterable[Path]:
    include_extensions = include_extensions or DEFAULT_INCLUDE_EXTENSIONS
    excluded_dirs = excluded_dirs or DEFAULT_EXCLUDED_DIRS

    for path in project_root.rglob("*"):
        if not path.is_file():
            continue

        parts = set(path.parts)
        if parts & excluded_dirs:
            continue

        if path.suffix.lower() not in include_extensions:
            continue

        yield path


def build_agent_descriptor(project_root: str | Path, file_path: str | Path) -> AgentDescriptor:
    root = _normalize_root(project_root)
    path = Path(file_path).expanduser().resolve()

    relative_path = path.relative_to(root).as_posix()
    language = _infer_language(path)
    content = _read_text_safe(path)
    agent_id = _stable_agent_id(relative_path)

    try:
        stat = path.stat()
        size_bytes = stat.st_size
        last_modified_ts = stat.st_mtime
        exists = True
    except OSError:
        size_bytes = 0
        last_modified_ts = None
        exists = False

    return AgentDescriptor(
        agent_id=agent_id,
        relative_path=relative_path,
        absolute_path=str(path),
        language=language,
        threat_profile=_threat_profile_for(path, language, content),
        protected_actions=_protected_actions_for(language, path, content),
        exists=exists,
        size_bytes=size_bytes,
        file_hash=_hash_file(path) if exists else None,
        last_modified_ts=last_modified_ts,
        tags=_tags_for(path, language, content),
        baseline_status=_fetch_baseline_status(agent_id),
    )


def discover_agents(
    project_root: str | Path,
    include_extensions: set[str] | None = None,
    excluded_dirs: set[str] | None = None,
) -> AgentRegistry:
    root = _normalize_root(project_root)

    items = [
        build_agent_descriptor(root, path)
        for path in _iter_candidate_files(
            root,
            include_extensions=include_extensions,
            excluded_dirs=excluded_dirs,
        )
    ]

    items.sort(key=lambda item: item.relative_path)

    return AgentRegistry(
        project_root=str(root),
        count=len(items),
        items=items,
    )


def get_agent_by_path(
    registry: AgentRegistry,
    relative_path: str,
) -> AgentDescriptor | None:
    normalized = relative_path.replace("\\", "/").strip()
    for item in registry.items:
        if item.relative_path == normalized:
            return item
    return None


def get_agent_by_id(
    registry: AgentRegistry,
    agent_id: str,
) -> AgentDescriptor | None:
    for item in registry.items:
        if item.agent_id == agent_id:
            return item
    return None


def save_registry(
    registry: AgentRegistry,
    output_path: str | Path,
) -> Path:
    path = Path(output_path).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(registry.to_dict(), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return path


if __name__ == "__main__":
    root = Path().resolve()
    registry = discover_agents(root)
    print(json.dumps(registry.to_dict(), ensure_ascii=False, indent=2))
