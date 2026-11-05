"""Third-party install scanner: resolves an install command to its public artifacts, fetches them over HTTPS, and scans them in the sandbox broker. Fail closed."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import io
import ipaddress
import json
import logging
import posixpath
import re
import socket
import tarfile
import time
from typing import Any, Final
from urllib.parse import quote, urljoin, urlsplit
import zipfile

import httpx

from app.runtime.return_scanner import ALLOW_VERDICT
from app.services.sandbox_broker_client import SandboxBrokerClient

logger = logging.getLogger(__name__)

SCAN_ACTION: Final[str] = "scan"
ARTIFACT_FETCH_BUDGET_SECONDS: Final[float] = 12.0
BROKER_SCAN_TIMEOUT_SECONDS: Final[float] = 8.0
MAX_ARTIFACT_BYTES: Final[int] = 20 * 1024 * 1024
MAX_MEMBER_BYTES: Final[int] = 2 * 1024 * 1024
MAX_MEMBERS: Final[int] = 5000
MAX_REDIRECTS: Final[int] = 5
MAX_SOURCES: Final[int] = 8
MAX_SCAN_TEXT_CHARS: Final[int] = 250_000
NPM_REGISTRY: Final[str] = "https://registry.npmjs.org"
PYPI_JSON: Final[str] = "https://pypi.org/pypi"
GITHUB_ARCHIVE: Final[str] = "https://codeload.github.com"

KIND_NPM: Final[str] = "npm"
KIND_PYPI: Final[str] = "pypi"
KIND_GITHUB: Final[str] = "github"
KIND_URL: Final[str] = "url"
ARCHIVE_TAR: Final[str] = "tar"
ARCHIVE_ZIP: Final[str] = "zip"
ARCHIVE_RAW: Final[str] = "raw"

DOWNLOAD_PIPE_PATTERN: Final[re.Pattern[str]] = re.compile(r"(?P<download>(?:curl|wget)(?:\s+-{1,2}[A-Za-z][A-Za-z0-9-]*)*\s+https://[^\s;&|`<>$()\"']+)\s*\|\s*(?:sudo\s+)?(?:sh|bash|zsh|python3?)")
DOWNLOAD_TOOLS: Final[frozenset[str]] = frozenset({"curl", "wget", "iwr", "irm", "invoke-webrequest", "invoke-restmethod"})
NPX_TOOLS: Final[frozenset[str]] = frozenset({"npx", "bunx", "pnpx"})
NPM_TOOLS: Final[frozenset[str]] = frozenset({"npm", "pnpm", "yarn", "bun"})
NPM_VERBS: Final[frozenset[str]] = frozenset({"install", "i", "add", "dlx", "exec", "x"})
PIP_TOOLS: Final[frozenset[str]] = frozenset({"pip", "pip3", "uv", "pipx", "uvx"})
SKILL_TOOLS: Final[frozenset[str]] = frozenset({"hermes", "gh", "openclaw", "goose", "claude"})
SKILL_VERBS: Final[frozenset[str]] = frozenset({"add", "install", "clone", "skill", "skills", "plugin", "plugins", "i"})
NPX_SAFE_FLAGS: Final[frozenset[str]] = frozenset({"-y", "--yes", "-q", "--quiet", "-s", "--silent"})
NPM_SAFE_FLAGS: Final[frozenset[str]] = frozenset({"-y", "--yes", "-g", "--global", "-D", "--save-dev", "-S", "--save", "--no-audit", "--no-fund", "--silent", "-s", "--quiet", "-q", "--prefer-offline"})
PIP_SAFE_FLAGS: Final[frozenset[str]] = frozenset({"-U", "--upgrade", "--user", "-q", "--quiet", "--no-cache-dir", "--pre", "--force-reinstall", "--no-deps", "--break-system-packages", "-y", "--yes"})
NPM_LIFECYCLE_SCRIPTS: Final[frozenset[str]] = frozenset({"preinstall", "install", "postinstall", "prepare", "prepublish", "preprepare", "postprepare"})
NATIVE_EXTENSIONS: Final[frozenset[str]] = frozenset({".exe", ".dll", ".so", ".dylib", ".node", ".wasm", ".bin", ".pyd", ".jar", ".class", ".msi", ".app", ".dmg", ".pkg", ".deb", ".rpm"})
ASSET_EXTENSIONS: Final[frozenset[str]] = frozenset({".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".woff", ".woff2", ".ttf", ".otf", ".eot"})

_NPM_SPEC: Final[re.Pattern[str]] = re.compile(r"(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*(?:@[A-Za-z0-9][A-Za-z0-9._+-]*)?")
_PYPI_SPEC: Final[re.Pattern[str]] = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*(?:\[[A-Za-z0-9,._-]+\])?(?:==[A-Za-z0-9._+!-]+)?")
_GITHUB_SHORTHAND: Final[re.Pattern[str]] = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*")
_GITHUB_URL: Final[re.Pattern[str]] = re.compile(r"https://github\.com/([A-Za-z0-9][A-Za-z0-9_.-]*)/([A-Za-z0-9][A-Za-z0-9_.-]*?)(?:\.git)?/?")


class InstallScanError(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class ScanOutcome:
    allowed: bool
    reasons: list[str]
    artifacts: list[str]


def _github_ref(token: str) -> str | None:
    if token.startswith("https://"):
        match = _GITHUB_URL.fullmatch(token)
        return f"{match.group(1)}/{match.group(2)}" if match else None
    return token if _GITHUB_SHORTHAND.fullmatch(token) else None


def _github_sources(tokens: list[str]) -> list[tuple[str, str]] | None:
    verb = any(token.lower() in SKILL_VERBS for token in tokens)
    sources: list[tuple[str, str]] = []
    for token in tokens:
        if token.startswith("https://github.com/"):
            ref = _github_ref(token)
            if ref is None:
                return None
            sources.append((KIND_GITHUB, ref))
        elif verb and _GITHUB_SHORTHAND.fullmatch(token):
            sources.append((KIND_GITHUB, token))
    return sources


def _npx_sources(args: list[str]) -> list[tuple[str, str]] | None:
    for token in args:
        if token.startswith("-"):
            if token not in NPX_SAFE_FLAGS:
                return None
            continue
        return [(KIND_NPM, token)] if _NPM_SPEC.fullmatch(token) else None
    return None


def _npm_install_sources(args: list[str]) -> list[tuple[str, str]] | None:
    sources: list[tuple[str, str]] = []
    for token in args:
        if token.startswith("-"):
            if token not in NPM_SAFE_FLAGS:
                return None
        elif _NPM_SPEC.fullmatch(token):
            sources.append((KIND_NPM, token))
        else:
            return None
    return sources or None


def _pip_sources(tool: str, args: list[str]) -> list[tuple[str, str]] | None:
    if tool == "uv" and args[:1] == ["pip"]:
        args = args[1:]
    if tool == "uvx":
        packages = args
    elif tool == "pipx":
        if args[:1] not in (["install"], ["run"]):
            return None
        packages = args[1:]
    else:
        if args[:1] not in (["install"], ["add"]):
            return None
        packages = args[1:]
    sources: list[tuple[str, str]] = []
    for token in packages:
        if token.startswith("-"):
            if token not in PIP_SAFE_FLAGS:
                return None
        elif _PYPI_SPEC.fullmatch(token):
            sources.append((KIND_PYPI, token))
        else:
            return None
    return sources or None


def _line_sources(tokens: list[str]) -> list[tuple[str, str]] | None:
    head = tokens[0].lower()
    if any("://" in token and not token.startswith("https://") for token in tokens):
        return None
    if head in DOWNLOAD_TOOLS:
        return [(KIND_URL, token) for token in tokens if token.startswith("https://")] or None
    if head == "git":
        ref = _github_ref(tokens[2]) if len(tokens) >= 3 and tokens[1] == "clone" else None
        return [(KIND_GITHUB, ref)] if ref else None

    github = _github_sources(tokens)
    if github is None:
        return None
    if head in NPX_TOOLS:
        primary = _npx_sources(tokens[1:])
    elif head in NPM_TOOLS and len(tokens) > 1 and tokens[1].lower() in NPM_VERBS:
        primary = _npm_install_sources(tokens[2:])
    elif head in PIP_TOOLS:
        primary = _pip_sources(head, tokens[1:])
    elif head in SKILL_TOOLS:
        primary = []
    else:
        return None
    if primary is None:
        return None
    return (primary + github) or None


def download_pipe_body(command: str) -> str | None:
    """Return the download half of an exact `curl|wget URL | shell` command. The scanned artifact is what runs."""
    match = DOWNLOAD_PIPE_PATTERN.fullmatch(command.strip())
    return match.group("download") if match else None


def resolve_install_sources(command: str) -> list[tuple[str, str]] | None:
    """Return (kind, value) source references for every line, or None when any line cannot be resolved."""
    sources: list[tuple[str, str]] = []
    for line in command.splitlines():
        tokens = line.split()
        if not tokens:
            continue
        found = _line_sources(tokens)
        if not found:
            return None
        sources.extend(found)
    return sources or None


def _require_public_https(url: str) -> None:
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password:
        raise InstallScanError("artifact_url_not_https")
    try:
        addresses = socket.getaddrinfo(parts.hostname, parts.port or 443, type=socket.SOCK_STREAM)
    except (OSError, UnicodeError):
        raise InstallScanError("artifact_host_unresolvable") from None
    # httpx resolves again when it connects, so this check narrows DNS rebinding but does not close it.
    for address in addresses:
        if not ipaddress.ip_address(address[4][0]).is_global:
            raise InstallScanError("artifact_host_not_public")


def _read_capped(response: httpx.Response, deadline: float) -> bytes:
    chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_bytes():
        total += len(chunk)
        if total > MAX_ARTIFACT_BYTES:
            raise InstallScanError("artifact_too_large")
        if time.monotonic() > deadline:
            raise InstallScanError("artifact_fetch_timeout")
        chunks.append(chunk)
    return b"".join(chunks)


def _fetch(url: str, deadline: float) -> bytes:
    current = url
    with httpx.Client(follow_redirects=False) as client:
        for _ in range(MAX_REDIRECTS + 1):
            _require_public_https(current)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise InstallScanError("artifact_fetch_timeout")
            try:
                with client.stream("GET", current, timeout=remaining) as response:
                    if response.is_redirect:
                        location = response.headers.get("location")
                        if not location:
                            raise InstallScanError("artifact_fetch_failed")
                        current = urljoin(current, location)
                        continue
                    if not response.is_success:
                        raise InstallScanError("artifact_fetch_failed")
                    return _read_capped(response, deadline)
            except httpx.HTTPError:
                raise InstallScanError("artifact_fetch_failed") from None
    raise InstallScanError("artifact_redirect_limit")


def _fetch_json(url: str, deadline: float) -> Any:
    try:
        return json.loads(_fetch(url, deadline))
    except ValueError:
        raise InstallScanError("source_metadata_invalid") from None


def _split_npm_spec(spec: str) -> tuple[str, str | None]:
    index = spec.rfind("@")
    return (spec[:index], spec[index + 1 :]) if index > 0 else (spec, None)


def _download_target(kind: str, value: str, deadline: float) -> tuple[str, str]:
    """Return the artifact URL and its archive format for one resolved source."""
    try:
        if kind == KIND_NPM:
            name, version = _split_npm_spec(value)
            metadata = _fetch_json(f"{NPM_REGISTRY}/{quote(name, safe='@')}", deadline)
            version = version or metadata["dist-tags"]["latest"]
            return str(metadata["versions"][version]["dist"]["tarball"]), ARCHIVE_TAR
        if kind == KIND_PYPI:
            name, _, version = value.partition("==")
            name = re.sub(r"\[.*\]$", "", name)
            version_part = f"{quote(version, safe='')}/" if version else ""
            metadata = _fetch_json(f"{PYPI_JSON}/{quote(name, safe='')}/{version_part}json", deadline)
            wheels = [entry for entry in metadata["urls"] if entry.get("packagetype") == "bdist_wheel"]
            if not wheels:
                raise InstallScanError("no_wheel_artifact")
            return str(wheels[0]["url"]), ARCHIVE_ZIP
        if kind == KIND_GITHUB:
            owner, _, repo = value.partition("/")
            return f"{GITHUB_ARCHIVE}/{owner}/{repo}/tar.gz/HEAD", ARCHIVE_TAR
        return value, ARCHIVE_RAW
    except (KeyError, TypeError, IndexError, AttributeError):
        raise InstallScanError("source_metadata_invalid") from None


def _check_member_name(name: str) -> None:
    parts = name.split("/")
    if not name or name.startswith("/") or "\\" in name or ":" in parts[0] or ".." in parts:
        raise InstallScanError("unsafe_member_path")


def _tar_members(data: bytes) -> list[tuple[str, bytes]]:
    members: list[tuple[str, bytes]] = []
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
        for member in archive:
            if member.isdir():
                continue
            if not member.isfile():
                raise InstallScanError("link_or_device_member")
            if member.size > MAX_MEMBER_BYTES:
                raise InstallScanError("member_too_large")
            _check_member_name(member.name)
            extracted = archive.extractfile(member)
            if extracted is None:
                raise InstallScanError("link_or_device_member")
            members.append((member.name, extracted.read()))
            if len(members) > MAX_MEMBERS:
                raise InstallScanError("too_many_members")
    return members


def _zip_members(data: bytes) -> list[tuple[str, bytes]]:
    members: list[tuple[str, bytes]] = []
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            if (info.external_attr >> 16) & 0o170000 == 0o120000:
                raise InstallScanError("link_or_device_member")
            if info.file_size > MAX_MEMBER_BYTES:
                raise InstallScanError("member_too_large")
            _check_member_name(info.filename)
            members.append((info.filename, archive.read(info)))
            if len(members) > MAX_MEMBERS:
                raise InstallScanError("too_many_members")
    return members


def _members(archive: str, data: bytes, name: str) -> list[tuple[str, bytes]]:
    if archive == ARCHIVE_TAR:
        return _tar_members(data)
    if archive == ARCHIVE_ZIP:
        return _zip_members(data)
    return [(name, data)]


def _decode_text(name: str, data: bytes) -> str | None:
    if b"\x00" not in data:
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            pass
    if posixpath.splitext(name)[1].lower() in ASSET_EXTENSIONS:
        return None
    raise InstallScanError("binary_member")


def _check_npm_scripts(text: str) -> None:
    try:
        manifest = json.loads(text)
    except ValueError:
        raise InstallScanError("npm_manifest_invalid") from None
    scripts = manifest.get("scripts") if isinstance(manifest, dict) else None
    if isinstance(scripts, dict) and NPM_LIFECYCLE_SCRIPTS.intersection(scripts):
        raise InstallScanError("npm_lifecycle_script")


def _scan_members(kind: str, members: list[tuple[str, bytes]]) -> list[str]:
    parts: list[str] = []
    manifest_checked = False
    for name, data in members:
        extension = posixpath.splitext(name)[1].lower()
        if extension in NATIVE_EXTENSIONS:
            raise InstallScanError("native_binary_member")
        if kind == KIND_PYPI and extension == ".pth":
            raise InstallScanError("pth_file_member")
        text = _decode_text(name, data)
        if text is None:
            continue
        if kind == KIND_NPM and name.count("/") == 1 and name.endswith("/package.json"):
            manifest_checked = True
            _check_npm_scripts(text)
        parts.append(f"\n### {name}\n{text}")
    if kind == KIND_NPM and not manifest_checked:
        raise InstallScanError("npm_manifest_missing")
    return parts


def _broker_verdict(text: str, platform: str, digests: list[str]) -> ScanOutcome:
    if len(text) > MAX_SCAN_TEXT_CHARS:
        raise InstallScanError("artifact_too_large_to_scan")
    payload = {"content": text, "install": {"platform": platform, "sha256": digests}}
    data = SandboxBrokerClient().run(SCAN_ACTION, f"install:{platform}", payload, timeout_seconds=BROKER_SCAN_TIMEOUT_SECONDS)
    if data.get("verdict") == ALLOW_VERDICT and data.get("status") == "completed" and not data.get("untrusted"):
        return ScanOutcome(True, ["third_party_scanned_clean"], digests)
    code = re.sub(r"[^a-z0-9_]", "_", str(data.get("reason") or "blocked").lower())[:64]
    return ScanOutcome(False, [f"sandbox_{code}"], digests)


def _scan(command: str, platform: str) -> ScanOutcome:
    sources = resolve_install_sources(command)
    if not sources:
        raise InstallScanError("unresolvable_install_source")
    if len(sources) > MAX_SOURCES:
        raise InstallScanError("too_many_install_sources")
    deadline = time.monotonic() + ARTIFACT_FETCH_BUDGET_SECONDS
    digests: list[str] = []
    texts: list[str] = []
    for kind, value in sources:
        url, archive = _download_target(kind, value, deadline)
        data = _fetch(url, deadline)
        digests.append(hashlib.sha256(data).hexdigest())
        name = posixpath.basename(urlsplit(url).path) or "download"
        texts.extend(_scan_members(kind, _members(archive, data, name)))
    return _broker_verdict("".join(texts), platform, digests)


def scan_third_party_install(command: str, *, platform: str) -> ScanOutcome:
    """Allow a third-party install only when every resolved artifact is fetched and scans clean. Any failure blocks."""
    try:
        return _scan(command, platform)
    except InstallScanError as error:
        return ScanOutcome(False, [error.reason], [])
    except Exception:
        logger.exception("third-party install scan failed; blocking")
        return ScanOutcome(False, ["install_scan_error"], [])
