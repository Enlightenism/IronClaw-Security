from __future__ import annotations

import os
from urllib.parse import urlsplit

DEFAULT_CLAUDE_UPSTREAM_HOSTS = "api.anthropic.com"


def allowed_claude_upstream_hosts() -> frozenset[str]:
    raw = os.environ.get("CLAUDE_UPSTREAM_ALLOWED_HOSTS", DEFAULT_CLAUDE_UPSTREAM_HOSTS)
    return frozenset(item.strip().lower() for item in raw.split(",") if item.strip())


def is_allowed_claude_upstream_url(upstream_url: object) -> bool:
    if not isinstance(upstream_url, str):
        return False
    try:
        parts = urlsplit(upstream_url.strip())
    except ValueError:
        return False
    return parts.scheme == "https" and (parts.hostname or "") in allowed_claude_upstream_hosts()
