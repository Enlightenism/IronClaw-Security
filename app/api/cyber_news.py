from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime
import html
import logging
import re
import time
from typing import Any, Final

from fastapi import APIRouter, HTTPException
import feedparser
import httpx
from pydantic import BaseModel

logger = logging.getLogger(__name__)


router = APIRouter(tags=["cyber-news"])


REQUEST_TIMEOUT_SECONDS: Final[float] = 15.0
CACHE_TTL_SECONDS: Final[float] = 600.0
MAX_ITEMS_PER_FEED: Final[int] = 15
USER_AGENT: Final[str] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
ACCEPT_HEADER: Final[str] = "application/rss+xml, application/atom+xml, application/xml, text/xml;q=0.9, */*;q=0.8"
_TAG_PATTERN: Final[re.Pattern[str]] = re.compile(r"<[^>]*>")
_MIN_DATETIME: Final[datetime] = datetime.min.replace(tzinfo=UTC)


@dataclass(frozen=True)
class _FeedSource:
    key: str
    source: str
    url: str


_FEED_SOURCES: Final[tuple[_FeedSource, ...]] = (
    _FeedSource(
        key="attacks",
        source="Global Cyber Attack News",
        url=("https://news.google.com/rss/search?q=cyber+attack+OR+ransomware+OR+data+breach&hl=en-US&gl=US&ceid=US:en"),
    ),
    _FeedSource(
        key="hacker_news",
        source="The Hacker News",
        url="https://feeds.feedburner.com/TheHackersNews",
    ),
    _FeedSource(
        key="cisa",
        source="CISA News",
        url=("https://news.google.com/rss/search?q=CISA+OR+%22Cybersecurity+and+Infrastructure+Security+Agency%22+OR+%22CISA+KEV%22+when:7d&hl=en-US&gl=US&ceid=US:en"),
    ),
    _FeedSource(
        key="bleeping_computer",
        source="BleepingComputer",
        url="https://www.bleepingcomputer.com/feed/",
    ),
)


class CyberNewsItem(BaseModel):
    title: str
    link: str
    published_at: str | None
    source: str


class CyberNewsFeeds(BaseModel):
    attacks: list[CyberNewsItem]
    hacker_news: list[CyberNewsItem]
    cisa: list[CyberNewsItem]
    bleeping_computer: list[CyberNewsItem]


class CyberNewsResponse(BaseModel):
    updated_at: str
    feeds: CyberNewsFeeds


@dataclass
class _NewsCache:
    payload: CyberNewsResponse | None = None
    expires_at: float = 0.0
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)


_cache = _NewsCache()


def _sanitize_title(raw: object) -> str:
    text = _TAG_PATTERN.sub(" ", str(raw or ""))
    return " ".join(html.unescape(text).split())


def _entry_datetime(entry: Any) -> datetime | None:
    struct = entry.get("published_parsed") or entry.get("updated_parsed")

    if not struct:
        return None

    return datetime(*struct[:6], tzinfo=UTC)


def _parse_entries(
    parsed: Any,
    source: str,
) -> list[tuple[datetime | None, CyberNewsItem]]:
    items: list[tuple[datetime | None, CyberNewsItem]] = []

    for entry in parsed.entries:
        title = _sanitize_title(entry.get("title"))
        link = str(entry.get("link") or "").strip()

        if not title or not link.startswith(("https://", "http://")):
            continue

        published = _entry_datetime(entry)

        items.append(
            (
                published,
                CyberNewsItem(
                    title=title,
                    link=link,
                    published_at=published.isoformat() if published else None,
                    source=source,
                ),
            )
        )

    items.sort(key=lambda pair: pair[0] or _MIN_DATETIME, reverse=True)
    return items[:MAX_ITEMS_PER_FEED]


async def _fetch_feed(
    client: httpx.AsyncClient,
    feed: _FeedSource,
) -> list[tuple[datetime | None, CyberNewsItem]]:
    try:
        response = await client.get(feed.url)
        response.raise_for_status()

        parsed = await asyncio.to_thread(feedparser.parse, response.content)

        if parsed.bozo and not parsed.entries:
            logger.warning(
                "cyber_news: unreadable feed %s: %s",
                feed.key,
                getattr(parsed, "bozo_exception", "unknown parse error"),
            )
            return []

        return _parse_entries(parsed, feed.source)
    except Exception as exc:
        logger.exception(
            "cyber_news: feed failed %s: %s",
            feed.key,
            exc,
        )
        return []


async def _build_payload() -> CyberNewsResponse:
    async with httpx.AsyncClient(
        timeout=REQUEST_TIMEOUT_SECONDS,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": ACCEPT_HEADER,
        },
        follow_redirects=True,
    ) as client:
        results = await asyncio.gather(
            *(_fetch_feed(client, feed) for feed in _FEED_SOURCES),
            return_exceptions=True,
        )

    if all(isinstance(result, BaseException) for result in results):
        raise HTTPException(
            status_code=503,
            detail="Cyber news feeds are temporarily unavailable.",
        )

    collected: dict[str, list[CyberNewsItem]] = {}

    for feed, result in zip(_FEED_SOURCES, results, strict=True):
        if isinstance(result, BaseException):
            logger.warning(
                "cyber_news: feed %s failed: %s",
                feed.key,
                type(result).__name__,
            )
            collected[feed.key] = []
        else:
            collected[feed.key] = [item for _, item in result]

    return CyberNewsResponse(
        updated_at=datetime.now(UTC).isoformat(),
        feeds=CyberNewsFeeds(**collected),
    )


@router.get("/cyber-news")
async def get_cyber_news() -> CyberNewsResponse:
    async with _cache.lock:
        if _cache.payload is not None and time.monotonic() < _cache.expires_at:
            return _cache.payload

        payload = await _build_payload()
        _cache.payload = payload
        _cache.expires_at = time.monotonic() + CACHE_TTL_SECONDS
        return payload
