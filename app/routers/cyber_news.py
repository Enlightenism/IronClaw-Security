import asyncio
from datetime import UTC, datetime
import logging
import re

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
import feedparser
import httpx

router = APIRouter(prefix="/api", tags=["cyber-news"])

logger = logging.getLogger(__name__)

FEEDS = {
    "attacks": {
        "source": "CISA Known Exploited Vulnerabilities",
        "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    },
    "hacker_news": {
        "source": "The Hacker News",
        "url": "https://feeds.feedburner.com/TheHackersNews",
    },
    "cisa": {
        "source": "CISA",
        "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    },
    "bleeping_computer": {
        "source": "BleepingComputer",
        "url": "https://www.bleepingcomputer.com/feed/",
    },
}

CACHE_TTL_SECONDS = 600
MAX_ITEMS_PER_FEED = 15

_cache = {
    "data": None,
    "expires_at": 0,
}

TAG_PATTERN = re.compile(r"<[^>]+>")


def clean_text(value):
    if not value:
        return ""

    return TAG_PATTERN.sub("", value).strip()


def parse_published(entry):
    published = entry.get("published") or entry.get("updated") or entry.get("dc:date") or entry.get("published_parsed") or entry.get("updated_parsed")

    if not published:
        return None

    try:
        if isinstance(published, str):
            parsed = feedparser._parse_date(published)
            if parsed:
                return datetime.fromtimestamp(parsed, tz=UTC).isoformat()
            return None

        return datetime.fromtimestamp(
            published.timestamp() if hasattr(published, "timestamp") else published,
            tz=UTC,
        ).isoformat()
    except Exception:
        return None


def parse_feed(feed_key, feed_config, xml_text):
    parsed = feedparser.parse(xml_text)

    if parsed.bozo and not parsed.entries:
        logger.warning(
            "cyber_news: feed parse failed for %s: %s",
            feed_key,
            getattr(parsed, "bozo_exception", "unknown parse error"),
        )

    entries = parsed.entries[:MAX_ITEMS_PER_FEED]
    items = []

    for entry in entries:
        title = clean_text(entry.get("title", ""))
        link = entry.get("link", "")

        if not title or not link:
            continue

        items.append(
            {
                "title": title,
                "link": link,
                "published_at": parse_published(entry),
                "source": feed_config["source"],
            }
        )

    items.sort(
        key=lambda item: item["published_at"] or "",
        reverse=True,
    )

    return feed_key, items


async def fetch_feed(client, feed_key, feed_config):
    try:
        response = await client.get(
            feed_config["url"],
            headers={
                "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"),
                "Accept": ("application/rss+xml, application/xml, text/xml, */*"),
            },
        )

        if response.status_code != 200:
            logger.warning(
                "cyber_news: feed request failed for %s: status=%s body=%s",
                feed_key,
                response.status_code,
                response.text[:300],
            )
            return feed_key, []

        content_type = response.headers.get("content-type", "")
        logger.info(
            "cyber_news: feed fetched for %s: status=%s content_type=%s bytes=%s",
            feed_key,
            response.status_code,
            content_type,
            len(response.content),
        )

        return parse_feed(feed_key, feed_config, response.text)
    except Exception as exc:
        logger.exception("cyber_news: feed fetch failed for %s: %s", feed_key, exc)
        return feed_key, []


async def get_cyber_news():
    now = datetime.now(UTC).timestamp()

    if _cache["data"] and _cache["expires_at"] > now:
        return _cache["data"]

    async with httpx.AsyncClient(
        timeout=15.0,
        follow_redirects=True,
    ) as client:
        results = await asyncio.gather(*(fetch_feed(client, feed_key, feed_config) for feed_key, feed_config in FEEDS.items()))

    feeds = {
        "attacks": [],
        "hacker_news": [],
        "cisa": [],
        "bleeping_computer": [],
    }

    for feed_key, items in results:
        feeds[feed_key] = items

    if not any(feeds.values()):
        raise HTTPException(
            status_code=503,
            detail="All cybersecurity news feeds are currently unavailable.",
        )

    response_data = {
        "updated_at": datetime.now(UTC).isoformat(),
        "feeds": feeds,
    }

    _cache["data"] = response_data
    _cache["expires_at"] = now + CACHE_TTL_SECONDS

    return response_data


@router.get("/cyber-news")
async def cyber_news():
    data = await get_cyber_news()
    return JSONResponse(content=data)
