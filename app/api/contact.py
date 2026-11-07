from __future__ import annotations

import asyncio
from email.message import EmailMessage
from email.utils import formataddr
import logging
import os
import re
import smtplib
import ssl
from typing import Final

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.rate_limit import enforce_rate_limit

logger = logging.getLogger(__name__)

router = APIRouter(tags=["contact"])

CONTACT_RECIPIENT: Final[str] = "Enlightenism333@gmail.com"
SMTP_TIMEOUT_SECONDS: Final[float] = 15.0
CONTACT_RATE_LIMIT: Final[int] = 5
CONTACT_RATE_WINDOW_SECONDS: Final[int] = 600
_EMAIL_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_HEADER_BREAK_PATTERN: Final[re.Pattern[str]] = re.compile(r"[\r\n]")


class ContactRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    name: str = Field(..., min_length=1, max_length=120)
    email: str = Field(..., min_length=3, max_length=254)
    message: str = Field(..., min_length=1, max_length=5000)

    @field_validator("name")
    @classmethod
    def _validate_name(cls, value: str) -> str:
        if _HEADER_BREAK_PATTERN.search(value):
            raise ValueError("name must not contain line breaks")
        return value

    @field_validator("email")
    @classmethod
    def _validate_email(cls, value: str) -> str:
        if _HEADER_BREAK_PATTERN.search(value) or not _EMAIL_PATTERN.match(value):
            raise ValueError("email must be a valid email address")
        return value


def _smtp_config() -> tuple[str, int, str, str | None, str | None] | None:
    host = os.getenv("IRONCLAW_SMTP_HOST")
    username = os.getenv("IRONCLAW_SMTP_USERNAME") or None
    password = os.getenv("IRONCLAW_SMTP_PASSWORD") or None
    sender = os.getenv("IRONCLAW_SMTP_SENDER") or username
    try:
        port = int(os.getenv("IRONCLAW_SMTP_PORT", "587"))
    except ValueError:
        return None
    if not host or not sender:
        return None
    return host, port, sender, username, password


def _deliver_contact_email(payload: ContactRequest, config: tuple[str, int, str, str | None, str | None]) -> None:
    host, port, sender, username, password = config
    message = EmailMessage()
    message["Subject"] = f"IronClaw Security contact form: {payload.name}"
    message["From"] = sender
    message["To"] = CONTACT_RECIPIENT
    message["Reply-To"] = formataddr((payload.name, payload.email))
    message.set_content(f"Name: {payload.name}\nEmail: {payload.email}\n\n{payload.message}")

    use_tls = os.getenv("IRONCLAW_SMTP_TLS", "true").lower() in ("1", "true", "yes")
    with smtplib.SMTP(host, port, timeout=SMTP_TIMEOUT_SECONDS) as smtp:
        if use_tls:
            smtp.starttls(context=ssl.create_default_context())
        if username and password:
            smtp.login(username, password)
        smtp.send_message(message)


@router.post("/contact", summary="Submit the public contact form")
async def submit_contact(payload: ContactRequest, request: Request) -> dict[str, str]:
    enforce_rate_limit(
        request,
        bucket="contact",
        limit=CONTACT_RATE_LIMIT,
        window_seconds=CONTACT_RATE_WINDOW_SECONDS,
    )

    config = _smtp_config()
    if config is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Contact form is not configured. Please try again later.",
        )

    try:
        await asyncio.to_thread(_deliver_contact_email, payload, config)
    except (smtplib.SMTPException, OSError):
        logger.exception("contact | email delivery failed")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Message could not be sent. Please try again later.",
        ) from None

    logger.info("contact | message delivered")
    return {"status": "sent"}
