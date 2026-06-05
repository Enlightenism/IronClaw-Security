from __future__ import annotations

import logging
import os
import threading
from typing import TYPE_CHECKING

from app.services.notification_service import (
    EmailConfig,
    NotificationEngine,
    PagerDutyConfig,
    SlackConfig,
    build_notification_engine,
)

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

_lock: threading.Lock = threading.Lock()
_instance: NotificationEngine | None = None


def _build_from_env() -> NotificationEngine:
    dry_run: bool = os.getenv("IRONCLAW_NOTIFICATION_DRY_RUN", "true").lower() in (
        "1",
        "true",
        "yes",
    )

    email_config: EmailConfig | None = None
    smtp_host = os.getenv("IRONCLAW_SMTP_HOST")
    smtp_port_raw = os.getenv("IRONCLAW_SMTP_PORT", "587")
    smtp_sender = os.getenv("IRONCLAW_SMTP_SENDER")
    smtp_recipients_raw = os.getenv("IRONCLAW_SMTP_RECIPIENTS", "")
    smtp_username = os.getenv("IRONCLAW_SMTP_USERNAME")
    smtp_password = os.getenv("IRONCLAW_SMTP_PASSWORD")
    smtp_tls = os.getenv("IRONCLAW_SMTP_TLS", "true").lower() in ("1", "true", "yes")

    if smtp_host and smtp_sender and smtp_recipients_raw:
        recipients = tuple(r.strip() for r in smtp_recipients_raw.split(",") if r.strip())
        if recipients:
            try:
                email_config = EmailConfig(
                    smtp_host=smtp_host,
                    smtp_port=int(smtp_port_raw),
                    sender_address=smtp_sender,
                    recipients=recipients,
                    use_tls=smtp_tls,
                    username=smtp_username or None,
                    password=smtp_password or None,
                )
            except Exception:  # noqa: BLE001
                logger.warning("notification_engine | email_config build failed — email disabled")

    slack_config: SlackConfig | None = None
    slack_webhook = os.getenv("IRONCLAW_SLACK_WEBHOOK_URL")
    slack_channel = os.getenv("IRONCLAW_SLACK_CHANNEL", "#ironclaw-alerts")
    slack_username = os.getenv("IRONCLAW_SLACK_USERNAME", "IronClaw-Security")
    slack_icon = os.getenv("IRONCLAW_SLACK_ICON_EMOJI", ":shield:")
    slack_mention = os.getenv("IRONCLAW_SLACK_MENTION_ON_CRITICAL") or None

    if slack_webhook:
        try:
            slack_config = SlackConfig(
                webhook_url=slack_webhook,
                channel=slack_channel,
                username=slack_username,
                icon_emoji=slack_icon,
                mention_on_critical=slack_mention,
            )
        except Exception:  # noqa: BLE001
            logger.warning("notification_engine | slack_config build failed — slack disabled")

    pagerduty_config: PagerDutyConfig | None = None
    pd_routing_key = os.getenv("IRONCLAW_PAGERDUTY_ROUTING_KEY")
    pd_service_name = os.getenv("IRONCLAW_PAGERDUTY_SERVICE_NAME", "IronClaw-Security")
    pd_dedup_prefix = os.getenv("IRONCLAW_PAGERDUTY_DEDUP_KEY_PREFIX", "ironclaw")
    pd_default_severity = os.getenv("IRONCLAW_PAGERDUTY_DEFAULT_SEVERITY", "critical")  # type: ignore[assignment]

    if pd_routing_key:
        try:
            pagerduty_config = PagerDutyConfig(
                routing_key=pd_routing_key,
                service_name=pd_service_name,
                default_severity=pd_default_severity,  # type: ignore[arg-type]
                dedup_key_prefix=pd_dedup_prefix,
            )
        except Exception:  # noqa: BLE001
            logger.warning("notification_engine | pagerduty_config build failed — pagerduty disabled")

    engine = build_notification_engine(
        email_config=email_config,
        slack_config=slack_config,
        pagerduty_config=pagerduty_config,
        dry_run=dry_run,
    )

    channels_active = []
    if email_config:
        channels_active.append("email")
    if slack_config:
        channels_active.append("slack")
    if pagerduty_config:
        channels_active.append("pagerduty")

    logger.info(
        "notification_engine | singleton initialized | dry_run=%s channels=%s",
        dry_run,
        channels_active or ["none"],
    )
    return engine


def get_notification_engine() -> NotificationEngine:
    global _instance  # noqa: PLW0603
    if _instance is not None:
        return _instance
    with _lock:
        if _instance is None:
            _instance = _build_from_env()
    return _instance


def reset_notification_engine(engine: NotificationEngine | None = None) -> None:
    global _instance  # noqa: PLW0603
    with _lock:
        _instance = engine
    logger.debug("notification_engine | singleton reset | replaced=%s", engine is not None)
