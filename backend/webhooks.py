"""
Webhook delivery for deal events.

Registered webhooks receive POST requests with JSON payloads when deal
events occur (funded, shipped, released, refunded, disputed, etc.).

Webhooks are persisted in the database alongside deals. Each webhook has:
- A target URL
- An optional secret for HMAC-SHA256 signature verification
- Event filter (which events to receive)

Delivery is fire-and-forget with a single retry on failure.
"""
import hashlib
import hmac
import json
import logging
import time
from datetime import datetime, timezone
from typing import Optional

import httpx

from backend.database.connection import get_db_session
from backend.database.models import WebhookModel

logger = logging.getLogger(__name__)


def register_webhook(url: str, secret: Optional[str] = None, events: Optional[list[str]] = None) -> dict:
    """Register a new webhook endpoint (persisted to DB)."""
    webhook_id = hashlib.sha256(f"{url}:{time.time()}".encode()).hexdigest()[:16]
    events_list = events or ["*"]

    with get_db_session() as db:
        webhook = WebhookModel(
            id=webhook_id,
            url=url,
            secret=secret,
            events=json.dumps(events_list),
            active=True,
            created_at=datetime.now(timezone.utc),
        )
        db.add(webhook)
        result = webhook.to_dict(redact_secret=True)

    logger.info("Webhook registered: id=%s url=%s events=%s", webhook_id, url, events_list)
    return result


def unregister_webhook(webhook_id: str) -> bool:
    """Remove a webhook by ID."""
    with get_db_session() as db:
        webhook = db.query(WebhookModel).filter(WebhookModel.id == webhook_id).first()
        if not webhook:
            return False
        db.delete(webhook)

    logger.info("Webhook unregistered: id=%s", webhook_id)
    return True


def list_webhooks() -> list[dict]:
    """List all registered webhooks (secrets redacted)."""
    with get_db_session() as db:
        webhooks = db.query(WebhookModel).order_by(WebhookModel.created_at.desc()).all()
        return [w.to_dict(redact_secret=True) for w in webhooks]


def _get_active_webhooks() -> list[dict]:
    """Load active webhooks from DB (with secrets, for delivery)."""
    with get_db_session() as db:
        webhooks = db.query(WebhookModel).filter(WebhookModel.active == True).all()
        return [w.to_dict(redact_secret=False) for w in webhooks]


def _matches_event(webhook: dict, event: str) -> bool:
    """Check if a webhook is subscribed to an event."""
    events = webhook.get("events", ["*"])
    return "*" in events or event in events


def _sign_payload(payload_bytes: bytes, secret: str) -> str:
    """Create HMAC-SHA256 signature for webhook payload."""
    return hmac.new(secret.encode(), payload_bytes, hashlib.sha256).hexdigest()


async def deliver_webhook_event(event: str, deal_id: str, data: dict = None):
    """
    Deliver an event to all matching webhooks.

    Fire-and-forget: failures are logged but don't propagate.
    Single retry with 2-second delay on failure.
    """
    all_webhooks = _get_active_webhooks()
    matching = [w for w in all_webhooks if _matches_event(w, event)]
    if not matching:
        return

    payload = {
        "event": event,
        "deal_id": deal_id,
        "timestamp": int(time.time()),
        "data": data or {},
    }
    payload_bytes = json.dumps(payload, separators=(",", ":")).encode()

    async with httpx.AsyncClient(timeout=10.0) as client:
        for webhook in matching:
            headers = {"Content-Type": "application/json"}
            if webhook.get("secret"):
                headers["X-Webhook-Signature"] = _sign_payload(payload_bytes, webhook["secret"])

            for attempt in range(2):
                try:
                    resp = await client.post(webhook["url"], content=payload_bytes, headers=headers)
                    if resp.status_code < 400:
                        logger.debug("Webhook delivered: %s → %s (status %d)", event, webhook["url"], resp.status_code)
                        break
                    else:
                        logger.warning("Webhook delivery failed: %s → %s (status %d)", event, webhook["url"], resp.status_code)
                except Exception as e:
                    logger.warning("Webhook delivery error: %s → %s (%s)", event, webhook["url"], e)

                if attempt == 0:
                    import asyncio
                    await asyncio.sleep(2)
