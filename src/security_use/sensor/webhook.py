"""Webhook alerter for sending security alerts."""

import asyncio
import logging
from datetime import datetime
from typing import Optional

import httpx

from .models import ActionTaken, AlertPayload, AlertResponse, SecurityEvent

logger = logging.getLogger(__name__)


class WebhookAlerter:
    """Sends security alerts to a webhook endpoint."""

    def __init__(
        self,
        webhook_url: str,
        retry_count: int = 3,
        retry_delay: float = 1.0,
        timeout: float = 10.0,
        headers: Optional[dict[str, str]] = None,
    ):
        """Initialize the webhook alerter.

        Args:
            webhook_url: URL to send alerts to.
            retry_count: Number of retry attempts on failure.
            retry_delay: Delay in seconds between retries (doubles each attempt).
            timeout: Request timeout in seconds.
            headers: Additional headers to include in requests.
        """
        self.webhook_url = webhook_url
        self.retry_count = retry_count
        self.retry_delay = retry_delay
        self.timeout = timeout
        self.headers = headers or {}

    async def send_alert(
        self,
        event: SecurityEvent,
        action_taken: ActionTaken = ActionTaken.LOGGED,
    ) -> AlertResponse:
        """Send a security alert to the webhook.

        Args:
            event: The security event to report.
            action_taken: What action was taken in response.

        Returns:
            AlertResponse with success status and details.
        """
        payload = AlertPayload(
            timestamp=datetime.utcnow(),
            alert=event,
            action_taken=action_taken,
        )

        attempt = 0
        last_error: Optional[str] = None
        last_status = 0

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            while attempt <= self.retry_count:
                try:
                    response = await client.post(
                        self.webhook_url,
                        json=payload.to_dict(),
                        headers={
                            "Content-Type": "application/json",
                            "User-Agent": "security-use-sensor/1.0",
                            **self.headers,
                        },
                    )
                    last_status = response.status_code

                    if 200 <= response.status_code < 300:
                        logger.info(
                            "Alert sent successfully: %s (attempt %d)",
                            event.event_type.value,
                            attempt + 1,
                        )
                        return AlertResponse(
                            success=True,
                            webhook_status=response.status_code,
                            retry_count=attempt,
                        )

                    # Non-success status code
                    last_error = f"HTTP {response.status_code}: {response.text[:200]}"
                    logger.warning(
                        "Webhook returned %d (attempt %d/%d): %s",
                        response.status_code,
                        attempt + 1,
                        self.retry_count + 1,
                        response.text[:100],
                    )

                except httpx.TimeoutException as e:
                    last_error = f"Timeout: {e}"
                    logger.warning(
                        "Webhook timeout (attempt %d/%d): %s",
                        attempt + 1,
                        self.retry_count + 1,
                        e,
                    )

                except httpx.RequestError as e:
                    last_error = f"Request error: {e}"
                    logger.warning(
                        "Webhook request error (attempt %d/%d): %s",
                        attempt + 1,
                        self.retry_count + 1,
                        e,
                    )

                attempt += 1
                if attempt <= self.retry_count:
                    delay = self.retry_delay * (2 ** (attempt - 1))
                    await asyncio.sleep(delay)

        logger.error(
            "Failed to send alert after %d attempts: %s",
            self.retry_count + 1,
            last_error,
        )
        return AlertResponse(
            success=False,
            webhook_status=last_status,
            retry_count=attempt - 1,
            error_message=last_error,
        )

    def send_alert_sync(
        self,
        event: SecurityEvent,
        action_taken: ActionTaken = ActionTaken.LOGGED,
    ) -> AlertResponse:
        """Synchronous version of send_alert for non-async contexts.

        Args:
            event: The security event to report.
            action_taken: What action was taken in response.

        Returns:
            AlertResponse with success status and details.
        """
        payload = AlertPayload(
            timestamp=datetime.utcnow(),
            alert=event,
            action_taken=action_taken,
        )

        attempt = 0
        last_error: Optional[str] = None
        last_status = 0

        with httpx.Client(timeout=self.timeout) as client:
            while attempt <= self.retry_count:
                try:
                    response = client.post(
                        self.webhook_url,
                        json=payload.to_dict(),
                        headers={
                            "Content-Type": "application/json",
                            "User-Agent": "security-use-sensor/1.0",
                            **self.headers,
                        },
                    )
                    last_status = response.status_code

                    if 200 <= response.status_code < 300:
                        logger.info(
                            "Alert sent successfully: %s (attempt %d)",
                            event.event_type.value,
                            attempt + 1,
                        )
                        return AlertResponse(
                            success=True,
                            webhook_status=response.status_code,
                            retry_count=attempt,
                        )

                    last_error = f"HTTP {response.status_code}: {response.text[:200]}"
                    logger.warning(
                        "Webhook returned %d (attempt %d/%d)",
                        response.status_code,
                        attempt + 1,
                        self.retry_count + 1,
                    )

                except httpx.TimeoutException as e:
                    last_error = f"Timeout: {e}"
                    logger.warning(
                        "Webhook timeout (attempt %d/%d)",
                        attempt + 1,
                        self.retry_count + 1,
                    )

                except httpx.RequestError as e:
                    last_error = f"Request error: {e}"
                    logger.warning(
                        "Webhook request error (attempt %d/%d)",
                        attempt + 1,
                        self.retry_count + 1,
                    )

                attempt += 1
                if attempt <= self.retry_count:
                    import time

                    delay = self.retry_delay * (2 ** (attempt - 1))
                    time.sleep(delay)

        logger.error(
            "Failed to send alert after %d attempts: %s",
            self.retry_count + 1,
            last_error,
        )
        return AlertResponse(
            success=False,
            webhook_status=last_status,
            retry_count=attempt - 1,
            error_message=last_error,
        )
