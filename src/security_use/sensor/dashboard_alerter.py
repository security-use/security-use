"""Dashboard alerter for sending runtime security alerts."""

import logging
import os
from datetime import datetime
from typing import Optional
from urllib.parse import urljoin, urlparse

import httpx

from .circuit_breaker import CircuitBreaker, CircuitStats
from .models import ActionTaken, SecurityEvent

logger = logging.getLogger(__name__)

# Default dashboard API URL
DEFAULT_DASHBOARD_URL = "https://lhirdknhtzkqynfavdao.supabase.co/functions/v1"

# Reduced defaults for better production behavior
DEFAULT_TIMEOUT = 2.0  # Reduced from 10.0
DEFAULT_RETRY_COUNT = 2  # Reduced from 3


class DashboardAlerter:
    """Send security alerts to the SecurityUse dashboard.

    Uses API key authentication to send runtime attack alerts directly
    to the dashboard without requiring a custom webhook URL.

    Usage:
        from security_use.sensor import DashboardAlerter

        # Uses SECURITY_USE_API_KEY environment variable
        alerter = DashboardAlerter()

        # Or pass API key directly
        alerter = DashboardAlerter(api_key="su_...")
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        dashboard_url: Optional[str] = None,
        timeout: float = DEFAULT_TIMEOUT,
        retry_count: int = DEFAULT_RETRY_COUNT,
        circuit_failure_threshold: int = 5,
        circuit_reset_timeout: float = 60.0,
    ):
        """Initialize the dashboard alerter.

        Args:
            api_key: SecurityUse API key. If not provided, reads from
                     SECURITY_USE_API_KEY environment variable.
            dashboard_url: Base URL for the dashboard API. Defaults to
                          SecurityUse cloud.
            timeout: Request timeout in seconds (default: 2.0).
            retry_count: Number of retry attempts on failure (default: 2).
            circuit_failure_threshold: Consecutive failures before opening circuit.
            circuit_reset_timeout: Seconds to wait before trying again (half-open).
        """
        self.api_key = api_key or os.environ.get("SECURITY_USE_API_KEY")
        self.dashboard_url = dashboard_url or os.environ.get(
            "SECURITY_USE_DASHBOARD_URL", DEFAULT_DASHBOARD_URL
        )
        self.timeout = timeout
        self.retry_count = retry_count

        # Validate configuration
        self._config_valid = True
        self._config_error: Optional[str] = None

        if not self.api_key:
            logger.warning(
                "No API key provided. Set SECURITY_USE_API_KEY environment variable "
                "or pass api_key parameter to enable dashboard alerting."
            )
            self._config_valid = False
            self._config_error = "No API key configured"

        # Validate dashboard URL
        if self.dashboard_url:
            try:
                parsed = urlparse(self.dashboard_url)
                if not parsed.scheme or not parsed.netloc:
                    raise ValueError("Invalid URL format: missing scheme or host")
            except Exception as e:
                logger.error(f"Invalid dashboard URL '{self.dashboard_url}': {e}")
                self._config_valid = False
                self._config_error = f"Invalid dashboard URL: {e}"

        # Initialize circuit breaker
        self._circuit_breaker = CircuitBreaker(
            failure_threshold=circuit_failure_threshold,
            reset_timeout=circuit_reset_timeout,
            name="dashboard_alerter",
        )

        # Shared HTTP clients for connection reuse (lazy initialization)
        self._async_client: Optional[httpx.AsyncClient] = None
        self._sync_client: Optional[httpx.Client] = None

    @property
    def is_configured(self) -> bool:
        """Check if the alerter is properly configured."""
        return bool(self.api_key) and self._config_valid

    @property
    def config_error(self) -> Optional[str]:
        """Get configuration error message if any."""
        return self._config_error

    def _get_async_client(self) -> httpx.AsyncClient:
        """Get or create the async HTTP client."""
        if self._async_client is None or self._async_client.is_closed:
            self._async_client = httpx.AsyncClient(
                timeout=self.timeout,
                limits=httpx.Limits(
                    max_keepalive_connections=5,
                    max_connections=10,
                ),
            )
        return self._async_client

    def _get_sync_client(self) -> httpx.Client:
        """Get or create the sync HTTP client."""
        if self._sync_client is None or self._sync_client.is_closed:
            self._sync_client = httpx.Client(
                timeout=self.timeout,
                limits=httpx.Limits(
                    max_keepalive_connections=5,
                    max_connections=10,
                ),
            )
        return self._sync_client

    async def close(self) -> None:
        """Close the async HTTP client."""
        if self._async_client is not None:
            await self._async_client.aclose()
            self._async_client = None

    def close_sync(self) -> None:
        """Close the sync HTTP client."""
        if self._sync_client is not None:
            self._sync_client.close()
            self._sync_client = None

    def _build_payload(
        self,
        event: SecurityEvent,
        action: ActionTaken,
    ) -> dict:
        """Build the alert payload for the dashboard.

        Args:
            event: The security event that was detected.
            action: The action taken (blocked or logged).

        Returns:
            Dictionary payload for the API.
        """
        # Get the attack type value (handle both enum and string)
        attack_type = (
            event.event_type.value if hasattr(event.event_type, "value") else str(event.event_type)
        )

        # Get matched pattern info
        pattern_str = ""
        matched_value = ""
        if event.matched_pattern:
            pattern_str = event.matched_pattern.pattern
            matched_value = event.matched_pattern.matched_value or ""

        return {
            "scan_type": "runtime",
            "status": "completed",
            "findings": [
                {
                    "finding_type": "attack",
                    "category": "runtime",
                    "severity": event.severity.upper()
                    if isinstance(event.severity, str)
                    else event.severity,
                    "title": f"{attack_type.replace('_', ' ').title()} attack detected",
                    "description": event.description,
                    "pattern": pattern_str,
                    "payload_preview": matched_value[:500] if matched_value else None,
                    "recommendation": self._get_recommendation(attack_type),
                    "file_path": event.path,
                    "metadata": {
                        "source_ip": event.source_ip,
                        "method": event.method,
                        "user_agent": event.request_headers.get("user-agent")
                        if event.request_headers
                        else None,
                        "action_taken": action.value if hasattr(action, "value") else str(action),
                        "confidence": event.confidence,
                        "timestamp": event.timestamp.isoformat()
                        if event.timestamp
                        else datetime.utcnow().isoformat(),
                    },
                }
            ],
            "metadata": {
                "sensor_version": "0.2.9",
                "alert_type": "runtime_attack",
            },
        }

    def _get_recommendation(self, attack_type: str) -> str:
        """Get remediation recommendation for attack type."""
        recommendations = {
            "sql_injection": "Review and parameterize database queries. Use ORM or prepared statements.",
            "xss": "Sanitize and escape user input before rendering. Use Content-Security-Policy headers.",
            "path_traversal": "Validate file paths and use allowlists. Never construct paths from user input.",
            "command_injection": "Avoid shell commands with user input. Use subprocess with shell=False.",
            "rate_limit": "Implement proper rate limiting and consider blocking the source IP.",
            "suspicious_headers": "Investigate the source. May indicate automated scanning or attack tools.",
        }
        return recommendations.get(
            attack_type.lower().replace(" ", "_"),
            "Review the attack pattern and implement appropriate input validation.",
        )

    async def send_alert(
        self,
        event: SecurityEvent,
        action: ActionTaken,
    ) -> bool:
        """Send an alert to the dashboard asynchronously.

        Args:
            event: The security event that was detected.
            action: The action taken (blocked or logged).

        Returns:
            True if the alert was sent successfully, False otherwise.
        """
        # Early return if not configured (graceful degradation)
        if not self.is_configured:
            logger.debug(f"Dashboard alerter not configured ({self._config_error}), skipping alert")
            return False

        # Check circuit breaker first
        if not self._circuit_breaker.allow_request():
            logger.debug(f"Circuit breaker open, skipping alert: {event.event_type.value}")
            return False

        payload = self._build_payload(event, action)
        url = urljoin(self.dashboard_url + "/", "runtime-alert")

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        client = self._get_async_client()

        for attempt in range(self.retry_count):
            try:
                response = await client.post(url, json=payload, headers=headers)

                if response.status_code in (200, 201, 202):
                    self._circuit_breaker.record_success()
                    logger.info(f"Alert sent to dashboard: {event.event_type.value}")
                    return True
                elif response.status_code == 401:
                    # Auth error, don't count as circuit failure
                    logger.error("Invalid API key for dashboard alerting")
                    return False
                elif response.status_code == 404:
                    # Fallback to scan-upload endpoint
                    url = urljoin(self.dashboard_url + "/", "scan-upload")
                    continue
                else:
                    logger.warning(
                        f"Dashboard alert failed (attempt {attempt + 1}): "
                        f"{response.status_code} - {response.text}"
                    )

            except (httpx.TimeoutException, httpx.ConnectError) as e:
                logger.warning(f"Dashboard connection failed (attempt {attempt + 1}): {e}")
            except Exception as e:
                logger.error(f"Dashboard alert error (attempt {attempt + 1}): {e}")

        # All attempts failed
        self._circuit_breaker.record_failure()
        return False

    def send_alert_sync(
        self,
        event: SecurityEvent,
        action: ActionTaken,
    ) -> bool:
        """Send an alert to the dashboard synchronously.

        Args:
            event: The security event that was detected.
            action: The action taken (blocked or logged).

        Returns:
            True if the alert was sent successfully, False otherwise.
        """
        # Early return if not configured (graceful degradation)
        if not self.is_configured:
            logger.debug(f"Dashboard alerter not configured ({self._config_error}), skipping alert")
            return False

        # Check circuit breaker first
        if not self._circuit_breaker.allow_request():
            logger.debug(f"Circuit breaker open, skipping alert: {event.event_type.value}")
            return False

        payload = self._build_payload(event, action)
        url = urljoin(self.dashboard_url + "/", "runtime-alert")

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        client = self._get_sync_client()

        for attempt in range(self.retry_count):
            try:
                response = client.post(url, json=payload, headers=headers)

                if response.status_code in (200, 201, 202):
                    self._circuit_breaker.record_success()
                    logger.info(f"Alert sent to dashboard: {event.event_type.value}")
                    return True
                elif response.status_code == 401:
                    # Auth error, don't count as circuit failure
                    logger.error("Invalid API key for dashboard alerting")
                    return False
                elif response.status_code == 404:
                    # Fallback to scan-upload endpoint
                    url = urljoin(self.dashboard_url + "/", "scan-upload")
                    continue
                else:
                    logger.warning(
                        f"Dashboard alert failed (attempt {attempt + 1}): "
                        f"{response.status_code} - {response.text}"
                    )

            except (httpx.TimeoutException, httpx.ConnectError) as e:
                logger.warning(f"Dashboard connection failed (attempt {attempt + 1}): {e}")
            except Exception as e:
                logger.error(f"Dashboard alert error (attempt {attempt + 1}): {e}")

        # All attempts failed
        self._circuit_breaker.record_failure()
        return False

    @property
    def circuit_breaker_stats(self) -> CircuitStats:
        """Get circuit breaker statistics."""
        return self._circuit_breaker.stats
