"""Framework middleware adapters for security monitoring."""

import asyncio
import logging
import threading
from io import BytesIO
from typing import Any, Callable, Coroutine, Optional
from urllib.parse import parse_qs

from .alert_queue import get_alert_queue
from .config import SensorConfig, create_config
from .dashboard_alerter import DashboardAlerter
from .detector import AttackDetector
from .models import ActionTaken, RequestData
from .webhook import WebhookAlerter

logger = logging.getLogger(__name__)


# Global alert stats tracking (thread-safe)
class _AlertStats:
    """Thread-safe alert statistics tracking."""

    def __init__(self):
        self._lock = threading.Lock()
        self._sent = 0
        self._failed = 0

    def record_sent(self) -> None:
        """Record a successfully sent alert."""
        with self._lock:
            self._sent += 1

    def record_failed(self) -> None:
        """Record a failed alert."""
        with self._lock:
            self._failed += 1

    @property
    def sent(self) -> int:
        """Get count of sent alerts."""
        with self._lock:
            return self._sent

    @property
    def failed(self) -> int:
        """Get count of failed alerts."""
        with self._lock:
            return self._failed

    def reset(self) -> None:
        """Reset all statistics."""
        with self._lock:
            self._sent = 0
            self._failed = 0

    def to_dict(self) -> dict:
        """Get stats as dictionary."""
        with self._lock:
            return {"sent": self._sent, "failed": self._failed}


_alert_stats = _AlertStats()


def get_alert_stats() -> dict:
    """Get alert delivery statistics.

    Returns:
        Dictionary with 'sent' and 'failed' counts.
    """
    return _alert_stats.to_dict()


def reset_alert_stats() -> None:
    """Reset alert statistics (mainly for testing)."""
    _alert_stats.reset()


def fire_and_forget(
    coro: Coroutine[Any, Any, Any],
    name: str = "alert_task",
) -> asyncio.Task:
    """Create a task that logs exceptions instead of swallowing them.

    This wrapper ensures that exceptions in fire-and-forget async tasks
    are properly logged rather than being silently ignored.

    Args:
        coro: The coroutine to run.
        name: Task name for logging/debugging.

    Returns:
        The created task.
    """

    async def wrapper():
        try:
            result = await coro
            # Track success if the alert was sent (result is True or truthy)
            if result:
                _alert_stats.record_sent()
            else:
                _alert_stats.record_failed()
            return result
        except asyncio.CancelledError:
            logger.debug(f"Task '{name}' was cancelled")
            raise
        except Exception as e:
            _alert_stats.record_failed()
            logger.error(
                f"Task '{name}' failed with exception: {type(e).__name__}: {e}",
                exc_info=True,
            )
            return None

    task = asyncio.create_task(wrapper(), name=name)
    return task


class SecurityMiddleware:
    """ASGI middleware for FastAPI/Starlette security monitoring.

    Usage with dashboard (recommended):
        from fastapi import FastAPI
        from security_use.sensor import SecurityMiddleware

        app = FastAPI()
        app.add_middleware(
            SecurityMiddleware,
            api_key="su_...",  # Or set SECURITY_USE_API_KEY env var
            block_on_detection=True,
        )

    Usage with auto-detection of vulnerable endpoints:
        app.add_middleware(
            SecurityMiddleware,
            auto_detect_vulnerable=True,
            project_path="./",
        )

    Legacy usage with webhook:
        app.add_middleware(
            SecurityMiddleware,
            webhook_url="https://your-webhook.com/alerts",
        )
    """

    def __init__(
        self,
        app: Any,
        api_key: Optional[str] = None,
        webhook_url: Optional[str] = None,
        block_on_detection: bool = True,
        excluded_paths: Optional[list[str]] = None,
        watch_paths: Optional[list[str]] = None,
        auto_detect_vulnerable: bool = False,
        project_path: Optional[str] = None,
        enabled_detectors: Optional[list[str]] = None,
        rate_limit_threshold: int = 100,
        config: Optional[SensorConfig] = None,
    ):
        """Initialize the security middleware.

        Args:
            app: The ASGI application.
            api_key: SecurityUse API key for dashboard alerting.
            webhook_url: URL to send alerts to (legacy).
            block_on_detection: Return 403 on attack detection.
            excluded_paths: Paths to skip monitoring.
            watch_paths: Only monitor these paths (None = all).
            auto_detect_vulnerable: Auto-detect vulnerable endpoints.
            project_path: Project path for auto-detection.
            enabled_detectors: List of detector types to enable.
            rate_limit_threshold: Requests per minute per IP.
            config: Optional pre-configured SensorConfig.
        """
        self.app = app

        if config:
            self.config = config
        else:
            self.config = create_config(
                api_key=api_key,
                webhook_url=webhook_url,
                block_on_detection=block_on_detection,
                excluded_paths=excluded_paths,
                watch_paths=watch_paths,
                auto_detect_vulnerable=auto_detect_vulnerable,
                project_path=project_path,
                enabled_detectors=enabled_detectors,
                rate_limit_threshold=rate_limit_threshold,
            )

        # Auto-detect vulnerable endpoints if requested
        if self.config.auto_detect_vulnerable and self.config.project_path:
            self._detect_vulnerable_endpoints()

        self.detector = AttackDetector(
            enabled_detectors=self.config.enabled_detectors,
            rate_limit_threshold=self.config.rate_limit_threshold,
            rate_limit_window=self.config.rate_limit_window,
            rate_limit_cleanup_interval=self.config.rate_limit_cleanup_interval,
            rate_limit_max_ips=self.config.rate_limit_max_ips,
        )

        # Set up alerters based on config
        self.dashboard_alerter: Optional[DashboardAlerter] = None
        self.webhook_alerter: Optional[WebhookAlerter] = None

        if self.config.alert_mode in ("dashboard", "both"):
            self.dashboard_alerter = DashboardAlerter(
                api_key=self.config.api_key,
                dashboard_url=self.config.dashboard_url,
                timeout=self.config.webhook_timeout,
                retry_count=self.config.webhook_retry_count,
            )

        if self.config.alert_mode in ("webhook", "both") and self.config.webhook_url:
            self.webhook_alerter = WebhookAlerter(
                webhook_url=self.config.webhook_url,
                retry_count=self.config.webhook_retry_count,
                timeout=self.config.webhook_timeout,
                headers=self.config.webhook_headers,
            )

        # Log configuration
        if self.config.watch_paths:
            logger.info(f"SecurityMiddleware monitoring {len(self.config.watch_paths)} paths")
        else:
            logger.info("SecurityMiddleware monitoring all paths")

    def _detect_vulnerable_endpoints(self) -> None:
        """Auto-detect vulnerable endpoints from project scan."""
        try:
            from .endpoint_analyzer import VulnerableEndpointDetector

            detector = VulnerableEndpointDetector()
            paths = detector.get_watch_paths(self.config.project_path)

            if paths:
                # Merge with existing watch_paths
                existing = set(self.config.watch_paths or [])
                self.config.watch_paths = list(existing | set(paths))
                logger.info(f"Auto-detected {len(paths)} vulnerable endpoints to monitor")
            else:
                logger.info("No vulnerable endpoints detected")

        except Exception as e:
            logger.warning(f"Failed to auto-detect vulnerable endpoints: {e}")

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        """ASGI interface."""
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Extract request data
        path = scope.get("path", "/")

        # Check if path should be monitored
        if not self.config.should_monitor_path(path):
            await self.app(scope, receive, send)
            return

        # Buffer the body and create a replay receive function
        body, receive_wrapper = await self._buffer_body(receive)

        # Build request data for analysis
        request_data = self._build_request_data(scope, body)

        # Analyze for attacks
        events = self.detector.analyze_request(request_data)

        if events:
            action = ActionTaken.BLOCKED if self.config.block_on_detection else ActionTaken.LOGGED

            # Send alerts asynchronously with error handling
            for event in events:
                if self.dashboard_alerter:
                    fire_and_forget(
                        self.dashboard_alerter.send_alert(event, action),
                        name=f"dashboard_alert_{event.event_type.value}",
                    )
                if self.webhook_alerter:
                    fire_and_forget(
                        self.webhook_alerter.send_alert(event, action),
                        name=f"webhook_alert_{event.event_type.value}",
                    )

            if self.config.block_on_detection:
                # Return 403 Forbidden
                await self._send_blocked_response(send, events[0])
                return

        # Continue to application with replay receive that provides the buffered body
        await self.app(scope, receive_wrapper, send)

    async def _buffer_body(self, receive: Callable) -> tuple[bytes, Callable]:
        """Buffer the entire request body and create a replay receive function.

        Returns:
            Tuple of (full_body, receive_wrapper) where receive_wrapper
            can be passed to the app to replay the body.
        """
        body_parts = []

        # Read all body chunks
        while True:
            message = await receive()
            if message["type"] == "http.request":
                body_parts.append(message.get("body", b""))
                if not message.get("more_body", False):
                    break
            elif message["type"] == "http.disconnect":
                break

        full_body = b"".join(body_parts)

        # Handle large bodies - truncate for analysis if needed
        max_body_size = getattr(self.config, "max_body_size", 1024 * 1024)
        analysis_body = full_body[:max_body_size] if len(full_body) > max_body_size else full_body

        # Create a receive function that replays the buffered body
        body_sent = False

        async def receive_wrapper() -> dict:
            nonlocal body_sent
            if not body_sent:
                body_sent = True
                return {
                    "type": "http.request",
                    "body": full_body,
                    "more_body": False,
                }
            # After body is sent, wait for disconnect or return empty
            return {
                "type": "http.request",
                "body": b"",
                "more_body": False,
            }

        return analysis_body, receive_wrapper

    def _build_request_data(self, scope: dict, body: bytes) -> RequestData:
        """Build request data from ASGI scope and buffered body."""
        method = scope.get("method", "GET")
        path = scope.get("path", "/")
        query_string = scope.get("query_string", b"").decode("utf-8")

        # Parse query params
        query_params = {}
        if query_string:
            parsed = parse_qs(query_string)
            query_params = {k: v[0] if len(v) == 1 else v for k, v in parsed.items()}

        # Extract headers
        headers = {}
        for key, value in scope.get("headers", []):
            headers[key.decode("utf-8").lower()] = value.decode("utf-8")

        # Get client IP
        client = scope.get("client")
        source_ip = client[0] if client else "unknown"

        # Check for forwarded IP
        if "x-forwarded-for" in headers:
            source_ip = headers["x-forwarded-for"].split(",")[0].strip()
        elif "x-real-ip" in headers:
            source_ip = headers["x-real-ip"]

        return RequestData(
            method=method,
            path=path,
            query_params=query_params,
            headers=headers,
            body=body.decode("utf-8", errors="replace") if body else None,
            source_ip=source_ip,
        )

    async def _send_blocked_response(self, send: Callable, event: Any) -> None:
        """Send a 403 Forbidden response."""
        body = b'{"error": "Request blocked due to security policy"}'

        await send(
            {
                "type": "http.response.start",
                "status": 403,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                ],
            }
        )
        await send(
            {
                "type": "http.response.body",
                "body": body,
            }
        )


class FlaskSecurityMiddleware:
    """WSGI middleware for Flask security monitoring.

    Usage with dashboard (recommended):
        from flask import Flask
        from security_use.sensor import FlaskSecurityMiddleware

        app = Flask(__name__)
        app.wsgi_app = FlaskSecurityMiddleware(
            app.wsgi_app,
            api_key="su_...",  # Or set SECURITY_USE_API_KEY env var
        )

    Usage with auto-detection:
        app.wsgi_app = FlaskSecurityMiddleware(
            app.wsgi_app,
            auto_detect_vulnerable=True,
            project_path="./",
        )
    """

    def __init__(
        self,
        app: Any,
        api_key: Optional[str] = None,
        webhook_url: Optional[str] = None,
        block_on_detection: bool = True,
        excluded_paths: Optional[list[str]] = None,
        watch_paths: Optional[list[str]] = None,
        auto_detect_vulnerable: bool = False,
        project_path: Optional[str] = None,
        enabled_detectors: Optional[list[str]] = None,
        rate_limit_threshold: int = 100,
        config: Optional[SensorConfig] = None,
    ):
        """Initialize the Flask security middleware.

        Args:
            app: The WSGI application.
            api_key: SecurityUse API key for dashboard alerting.
            webhook_url: URL to send alerts to (legacy).
            block_on_detection: Return 403 on attack detection.
            excluded_paths: Paths to skip monitoring.
            watch_paths: Only monitor these paths (None = all).
            auto_detect_vulnerable: Auto-detect vulnerable endpoints.
            project_path: Project path for auto-detection.
            enabled_detectors: List of detector types to enable.
            rate_limit_threshold: Requests per minute per IP.
            config: Optional pre-configured SensorConfig.
        """
        self.app = app

        if config:
            self.config = config
        else:
            self.config = create_config(
                api_key=api_key,
                webhook_url=webhook_url,
                block_on_detection=block_on_detection,
                excluded_paths=excluded_paths,
                watch_paths=watch_paths,
                auto_detect_vulnerable=auto_detect_vulnerable,
                project_path=project_path,
                enabled_detectors=enabled_detectors,
                rate_limit_threshold=rate_limit_threshold,
            )

        # Auto-detect vulnerable endpoints if requested
        if self.config.auto_detect_vulnerable and self.config.project_path:
            self._detect_vulnerable_endpoints()

        self.detector = AttackDetector(
            enabled_detectors=self.config.enabled_detectors,
            rate_limit_threshold=self.config.rate_limit_threshold,
            rate_limit_window=self.config.rate_limit_window,
            rate_limit_cleanup_interval=self.config.rate_limit_cleanup_interval,
            rate_limit_max_ips=self.config.rate_limit_max_ips,
        )

        # Set up alerters based on config
        self.dashboard_alerter: Optional[DashboardAlerter] = None
        self.webhook_alerter: Optional[WebhookAlerter] = None

        if self.config.alert_mode in ("dashboard", "both"):
            self.dashboard_alerter = DashboardAlerter(
                api_key=self.config.api_key,
                dashboard_url=self.config.dashboard_url,
                timeout=self.config.webhook_timeout,
                retry_count=self.config.webhook_retry_count,
            )

        if self.config.alert_mode in ("webhook", "both") and self.config.webhook_url:
            self.webhook_alerter = WebhookAlerter(
                webhook_url=self.config.webhook_url,
                retry_count=self.config.webhook_retry_count,
                timeout=self.config.webhook_timeout,
                headers=self.config.webhook_headers,
            )

        # Get shared alert queue for non-blocking alert delivery
        self._alert_queue = get_alert_queue()

        # Log configuration
        if self.config.watch_paths:
            logger.info(f"FlaskSecurityMiddleware monitoring {len(self.config.watch_paths)} paths")
        else:
            logger.info("FlaskSecurityMiddleware monitoring all paths")

    def _detect_vulnerable_endpoints(self) -> None:
        """Auto-detect vulnerable endpoints from project scan."""
        try:
            from .endpoint_analyzer import VulnerableEndpointDetector

            detector = VulnerableEndpointDetector()
            paths = detector.get_watch_paths(self.config.project_path)

            if paths:
                existing = set(self.config.watch_paths or [])
                self.config.watch_paths = list(existing | set(paths))
                logger.info(f"Auto-detected {len(paths)} vulnerable endpoints to monitor")
            else:
                logger.info("No vulnerable endpoints detected")

        except Exception as e:
            logger.warning(f"Failed to auto-detect vulnerable endpoints: {e}")

    def __call__(self, environ: dict, start_response: Callable) -> Any:
        """WSGI interface."""
        path = environ.get("PATH_INFO", "/")

        # Check if path should be monitored
        if not self.config.should_monitor_path(path):
            return self.app(environ, start_response)

        request_data = self._extract_request_data(environ)

        # Analyze for attacks
        events = self.detector.analyze_request(request_data)

        if events:
            action = ActionTaken.BLOCKED if self.config.block_on_detection else ActionTaken.LOGGED

            # Queue alerts for background sending (non-blocking)
            for event in events:
                if self.dashboard_alerter:
                    self._alert_queue.enqueue(event, action, self.dashboard_alerter)
                if self.webhook_alerter:
                    self._alert_queue.enqueue(event, action, self.webhook_alerter)

            if self.config.block_on_detection:
                # Return 403 Forbidden
                return self._blocked_response(start_response)

        return self.app(environ, start_response)

    def _extract_request_data(self, environ: dict) -> RequestData:
        """Extract request data from WSGI environ."""
        method = environ.get("REQUEST_METHOD", "GET")
        path = environ.get("PATH_INFO", "/")
        query_string = environ.get("QUERY_STRING", "")

        # Parse query params
        query_params = {}
        if query_string:
            parsed = parse_qs(query_string)
            query_params = {k: v[0] if len(v) == 1 else v for k, v in parsed.items()}

        # Extract headers
        headers = {}
        for key, value in environ.items():
            if key.startswith("HTTP_"):
                header_name = key[5:].lower().replace("_", "-")
                headers[header_name] = value
            elif key in ("CONTENT_TYPE", "CONTENT_LENGTH"):
                headers[key.lower().replace("_", "-")] = value

        # Get client IP
        source_ip = environ.get("REMOTE_ADDR", "unknown")
        if "HTTP_X_FORWARDED_FOR" in environ:
            source_ip = environ["HTTP_X_FORWARDED_FOR"].split(",")[0].strip()
        elif "HTTP_X_REAL_IP" in environ:
            source_ip = environ["HTTP_X_REAL_IP"]

        # Read body
        body = None
        content_length = environ.get("CONTENT_LENGTH")
        if content_length:
            try:
                length = int(content_length)
                if length > 0:
                    wsgi_input = environ.get("wsgi.input")
                    if wsgi_input:
                        body_bytes = wsgi_input.read(length)
                        body = body_bytes.decode("utf-8", errors="replace")
                        # Reset stream for the application
                        environ["wsgi.input"] = BytesIO(body_bytes)
            except (ValueError, TypeError):
                pass

        return RequestData(
            method=method,
            path=path,
            query_params=query_params,
            headers=headers,
            body=body,
            source_ip=source_ip,
        )

    def _blocked_response(self, start_response: Callable) -> list[bytes]:
        """Return a 403 Forbidden response."""
        body = b'{"error": "Request blocked due to security policy"}'
        start_response(
            "403 Forbidden",
            [
                ("Content-Type", "application/json"),
                ("Content-Length", str(len(body))),
            ],
        )
        return [body]


class DjangoSecurityMiddleware:
    """Django middleware for runtime security monitoring.

    Add to MIDDLEWARE in settings.py (preferably at the top):

        MIDDLEWARE = [
            'security_use.sensor.DjangoSecurityMiddleware',
            'django.middleware.security.SecurityMiddleware',
            ...
        ]

    Configure via Django settings:

        SECURITY_USE_BLOCK_ON_DETECTION = True  # Block detected attacks
        SECURITY_USE_EXCLUDED_PATHS = ['/health/', '/metrics/']
        SECURITY_USE_API_KEY = 'su_...'  # Dashboard API key
        SECURITY_USE_WEBHOOK_URL = '...'  # Optional webhook URL
    """

    def __init__(self, get_response):
        """Initialize Django middleware.

        Args:
            get_response: Django's get_response callable.
        """
        self.get_response = get_response

        # Import Django settings lazily
        from django.conf import settings

        # Build config from Django settings
        self.config = SensorConfig(
            enabled=getattr(settings, "SECURITY_USE_ENABLED", True),
            api_key=getattr(settings, "SECURITY_USE_API_KEY", None),
            webhook_url=getattr(settings, "SECURITY_USE_WEBHOOK_URL", None),
            block_on_detection=getattr(settings, "SECURITY_USE_BLOCK_ON_DETECTION", True),
            excluded_paths=getattr(
                settings, "SECURITY_USE_EXCLUDED_PATHS", ["/health/", "/metrics/"]
            ),
            watch_paths=getattr(settings, "SECURITY_USE_WATCH_PATHS", None),
        )

        self.detector = AttackDetector()

        # Set up alerters
        self.dashboard_alerter = None
        self.webhook_alerter = None

        if self.config.api_key:
            self.dashboard_alerter = DashboardAlerter(api_key=self.config.api_key)

        if self.config.webhook_url:
            self.webhook_alerter = WebhookAlerter(webhook_url=self.config.webhook_url)

        self._alert_queue = get_alert_queue()

    def __call__(self, request):
        """Process the request through security checks.

        Args:
            request: Django HttpRequest object.

        Returns:
            HttpResponse from the view or a 403 response if blocked.
        """
        from django.http import JsonResponse

        if not self.config.enabled:
            return self.get_response(request)

        # Check excluded paths
        if self.config.excluded_paths:
            for excluded in self.config.excluded_paths:
                if request.path.startswith(excluded):
                    return self.get_response(request)

        # Check watch paths (if specified, only analyze those)
        if self.config.watch_paths:
            should_analyze = any(
                request.path.startswith(watch) for watch in self.config.watch_paths
            )
            if not should_analyze:
                return self.get_response(request)

        # Extract request data
        request_data = self._extract_request_data(request)

        # Analyze for attacks
        events = self.detector.analyze_request(request_data)

        if events:
            action = ActionTaken.BLOCKED if self.config.block_on_detection else ActionTaken.LOGGED

            # Queue alerts for background sending
            for event in events:
                if self.dashboard_alerter:
                    self._alert_queue.enqueue(event, action, self.dashboard_alerter)
                if self.webhook_alerter:
                    self._alert_queue.enqueue(event, action, self.webhook_alerter)

            if self.config.block_on_detection:
                return JsonResponse(
                    {"error": "Request blocked due to security policy"},
                    status=403,
                )

        return self.get_response(request)

    def _extract_request_data(self, request) -> RequestData:
        """Extract request data from Django request.

        Args:
            request: Django HttpRequest object.

        Returns:
            Normalized RequestData for analysis.
        """
        # Get query params
        query_params = dict(request.GET)
        # Flatten single-value lists
        query_params = {k: v[0] if len(v) == 1 else v for k, v in query_params.items()}

        # Get headers (Django stores them as META with HTTP_ prefix)
        headers = {}
        for key, value in request.META.items():
            if key.startswith("HTTP_"):
                header_name = key[5:].lower().replace("_", "-")
                headers[header_name] = value
            elif key in ("CONTENT_TYPE", "CONTENT_LENGTH"):
                headers[key.lower().replace("_", "-")] = value

        # Get client IP
        source_ip = request.META.get("REMOTE_ADDR", "unknown")
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            source_ip = x_forwarded_for.split(",")[0].strip()

        # Get body
        body = None
        if request.body:
            try:
                body = request.body.decode("utf-8", errors="replace")
            except Exception:
                pass

        return RequestData(
            method=request.method,
            path=request.path,
            query_params=query_params,
            headers=headers,
            body=body,
            source_ip=source_ip,
        )
