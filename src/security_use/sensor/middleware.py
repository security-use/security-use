"""Framework middleware adapters for security monitoring."""

import asyncio
import logging
from io import BytesIO
from typing import Any, Callable, Optional
from urllib.parse import parse_qs

from .config import SensorConfig, create_config
from .detector import AttackDetector
from .models import ActionTaken, RequestData
from .webhook import WebhookAlerter

logger = logging.getLogger(__name__)


class SecurityMiddleware:
    """ASGI middleware for FastAPI/Starlette security monitoring.

    Usage:
        from fastapi import FastAPI
        from security_use.sensor import SecurityMiddleware

        app = FastAPI()
        app.add_middleware(
            SecurityMiddleware,
            webhook_url="https://your-dashboard.com/webhook",
            block_on_detection=True,
        )
    """

    def __init__(
        self,
        app: Any,
        webhook_url: str,
        block_on_detection: bool = False,
        excluded_paths: Optional[list[str]] = None,
        enabled_detectors: Optional[list[str]] = None,
        rate_limit_threshold: int = 100,
        config: Optional[SensorConfig] = None,
    ):
        """Initialize the security middleware.

        Args:
            app: The ASGI application.
            webhook_url: URL to send alerts to.
            block_on_detection: Return 403 on attack detection.
            excluded_paths: Paths to skip monitoring.
            enabled_detectors: List of detector types to enable.
            rate_limit_threshold: Requests per minute per IP.
            config: Optional pre-configured SensorConfig.
        """
        self.app = app

        if config:
            self.config = config
        else:
            self.config = create_config(
                webhook_url=webhook_url,
                block_on_detection=block_on_detection,
                excluded_paths=excluded_paths,
                enabled_detectors=enabled_detectors,
                rate_limit_threshold=rate_limit_threshold,
            )

        self.detector = AttackDetector(
            enabled_detectors=self.config.enabled_detectors,
            rate_limit_threshold=self.config.rate_limit_threshold,
            rate_limit_window=self.config.rate_limit_window,
        )

        self.alerter = WebhookAlerter(
            webhook_url=self.config.webhook_url,
            retry_count=self.config.webhook_retry_count,
            timeout=self.config.webhook_timeout,
            headers=self.config.webhook_headers,
        )

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        """ASGI interface."""
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Extract request data
        path = scope.get("path", "/")

        # Check if path is excluded
        if self.config.is_path_excluded(path):
            await self.app(scope, receive, send)
            return

        request_data = await self._extract_request_data(scope, receive)

        # Analyze for attacks
        events = self.detector.analyze_request(request_data)

        if events:
            action = (
                ActionTaken.BLOCKED
                if self.config.block_on_detection
                else ActionTaken.LOGGED
            )

            # Send alerts asynchronously
            for event in events:
                asyncio.create_task(self.alerter.send_alert(event, action))

            if self.config.block_on_detection:
                # Return 403 Forbidden
                await self._send_blocked_response(send, events[0])
                return

        # Continue to application
        await self.app(scope, receive, send)

    async def _extract_request_data(
        self, scope: dict, receive: Callable
    ) -> RequestData:
        """Extract request data from ASGI scope."""
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

        # Read body (need to buffer for re-reading)
        body = b""
        body_parts = []

        async def receive_wrapper():
            nonlocal body
            message = await receive()
            if message["type"] == "http.request":
                chunk = message.get("body", b"")
                body_parts.append(chunk)
                body = b"".join(body_parts)
            return message

        # We need to consume the body here
        message = await receive()
        if message["type"] == "http.request":
            body = message.get("body", b"")

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

    Usage:
        from flask import Flask
        from security_use.sensor import FlaskSecurityMiddleware

        app = Flask(__name__)
        app.wsgi_app = FlaskSecurityMiddleware(
            app.wsgi_app,
            webhook_url="https://your-dashboard.com/webhook",
        )
    """

    def __init__(
        self,
        app: Any,
        webhook_url: str,
        block_on_detection: bool = False,
        excluded_paths: Optional[list[str]] = None,
        enabled_detectors: Optional[list[str]] = None,
        rate_limit_threshold: int = 100,
        config: Optional[SensorConfig] = None,
    ):
        """Initialize the Flask security middleware.

        Args:
            app: The WSGI application.
            webhook_url: URL to send alerts to.
            block_on_detection: Return 403 on attack detection.
            excluded_paths: Paths to skip monitoring.
            enabled_detectors: List of detector types to enable.
            rate_limit_threshold: Requests per minute per IP.
            config: Optional pre-configured SensorConfig.
        """
        self.app = app

        if config:
            self.config = config
        else:
            self.config = create_config(
                webhook_url=webhook_url,
                block_on_detection=block_on_detection,
                excluded_paths=excluded_paths,
                enabled_detectors=enabled_detectors,
                rate_limit_threshold=rate_limit_threshold,
            )

        self.detector = AttackDetector(
            enabled_detectors=self.config.enabled_detectors,
            rate_limit_threshold=self.config.rate_limit_threshold,
            rate_limit_window=self.config.rate_limit_window,
        )

        self.alerter = WebhookAlerter(
            webhook_url=self.config.webhook_url,
            retry_count=self.config.webhook_retry_count,
            timeout=self.config.webhook_timeout,
            headers=self.config.webhook_headers,
        )

    def __call__(self, environ: dict, start_response: Callable) -> Any:
        """WSGI interface."""
        path = environ.get("PATH_INFO", "/")

        # Check if path is excluded
        if self.config.is_path_excluded(path):
            return self.app(environ, start_response)

        request_data = self._extract_request_data(environ)

        # Analyze for attacks
        events = self.detector.analyze_request(request_data)

        if events:
            action = (
                ActionTaken.BLOCKED
                if self.config.block_on_detection
                else ActionTaken.LOGGED
            )

            # Send alerts synchronously (or could use thread pool)
            for event in events:
                self.alerter.send_alert_sync(event, action)

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
