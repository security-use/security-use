"""Security sensor for runtime attack detection and webhook alerting.

This module provides middleware for FastAPI and Flask applications that
detects malicious patterns in HTTP requests and sends alerts to webhooks.

Example usage with FastAPI:
    from fastapi import FastAPI
    from security_use.sensor import SecurityMiddleware

    app = FastAPI()
    app.add_middleware(
        SecurityMiddleware,
        webhook_url="https://your-dashboard.com/webhook",
        block_on_detection=True,
    )

Example usage with Flask:
    from flask import Flask
    from security_use.sensor import FlaskSecurityMiddleware

    app = Flask(__name__)
    app.wsgi_app = FlaskSecurityMiddleware(
        app.wsgi_app,
        webhook_url="https://your-dashboard.com/webhook",
    )

Programmatic usage:
    from security_use.sensor import AttackDetector, WebhookAlerter, RequestData

    detector = AttackDetector()
    alerter = WebhookAlerter("https://your-dashboard.com/webhook")

    request = RequestData(
        method="POST",
        path="/api/users",
        body="username=admin' OR 1=1--",
        source_ip="192.168.1.100",
    )

    events = detector.analyze_request(request)
    for event in events:
        await alerter.send_alert(event)
"""

from .config import SensorConfig, create_config
from .detector import AttackDetector, RateLimiter
from .middleware import FlaskSecurityMiddleware, SecurityMiddleware
from .models import (
    ActionTaken,
    AlertPayload,
    AlertResponse,
    AttackType,
    MatchedPattern,
    RequestData,
    SecurityEvent,
)
from .webhook import WebhookAlerter

__all__ = [
    # Middleware
    "SecurityMiddleware",
    "FlaskSecurityMiddleware",
    # Detection
    "AttackDetector",
    "RateLimiter",
    # Webhook
    "WebhookAlerter",
    # Configuration
    "SensorConfig",
    "create_config",
    # Models
    "SecurityEvent",
    "RequestData",
    "MatchedPattern",
    "AlertPayload",
    "AlertResponse",
    "AttackType",
    "ActionTaken",
]
