"""Security sensor for runtime attack detection and alerting.

This module provides middleware for FastAPI and Flask applications that
detects malicious patterns in HTTP requests and sends alerts to the
SecurityUse dashboard or custom webhooks.

Example usage with dashboard (recommended):
    from fastapi import FastAPI
    from security_use.sensor import SecurityMiddleware

    app = FastAPI()
    app.add_middleware(
        SecurityMiddleware,
        api_key="su_...",  # Or set SECURITY_USE_API_KEY env var
        block_on_detection=True,
    )

Example with auto-detection of vulnerable endpoints:
    app.add_middleware(
        SecurityMiddleware,
        auto_detect_vulnerable=True,
        project_path="./",
    )

Example with selective monitoring:
    app.add_middleware(
        SecurityMiddleware,
        watch_paths=["/api/users", "/api/search", "/admin/*"],
    )

Example usage with Flask:
    from flask import Flask
    from security_use.sensor import FlaskSecurityMiddleware

    app = Flask(__name__)
    app.wsgi_app = FlaskSecurityMiddleware(
        app.wsgi_app,
        api_key="su_...",
    )

Legacy usage with webhook:
    app.add_middleware(
        SecurityMiddleware,
        webhook_url="https://your-webhook.com/alerts",
    )

Programmatic usage:
    from security_use.sensor import AttackDetector, DashboardAlerter, RequestData

    detector = AttackDetector()
    alerter = DashboardAlerter(api_key="su_...")

    request = RequestData(
        method="POST",
        path="/api/users",
        body="username=admin' OR 1=1--",
        source_ip="192.168.1.100",
    )

    events = detector.analyze_request(request)
    for event in events:
        await alerter.send_alert(event)

Endpoint analysis:
    from security_use.sensor import VulnerableEndpointDetector

    detector = VulnerableEndpointDetector()
    result = detector.analyze("./my-project")

    # Get paths that use vulnerable packages
    for endpoint in result.vulnerable_endpoints:
        print(f"{endpoint.path} - risk: {endpoint.risk_score}")
"""

from .config import SensorConfig, create_config
from .dashboard_alerter import DashboardAlerter
from .detector import AttackDetector, RateLimiter
from .endpoint_analyzer import (
    AnalysisResult,
    EndpointInfo,
    VulnerableEndpointDetector,
    detect_vulnerable_endpoints,
)
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
    # Alerting
    "DashboardAlerter",
    "WebhookAlerter",
    # Endpoint Analysis
    "VulnerableEndpointDetector",
    "detect_vulnerable_endpoints",
    "EndpointInfo",
    "AnalysisResult",
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
