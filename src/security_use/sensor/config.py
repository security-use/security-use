"""Configuration for the security sensor."""

import os
from dataclasses import dataclass, field


@dataclass
class SensorConfig:
    """Configuration for the security sensor middleware."""

    # Alerting mode: "dashboard", "webhook", or "both"
    alert_mode: str = "dashboard"

    # Dashboard settings (preferred)
    api_key: str | None = None
    dashboard_url: str | None = None

    # Webhook settings (legacy/fallback)
    webhook_url: str | None = None
    webhook_headers: dict[str, str] = field(default_factory=dict)
    webhook_retry_count: int = 2  # Reduced from 3 for faster failure recovery
    webhook_timeout: float = 2.0  # Reduced from 10.0 for production use

    # Detection settings
    enabled_detectors: list[str] = field(
        default_factory=lambda: [
            "sqli",
            "xss",
            "path_traversal",
            "command_injection",
            "rate_limit",
            "suspicious_headers",
        ]
    )

    # Rate limiting
    rate_limit_threshold: int = 100  # requests per window per IP
    rate_limit_window: int = 60  # seconds
    rate_limit_cleanup_interval: int = 300  # seconds between cleanup runs
    rate_limit_max_ips: int = 100000  # max tracked IPs to prevent memory leak

    # Alert queue settings (for non-blocking alert delivery in Flask)
    alert_queue_size: int = 1000  # max queued alerts
    alert_queue_workers: int = 2  # number of worker threads
    alert_queue_drain_timeout: float = 5.0  # seconds to wait on shutdown

    # Body handling
    max_body_size: int = 1024 * 1024  # 1MB max body for analysis

    # Behavior
    block_on_detection: bool = True  # Return 403 on attack detection (default True now)
    excluded_paths: list[str] = field(default_factory=list)  # Paths to skip

    # Selective monitoring
    watch_paths: list[str] | None = None  # Only monitor these paths (None = all)
    auto_detect_vulnerable: bool = False  # Auto-detect vulnerable endpoints
    project_path: str | None = None  # Project path for auto-detection

    # Logging
    log_requests: bool = False  # Log all requests (not just attacks)
    log_level: str = "WARNING"

    @classmethod
    def from_dict(cls, data: dict) -> "SensorConfig":
        """Create config from dictionary."""
        return cls(
            alert_mode=data.get("alert_mode", "dashboard"),
            api_key=data.get("api_key") or os.environ.get("SECURITY_USE_API_KEY"),
            dashboard_url=data.get("dashboard_url") or os.environ.get("SECURITY_USE_DASHBOARD_URL"),
            webhook_url=data.get("webhook_url"),
            webhook_headers=data.get("webhook_headers", {}),
            webhook_retry_count=data.get("webhook_retry_count", 2),
            webhook_timeout=data.get("webhook_timeout", 2.0),
            enabled_detectors=data.get(
                "enabled_detectors",
                [
                    "sqli",
                    "xss",
                    "path_traversal",
                    "command_injection",
                    "rate_limit",
                    "suspicious_headers",
                ],
            ),
            rate_limit_threshold=data.get("rate_limit_threshold", 100),
            rate_limit_window=data.get("rate_limit_window", 60),
            rate_limit_cleanup_interval=data.get("rate_limit_cleanup_interval", 300),
            rate_limit_max_ips=data.get("rate_limit_max_ips", 100000),
            alert_queue_size=data.get("alert_queue_size", 1000),
            alert_queue_workers=data.get("alert_queue_workers", 2),
            alert_queue_drain_timeout=data.get("alert_queue_drain_timeout", 5.0),
            max_body_size=data.get("max_body_size", 1024 * 1024),
            block_on_detection=data.get("block_on_detection", True),
            excluded_paths=data.get("excluded_paths", []),
            watch_paths=data.get("watch_paths"),
            auto_detect_vulnerable=data.get("auto_detect_vulnerable", False),
            project_path=data.get("project_path"),
            log_requests=data.get("log_requests", False),
            log_level=data.get("log_level", "WARNING"),
        )

    def to_dict(self) -> dict:
        """Convert config to dictionary."""
        return {
            "alert_mode": self.alert_mode,
            "api_key": self.api_key,
            "dashboard_url": self.dashboard_url,
            "webhook_url": self.webhook_url,
            "webhook_headers": self.webhook_headers,
            "webhook_retry_count": self.webhook_retry_count,
            "webhook_timeout": self.webhook_timeout,
            "enabled_detectors": self.enabled_detectors,
            "rate_limit_threshold": self.rate_limit_threshold,
            "rate_limit_window": self.rate_limit_window,
            "rate_limit_cleanup_interval": self.rate_limit_cleanup_interval,
            "rate_limit_max_ips": self.rate_limit_max_ips,
            "alert_queue_size": self.alert_queue_size,
            "alert_queue_workers": self.alert_queue_workers,
            "alert_queue_drain_timeout": self.alert_queue_drain_timeout,
            "max_body_size": self.max_body_size,
            "block_on_detection": self.block_on_detection,
            "excluded_paths": self.excluded_paths,
            "watch_paths": self.watch_paths,
            "auto_detect_vulnerable": self.auto_detect_vulnerable,
            "project_path": self.project_path,
            "log_requests": self.log_requests,
            "log_level": self.log_level,
        }

    def is_path_excluded(self, path: str) -> bool:
        """Check if a path should be excluded from monitoring."""
        for excluded in self.excluded_paths:
            if excluded.endswith("*"):
                if path.startswith(excluded[:-1]):
                    return True
            elif path == excluded:
                return True
        return False

    def should_monitor_path(self, path: str) -> bool:
        """Check if a path should be monitored.

        Returns True if:
        - Path is not in excluded_paths AND
        - Either watch_paths is None (monitor all) OR path is in watch_paths
        """
        if self.is_path_excluded(path):
            return False

        if self.watch_paths is None:
            return True

        # Check watch_paths with wildcard support
        for watch_path in self.watch_paths:
            if watch_path.endswith("*"):
                if path.startswith(watch_path[:-1]):
                    return True
            elif path == watch_path or path.startswith(watch_path + "/"):
                return True

        return False


def create_config(
    api_key: str | None = None,
    webhook_url: str | None = None,
    block_on_detection: bool = True,
    excluded_paths: list[str] | None = None,
    watch_paths: list[str] | None = None,
    auto_detect_vulnerable: bool = False,
    project_path: str | None = None,
    enabled_detectors: list[str] | None = None,
    rate_limit_threshold: int = 100,
    **kwargs,
) -> SensorConfig:
    """Convenience function to create a sensor configuration.

    Args:
        api_key: SecurityUse API key for dashboard alerting.
        webhook_url: URL to send alerts to (legacy, use api_key instead).
        block_on_detection: Whether to return 403 on attack detection.
        excluded_paths: List of paths to exclude from monitoring.
        watch_paths: List of paths to monitor (None = all paths).
        auto_detect_vulnerable: Auto-detect vulnerable endpoints to monitor.
        project_path: Project path for auto-detection.
        enabled_detectors: List of detector types to enable.
        rate_limit_threshold: Requests per minute per IP before rate limiting.
        **kwargs: Additional configuration options.

    Returns:
        SensorConfig instance.
    """
    # Determine alert mode
    alert_mode = "dashboard"
    if api_key or os.environ.get("SECURITY_USE_API_KEY"):
        alert_mode = "dashboard"
    elif webhook_url:
        alert_mode = "webhook"

    config_dict = {
        "alert_mode": alert_mode,
        "api_key": api_key,
        "webhook_url": webhook_url,
        "block_on_detection": block_on_detection,
        "excluded_paths": excluded_paths or [],
        "watch_paths": watch_paths,
        "auto_detect_vulnerable": auto_detect_vulnerable,
        "project_path": project_path,
        "rate_limit_threshold": rate_limit_threshold,
        **kwargs,
    }

    if enabled_detectors is not None:
        config_dict["enabled_detectors"] = enabled_detectors

    return SensorConfig.from_dict(config_dict)
