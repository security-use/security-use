"""Configuration for the security sensor."""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class SensorConfig:
    """Configuration for the security sensor middleware."""

    # Webhook settings
    webhook_url: str
    webhook_headers: dict[str, str] = field(default_factory=dict)
    webhook_retry_count: int = 3
    webhook_timeout: float = 10.0

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

    # Behavior
    block_on_detection: bool = False  # Return 403 or just alert
    excluded_paths: list[str] = field(default_factory=list)  # Paths to skip

    # Logging
    log_requests: bool = False  # Log all requests (not just attacks)
    log_level: str = "WARNING"

    @classmethod
    def from_dict(cls, data: dict) -> "SensorConfig":
        """Create config from dictionary."""
        return cls(
            webhook_url=data["webhook_url"],
            webhook_headers=data.get("webhook_headers", {}),
            webhook_retry_count=data.get("webhook_retry_count", 3),
            webhook_timeout=data.get("webhook_timeout", 10.0),
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
            block_on_detection=data.get("block_on_detection", False),
            excluded_paths=data.get("excluded_paths", []),
            log_requests=data.get("log_requests", False),
            log_level=data.get("log_level", "WARNING"),
        )

    def to_dict(self) -> dict:
        """Convert config to dictionary."""
        return {
            "webhook_url": self.webhook_url,
            "webhook_headers": self.webhook_headers,
            "webhook_retry_count": self.webhook_retry_count,
            "webhook_timeout": self.webhook_timeout,
            "enabled_detectors": self.enabled_detectors,
            "rate_limit_threshold": self.rate_limit_threshold,
            "rate_limit_window": self.rate_limit_window,
            "block_on_detection": self.block_on_detection,
            "excluded_paths": self.excluded_paths,
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


def create_config(
    webhook_url: str,
    block_on_detection: bool = False,
    excluded_paths: Optional[list[str]] = None,
    enabled_detectors: Optional[list[str]] = None,
    rate_limit_threshold: int = 100,
    **kwargs,
) -> SensorConfig:
    """Convenience function to create a sensor configuration.

    Args:
        webhook_url: URL to send alerts to.
        block_on_detection: Whether to return 403 on attack detection.
        excluded_paths: List of paths to exclude from monitoring.
        enabled_detectors: List of detector types to enable.
        rate_limit_threshold: Requests per minute per IP before rate limiting.
        **kwargs: Additional configuration options.

    Returns:
        SensorConfig instance.
    """
    config_dict = {
        "webhook_url": webhook_url,
        "block_on_detection": block_on_detection,
        "excluded_paths": excluded_paths or [],
        "rate_limit_threshold": rate_limit_threshold,
        **kwargs,
    }

    if enabled_detectors is not None:
        config_dict["enabled_detectors"] = enabled_detectors

    return SensorConfig.from_dict(config_dict)
