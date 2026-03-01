"""Configuration for the security sensor."""

import ipaddress
import logging
import os
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


class DetectorMode(Enum):
    """Mode for individual detectors."""

    BLOCK = "block"
    LOG = "log"
    DISABLED = "disabled"


@dataclass
class DetectorConfig:
    """Configuration for a single detector."""

    mode: DetectorMode = DetectorMode.BLOCK
    min_confidence_to_block: str = "HIGH"
    min_confidence_to_log: str = "LOW"


@dataclass
class AllowlistConfig:
    """Configuration for detection allowlists."""

    paths: list[str] = field(default_factory=list)
    source_ips: list[str] = field(default_factory=list)
    user_agents: list[str] = field(default_factory=list)
    payload_patterns: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Compile regex patterns."""
        self._compiled_paths: list[re.Pattern] = [re.compile(p) for p in self.paths]
        self._compiled_user_agents: list[re.Pattern] = [
            re.compile(p) for p in self.user_agents
        ]
        self._compiled_payloads: list[re.Pattern] = [
            re.compile(p) for p in self.payload_patterns
        ]

    def is_path_allowed(self, path: str) -> bool:
        """Check if path is in allowlist."""
        return any(p.search(path) for p in self._compiled_paths)

    def is_ip_allowed(self, ip: str) -> bool:
        """Check if IP is in allowlist."""
        try:
            check_ip = ipaddress.ip_address(ip)
            for allowed in self.source_ips:
                if "/" in allowed:
                    if check_ip in ipaddress.ip_network(allowed, strict=False):
                        return True
                elif ip == allowed:
                    return True
        except ValueError:
            pass
        return False

    def is_user_agent_allowed(self, user_agent: str) -> bool:
        """Check if user agent is in allowlist."""
        return any(p.search(user_agent) for p in self._compiled_user_agents)

    def is_payload_allowed(self, payload: str) -> bool:
        """Check if payload matches an allowed pattern."""
        return any(p.search(payload) for p in self._compiled_payloads)

    def is_request_allowed(self, request: "RequestData") -> bool:
        """Check if a request matches any allowlist rule."""
        if self.is_path_allowed(request.path):
            return True
        if self.is_ip_allowed(request.source_ip):
            return True
        user_agent = request.headers.get("user-agent", "")
        if user_agent and self.is_user_agent_allowed(user_agent):
            return True
        for key, value in request.query_params.items():
            if self.is_payload_allowed(f"{key}={value}"):
                return True
        if request.body and self.is_payload_allowed(request.body):
            return True
        return False


@dataclass
class SensorConfig:
    """Configuration for the security sensor middleware."""

    # Alerting mode: "dashboard", "webhook", or "both"
    alert_mode: str = "dashboard"

    # Dashboard settings (preferred)
    api_key: Optional[str] = None
    dashboard_url: Optional[str] = None

    # Webhook settings (legacy/fallback)
    webhook_url: Optional[str] = None
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
    watch_paths: Optional[list[str]] = None  # Only monitor these paths (None = all)
    auto_detect_vulnerable: bool = False  # Auto-detect vulnerable endpoints
    project_path: Optional[str] = None  # Project path for auto-detection

    # Confidence thresholds
    min_block_confidence: str = "HIGH"
    min_alert_confidence: str = "MEDIUM"

    # Allowlist configuration
    allowlist: AllowlistConfig = field(default_factory=AllowlistConfig)

    # Global learning mode - overrides all detectors to LOG
    learning_mode: bool = False

    # Per-detector configuration
    detector_configs: dict[str, DetectorConfig] = field(default_factory=dict)

    # Logging
    log_requests: bool = False  # Log all requests (not just attacks)
    log_level: str = "WARNING"

    def get_detector_config(self, detector_name: str) -> DetectorConfig:
        """Get config for a detector, with defaults."""
        return self.detector_configs.get(detector_name, DetectorConfig())

    def should_block_detector(self, detector_name: str, confidence: str) -> bool:
        """Check if a detection should trigger blocking."""
        if self.learning_mode:
            return False
        config = self.get_detector_config(detector_name)
        if config.mode != DetectorMode.BLOCK:
            return False
        confidence_levels = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
        return confidence_levels.get(confidence, 0) >= confidence_levels.get(
            config.min_confidence_to_block, 3
        )

    def should_log_detector(self, detector_name: str, confidence: str) -> bool:
        """Check if a detection should be logged/alerted."""
        config = self.get_detector_config(detector_name)
        if config.mode == DetectorMode.DISABLED:
            return False
        confidence_levels = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
        return confidence_levels.get(confidence, 0) >= confidence_levels.get(
            config.min_confidence_to_log, 1
        )

    @classmethod
    def from_dict(cls, data: dict) -> "SensorConfig":
        """Create config from dictionary."""
        # Parse allowlist config
        allowlist_data = data.get("allowlist", {})
        allowlist = AllowlistConfig(
            paths=allowlist_data.get("paths", []),
            source_ips=allowlist_data.get("source_ips", []),
            user_agents=allowlist_data.get("user_agents", []),
            payload_patterns=allowlist_data.get("payload_patterns", []),
        ) if allowlist_data else AllowlistConfig()

        # Parse detector configs
        detector_configs_data = data.get("detector_configs", {})
        detector_configs = {}
        for name, dc_data in detector_configs_data.items():
            if isinstance(dc_data, dict):
                mode_str = dc_data.get("mode", "block")
                mode = DetectorMode(mode_str) if isinstance(mode_str, str) else mode_str
                detector_configs[name] = DetectorConfig(
                    mode=mode,
                    min_confidence_to_block=dc_data.get("min_confidence_to_block", "HIGH"),
                    min_confidence_to_log=dc_data.get("min_confidence_to_log", "LOW"),
                )

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
            min_block_confidence=data.get("min_block_confidence", "HIGH"),
            min_alert_confidence=data.get("min_alert_confidence", "MEDIUM"),
            allowlist=allowlist,
            learning_mode=data.get("learning_mode", False),
            detector_configs=detector_configs,
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
            "min_block_confidence": self.min_block_confidence,
            "min_alert_confidence": self.min_alert_confidence,
            "learning_mode": self.learning_mode,
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
    api_key: Optional[str] = None,
    webhook_url: Optional[str] = None,
    block_on_detection: bool = True,
    excluded_paths: Optional[list[str]] = None,
    watch_paths: Optional[list[str]] = None,
    auto_detect_vulnerable: bool = False,
    project_path: Optional[str] = None,
    enabled_detectors: Optional[list[str]] = None,
    rate_limit_threshold: int = 100,
    min_block_confidence: str = "HIGH",
    min_alert_confidence: str = "MEDIUM",
    allowlist: Optional[AllowlistConfig] = None,
    learning_mode: bool = False,
    detector_configs: Optional[dict[str, DetectorConfig]] = None,
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
        min_block_confidence: Minimum confidence to block (HIGH, MEDIUM, LOW).
        min_alert_confidence: Minimum confidence to alert (HIGH, MEDIUM, LOW).
        allowlist: Allowlist configuration for skipping detection.
        learning_mode: If True, log everything but never block.
        detector_configs: Per-detector configuration.
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

    config_dict: dict = {
        "alert_mode": alert_mode,
        "api_key": api_key,
        "webhook_url": webhook_url,
        "block_on_detection": block_on_detection,
        "excluded_paths": excluded_paths or [],
        "watch_paths": watch_paths,
        "auto_detect_vulnerable": auto_detect_vulnerable,
        "project_path": project_path,
        "rate_limit_threshold": rate_limit_threshold,
        "min_block_confidence": min_block_confidence,
        "min_alert_confidence": min_alert_confidence,
        "learning_mode": learning_mode,
        **kwargs,
    }

    if enabled_detectors is not None:
        config_dict["enabled_detectors"] = enabled_detectors

    result = SensorConfig.from_dict(config_dict)

    # Set allowlist and detector_configs directly (they are complex objects)
    if allowlist is not None:
        result.allowlist = allowlist
    if detector_configs is not None:
        result.detector_configs = detector_configs

    return result
