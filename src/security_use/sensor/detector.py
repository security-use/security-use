"""Attack pattern detection engine."""

import re
import threading
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from time import time
from typing import Optional

from .models import AttackType, MatchedPattern, RequestData, SecurityEvent


CONFIDENCE_LEVELS = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}


@dataclass
class DetectionPattern:
    """A pattern for detecting attacks."""

    pattern: str
    compiled: re.Pattern
    attack_type: AttackType
    severity: str
    description: str
    confidence: str = "HIGH"


# High confidence SQL injection patterns (definitely attacks)
SQLI_HIGH_CONFIDENCE = [
    (r"['\"](\s|\+)*(or|and)(\s|\+)*['\"]?\s*['\"]?\s*(=|like)", "OR/AND injection"),
    (r"['\"]\s*;\s*(drop|delete|truncate|update|insert|create|alter)\s", "Stacked query"),
    (r"['\"]\s*--", "Comment injection"),
    (r"['\"]\s*/\*", "Block comment injection"),
    (r"(\d+|['\"])\s+union(\s+all)?\s+select", "UNION injection"),
    (r"['\"](\s|\+)*(or|and)(\s|\+)*1(\s|\+)*=(\s|\+)*1", "Tautology injection"),
    (r"['\"](\s|\+)*(or|and)(\s|\+)*['\"][^'\"]+['\"](\s|\+)*=(\s|\+)*['\"]", "String tautology"),
    (r"(?i)exec(\s|\+)+(s|x)p\w+", "SQL stored procedure execution"),
]

# Medium confidence patterns (likely attacks, but could be false positive)
SQLI_MEDIUM_CONFIDENCE = [
    (r"(?i)((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))", "Encoded OR injection"),
    (r"(?i)((\%27)|(\'))union", "UNION injection with quote"),
    (r"(?i)(%27|%22)(\s|%20)*(or|and)(\s|%20)*(%27|%22)?", "Encoded OR/AND"),
    (r"(?i)--\s*(drop|delete|select|update|insert)", "Comment with SQL"),
    (r"(?i)((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))", "SQL tautology attempt"),
]

# Low confidence patterns (suspicious but often benign - log only)
SQLI_LOW_CONFIDENCE = [
    (r"(?i);\s*(select|insert|update|delete)\s", "SQL keyword after semicolon"),
    (r"(?i)(\%27)|(\')|(\-\-)|(\%23)|(#)", "Basic SQL meta-characters"),
]

# Combined with confidence levels
SQLI_PATTERNS = [
    *[(p, d, "HIGH") for p, d in SQLI_HIGH_CONFIDENCE],
    *[(p, d, "MEDIUM") for p, d in SQLI_MEDIUM_CONFIDENCE],
    *[(p, d, "LOW") for p, d in SQLI_LOW_CONFIDENCE],
]

# XSS patterns (all HIGH confidence - HTML tags are rarely legitimate in params)
XSS_PATTERNS = [
    (r"(?i)<script[^>]*>", "Script tag injection", "HIGH"),
    (r"(?i)javascript\s*:", "JavaScript protocol", "HIGH"),
    (r"(?i)on\w+\s*=", "Event handler injection", "HIGH"),
    (r"(?i)<iframe[^>]*>", "IFrame injection", "HIGH"),
    (r"(?i)<img[^>]+onerror", "Image onerror handler", "HIGH"),
    (r"(?i)<svg[^>]+onload", "SVG onload handler", "HIGH"),
    (r"(?i)expression\s*\(", "CSS expression", "MEDIUM"),
    (r"(?i)vbscript\s*:", "VBScript protocol", "HIGH"),
    (r"(?i)<embed[^>]*>", "Embed tag injection", "MEDIUM"),
    (r"(?i)<object[^>]*>", "Object tag injection", "MEDIUM"),
]

# Path traversal patterns
PATH_TRAVERSAL_PATTERNS = [
    (r"\.\./", "Basic path traversal", "HIGH"),
    (r"\.\.\\", "Windows path traversal", "HIGH"),
    (r"%2e%2e%2f", "URL encoded path traversal", "HIGH"),
    (r"%2e%2e/", "Partial URL encoded traversal", "HIGH"),
    (r"\.%2e/", "Mixed encoding traversal", "HIGH"),
    (r"%2e\./", "Mixed encoding traversal variant", "HIGH"),
    (r"%252e%252e%252f", "Double URL encoded traversal", "HIGH"),
    (r"/etc/passwd", "Unix password file access", "HIGH"),
    (r"/etc/shadow", "Unix shadow file access", "HIGH"),
    (r"c:\\windows", "Windows system directory", "HIGH"),
]

# Command injection patterns
COMMAND_INJECTION_PATTERNS = [
    (r";\s*(ls|cat|rm|wget|curl|nc|bash|sh|python|perl|ruby)\b", "Unix command injection", "HIGH"),
    (r"\|\s*(ls|cat|rm|wget|curl|nc|bash|sh)\b", "Pipe command injection", "HIGH"),
    (r"`[^`]+`", "Backtick command execution", "HIGH"),
    (r"\$\([^)]+\)", "Command substitution", "HIGH"),
    (r"&\s*(ls|cat|rm|wget|curl|nc|bash|sh)\b", "Background command injection", "HIGH"),
    (r";\s*(dir|type|del|copy|move|net|powershell|cmd)\b", "Windows command injection", "HIGH"),
    (r"\|\s*(dir|type|del|copy|move|net)\b", "Windows pipe injection", "HIGH"),
]

# Suspicious headers
SUSPICIOUS_HEADER_PATTERNS = [
    (r"(?i)(sqlmap|nikto|nmap|masscan|dirbuster|gobuster)", "Known attack tool", "HIGH"),
    (r"(?i)(havij|acunetix|nessus|openvas|burp)", "Security scanner", "HIGH"),
    (r"(?i)(\$\{|\%\{)", "Log4j/Template injection attempt", "HIGH"),
]


class RateLimiter:
    """Track request frequency per IP with automatic memory cleanup.

    This rate limiter periodically cleans up stale IPs to prevent unbounded
    memory growth. It also enforces a maximum number of tracked IPs.
    """

    def __init__(
        self,
        threshold: int = 100,
        window_seconds: int = 60,
        cleanup_interval: int = 300,
        max_tracked_ips: int = 100000,
    ):
        """Initialize the rate limiter.

        Args:
            threshold: Requests per window before rate limit triggers.
            window_seconds: Time window in seconds for rate limiting.
            cleanup_interval: Seconds between cleanup runs.
            max_tracked_ips: Maximum number of IPs to track.
        """
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.cleanup_interval = cleanup_interval
        self.max_tracked_ips = max_tracked_ips

        self._requests: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.Lock()
        self._last_cleanup = time()

        # Stats
        self.total_cleaned = 0

    def check(self, ip: str) -> bool:
        """Check if IP has exceeded rate limit. Returns True if exceeded."""
        now = time()

        with self._lock:
            # Trigger cleanup if interval passed
            if now - self._last_cleanup > self.cleanup_interval:
                self._cleanup(now)

            cutoff = now - self.window_seconds

            # Clean old entries for this IP
            self._requests[ip] = [t for t in self._requests[ip] if t > cutoff]

            # Add current request
            self._requests[ip].append(now)

            return len(self._requests[ip]) > self.threshold

    def _cleanup(self, now: float) -> None:
        """Remove IPs with no recent requests. Must be called with lock held."""
        cutoff = now - self.window_seconds

        # Find IPs to remove
        to_remove = []
        for ip, timestamps in self._requests.items():
            # Remove if no recent timestamps
            if not timestamps or all(t <= cutoff for t in timestamps):
                to_remove.append(ip)

        # Remove stale IPs
        for ip in to_remove:
            del self._requests[ip]

        self.total_cleaned += len(to_remove)
        self._last_cleanup = now

        # Emergency cleanup if still too many IPs
        if len(self._requests) > self.max_tracked_ips:
            self._emergency_cleanup(now)

    def _emergency_cleanup(self, now: float) -> None:
        """Emergency cleanup when max IPs exceeded. Must be called with lock held.

        Removes least recently active IPs until under limit.
        """
        if len(self._requests) <= self.max_tracked_ips:
            return

        # Sort IPs by most recent timestamp
        ip_last_seen = []
        for ip, timestamps in self._requests.items():
            last_seen = max(timestamps) if timestamps else 0
            ip_last_seen.append((ip, last_seen))

        # Sort by last seen (oldest first)
        ip_last_seen.sort(key=lambda x: x[1])

        # Remove oldest until under limit (with buffer)
        to_remove = len(self._requests) - self.max_tracked_ips + 1000
        for ip, _ in ip_last_seen[:to_remove]:
            del self._requests[ip]
            self.total_cleaned += 1

    def get_request_count(self, ip: str) -> int:
        """Get current request count for IP."""
        now = time()
        cutoff = now - self.window_seconds

        with self._lock:
            self._requests[ip] = [t for t in self._requests[ip] if t > cutoff]
            return len(self._requests[ip])

    def reset(self, ip: Optional[str] = None) -> None:
        """Reset rate limit tracking."""
        with self._lock:
            if ip:
                self._requests.pop(ip, None)
            else:
                self._requests.clear()

    @property
    def tracked_ip_count(self) -> int:
        """Number of IPs currently being tracked."""
        return len(self._requests)

    @property
    def stats(self) -> dict:
        """Get rate limiter statistics."""
        return {
            "tracked_ips": len(self._requests),
            "total_cleaned": self.total_cleaned,
            "threshold": self.threshold,
            "window_seconds": self.window_seconds,
            "max_tracked_ips": self.max_tracked_ips,
        }


class AttackDetector:
    """Detects malicious patterns in HTTP requests."""

    def __init__(
        self,
        enabled_detectors: Optional[list[str]] = None,
        rate_limit_threshold: int = 100,
        rate_limit_window: int = 60,
        rate_limit_cleanup_interval: int = 300,
        rate_limit_max_ips: int = 100000,
        min_block_confidence: str = "HIGH",
        min_alert_confidence: str = "MEDIUM",
        allowlist: Optional["AllowlistConfig"] = None,
    ):
        """Initialize the attack detector.

        Args:
            enabled_detectors: List of detector types to enable.
                Options: "sqli", "xss", "path_traversal", "command_injection",
                         "rate_limit", "suspicious_headers"
                Defaults to all detectors.
            rate_limit_threshold: Requests per window before rate limit triggers.
            rate_limit_window: Time window in seconds for rate limiting.
            rate_limit_cleanup_interval: Seconds between cleanup runs.
            rate_limit_max_ips: Maximum number of IPs to track.
            min_block_confidence: Minimum confidence level to block requests.
            min_alert_confidence: Minimum confidence level to create alerts.
            allowlist: Optional allowlist configuration for skipping detection.
        """
        self.enabled_detectors = enabled_detectors or [
            "sqli",
            "xss",
            "path_traversal",
            "command_injection",
            "rate_limit",
            "suspicious_headers",
        ]
        self.rate_limiter = RateLimiter(
            threshold=rate_limit_threshold,
            window_seconds=rate_limit_window,
            cleanup_interval=rate_limit_cleanup_interval,
            max_tracked_ips=rate_limit_max_ips,
        )
        self.min_block_confidence = CONFIDENCE_LEVELS.get(min_block_confidence, 3)
        self.min_alert_confidence = CONFIDENCE_LEVELS.get(min_alert_confidence, 2)
        self.allowlist = allowlist
        self._patterns = self._compile_patterns()

    def _compile_patterns(self) -> dict[AttackType, list[DetectionPattern]]:
        """Compile all detection patterns."""
        patterns: dict[AttackType, list[DetectionPattern]] = {}

        if "sqli" in self.enabled_detectors:
            patterns[AttackType.SQL_INJECTION] = [
                DetectionPattern(
                    pattern=p,
                    compiled=re.compile(p, re.IGNORECASE),
                    attack_type=AttackType.SQL_INJECTION,
                    severity="HIGH" if conf == "HIGH" else "MEDIUM",
                    description=desc,
                    confidence=conf,
                )
                for p, desc, conf in SQLI_PATTERNS
            ]

        if "xss" in self.enabled_detectors:
            patterns[AttackType.XSS] = [
                DetectionPattern(
                    pattern=p,
                    compiled=re.compile(p),
                    attack_type=AttackType.XSS,
                    severity="MEDIUM" if conf != "HIGH" else "MEDIUM",
                    description=desc,
                    confidence=conf,
                )
                for p, desc, conf in XSS_PATTERNS
            ]

        if "path_traversal" in self.enabled_detectors:
            patterns[AttackType.PATH_TRAVERSAL] = [
                DetectionPattern(
                    pattern=p,
                    compiled=re.compile(p, re.IGNORECASE),
                    attack_type=AttackType.PATH_TRAVERSAL,
                    severity="HIGH",
                    description=desc,
                    confidence=conf,
                )
                for p, desc, conf in PATH_TRAVERSAL_PATTERNS
            ]

        if "command_injection" in self.enabled_detectors:
            patterns[AttackType.COMMAND_INJECTION] = [
                DetectionPattern(
                    pattern=p,
                    compiled=re.compile(p, re.IGNORECASE),
                    attack_type=AttackType.COMMAND_INJECTION,
                    severity="CRITICAL",
                    description=desc,
                    confidence=conf,
                )
                for p, desc, conf in COMMAND_INJECTION_PATTERNS
            ]

        if "suspicious_headers" in self.enabled_detectors:
            patterns[AttackType.SUSPICIOUS_HEADER] = [
                DetectionPattern(
                    pattern=p,
                    compiled=re.compile(p),
                    attack_type=AttackType.SUSPICIOUS_HEADER,
                    severity="MEDIUM",
                    description=desc,
                    confidence=conf,
                )
                for p, desc, conf in SUSPICIOUS_HEADER_PATTERNS
            ]

        return patterns

    def _check_string(
        self,
        value: str,
        location: str,
        field: Optional[str],
        request: RequestData,
    ) -> list[SecurityEvent]:
        """Check a string value against all patterns."""
        events = []

        for attack_type, patterns in self._patterns.items():
            for pattern in patterns:
                # Skip patterns below alert confidence threshold
                pattern_conf = CONFIDENCE_LEVELS.get(pattern.confidence, 3)
                if pattern_conf < self.min_alert_confidence:
                    continue

                match = pattern.compiled.search(value)
                if match:
                    events.append(
                        SecurityEvent(
                            event_type=attack_type,
                            severity=pattern.severity,
                            timestamp=datetime.now(timezone.utc),
                            source_ip=request.source_ip,
                            path=request.path,
                            method=request.method,
                            matched_pattern=MatchedPattern(
                                pattern=pattern.pattern,
                                location=location,
                                field=field,
                                matched_value=match.group(0),
                            ),
                            request_headers=request.headers,
                            request_body=request.body,
                            request_id=request.request_id,
                            confidence=pattern.confidence,
                            description=pattern.description,
                        )
                    )
                    # Only report first match per attack type per location
                    break

        return events

    def should_block(self, events: list[SecurityEvent]) -> bool:
        """Check if any event warrants blocking based on confidence.

        Args:
            events: List of detected security events.

        Returns:
            True if any event meets the blocking confidence threshold.
        """
        return any(
            CONFIDENCE_LEVELS.get(
                e.confidence if isinstance(e.confidence, str) else "HIGH", 3
            )
            >= self.min_block_confidence
            for e in events
        )

    def _is_allowed(self, request: RequestData) -> bool:
        """Check if request matches any allowlist rule."""
        if self.allowlist is None:
            return False
        return self.allowlist.is_request_allowed(request)

    def analyze_request(self, request: RequestData) -> list[SecurityEvent]:
        """Analyze an HTTP request for malicious patterns.

        Args:
            request: Normalized request data to analyze.

        Returns:
            List of detected security events.
        """
        # Check allowlist first (fast path)
        if self._is_allowed(request):
            return []

        events: list[SecurityEvent] = []

        # Check rate limiting
        if "rate_limit" in self.enabled_detectors:
            if self.rate_limiter.check(request.source_ip):
                events.append(
                    SecurityEvent(
                        event_type=AttackType.RATE_LIMIT_EXCEEDED,
                        severity="MEDIUM",
                        timestamp=datetime.now(timezone.utc),
                        source_ip=request.source_ip,
                        path=request.path,
                        method=request.method,
                        matched_pattern=MatchedPattern(
                            pattern="rate_limit",
                            location="request",
                            field=None,
                            matched_value=str(
                                self.rate_limiter.get_request_count(request.source_ip)
                            ),
                        ),
                        request_headers=request.headers,
                        request_id=request.request_id,
                        description=f"Rate limit exceeded: {self.rate_limiter.get_request_count(request.source_ip)} requests",
                    )
                )

        # Check path
        events.extend(self._check_string(request.path, "path", None, request))

        # Check query parameters
        for key, value in request.query_params.items():
            events.extend(self._check_string(key, "query", "key", request))
            events.extend(self._check_string(value, "query", key, request))

        # Check headers
        if "suspicious_headers" in self.enabled_detectors:
            for key, value in request.headers.items():
                # Only check user-agent and other relevant headers for attack tools
                if key.lower() in ("user-agent", "referer", "x-forwarded-for"):
                    events.extend(self._check_string(value, "header", key, request))

        # Check body
        if request.body:
            events.extend(self._check_string(request.body, "body", None, request))

        return events
