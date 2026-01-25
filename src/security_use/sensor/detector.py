"""Attack pattern detection engine."""

import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from time import time
from typing import Optional

from .models import AttackType, MatchedPattern, RequestData, SecurityEvent


@dataclass
class DetectionPattern:
    """A pattern for detecting attacks."""

    pattern: str
    compiled: re.Pattern
    attack_type: AttackType
    severity: str
    description: str


# SQL Injection patterns
SQLI_PATTERNS = [
    (r"(?i)(\%27)|(\')|(\-\-)|(\%23)|(#)", "Basic SQL injection characters"),
    (r"(?i)((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))", "SQL tautology attempt"),
    (r"(?i)\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))", "OR injection"),
    (r"(?i)((\%27)|(\'))union", "UNION injection"),
    (r"(?i)union\s+(all\s+)?select", "UNION SELECT"),
    (r"(?i)(select|insert|update|delete|drop|create|alter)\s+", "SQL keyword"),
    (r"(?i)exec(\s|\+)+(s|x)p\w+", "SQL stored procedure execution"),
    (r"(?i);\s*(drop|delete|truncate|update|insert)", "SQL statement injection"),
]

# XSS patterns
XSS_PATTERNS = [
    (r"(?i)<script[^>]*>", "Script tag injection"),
    (r"(?i)javascript\s*:", "JavaScript protocol"),
    (r"(?i)on\w+\s*=", "Event handler injection"),
    (r"(?i)<iframe[^>]*>", "IFrame injection"),
    (r"(?i)<img[^>]+onerror", "Image onerror handler"),
    (r"(?i)<svg[^>]+onload", "SVG onload handler"),
    (r"(?i)expression\s*\(", "CSS expression"),
    (r"(?i)vbscript\s*:", "VBScript protocol"),
    (r"(?i)<embed[^>]*>", "Embed tag injection"),
    (r"(?i)<object[^>]*>", "Object tag injection"),
]

# Path traversal patterns
PATH_TRAVERSAL_PATTERNS = [
    (r"\.\./", "Basic path traversal"),
    (r"\.\.\\", "Windows path traversal"),
    (r"%2e%2e%2f", "URL encoded path traversal"),
    (r"%2e%2e/", "Partial URL encoded traversal"),
    (r"\.%2e/", "Mixed encoding traversal"),
    (r"%2e\./", "Mixed encoding traversal variant"),
    (r"%252e%252e%252f", "Double URL encoded traversal"),
    (r"/etc/passwd", "Unix password file access"),
    (r"/etc/shadow", "Unix shadow file access"),
    (r"c:\\windows", "Windows system directory"),
]

# Command injection patterns
COMMAND_INJECTION_PATTERNS = [
    (r";\s*(ls|cat|rm|wget|curl|nc|bash|sh|python|perl|ruby)\b", "Unix command injection"),
    (r"\|\s*(ls|cat|rm|wget|curl|nc|bash|sh)\b", "Pipe command injection"),
    (r"`[^`]+`", "Backtick command execution"),
    (r"\$\([^)]+\)", "Command substitution"),
    (r"&\s*(ls|cat|rm|wget|curl|nc|bash|sh)\b", "Background command injection"),
    (r";\s*(dir|type|del|copy|move|net|powershell|cmd)\b", "Windows command injection"),
    (r"\|\s*(dir|type|del|copy|move|net)\b", "Windows pipe injection"),
]

# Suspicious headers
SUSPICIOUS_HEADER_PATTERNS = [
    (r"(?i)(sqlmap|nikto|nmap|masscan|dirbuster|gobuster)", "Known attack tool"),
    (r"(?i)(havij|acunetix|nessus|openvas|burp)", "Security scanner"),
    (r"(?i)(\$\{|\%\{)", "Log4j/Template injection attempt"),
]


class RateLimiter:
    """Track request frequency per IP."""

    def __init__(self, threshold: int = 100, window_seconds: int = 60):
        self.threshold = threshold
        self.window_seconds = window_seconds
        self._requests: dict[str, list[float]] = defaultdict(list)

    def check(self, ip: str) -> bool:
        """Check if IP has exceeded rate limit. Returns True if exceeded."""
        now = time()
        cutoff = now - self.window_seconds

        # Clean old entries
        self._requests[ip] = [t for t in self._requests[ip] if t > cutoff]

        # Add current request
        self._requests[ip].append(now)

        return len(self._requests[ip]) > self.threshold

    def get_request_count(self, ip: str) -> int:
        """Get current request count for IP."""
        now = time()
        cutoff = now - self.window_seconds
        self._requests[ip] = [t for t in self._requests[ip] if t > cutoff]
        return len(self._requests[ip])

    def reset(self, ip: Optional[str] = None) -> None:
        """Reset rate limit tracking."""
        if ip:
            self._requests.pop(ip, None)
        else:
            self._requests.clear()


class AttackDetector:
    """Detects malicious patterns in HTTP requests."""

    def __init__(
        self,
        enabled_detectors: Optional[list[str]] = None,
        rate_limit_threshold: int = 100,
        rate_limit_window: int = 60,
    ):
        """Initialize the attack detector.

        Args:
            enabled_detectors: List of detector types to enable.
                Options: "sqli", "xss", "path_traversal", "command_injection",
                         "rate_limit", "suspicious_headers"
                Defaults to all detectors.
            rate_limit_threshold: Requests per window before rate limit triggers.
            rate_limit_window: Time window in seconds for rate limiting.
        """
        self.enabled_detectors = enabled_detectors or [
            "sqli",
            "xss",
            "path_traversal",
            "command_injection",
            "rate_limit",
            "suspicious_headers",
        ]
        self.rate_limiter = RateLimiter(rate_limit_threshold, rate_limit_window)
        self._patterns = self._compile_patterns()

    def _compile_patterns(self) -> dict[AttackType, list[DetectionPattern]]:
        """Compile all detection patterns."""
        patterns: dict[AttackType, list[DetectionPattern]] = {}

        if "sqli" in self.enabled_detectors:
            patterns[AttackType.SQL_INJECTION] = [
                DetectionPattern(
                    pattern=p,
                    compiled=re.compile(p),
                    attack_type=AttackType.SQL_INJECTION,
                    severity="HIGH",
                    description=desc,
                )
                for p, desc in SQLI_PATTERNS
            ]

        if "xss" in self.enabled_detectors:
            patterns[AttackType.XSS] = [
                DetectionPattern(
                    pattern=p,
                    compiled=re.compile(p),
                    attack_type=AttackType.XSS,
                    severity="MEDIUM",
                    description=desc,
                )
                for p, desc in XSS_PATTERNS
            ]

        if "path_traversal" in self.enabled_detectors:
            patterns[AttackType.PATH_TRAVERSAL] = [
                DetectionPattern(
                    pattern=p,
                    compiled=re.compile(p, re.IGNORECASE),
                    attack_type=AttackType.PATH_TRAVERSAL,
                    severity="HIGH",
                    description=desc,
                )
                for p, desc in PATH_TRAVERSAL_PATTERNS
            ]

        if "command_injection" in self.enabled_detectors:
            patterns[AttackType.COMMAND_INJECTION] = [
                DetectionPattern(
                    pattern=p,
                    compiled=re.compile(p, re.IGNORECASE),
                    attack_type=AttackType.COMMAND_INJECTION,
                    severity="CRITICAL",
                    description=desc,
                )
                for p, desc in COMMAND_INJECTION_PATTERNS
            ]

        if "suspicious_headers" in self.enabled_detectors:
            patterns[AttackType.SUSPICIOUS_HEADER] = [
                DetectionPattern(
                    pattern=p,
                    compiled=re.compile(p),
                    attack_type=AttackType.SUSPICIOUS_HEADER,
                    severity="MEDIUM",
                    description=desc,
                )
                for p, desc in SUSPICIOUS_HEADER_PATTERNS
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
                match = pattern.compiled.search(value)
                if match:
                    events.append(
                        SecurityEvent(
                            event_type=attack_type,
                            severity=pattern.severity,
                            timestamp=datetime.utcnow(),
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
                            description=pattern.description,
                        )
                    )
                    # Only report first match per attack type per location
                    break

        return events

    def analyze_request(self, request: RequestData) -> list[SecurityEvent]:
        """Analyze an HTTP request for malicious patterns.

        Args:
            request: Normalized request data to analyze.

        Returns:
            List of detected security events.
        """
        events: list[SecurityEvent] = []

        # Check rate limiting
        if "rate_limit" in self.enabled_detectors:
            if self.rate_limiter.check(request.source_ip):
                events.append(
                    SecurityEvent(
                        event_type=AttackType.RATE_LIMIT_EXCEEDED,
                        severity="MEDIUM",
                        timestamp=datetime.utcnow(),
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
