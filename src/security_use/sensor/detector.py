"""Attack pattern detection engine."""

import re
import threading
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

# SSRF (Server-Side Request Forgery) patterns
SSRF_PATTERNS = [
    (r"(?i)(localhost|127\.0\.0\.1|0\.0\.0\.0)", "Localhost access attempt"),
    (r"(?i)(169\.254\.169\.254)", "AWS metadata endpoint access"),
    (r"(?i)(metadata\.google\.internal)", "GCP metadata endpoint access"),
    (r"(?i)(100\.100\.100\.200)", "Alibaba Cloud metadata access"),
    (r"(?i)file://", "File protocol access"),
    (r"(?i)gopher://", "Gopher protocol access"),
    (r"(?i)dict://", "Dict protocol access"),
    (r"(?i)ftp://", "FTP protocol access"),
    (r"(?i)(10\.\d{1,3}\.\d{1,3}\.\d{1,3})", "Private IP access (10.x.x.x)"),
    (r"(?i)(172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})", "Private IP access (172.16-31.x.x)"),
    (r"(?i)(192\.168\.\d{1,3}\.\d{1,3})", "Private IP access (192.168.x.x)"),
]

# SSTI (Server-Side Template Injection) patterns
SSTI_PATTERNS = [
    (r"\{\{\s*[\d+\-*/]+\s*\}\}", "Jinja2 expression injection"),
    (r"\{\{.*config.*\}\}", "Jinja2 config access"),
    (r"\{\{.*__class__.*\}\}", "Python class introspection"),
    (r"\{\{.*__mro__.*\}\}", "Python MRO traversal"),
    (r"\{\{.*__globals__.*\}\}", "Python globals access"),
    (r"\{\{.*__builtins__.*\}\}", "Python builtins access"),
    (r"\$\{.*\}", "Expression language injection"),
    (r"#\{.*\}", "Spring EL injection"),
    (r"<%.*%>", "ERB/JSP template injection"),
    (r"\{\{.*\|safe.*\}\}", "Template filter bypass attempt"),
]

# NoSQL Injection patterns (MongoDB, etc.)
NOSQL_INJECTION_PATTERNS = [
    (r"\$where\s*:", "MongoDB $where injection"),
    (r"\$gt\s*:", "MongoDB comparison operator injection"),
    (r"\$lt\s*:", "MongoDB comparison operator injection"),
    (r"\$ne\s*:", "MongoDB not-equal injection"),
    (r"\$regex\s*:", "MongoDB regex injection"),
    (r"\$or\s*:\s*\[", "MongoDB $or injection"),
    (r"\$and\s*:\s*\[", "MongoDB $and injection"),
    (r"(?i)[\'\"]?\$[a-z]+[\'\"]?\s*:", "Generic MongoDB operator injection"),
    (r"(?i)\.find\s*\(\s*\{", "MongoDB find injection attempt"),
]

# XXE (XML External Entity) patterns
XXE_PATTERNS = [
    (r"<!ENTITY\s+", "XML Entity declaration"),
    (r"<!DOCTYPE[^>]*\[", "DOCTYPE with DTD"),
    (r"SYSTEM\s+['\"]file://", "XXE file:// access"),
    (r"SYSTEM\s+['\"]http://", "XXE http:// access"),
    (r"SYSTEM\s+['\"]https://", "XXE https:// access"),
    (r"PUBLIC\s+['\"]", "XXE PUBLIC declaration"),
    (r"%[a-zA-Z_][a-zA-Z0-9_]*;", "Parameter entity reference"),
    (r"&#x[0-9a-fA-F]+;", "Hex encoded entity (potential XXE)"),
]

# Deserialization attack patterns
DESERIALIZATION_PATTERNS = [
    (r"(?i)java\.lang\.Runtime", "Java Runtime class (RCE)"),
    (r"(?i)java\.lang\.ProcessBuilder", "Java ProcessBuilder (RCE)"),
    (r"(?i)rO0AB", "Java serialized object (base64)"),
    (r"(?i)aced0005", "Java serialized object (hex)"),
    (r"O:\d+:\"[^\"]+\"", "PHP serialized object"),
    (r"a:\d+:\{", "PHP serialized array"),
    (r"(?i)__reduce__", "Python pickle reduce"),
    (r"(?i)pickle\.loads", "Python pickle load"),
    (r"(?i)yaml\.unsafe_load", "Python YAML unsafe load"),
    (r"(?i)cPickle", "Python cPickle (unsafe)"),
]

# Suspicious headers
SUSPICIOUS_HEADER_PATTERNS = [
    (r"(?i)(sqlmap|nikto|nmap|masscan|dirbuster|gobuster)", "Known attack tool"),
    (r"(?i)(havij|acunetix|nessus|openvas|burp)", "Security scanner"),
    (r"(?i)(\$\{|\%\{)", "Log4j/Template injection attempt"),
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
        """
        self.enabled_detectors = enabled_detectors or [
            "sqli",
            "nosql",
            "xss",
            "path_traversal",
            "command_injection",
            "ssrf",
            "ssti",
            "xxe",
            "deserialization",
            "rate_limit",
            "suspicious_headers",
        ]
        self.rate_limiter = RateLimiter(
            threshold=rate_limit_threshold,
            window_seconds=rate_limit_window,
            cleanup_interval=rate_limit_cleanup_interval,
            max_tracked_ips=rate_limit_max_ips,
        )
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

        if "ssrf" in self.enabled_detectors:
            patterns[AttackType.SSRF] = [
                DetectionPattern(
                    pattern=p,
                    compiled=re.compile(p),
                    attack_type=AttackType.SSRF,
                    severity="HIGH",
                    description=desc,
                )
                for p, desc in SSRF_PATTERNS
            ]

        if "ssti" in self.enabled_detectors:
            patterns[AttackType.SSTI] = [
                DetectionPattern(
                    pattern=p,
                    compiled=re.compile(p),
                    attack_type=AttackType.SSTI,
                    severity="HIGH",
                    description=desc,
                )
                for p, desc in SSTI_PATTERNS
            ]

        if "nosql" in self.enabled_detectors:
            patterns[AttackType.NOSQL_INJECTION] = [
                DetectionPattern(
                    pattern=p,
                    compiled=re.compile(p),
                    attack_type=AttackType.NOSQL_INJECTION,
                    severity="HIGH",
                    description=desc,
                )
                for p, desc in NOSQL_INJECTION_PATTERNS
            ]

        if "xxe" in self.enabled_detectors:
            patterns[AttackType.XXE] = [
                DetectionPattern(
                    pattern=p,
                    compiled=re.compile(p, re.IGNORECASE),
                    attack_type=AttackType.XXE,
                    severity="HIGH",
                    description=desc,
                )
                for p, desc in XXE_PATTERNS
            ]

        if "deserialization" in self.enabled_detectors:
            patterns[AttackType.DESERIALIZATION] = [
                DetectionPattern(
                    pattern=p,
                    compiled=re.compile(p),
                    attack_type=AttackType.DESERIALIZATION,
                    severity="CRITICAL",
                    description=desc,
                )
                for p, desc in DESERIALIZATION_PATTERNS
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
