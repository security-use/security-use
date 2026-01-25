"""Data models for security sensor events and alerts."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional
import uuid


class AttackType(Enum):
    """Types of attacks that can be detected."""

    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    PATH_TRAVERSAL = "path_traversal"
    COMMAND_INJECTION = "command_injection"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    SUSPICIOUS_HEADER = "suspicious_header"


class ActionTaken(Enum):
    """Action taken in response to detected threat."""

    LOGGED = "logged"
    BLOCKED = "blocked"


@dataclass
class RequestData:
    """Normalized HTTP request data for analysis."""

    method: str
    path: str
    query_params: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    source_ip: str = "unknown"
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))


@dataclass
class MatchedPattern:
    """Details about a matched attack pattern."""

    pattern: str
    location: str  # "path", "query", "body", "header"
    field: Optional[str] = None  # Specific field name if applicable
    matched_value: Optional[str] = None


@dataclass
class SecurityEvent:
    """Represents a detected security event."""

    event_type: AttackType
    severity: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    timestamp: datetime
    source_ip: str
    path: str
    method: str
    matched_pattern: MatchedPattern
    request_headers: dict[str, str] = field(default_factory=dict)
    request_body: Optional[str] = None
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    confidence: float = 0.9
    description: str = ""

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "event_type": self.event_type.value,
            "severity": self.severity,
            "timestamp": self.timestamp.isoformat(),
            "source_ip": self.source_ip,
            "path": self.path,
            "method": self.method,
            "matched_pattern": {
                "pattern": self.matched_pattern.pattern,
                "location": self.matched_pattern.location,
                "field": self.matched_pattern.field,
                "matched_value": self.matched_pattern.matched_value,
            },
            "request_id": self.request_id,
            "confidence": self.confidence,
            "description": self.description,
        }


@dataclass
class AlertPayload:
    """Webhook alert payload format."""

    version: str = "1.0"
    event_id: str = field(default_factory=lambda: f"evt_{uuid.uuid4().hex[:12]}")
    event_type: str = "security_alert"
    timestamp: datetime = field(default_factory=datetime.utcnow)
    alert: Optional[SecurityEvent] = None
    action_taken: ActionTaken = ActionTaken.LOGGED

    def to_dict(self) -> dict:
        """Convert to webhook payload format."""
        if self.alert is None:
            raise ValueError("Alert cannot be None")

        return {
            "version": self.version,
            "event": {
                "id": self.event_id,
                "type": self.event_type,
                "timestamp": self.timestamp.isoformat() + "Z",
            },
            "alert": {
                "type": self.alert.event_type.value,
                "severity": self.alert.severity,
                "confidence": self.alert.confidence,
                "description": self.alert.description,
            },
            "request": {
                "method": self.alert.method,
                "path": self.alert.path,
                "source_ip": self.alert.source_ip,
                "headers": self.alert.request_headers,
            },
            "matched": {
                "pattern": self.alert.matched_pattern.pattern,
                "location": self.alert.matched_pattern.location,
                "field": self.alert.matched_pattern.field,
            },
            "action_taken": self.action_taken.value,
        }


@dataclass
class AlertResponse:
    """Response from webhook alert attempt."""

    success: bool
    webhook_status: int
    retry_count: int
    error_message: Optional[str] = None
