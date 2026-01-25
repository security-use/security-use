"""Data models for security scan results."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(Enum):
    """Vulnerability severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def from_cvss(cls, score: Optional[float]) -> "Severity":
        """Convert CVSS score to severity level."""
        if score is None:
            return cls.UNKNOWN
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        return cls.LOW


@dataclass
class Vulnerability:
    """Represents a vulnerability in a dependency."""

    id: str
    package: str
    installed_version: str
    severity: Severity
    title: str
    description: str
    affected_versions: str
    fixed_version: Optional[str] = None
    cvss_score: Optional[float] = None
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Convert to dictionary representation."""
        return {
            "id": self.id,
            "package": self.package,
            "installed_version": self.installed_version,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "affected_versions": self.affected_versions,
            "fixed_version": self.fixed_version,
            "cvss_score": self.cvss_score,
            "references": self.references,
        }


@dataclass
class IaCFinding:
    """Represents a security finding in Infrastructure as Code."""

    rule_id: str
    title: str
    severity: Severity
    resource_type: str
    resource_name: str
    file_path: str
    line_number: int
    description: str
    remediation: str
    fix_code: Optional[str] = None

    def to_dict(self) -> dict:
        """Convert to dictionary representation."""
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "resource_type": self.resource_type,
            "resource_name": self.resource_name,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "description": self.description,
            "remediation": self.remediation,
            "fix_code": self.fix_code,
        }


@dataclass
class ScanResult:
    """Combined result from all security scans."""

    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    iac_findings: list[IaCFinding] = field(default_factory=list)
    scanned_files: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def total_issues(self) -> int:
        """Total number of security issues found."""
        return len(self.vulnerabilities) + len(self.iac_findings)

    @property
    def critical_count(self) -> int:
        """Count of critical severity issues."""
        return sum(
            1
            for v in self.vulnerabilities
            if v.severity == Severity.CRITICAL
        ) + sum(
            1
            for f in self.iac_findings
            if f.severity == Severity.CRITICAL
        )

    @property
    def high_count(self) -> int:
        """Count of high severity issues."""
        return sum(
            1 for v in self.vulnerabilities if v.severity == Severity.HIGH
        ) + sum(1 for f in self.iac_findings if f.severity == Severity.HIGH)

    def to_dict(self) -> dict:
        """Convert to dictionary representation."""
        return {
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "iac_findings": [f.to_dict() for f in self.iac_findings],
            "scanned_files": self.scanned_files,
            "errors": self.errors,
            "summary": {
                "total_issues": self.total_issues,
                "critical": self.critical_count,
                "high": self.high_count,
            },
        }
