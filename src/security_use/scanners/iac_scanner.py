"""Infrastructure as Code security scanner.

Scans Terraform, CloudFormation, and other IaC files for security
misconfigurations.
"""

import re
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


class Severity(str, Enum):
    """Finding severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


@dataclass
class IaCFinding:
    """Represents a detected IaC security issue."""
    rule_id: str
    title: str
    file_path: str
    line_number: int
    severity: Severity
    description: str
    remediation: str
    resource_name: Optional[str] = None
    resource_type: Optional[str] = None
    code_snippet: str = ""


@dataclass
class IaCScanResult:
    """Result of an IaC security scan."""
    findings: list[IaCFinding] = field(default_factory=list)
    scanned_files: list[str] = field(default_factory=list)
    scan_duration_ms: int = 0
    error: Optional[str] = None


# Security rules for Terraform
TERRAFORM_RULES = [
    {
        "id": "AWS001",
        "title": "S3 bucket is publicly accessible",
        "severity": Severity.CRITICAL,
        "pattern": r'acl\s*=\s*["\']public-read["\']',
        "resource_type": "aws_s3_bucket",
        "description": "S3 bucket allows public read access, exposing data to anyone on the internet.",
        "remediation": "Set acl to 'private' or remove the acl attribute and use bucket policy instead.",
    },
    {
        "id": "AWS002",
        "title": "S3 bucket versioning disabled",
        "severity": Severity.MEDIUM,
        "pattern": r'versioning\s*\{[^}]*enabled\s*=\s*false',
        "resource_type": "aws_s3_bucket",
        "description": "S3 bucket versioning is disabled, preventing recovery of accidentally deleted objects.",
        "remediation": "Enable versioning by setting enabled = true in the versioning block.",
    },
    {
        "id": "AWS003",
        "title": "Security group allows unrestricted ingress",
        "severity": Severity.HIGH,
        "pattern": r'cidr_blocks\s*=\s*\[\s*["\']0\.0\.0\.0/0["\']',
        "resource_type": "aws_security_group",
        "description": "Security group allows inbound traffic from any IP address.",
        "remediation": "Restrict cidr_blocks to specific IP ranges that need access.",
    },
    {
        "id": "AWS004",
        "title": "RDS instance publicly accessible",
        "severity": Severity.HIGH,
        "pattern": r'publicly_accessible\s*=\s*true',
        "resource_type": "aws_db_instance",
        "description": "RDS database instance is publicly accessible from the internet.",
        "remediation": "Set publicly_accessible = false and access via VPC or bastion host.",
    },
    {
        "id": "AWS005",
        "title": "EBS volume not encrypted",
        "severity": Severity.MEDIUM,
        "pattern": r'encrypted\s*=\s*false',
        "resource_type": "aws_ebs_volume",
        "description": "EBS volume is not encrypted, exposing data at rest.",
        "remediation": "Set encrypted = true to enable EBS encryption.",
    },
    {
        "id": "AWS006",
        "title": "IAM policy allows wildcard actions",
        "severity": Severity.HIGH,
        "pattern": r'"Action"\s*:\s*"\*"',
        "resource_type": "aws_iam_policy",
        "description": "IAM policy grants unrestricted actions, violating least privilege principle.",
        "remediation": "Specify only the required actions instead of using wildcard.",
    },
    {
        "id": "AWS007",
        "title": "CloudTrail logging disabled",
        "severity": Severity.HIGH,
        "pattern": r'enable_logging\s*=\s*false',
        "resource_type": "aws_cloudtrail",
        "description": "CloudTrail logging is disabled, preventing audit trail collection.",
        "remediation": "Set enable_logging = true to enable CloudTrail logging.",
    },
    {
        "id": "AWS008",
        "title": "KMS key rotation disabled",
        "severity": Severity.MEDIUM,
        "pattern": r'enable_key_rotation\s*=\s*false',
        "resource_type": "aws_kms_key",
        "description": "KMS key rotation is disabled, which may violate compliance requirements.",
        "remediation": "Set enable_key_rotation = true to enable automatic key rotation.",
    },
]


class IaCScanner:
    """Scanner for Infrastructure as Code security issues."""

    def __init__(self):
        self.rules = TERRAFORM_RULES

    def scan(self, path: str) -> IaCScanResult:
        """Scan a directory for IaC security issues.

        Args:
            path: Path to the directory or file to scan.

        Returns:
            IaCScanResult with any findings.
        """
        start_time = time.time()
        path_obj = Path(path)

        if not path_obj.exists():
            return IaCScanResult(error=f"Path does not exist: {path}")

        # Find IaC files
        iac_files = self._find_iac_files(path_obj)
        if not iac_files:
            return IaCScanResult(
                scanned_files=[],
                scan_duration_ms=int((time.time() - start_time) * 1000),
            )

        findings = []
        scanned_files = []

        for iac_file in iac_files:
            try:
                file_findings = self._scan_file(iac_file, path_obj)
                findings.extend(file_findings)
                scanned_files.append(str(iac_file.relative_to(path_obj) if path_obj.is_dir() else iac_file.name))
            except Exception:
                continue

        elapsed_ms = int((time.time() - start_time) * 1000)

        return IaCScanResult(
            findings=findings,
            scanned_files=scanned_files,
            scan_duration_ms=elapsed_ms,
        )

    def _find_iac_files(self, path: Path) -> list[Path]:
        """Find IaC files in the given path."""
        if path.is_file():
            if path.suffix in [".tf", ".yaml", ".yml", ".json"]:
                return [path]
            return []

        files = []
        patterns = ["*.tf", "*.yaml", "*.yml", "*.json"]

        for pattern in patterns:
            files.extend(path.glob(pattern))
            files.extend(path.glob(f"**/{pattern}"))

        # Filter to only IaC-related files
        iac_files = []
        for f in files:
            if f.suffix == ".tf":
                iac_files.append(f)
            elif f.suffix in [".yaml", ".yml"]:
                # Check if it looks like CloudFormation
                try:
                    content = f.read_text()[:500]
                    if "AWSTemplateFormatVersion" in content or "Resources:" in content:
                        iac_files.append(f)
                except Exception:
                    pass
            elif f.suffix == ".json":
                # Check if it looks like CloudFormation or Terraform
                try:
                    content = f.read_text()[:500]
                    if "AWSTemplateFormatVersion" in content or "terraform" in content.lower():
                        iac_files.append(f)
                except Exception:
                    pass

        # Remove duplicates
        seen = set()
        unique_files = []
        for f in iac_files:
            if f not in seen:
                seen.add(f)
                unique_files.append(f)

        return unique_files[:50]  # Limit files to scan

    def _scan_file(self, file_path: Path, base_path: Path) -> list[IaCFinding]:
        """Scan a single file for security issues."""
        findings = []
        content = file_path.read_text()
        lines = content.split("\n")

        for rule in self.rules:
            pattern = re.compile(rule["pattern"], re.IGNORECASE | re.MULTILINE)
            for match in pattern.finditer(content):
                # Find line number
                line_num = content[:match.start()].count("\n") + 1

                # Extract resource name
                resource_name = self._extract_resource_name(content, match.start())

                # Get code snippet (context around the match)
                start_line = max(0, line_num - 2)
                end_line = min(len(lines), line_num + 2)
                code_snippet = "\n".join(lines[start_line:end_line])

                rel_path = str(file_path.relative_to(base_path) if base_path.is_dir() else file_path.name)

                findings.append(IaCFinding(
                    rule_id=rule["id"],
                    title=rule["title"],
                    file_path=rel_path,
                    line_number=line_num,
                    severity=rule["severity"],
                    description=rule["description"],
                    remediation=rule["remediation"],
                    resource_name=resource_name,
                    resource_type=rule["resource_type"],
                    code_snippet=code_snippet,
                ))

        return findings

    def _extract_resource_name(self, content: str, position: int) -> Optional[str]:
        """Extract resource name from the resource block containing the position."""
        # Look backwards for resource declaration
        before = content[:position]
        match = re.search(
            r'resource\s+"[^"]+"\s+"([^"]+)"',
            before,
            re.IGNORECASE
        )
        if match:
            return match.group(1)

        # Try module or other block types
        match = re.search(r'(module|data)\s+"([^"]+)"', before, re.IGNORECASE)
        if match:
            return match.group(2)

        return None
