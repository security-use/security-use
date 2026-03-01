"""Main scanner interface for security_use."""

from pathlib import Path
from typing import Optional

from security_use.models import ScanResult


def scan_dependencies(
    path: Optional[str] = None,
    file_content: Optional[str] = None,
    file_type: Optional[str] = None,
) -> ScanResult:
    """Scan dependencies for known vulnerabilities.

    Args:
        path: Path to scan (file or directory). Defaults to current directory.
        file_content: Direct content to scan (alternative to path).
        file_type: Type of dependency file when using file_content.

    Returns:
        ScanResult containing any vulnerabilities found.
    """
    from security_use.dependency_scanner import DependencyScanner

    scanner = DependencyScanner()

    if file_content is not None:
        return scanner.scan_content(file_content, file_type or "requirements.txt")

    scan_path = Path(path) if path else Path.cwd()
    return scanner.scan_path(scan_path)


def scan_iac(
    path: Optional[str] = None,
    file_content: Optional[str] = None,
    file_type: Optional[str] = None,
) -> ScanResult:
    """Scan Infrastructure as Code for security misconfigurations.

    Args:
        path: Path to scan (file or directory). Defaults to current directory.
        file_content: Direct content to scan (alternative to path).
        file_type: Type of IaC file when using file_content (e.g., "terraform", "cloudformation").

    Returns:
        ScanResult containing any IaC findings.
    """
    from security_use.iac_scanner import IaCScanner

    scanner = IaCScanner()

    if file_content is not None:
        # Map file_type to a synthetic file path with correct extension
        # so the parser can be selected correctly
        file_type_to_extension = {
            "terraform": "inline.tf",
            "tf": "inline.tf",
            "cloudformation": "inline.yaml",
            "cfn": "inline.yaml",
            "yaml": "inline.yaml",
            "yml": "inline.yml",
            "json": "inline.json",
        }
        file_type_lower = (file_type or "terraform").lower()
        synthetic_path = file_type_to_extension.get(file_type_lower, f"inline.{file_type_lower}")
        return scanner.scan_content(file_content, synthetic_path)

    scan_path = Path(path) if path else Path.cwd()
    return scanner.scan_path(scan_path)


def get_vulnerability_fix(vulnerability_id: str, package: str) -> Optional[str]:
    """Get the recommended fix version for a vulnerability.

    Args:
        vulnerability_id: The CVE or vulnerability ID.
        package: The package name.

    Returns:
        Recommended version to upgrade to, or None if unknown.
    """
    from security_use.osv_client import OSVClient

    client = OSVClient()
    return client.get_fix_version(vulnerability_id, package)
