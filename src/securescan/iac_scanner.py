"""IaC scanner module - placeholder for Issue #5."""

from pathlib import Path

from securescan.models import ScanResult


class IaCScanner:
    """Scanner for Infrastructure as Code files."""

    def scan_path(self, path: Path) -> ScanResult:
        """Scan a path for IaC security issues."""
        raise NotImplementedError("Implemented in Issue #5")

    def scan_content(self, content: str, file_type: str) -> ScanResult:
        """Scan IaC file content for security issues."""
        raise NotImplementedError("Implemented in Issue #5")
