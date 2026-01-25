"""Dependency scanner module - placeholder for Issue #2."""

from pathlib import Path

from securescan.models import ScanResult


class DependencyScanner:
    """Scanner for dependency files."""

    def scan_path(self, path: Path) -> ScanResult:
        """Scan a path for dependency vulnerabilities."""
        raise NotImplementedError("Implemented in Issue #2")

    def scan_content(self, content: str, file_type: str) -> ScanResult:
        """Scan dependency file content for vulnerabilities."""
        raise NotImplementedError("Implemented in Issue #2")
