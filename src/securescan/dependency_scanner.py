"""Dependency scanner for detecting vulnerable packages."""

from pathlib import Path
from typing import Optional

from securescan.models import ScanResult, Vulnerability
from securescan.parsers import (
    Dependency,
    DependencyParser,
    PipfileParser,
    PoetryLockParser,
    PyProjectParser,
    RequirementsParser,
)
from securescan.parsers.pipfile import PipfileLockParser


class DependencyScanner:
    """Scanner for dependency files."""

    PARSERS: list[type[DependencyParser]] = [
        RequirementsParser,
        PyProjectParser,
        PipfileParser,
        PipfileLockParser,
        PoetryLockParser,
    ]

    DEPENDENCY_FILES = [
        "requirements.txt",
        "requirements-dev.txt",
        "requirements-test.txt",
        "requirements.in",
        "pyproject.toml",
        "Pipfile",
        "Pipfile.lock",
        "poetry.lock",
        "setup.py",
    ]

    def __init__(self) -> None:
        """Initialize the dependency scanner."""
        self._osv_client: Optional["OSVClient"] = None

    @property
    def osv_client(self) -> "OSVClient":
        """Lazy-load the OSV client."""
        if self._osv_client is None:
            from securescan.osv_client import OSVClient
            self._osv_client = OSVClient()
        return self._osv_client

    def scan_path(self, path: Path) -> ScanResult:
        """Scan a path for dependency vulnerabilities.

        Args:
            path: File or directory path to scan.

        Returns:
            ScanResult containing vulnerabilities found.
        """
        result = ScanResult()

        if path.is_file():
            files = [path]
        else:
            files = self._find_dependency_files(path)

        for file_path in files:
            try:
                content = file_path.read_text(encoding="utf-8")
                file_result = self.scan_content(content, file_path.name)
                result.vulnerabilities.extend(file_result.vulnerabilities)
                result.scanned_files.append(str(file_path))
            except Exception as e:
                result.errors.append(f"Error scanning {file_path}: {e}")

        return result

    def scan_content(self, content: str, file_type: str) -> ScanResult:
        """Scan dependency file content for vulnerabilities.

        Args:
            content: The file content to scan.
            file_type: The filename or type (e.g., 'requirements.txt').

        Returns:
            ScanResult containing vulnerabilities found.
        """
        result = ScanResult()

        # Parse dependencies
        dependencies = self.parse_dependencies(content, file_type)
        if not dependencies:
            return result

        # Check for vulnerabilities
        vulnerabilities = self.check_vulnerabilities(dependencies)
        result.vulnerabilities = vulnerabilities

        return result

    def parse_dependencies(self, content: str, file_type: str) -> list[Dependency]:
        """Parse dependencies from file content.

        Args:
            content: The file content.
            file_type: The filename to determine parser.

        Returns:
            List of parsed dependencies.
        """
        parser = self._get_parser(file_type)
        if parser is None:
            return []

        return parser.parse(content)

    def check_vulnerabilities(
        self, dependencies: list[Dependency]
    ) -> list[Vulnerability]:
        """Check dependencies against vulnerability databases.

        Args:
            dependencies: List of dependencies to check.

        Returns:
            List of vulnerabilities found.
        """
        vulnerabilities = []

        # Build package list for batch query
        packages = [
            (dep.name, dep.version)
            for dep in dependencies
            if dep.version is not None
        ]

        if not packages:
            return vulnerabilities

        # Query OSV for vulnerabilities
        vuln_results = self.osv_client.query_batch(packages)

        for dep in dependencies:
            if dep.version is None:
                continue

            key = (dep.normalized_name, dep.version)
            if key in vuln_results:
                vulnerabilities.extend(vuln_results[key])

        return vulnerabilities

    def _find_dependency_files(self, directory: Path) -> list[Path]:
        """Find all dependency files in a directory.

        Args:
            directory: Directory to search.

        Returns:
            List of dependency file paths.
        """
        files = []

        for filename in self.DEPENDENCY_FILES:
            # Check root directory
            file_path = directory / filename
            if file_path.exists():
                files.append(file_path)

            # Check subdirectories (one level deep)
            for subdir in directory.iterdir():
                if subdir.is_dir() and not subdir.name.startswith("."):
                    sub_file = subdir / filename
                    if sub_file.exists():
                        files.append(sub_file)

        return files

    def _get_parser(self, file_type: str) -> Optional[DependencyParser]:
        """Get the appropriate parser for a file type.

        Args:
            file_type: The filename or file type.

        Returns:
            Parser instance or None if unsupported.
        """
        filename = file_type.lower()

        for parser_class in self.PARSERS:
            if any(
                supported.lower() in filename
                for supported in parser_class.supported_filenames()
            ):
                return parser_class()

        return None


# Type alias for OSVClient to avoid circular import
class OSVClient:
    """Type stub for OSVClient - actual implementation in osv_client.py."""

    def query_batch(
        self, packages: list[tuple[str, str]]
    ) -> dict[tuple[str, str], list[Vulnerability]]:
        """Query batch of packages for vulnerabilities."""
        ...
