"""Dependency scanner for detecting vulnerable packages."""

from pathlib import Path
from typing import Optional

from security_use.models import ScanResult, Vulnerability
from security_use.parsers import (
    Dependency,
    DependencyParser,
    MavenParser,
    NpmLockParser,
    NpmParser,
    PipfileParser,
    PoetryLockParser,
    PyProjectParser,
    RequirementsParser,
    GradleParser,
    YarnLockParser,
    PnpmLockParser,
    CsprojParser,
    PackagesConfigParser,
    CondaEnvironmentParser,
    ComposerParser,
    ComposerLockParser,
)
from security_use.parsers.pipfile import PipfileLockParser


class DependencyScanner:
    """Scanner for dependency files."""

    PARSERS: list[type[DependencyParser]] = [
        RequirementsParser,
        PyProjectParser,
        PipfileParser,
        PipfileLockParser,
        PoetryLockParser,
        MavenParser,
        NpmParser,
        NpmLockParser,
        GradleParser,
        YarnLockParser,
        PnpmLockParser,
        CsprojParser,
        PackagesConfigParser,
        CondaEnvironmentParser,
        ComposerParser,
        ComposerLockParser,
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
        "pom.xml",
        "package.json",
        "package-lock.json",
        "build.gradle",
        "build.gradle.kts",
        "yarn.lock",
        "pnpm-lock.yaml",
        "packages.config",
        "environment.yml",
        "environment.yaml",
        "composer.json",
        "composer.lock",
    ]

    def __init__(self) -> None:
        """Initialize the dependency scanner."""
        self._osv_client: Optional["OSVClient"] = None

    @property
    def osv_client(self) -> "OSVClient":
        """Lazy-load the OSV client."""
        if self._osv_client is None:
            from security_use.osv_client import OSVClient
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

        # Group dependencies by ecosystem
        by_ecosystem: dict[str, list[Dependency]] = {}
        for dep in dependencies:
            if dep.version is None:
                continue
            ecosystem = getattr(dep, "ecosystem", "PyPI") or "PyPI"
            if ecosystem not in by_ecosystem:
                by_ecosystem[ecosystem] = []
            by_ecosystem[ecosystem].append(dep)

        # Query each ecosystem separately
        for ecosystem, deps in by_ecosystem.items():
            packages = [(dep.name, dep.version) for dep in deps]

            if not packages:
                continue

            # Query OSV for vulnerabilities
            vuln_results = self.osv_client.query_batch(packages, ecosystem=ecosystem)

            for dep in deps:
                key = (dep.normalized_name, dep.version)
                if key in vuln_results:
                    vulnerabilities.extend(vuln_results[key])

        return vulnerabilities

    def _find_dependency_files(self, directory: Path, max_depth: int = 4) -> list[Path]:
        """Find all dependency files in a directory recursively.

        Args:
            directory: Directory to search.
            max_depth: Maximum depth to search (default: 4).

        Returns:
            List of dependency file paths.
        """
        files = []
        # Directories to skip (contain many nested dependencies we don't want to scan)
        skip_dirs = {
            "node_modules", ".git", ".venv", "venv", "__pycache__",
            ".tox", ".pytest_cache", "dist", "build", ".eggs",
            "target", ".gradle", ".m2"
        }

        def search_dir(path: Path, depth: int) -> None:
            if depth > max_depth:
                return

            try:
                for item in path.iterdir():
                    if item.is_file() and item.name in self.DEPENDENCY_FILES:
                        files.append(item)
                    elif item.is_dir() and not item.name.startswith(".") and item.name not in skip_dirs:
                        search_dir(item, depth + 1)
            except PermissionError:
                pass

        search_dir(directory, 0)
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
