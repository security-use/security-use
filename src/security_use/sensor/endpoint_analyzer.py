"""Analyze application endpoints to identify vulnerable paths.

This module combines dependency scanning with code analysis to identify
which API endpoints use vulnerable packages and should be monitored.
"""

import ast
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class EndpointInfo:
    """Information about a discovered endpoint."""

    path: str
    method: str = "GET"
    function_name: str = ""
    file_path: str = ""
    line_number: int = 0
    imports: list[str] = field(default_factory=list)
    vulnerable_packages: list[str] = field(default_factory=list)
    risk_score: float = 0.0


@dataclass
class AnalysisResult:
    """Result of endpoint vulnerability analysis."""

    all_endpoints: list[EndpointInfo] = field(default_factory=list)
    vulnerable_endpoints: list[EndpointInfo] = field(default_factory=list)
    vulnerable_paths: list[str] = field(default_factory=list)
    vulnerable_packages: dict[str, list[str]] = field(default_factory=dict)


class VulnerableEndpointDetector:
    """Detect which endpoints use vulnerable packages.

    Combines dependency scanning with static code analysis to identify
    API routes that should be monitored more closely.

    Usage:
        from security_use.sensor import VulnerableEndpointDetector

        detector = VulnerableEndpointDetector()
        result = detector.analyze("./my-project")

        # Get paths to monitor
        vulnerable_paths = result.vulnerable_paths
    """

    # Patterns for detecting route decorators
    FASTAPI_ROUTE_PATTERNS = [
        r'@(?:app|router)\.(?:get|post|put|delete|patch|options|head)\s*\(\s*["\']([^"\']+)["\']',
        r'@(?:app|router)\.api_route\s*\(\s*["\']([^"\']+)["\']',
    ]

    FLASK_ROUTE_PATTERNS = [
        r'@(?:app|bp|blueprint)\.route\s*\(\s*["\']([^"\']+)["\']',
        r'@(?:app|bp|blueprint)\.(?:get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',
    ]

    # High-risk packages that handle user input
    HIGH_RISK_PACKAGES = {
        "flask": ["request", "g", "session"],
        "fastapi": ["Request", "Form", "File", "Body", "Query", "Path"],
        "django": ["request", "HttpRequest"],
        "sqlalchemy": ["text", "execute", "raw"],
        "pymysql": ["cursor", "execute"],
        "psycopg2": ["cursor", "execute"],
        "sqlite3": ["cursor", "execute"],
        "subprocess": ["run", "call", "Popen", "check_output"],
        "os": ["system", "popen", "exec"],
        "pickle": ["loads", "load"],
        "yaml": ["load", "unsafe_load"],
        "eval": [],
        "exec": [],
    }

    def __init__(self, project_path: Optional[str] = None):
        """Initialize the endpoint detector.

        Args:
            project_path: Path to the project to analyze.
        """
        self.project_path = Path(project_path) if project_path else None
        self._vulnerable_packages: set[str] = set()

    def analyze(self, path: Optional[str] = None) -> AnalysisResult:
        """Analyze a project for vulnerable endpoints.

        Args:
            path: Path to the project. Uses project_path if not provided.

        Returns:
            AnalysisResult with vulnerable endpoints and paths.
        """
        project_path = Path(path) if path else self.project_path
        if not project_path:
            raise ValueError("No project path provided")

        result = AnalysisResult()

        # Step 1: Run dependency scan to find vulnerable packages
        self._scan_dependencies(project_path, result)

        # Step 2: Find all Python files
        python_files = self._find_python_files(project_path)

        # Step 3: Analyze each file for endpoints
        for file_path in python_files:
            try:
                self._analyze_file(file_path, result)
            except Exception as e:
                logger.debug(f"Error analyzing {file_path}: {e}")

        # Step 4: Calculate risk scores and filter vulnerable endpoints
        self._calculate_risk_scores(result)

        # Step 5: Extract vulnerable paths
        result.vulnerable_paths = list(set(
            ep.path for ep in result.vulnerable_endpoints
        ))

        return result

    def _scan_dependencies(self, project_path: Path, result: AnalysisResult) -> None:
        """Scan dependencies for vulnerabilities."""
        try:
            from security_use import scan_dependencies

            scan_result = scan_dependencies(str(project_path))

            for vuln in scan_result.vulnerabilities:
                package = vuln.package.lower()
                self._vulnerable_packages.add(package)

                if package not in result.vulnerable_packages:
                    result.vulnerable_packages[package] = []
                result.vulnerable_packages[package].append(vuln.cve_id or vuln.title)

            logger.info(f"Found {len(self._vulnerable_packages)} vulnerable packages")

        except Exception as e:
            logger.warning(f"Dependency scan failed: {e}")

    def _find_python_files(self, project_path: Path) -> list[Path]:
        """Find all Python files in the project."""
        skip_dirs = {
            "node_modules", ".git", ".venv", "venv", "__pycache__",
            ".tox", ".pytest_cache", "dist", "build", ".eggs"
        }

        files = []
        for file_path in project_path.rglob("*.py"):
            if not any(skip in file_path.parts for skip in skip_dirs):
                files.append(file_path)

        return files

    def _analyze_file(self, file_path: Path, result: AnalysisResult) -> None:
        """Analyze a Python file for endpoints."""
        try:
            content = file_path.read_text(encoding="utf-8")
        except Exception:
            return

        # Extract imports
        imports = self._extract_imports(content)

        # Find route decorators
        endpoints = self._find_routes(content, str(file_path), imports)

        for endpoint in endpoints:
            endpoint.imports = imports
            result.all_endpoints.append(endpoint)

    def _extract_imports(self, content: str) -> list[str]:
        """Extract imported packages from Python code."""
        imports = []

        try:
            tree = ast.parse(content)

            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.append(alias.name.split(".")[0])
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        imports.append(node.module.split(".")[0])

        except SyntaxError:
            # Fallback to regex
            import_pattern = r'^(?:from\s+(\w+)|import\s+(\w+))'
            for match in re.finditer(import_pattern, content, re.MULTILINE):
                pkg = match.group(1) or match.group(2)
                if pkg:
                    imports.append(pkg)

        return list(set(imports))

    def _find_routes(
        self, content: str, file_path: str, imports: list[str]
    ) -> list[EndpointInfo]:
        """Find route definitions in Python code."""
        endpoints = []
        lines = content.split("\n")

        # Combine patterns based on detected framework
        patterns = []
        if any(imp in ["fastapi", "starlette"] for imp in imports):
            patterns.extend(self.FASTAPI_ROUTE_PATTERNS)
        if any(imp in ["flask"] for imp in imports):
            patterns.extend(self.FLASK_ROUTE_PATTERNS)

        # If no framework detected, try all patterns
        if not patterns:
            patterns = self.FASTAPI_ROUTE_PATTERNS + self.FLASK_ROUTE_PATTERNS

        for i, line in enumerate(lines):
            for pattern in patterns:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    path = match.group(1)

                    # Detect HTTP method
                    method = "GET"
                    method_match = re.search(r'\.(get|post|put|delete|patch|options|head)\s*\(', line, re.I)
                    if method_match:
                        method = method_match.group(1).upper()

                    # Find function name (usually on next line or same line)
                    func_name = ""
                    for j in range(i, min(i + 3, len(lines))):
                        func_match = re.search(r'(?:async\s+)?def\s+(\w+)', lines[j])
                        if func_match:
                            func_name = func_match.group(1)
                            break

                    endpoints.append(EndpointInfo(
                        path=path,
                        method=method,
                        function_name=func_name,
                        file_path=file_path,
                        line_number=i + 1,
                    ))

        return endpoints

    def _calculate_risk_scores(self, result: AnalysisResult) -> None:
        """Calculate risk scores for endpoints and identify vulnerable ones."""
        for endpoint in result.all_endpoints:
            score = 0.0
            vulnerable_pkgs = []

            # Check if endpoint uses vulnerable packages
            for imp in endpoint.imports:
                imp_lower = imp.lower()

                # Direct vulnerable package
                if imp_lower in self._vulnerable_packages:
                    score += 0.5
                    vulnerable_pkgs.append(imp_lower)

                # High-risk package
                if imp_lower in self.HIGH_RISK_PACKAGES:
                    score += 0.3

            # Path-based risk factors
            path_lower = endpoint.path.lower()
            if any(term in path_lower for term in ["admin", "auth", "login", "password", "user"]):
                score += 0.2
            if any(term in path_lower for term in ["upload", "file", "download"]):
                score += 0.2
            if any(term in path_lower for term in ["search", "query", "filter"]):
                score += 0.1
            if any(term in path_lower for term in ["exec", "run", "eval", "shell"]):
                score += 0.3

            # Method-based risk
            if endpoint.method in ["POST", "PUT", "PATCH", "DELETE"]:
                score += 0.1

            endpoint.risk_score = min(score, 1.0)
            endpoint.vulnerable_packages = vulnerable_pkgs

            # Mark as vulnerable if score is high enough or uses vulnerable packages
            if score >= 0.3 or vulnerable_pkgs:
                result.vulnerable_endpoints.append(endpoint)

    def get_watch_paths(
        self,
        path: Optional[str] = None,
        min_risk_score: float = 0.0,
        include_high_risk: bool = True,
    ) -> list[str]:
        """Get list of paths that should be monitored.

        Args:
            path: Project path to analyze.
            min_risk_score: Minimum risk score for inclusion.
            include_high_risk: Include high-risk paths even without vulnerabilities.

        Returns:
            List of URL paths to monitor.
        """
        result = self.analyze(path)

        paths = set()

        for endpoint in result.vulnerable_endpoints:
            if endpoint.risk_score >= min_risk_score:
                paths.add(endpoint.path)

        if include_high_risk:
            for endpoint in result.all_endpoints:
                if endpoint.risk_score >= 0.5:
                    paths.add(endpoint.path)

        return list(paths)


def detect_vulnerable_endpoints(project_path: str) -> list[str]:
    """Convenience function to detect vulnerable endpoints.

    Args:
        project_path: Path to the project to analyze.

    Returns:
        List of vulnerable endpoint paths.
    """
    detector = VulnerableEndpointDetector()
    return detector.get_watch_paths(project_path)
