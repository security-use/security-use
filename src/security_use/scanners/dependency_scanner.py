"""Dependency vulnerability scanner.

Scans dependency files (requirements.txt, pyproject.toml, etc.) for known
vulnerabilities using the OSV database.
"""

import os
import re
import time
import json
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


class Severity(str, Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"

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
    """Represents a detected dependency vulnerability."""
    package_name: str
    installed_version: str
    severity: Severity
    description: str
    cve_id: Optional[str] = None
    fixed_version: Optional[str] = None
    remediation: str = ""
    vulnerable_range: str = ""
    references: list[str] = field(default_factory=list)


@dataclass
class DependencyScanResult:
    """Result of a dependency vulnerability scan."""
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    scanned_files: list[str] = field(default_factory=list)
    total_dependencies: int = 0
    scan_duration_ms: int = 0
    error: Optional[str] = None


class DependencyScanner:
    """Scanner for dependency vulnerabilities using OSV database."""

    def __init__(self):
        self.osv_api_url = "https://api.osv.dev/v1/query"

    def scan(self, path: str) -> DependencyScanResult:
        """Scan a directory for dependency vulnerabilities.

        Args:
            path: Path to the project directory to scan.

        Returns:
            DependencyScanResult with any vulnerabilities found.
        """
        start_time = time.time()
        path_obj = Path(path)

        if not path_obj.exists():
            return DependencyScanResult(
                error=f"Path does not exist: {path}"
            )

        # Find dependency files
        dep_files = self._find_dependency_files(path_obj)
        if not dep_files:
            return DependencyScanResult(
                scanned_files=[],
                total_dependencies=0,
                scan_duration_ms=int((time.time() - start_time) * 1000),
            )

        # Parse dependencies from files
        dependencies = {}
        scanned_files = []
        for dep_file in dep_files:
            try:
                file_deps = self._parse_dependency_file(dep_file)
                dependencies.update(file_deps)
                scanned_files.append(str(dep_file.relative_to(path_obj)))
            except Exception:
                continue

        # Query OSV for vulnerabilities
        vulnerabilities = []
        for package_name, version in dependencies.items():
            try:
                vulns = self._query_osv(package_name, version)
                vulnerabilities.extend(vulns)
            except Exception:
                continue

        elapsed_ms = int((time.time() - start_time) * 1000)

        return DependencyScanResult(
            vulnerabilities=vulnerabilities,
            scanned_files=scanned_files,
            total_dependencies=len(dependencies),
            scan_duration_ms=elapsed_ms,
        )

    def _find_dependency_files(self, path: Path) -> list[Path]:
        """Find dependency files in the given path."""
        files = []
        patterns = [
            "requirements*.txt",
            "pyproject.toml",
            "setup.py",
            "Pipfile",
            "Pipfile.lock",
            "poetry.lock",
        ]

        for pattern in patterns:
            files.extend(path.glob(pattern))
            files.extend(path.glob(f"**/{pattern}"))

        # Remove duplicates and limit depth
        seen = set()
        unique_files = []
        for f in files:
            if f not in seen and len(f.relative_to(path).parts) <= 3:
                seen.add(f)
                unique_files.append(f)

        return unique_files[:20]  # Limit to prevent scanning too many files

    def _parse_dependency_file(self, file_path: Path) -> dict[str, str]:
        """Parse a dependency file and return package -> version mapping."""
        dependencies = {}
        content = file_path.read_text()

        if file_path.name == "pyproject.toml":
            dependencies = self._parse_pyproject_toml(content)
        elif file_path.name.startswith("requirements"):
            dependencies = self._parse_requirements_txt(content)
        elif file_path.name == "Pipfile":
            dependencies = self._parse_pipfile(content)

        return dependencies

    def _parse_requirements_txt(self, content: str) -> dict[str, str]:
        """Parse requirements.txt format."""
        dependencies = {}
        for line in content.strip().split("\n"):
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue

            # Handle various formats: pkg==1.0, pkg>=1.0, pkg~=1.0, pkg
            match = re.match(r'^([a-zA-Z0-9_-]+)\s*([=<>~!]+)?\s*([\d.]+)?', line)
            if match:
                pkg_name = match.group(1).lower()
                version = match.group(3) or "0.0.0"
                dependencies[pkg_name] = version

        return dependencies

    def _parse_pyproject_toml(self, content: str) -> dict[str, str]:
        """Parse pyproject.toml dependencies."""
        dependencies = {}

        # Simple regex-based parsing for dependencies
        in_deps_section = False
        for line in content.split("\n"):
            if re.match(r'\[project\]', line) or re.match(r'dependencies\s*=', line):
                in_deps_section = True
                continue
            if in_deps_section and line.startswith("["):
                in_deps_section = False
                continue
            if in_deps_section:
                # Match "package>=version" or "package==version" in various formats
                match = re.search(r'"([a-zA-Z0-9_-]+)\s*([=<>~!]+)?\s*([\d.]+)?["\']?', line)
                if match:
                    pkg_name = match.group(1).lower()
                    version = match.group(3) or "0.0.0"
                    dependencies[pkg_name] = version

        return dependencies

    def _parse_pipfile(self, content: str) -> dict[str, str]:
        """Parse Pipfile dependencies."""
        dependencies = {}
        in_packages = False

        for line in content.split("\n"):
            if line.strip() == "[packages]":
                in_packages = True
                continue
            if line.startswith("["):
                in_packages = False
                continue
            if in_packages and "=" in line:
                parts = line.split("=", 1)
                if len(parts) == 2:
                    pkg_name = parts[0].strip().lower()
                    version_str = parts[1].strip().strip('"\'')
                    version = re.search(r'[\d.]+', version_str)
                    dependencies[pkg_name] = version.group() if version else "0.0.0"

        return dependencies

    def _query_osv(self, package_name: str, version: str) -> list[Vulnerability]:
        """Query OSV database for vulnerabilities."""
        vulnerabilities = []

        try:
            payload = json.dumps({
                "version": version,
                "package": {
                    "name": package_name,
                    "ecosystem": "PyPI"
                }
            }).encode()

            request = urllib.request.Request(
                self.osv_api_url,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST"
            )

            with urllib.request.urlopen(request, timeout=10) as response:
                data = json.loads(response.read().decode())

            for vuln in data.get("vulns", []):
                cve_id = None
                for alias in vuln.get("aliases", []):
                    if alias.startswith("CVE-"):
                        cve_id = alias
                        break

                # Determine severity
                severity = Severity.UNKNOWN
                for sev in vuln.get("severity", []):
                    if sev.get("type") == "CVSS_V3":
                        score_str = sev.get("score", "")
                        try:
                            # Extract score from vector or use directly
                            if "/" in score_str:
                                score = float(score_str.split("/")[0].split(":")[-1])
                            else:
                                score = float(score_str)
                            severity = Severity.from_cvss(score)
                        except (ValueError, IndexError):
                            pass
                        break

                # Get fixed version
                fixed_version = None
                vulnerable_range = ""
                for affected in vuln.get("affected", []):
                    for r in affected.get("ranges", []):
                        for event in r.get("events", []):
                            if "fixed" in event:
                                fixed_version = event["fixed"]
                            if "introduced" in event:
                                vulnerable_range = f">={event['introduced']}"

                vulnerabilities.append(Vulnerability(
                    package_name=package_name,
                    installed_version=version,
                    severity=severity,
                    description=vuln.get("summary", vuln.get("details", "No description available")),
                    cve_id=cve_id or vuln.get("id"),
                    fixed_version=fixed_version,
                    remediation=f"Upgrade to {package_name}>={fixed_version}" if fixed_version else "No fix available",
                    vulnerable_range=vulnerable_range,
                    references=[ref.get("url", "") for ref in vuln.get("references", [])[:3]],
                ))

        except (urllib.error.URLError, json.JSONDecodeError, TimeoutError):
            pass  # Silently fail for network issues

        return vulnerabilities
