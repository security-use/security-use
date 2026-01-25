"""Dependency vulnerability fixer.

Updates vulnerable dependencies to safe versions in requirements files.
"""

import re
import json
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class FixResult:
    """Result of applying a fix."""
    success: bool
    file_modified: str = ""
    old_version: str = ""
    new_version: str = ""
    diff: str = ""
    before: str = ""
    after: str = ""
    explanation: str = ""
    error: Optional[str] = None


class DependencyFixer:
    """Fixer for dependency vulnerabilities."""

    def fix(
        self,
        path: str,
        package_name: str,
        target_version: Optional[str] = None
    ) -> FixResult:
        """Fix a vulnerable dependency by updating its version.

        Args:
            path: Path to the project directory.
            package_name: Name of the package to update.
            target_version: Version to update to (if not specified, uses latest safe version).

        Returns:
            FixResult with the outcome.
        """
        path_obj = Path(path)

        if not path_obj.exists():
            return FixResult(
                success=False,
                error=f"Path does not exist: {path}"
            )

        # Find the requirements file containing the package
        req_file = self._find_package_file(path_obj, package_name)
        if not req_file:
            return FixResult(
                success=False,
                error=f"Package '{package_name}' not found in any dependency file"
            )

        try:
            original_content = req_file.read_text()
            old_version = self._get_package_version(original_content, package_name)

            if not old_version:
                return FixResult(
                    success=False,
                    error=f"Could not find version for '{package_name}'"
                )

            # Determine target version
            new_version = target_version or self._get_latest_version(package_name) or old_version

            if old_version == new_version:
                return FixResult(
                    success=False,
                    error=f"Package is already at version {new_version}"
                )

            # Update the file
            new_content = self._update_package_version(
                original_content, package_name, old_version, new_version
            )

            # Write the file
            req_file.write_text(new_content)

            # Generate diff
            diff = self._generate_diff(original_content, new_content, package_name, old_version, new_version)

            return FixResult(
                success=True,
                file_modified=str(req_file.relative_to(path_obj) if path_obj.is_dir() else req_file.name),
                old_version=old_version,
                new_version=new_version,
                diff=diff,
                explanation=f"Updated {package_name} from {old_version} to {new_version}",
            )

        except Exception as e:
            return FixResult(
                success=False,
                error=str(e)
            )

    def _find_package_file(self, path: Path, package_name: str) -> Optional[Path]:
        """Find the dependency file containing the package."""
        patterns = ["requirements*.txt", "pyproject.toml", "Pipfile"]

        for pattern in patterns:
            for f in path.glob(pattern):
                content = f.read_text()
                if re.search(rf'\b{re.escape(package_name)}\b', content, re.IGNORECASE):
                    return f

        return None

    def _get_package_version(self, content: str, package_name: str) -> Optional[str]:
        """Extract the current version of a package from file content."""
        # Try requirements.txt format
        match = re.search(
            rf'^{re.escape(package_name)}\s*[=<>~!]=?\s*([\d.]+)',
            content,
            re.MULTILINE | re.IGNORECASE
        )
        if match:
            return match.group(1)

        # Try pyproject.toml format
        match = re.search(
            rf'"{re.escape(package_name)}\s*[=<>~!]=?\s*([\d.]+)"',
            content,
            re.IGNORECASE
        )
        if match:
            return match.group(1)

        return None

    def _update_package_version(
        self,
        content: str,
        package_name: str,
        old_version: str,
        new_version: str
    ) -> str:
        """Update the package version in the file content."""
        # Replace in requirements.txt format
        pattern = rf'^({re.escape(package_name)}\s*[=<>~!]=?\s*){re.escape(old_version)}'
        new_content = re.sub(pattern, rf'\g<1>{new_version}', content, flags=re.MULTILINE | re.IGNORECASE)

        # If no change, try pyproject.toml format
        if new_content == content:
            pattern = rf'("{re.escape(package_name)}\s*[=<>~!>=]*){re.escape(old_version)}'
            new_content = re.sub(pattern, rf'\g<1>{new_version}', content, flags=re.IGNORECASE)

        return new_content

    def _generate_diff(
        self,
        old_content: str,
        new_content: str,
        package_name: str,
        old_version: str,
        new_version: str
    ) -> str:
        """Generate a simple diff of the changes."""
        old_lines = old_content.split("\n")
        new_lines = new_content.split("\n")

        diff_lines = []
        for i, (old_line, new_line) in enumerate(zip(old_lines, new_lines)):
            if old_line != new_line:
                diff_lines.append(f"-{old_line}")
                diff_lines.append(f"+{new_line}")

        if not diff_lines:
            diff_lines = [
                f"-{package_name}=={old_version}",
                f"+{package_name}=={new_version}",
            ]

        return "\n".join(diff_lines)

    def _get_latest_version(self, package_name: str) -> Optional[str]:
        """Get the latest version of a package from PyPI."""
        try:
            url = f"https://pypi.org/pypi/{package_name}/json"
            request = urllib.request.Request(url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(request, timeout=10) as response:
                data = json.loads(response.read().decode())
                return data.get("info", {}).get("version")
        except Exception:
            return None
