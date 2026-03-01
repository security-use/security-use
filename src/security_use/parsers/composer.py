"""Parser for PHP Composer files (composer.json, composer.lock)."""

import json
from typing import Optional

from security_use.parsers.base import Dependency, DependencyParser


class ComposerParser(DependencyParser):
    """Parser for composer.json files."""

    def parse(self, content: str) -> list[Dependency]:
        """Parse composer.json content."""
        dependencies = []

        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return dependencies

        # Parse require and require-dev sections
        for section in ["require", "require-dev"]:
            deps = data.get(section, {})
            if isinstance(deps, dict):
                for name, version_spec in deps.items():
                    # Skip PHP and extensions
                    if name == "php" or name.startswith("ext-"):
                        continue

                    # Extract version from spec
                    version = self._extract_version(version_spec)

                    dependencies.append(
                        Dependency(
                            name=name,
                            version=version,
                            version_spec=version_spec,
                            ecosystem="Packagist",
                        )
                    )

        return dependencies

    def _extract_version(self, spec: str) -> Optional[str]:
        """Extract a concrete version from a version specification."""
        # Handle various Composer version formats
        # ^1.0, ~1.0, >=1.0, 1.0.*, 1.0.0, etc.
        import re

        # Try to find a version number
        match = re.search(r"(\d+\.\d+(?:\.\d+)?)", spec)
        if match:
            return match.group(1)
        return None

    @classmethod
    def supported_filenames(cls) -> list[str]:
        """Return supported filenames."""
        return ["composer.json"]


class ComposerLockParser(DependencyParser):
    """Parser for composer.lock files."""

    def parse(self, content: str) -> list[Dependency]:
        """Parse composer.lock content."""
        dependencies = []

        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return dependencies

        # Parse packages and packages-dev sections
        for section in ["packages", "packages-dev"]:
            packages = data.get(section, [])
            if isinstance(packages, list):
                for pkg in packages:
                    name = pkg.get("name")
                    version = pkg.get("version")

                    if name:
                        # Remove 'v' prefix if present
                        if version and version.startswith("v"):
                            version = version[1:]

                        dependencies.append(
                            Dependency(
                                name=name,
                                version=version,
                                version_spec=f"={version}" if version else None,
                                ecosystem="Packagist",
                            )
                        )

        return dependencies

    @classmethod
    def supported_filenames(cls) -> list[str]:
        """Return supported filenames."""
        return ["composer.lock"]
