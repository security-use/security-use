"""npm package.json and package-lock.json parser."""

import json
import re
from typing import Optional

from security_use.parsers.base import Dependency, DependencyParser


class NpmParser(DependencyParser):
    """Parser for npm package.json files."""

    def parse(self, content: str) -> list[Dependency]:
        """Parse npm package.json content.

        Args:
            content: The package.json file content.

        Returns:
            List of dependencies found.
        """
        dependencies = []

        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return dependencies

        # Parse regular dependencies
        for name, version in data.get("dependencies", {}).items():
            parsed_version = self._parse_version(version)
            if parsed_version:
                dependencies.append(
                    Dependency(
                        name=name,
                        version=parsed_version,
                        version_spec=version,
                        ecosystem="npm",
                    )
                )

        # Parse dev dependencies
        for name, version in data.get("devDependencies", {}).items():
            parsed_version = self._parse_version(version)
            if parsed_version:
                dependencies.append(
                    Dependency(
                        name=name,
                        version=parsed_version,
                        version_spec=version,
                        ecosystem="npm",
                    )
                )

        # Parse peer dependencies
        for name, version in data.get("peerDependencies", {}).items():
            parsed_version = self._parse_version(version)
            if parsed_version:
                dependencies.append(
                    Dependency(
                        name=name,
                        version=parsed_version,
                        version_spec=version,
                        ecosystem="npm",
                    )
                )

        # Parse overrides (may have pinned versions)
        for name, version in data.get("overrides", {}).items():
            if isinstance(version, str):
                parsed_version = self._parse_version(version)
                if parsed_version:
                    dependencies.append(
                        Dependency(
                            name=name,
                            version=parsed_version,
                            version_spec=version,
                            ecosystem="npm",
                        )
                    )

        return dependencies

    def _parse_version(self, version_spec: str) -> Optional[str]:
        """Extract a concrete version from a version specifier.

        Args:
            version_spec: npm version specifier (e.g., "^1.2.3", "~1.2.3", "1.2.3")

        Returns:
            Concrete version string or None if can't be determined.
        """
        if not version_spec or not isinstance(version_spec, str):
            return None

        # Skip workspace references, URLs, git refs, etc.
        if version_spec.startswith(("workspace:", "file:", "git:", "git+", "http:", "https:")):
            return None

        # Skip "latest", "*", etc.
        if version_spec in ("*", "latest", "next", "canary"):
            return None

        # Remove npm: prefix if present
        if version_spec.startswith("npm:"):
            version_spec = version_spec.split("@")[-1]

        # Extract version from common patterns
        # ^1.2.3, ~1.2.3, >=1.2.3, >1.2.3, =1.2.3, 1.2.3
        match = re.match(r'^[\^~>=<]*(\d+\.\d+\.\d+(?:-[\w.]+)?)', version_spec)
        if match:
            return match.group(1)

        # Handle version ranges like "1.2.3 - 2.0.0" - use the lower bound
        range_match = re.match(r'^(\d+\.\d+\.\d+)\s*-', version_spec)
        if range_match:
            return range_match.group(1)

        return None

    @classmethod
    def supported_filenames(cls) -> list[str]:
        """Return supported filenames."""
        return ["package.json"]


class NpmLockParser(DependencyParser):
    """Parser for npm package-lock.json files."""

    def parse(self, content: str) -> list[Dependency]:
        """Parse npm package-lock.json content.

        Args:
            content: The package-lock.json file content.

        Returns:
            List of dependencies found with exact versions.
        """
        dependencies = []

        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return dependencies

        lock_version = data.get("lockfileVersion", 1)

        if lock_version >= 2:
            # npm v7+ lockfile format - use "packages" field
            packages = data.get("packages", {})
            for path, pkg_data in packages.items():
                if not path:  # Skip root package
                    continue

                # Extract package name from path (e.g., "node_modules/lodash")
                name = path.split("node_modules/")[-1]
                version = pkg_data.get("version")

                if name and version:
                    dependencies.append(
                        Dependency(
                            name=name,
                            version=version,
                            ecosystem="npm",
                        )
                    )
        else:
            # npm v6 lockfile format - use "dependencies" field
            self._parse_dependencies_v1(data.get("dependencies", {}), dependencies)

        return dependencies

    def _parse_dependencies_v1(
        self, deps: dict, result: list[Dependency], prefix: str = ""
    ) -> None:
        """Recursively parse dependencies from npm v6 lockfile format."""
        for name, dep_data in deps.items():
            version = dep_data.get("version")
            if version:
                result.append(
                    Dependency(
                        name=name,
                        version=version,
                        ecosystem="npm",
                    )
                )

            # Parse nested dependencies
            nested = dep_data.get("dependencies", {})
            if nested:
                self._parse_dependencies_v1(nested, result, f"{prefix}{name}/")

    @classmethod
    def supported_filenames(cls) -> list[str]:
        """Return supported filenames."""
        return ["package-lock.json"]
