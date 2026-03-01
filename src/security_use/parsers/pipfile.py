"""Parser for Pipfile and Pipfile.lock files."""

import json
import re
from typing import Any, Optional

from security_use.parsers.base import Dependency, DependencyParser

try:
    import tomllib
except ImportError:
    import tomli as tomllib  # type: ignore[import-not-found]


class PipfileParser(DependencyParser):
    """Parser for Pipfile (TOML format)."""

    def parse(self, content: str) -> list[Dependency]:
        """Parse Pipfile content."""
        try:
            data = tomllib.loads(content)
        except Exception:
            return []

        dependencies: list[Dependency] = []

        # Parse packages
        dependencies.extend(self._parse_section(data.get("packages", {})))

        # Parse dev-packages
        dependencies.extend(self._parse_section(data.get("dev-packages", {})))

        return dependencies

    def _parse_section(self, packages: dict[str, Any]) -> list[Dependency]:
        """Parse a packages section."""
        dependencies = []

        for name, spec in packages.items():
            version = None
            version_spec = None
            extras = None

            if isinstance(spec, str):
                version, version_spec = self._parse_version_spec(spec)
            elif isinstance(spec, dict):
                ver = spec.get("version")
                if ver:
                    version, version_spec = self._parse_version_spec(ver)
                extras = spec.get("extras")

            dependencies.append(
                Dependency(
                    name=name,
                    version=version,
                    version_spec=version_spec,
                    extras=extras,
                )
            )

        return dependencies

    def _parse_version_spec(self, spec: str) -> tuple[Optional[str], str]:
        """Parse a version specifier."""
        spec = spec.strip()

        if spec == "*":
            return None, spec

        # Extract exact version
        if spec.startswith("=="):
            return spec[2:].strip(), spec

        # For ranges, try to extract a version number
        match = re.search(r"[\d.]+", spec)
        if match:
            return match.group(0), spec

        return None, spec

    @classmethod
    def supported_filenames(cls) -> list[str]:
        """Return supported filenames."""
        return ["Pipfile"]


class PipfileLockParser(DependencyParser):
    """Parser for Pipfile.lock (JSON format)."""

    def parse(self, content: str) -> list[Dependency]:
        """Parse Pipfile.lock content."""
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return []

        dependencies: list[Dependency] = []

        # Parse default packages
        dependencies.extend(self._parse_section(data.get("default", {})))

        # Parse develop packages
        dependencies.extend(self._parse_section(data.get("develop", {})))

        return dependencies

    def _parse_section(self, packages: dict[str, Any]) -> list[Dependency]:
        """Parse a packages section."""
        dependencies = []

        for name, info in packages.items():
            version = None
            if isinstance(info, dict):
                ver = info.get("version", "")
                if ver.startswith("=="):
                    version = ver[2:]
                else:
                    version = ver

            dependencies.append(
                Dependency(
                    name=name,
                    version=version,
                    version_spec=info.get("version") if isinstance(info, dict) else None,
                )
            )

        return dependencies

    @classmethod
    def supported_filenames(cls) -> list[str]:
        """Return supported filenames."""
        return ["Pipfile.lock"]
