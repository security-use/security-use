"""Parser for Yarn lock files (yarn.lock)."""

import re
from typing import Optional

from security_use.parsers.base import Dependency, DependencyParser


class YarnLockParser(DependencyParser):
    """Parser for yarn.lock files."""

    # Regex to match package entries in yarn.lock v1 format
    # Example: "package-name@^1.0.0":
    PACKAGE_HEADER_RE = re.compile(
        r'^"?(?P<name>@?[^@\s]+)@(?P<version_spec>[^":\s]+)"?:?\s*$'
    )

    # Regex to match resolved version
    VERSION_RE = re.compile(r'^\s+version\s+"?(?P<version>[^"\s]+)"?\s*$')

    def parse(self, content: str) -> list[Dependency]:
        """Parse yarn.lock content."""
        dependencies = []
        current_package: Optional[str] = None
        current_version_spec: Optional[str] = None
        current_line: Optional[int] = None

        for line_num, line in enumerate(content.splitlines(), start=1):
            # Check for package header
            header_match = self.PACKAGE_HEADER_RE.match(line)
            if header_match:
                current_package = header_match.group("name")
                current_version_spec = header_match.group("version_spec")
                current_line = line_num
                continue

            # Check for version line
            if current_package:
                version_match = self.VERSION_RE.match(line)
                if version_match:
                    version = version_match.group("version")
                    dependencies.append(
                        Dependency(
                            name=current_package,
                            version=version,
                            version_spec=current_version_spec,
                            line_number=current_line,
                            ecosystem="npm",
                        )
                    )
                    current_package = None
                    current_version_spec = None
                    current_line = None

            # Reset on empty line (end of entry)
            if not line.strip():
                current_package = None
                current_version_spec = None
                current_line = None

        return dependencies

    @classmethod
    def supported_filenames(cls) -> list[str]:
        """Return supported filenames."""
        return ["yarn.lock"]


class PnpmLockParser(DependencyParser):
    """Parser for pnpm-lock.yaml files."""

    # Simple regex for YAML package entries
    # Matches: /package-name@version or /@scope/package-name@version
    PACKAGE_RE = re.compile(r"^  ['\"]?/?(?P<name>@?[^@\s:]+)@(?P<version>[^'\":\s]+)")

    def parse(self, content: str) -> list[Dependency]:
        """Parse pnpm-lock.yaml content."""
        dependencies = []
        seen_packages: set[str] = set()

        for line_num, line in enumerate(content.splitlines(), start=1):
            match = self.PACKAGE_RE.match(line)
            if match:
                name = match.group("name")
                version = match.group("version")

                # Deduplicate
                key = f"{name}@{version}"
                if key in seen_packages:
                    continue
                seen_packages.add(key)

                dependencies.append(
                    Dependency(
                        name=name,
                        version=version,
                        version_spec=f"={version}",
                        line_number=line_num,
                        ecosystem="npm",
                    )
                )

        return dependencies

    @classmethod
    def supported_filenames(cls) -> list[str]:
        """Return supported filenames."""
        return ["pnpm-lock.yaml"]
