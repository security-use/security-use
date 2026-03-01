"""Parser for Conda environment files (environment.yml)."""

import re
from typing import Optional

from security_use.parsers.base import Dependency, DependencyParser


class CondaEnvironmentParser(DependencyParser):
    """Parser for Conda environment.yml files."""

    # Regex for conda dependency format: package=version or package==version
    DEP_RE = re.compile(r"^\s*-\s*(?P<name>[a-zA-Z0-9_-]+)(?:[=<>]+(?P<version>[^\s#]+))?")

    def parse(self, content: str) -> list[Dependency]:
        """Parse environment.yml content."""
        dependencies = []
        in_dependencies = False
        in_pip = False

        for line_num, line in enumerate(content.splitlines(), start=1):
            stripped = line.strip()

            # Track which section we're in
            if stripped == "dependencies:":
                in_dependencies = True
                continue

            if stripped.startswith("- pip:"):
                in_pip = True
                continue

            # Exit dependencies section
            if stripped and not stripped.startswith("-") and ":" in stripped:
                in_dependencies = False
                in_pip = False
                continue

            if not in_dependencies:
                continue

            # Parse pip dependencies (these are PyPI packages)
            if in_pip:
                dep = self._parse_pip_dep(line, line_num)
                if dep:
                    dependencies.append(dep)
                continue

            # Parse conda dependencies
            match = self.DEP_RE.match(line)
            if match:
                name = match.group("name")
                version = match.group("version")

                # Skip python itself and other non-package entries
                if name.lower() in ("python", "pip"):
                    continue

                dependencies.append(
                    Dependency(
                        name=name,
                        version=version,
                        version_spec=f"={version}" if version else None,
                        line_number=line_num,
                        ecosystem="conda",
                    )
                )

        return dependencies

    def _parse_pip_dep(self, line: str, line_num: int) -> Optional[Dependency]:
        """Parse a pip dependency line from conda environment file."""
        # Format: - package==version or - package>=version
        match = re.match(r"^\s*-\s*(?P<name>[a-zA-Z0-9_-]+)(?P<spec>[=<>!]+(?P<version>[^\s#]+))?", line)
        if match:
            name = match.group("name")
            version = match.group("version")
            spec = match.group("spec")

            return Dependency(
                name=name,
                version=version,
                version_spec=spec,
                line_number=line_num,
                ecosystem="PyPI",
            )
        return None

    @classmethod
    def supported_filenames(cls) -> list[str]:
        """Return supported filenames."""
        return [
            "environment.yml",
            "environment.yaml",
            "conda-environment.yml",
            "conda-environment.yaml",
        ]
