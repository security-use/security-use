"""Parser for requirements.txt files."""

import re
from typing import Optional

from security_use.parsers.base import Dependency, DependencyParser


class RequirementsParser(DependencyParser):
    """Parser for requirements.txt format files."""

    # Regex patterns for parsing requirements
    COMMENT_RE = re.compile(r"#.*$")
    REQUIREMENT_RE = re.compile(
        r"^(?P<name>[a-zA-Z0-9][-a-zA-Z0-9._]*)"
        r"(?:\[(?P<extras>[^\]]+)\])?"
        r"(?P<spec>(?:[<>=!~]+[^;#\s,]+,?)+)?"
        r"(?:;.*)?$"
    )
    VERSION_RE = re.compile(r"[<>=!~]+(?P<version>[^,<>=!~;#\s]+)")

    def parse(self, content: str) -> list[Dependency]:
        """Parse requirements.txt content."""
        dependencies = []

        for line_num, line in enumerate(content.splitlines(), start=1):
            dep = self._parse_line(line, line_num)
            if dep:
                dependencies.append(dep)

        return dependencies

    def _parse_line(self, line: str, line_number: int) -> Optional[Dependency]:
        """Parse a single line from requirements.txt."""
        # Remove comments and whitespace
        line = self.COMMENT_RE.sub("", line).strip()

        # Skip empty lines and special directives
        if not line or line.startswith("-") or line.startswith("http"):
            return None

        # Skip editable installs
        if line.startswith("-e") or line.startswith("--"):
            return None

        match = self.REQUIREMENT_RE.match(line)
        if not match:
            return None

        name = match.group("name")
        extras_str = match.group("extras")
        spec = match.group("spec")

        extras = [e.strip() for e in extras_str.split(",")] if extras_str else None

        version = None
        if spec:
            # Extract exact version if pinned (==)
            if "==" in spec:
                ver_match = re.search(r"==([^,<>=!~;#\s]+)", spec)
                if ver_match:
                    version = ver_match.group(1)
            else:
                # For ranges, extract the lower bound
                ver_matches = self.VERSION_RE.findall(spec)
                if ver_matches:
                    version = ver_matches[0]

        return Dependency(
            name=name,
            version=version,
            version_spec=spec,
            line_number=line_number,
            extras=extras,
        )

    @classmethod
    def supported_filenames(cls) -> list[str]:
        """Return supported filenames."""
        return [
            "requirements.txt",
            "requirements-dev.txt",
            "requirements-test.txt",
            "requirements.in",
            "constraints.txt",
        ]
