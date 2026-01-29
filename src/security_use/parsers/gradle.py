"""Parser for Gradle build files (build.gradle, build.gradle.kts)."""

import re
from typing import Optional

from security_use.parsers.base import Dependency, DependencyParser


class GradleParser(DependencyParser):
    """Parser for Gradle build files."""

    # Regex patterns for Gradle dependencies
    # Groovy: implementation 'group:artifact:version'
    GROOVY_DEP_RE = re.compile(
        r"(?:implementation|api|compile|runtimeOnly|testImplementation|testCompile|compileOnly)"
        r"\s*['\"](?P<group>[^:]+):(?P<artifact>[^:]+):(?P<version>[^'\"]+)['\"]"
    )
    # Groovy: implementation group: 'group', name: 'artifact', version: 'version'
    GROOVY_MAP_RE = re.compile(
        r"(?:implementation|api|compile|runtimeOnly|testImplementation|testCompile|compileOnly)"
        r"\s+group:\s*['\"](?P<group>[^'\"]+)['\"],\s*"
        r"name:\s*['\"](?P<artifact>[^'\"]+)['\"],\s*"
        r"version:\s*['\"](?P<version>[^'\"]+)['\"]"
    )
    # Kotlin DSL: implementation("group:artifact:version")
    KOTLIN_DEP_RE = re.compile(
        r"(?:implementation|api|compile|runtimeOnly|testImplementation|testCompile|compileOnly)"
        r"\s*\(\s*['\"](?P<group>[^:]+):(?P<artifact>[^:]+):(?P<version>[^'\"]+)['\"]\s*\)"
    )

    def parse(self, content: str) -> list[Dependency]:
        """Parse Gradle build file content."""
        dependencies = []

        for line_num, line in enumerate(content.splitlines(), start=1):
            dep = self._parse_line(line, line_num)
            if dep:
                dependencies.append(dep)

        return dependencies

    def _parse_line(self, line: str, line_number: int) -> Optional[Dependency]:
        """Parse a single line from build.gradle."""
        line = line.strip()

        # Skip comments
        if line.startswith("//") or line.startswith("/*") or line.startswith("*"):
            return None

        # Try Groovy string format
        match = self.GROOVY_DEP_RE.search(line)
        if match:
            return self._create_dependency(match, line_number)

        # Try Groovy map format
        match = self.GROOVY_MAP_RE.search(line)
        if match:
            return self._create_dependency(match, line_number)

        # Try Kotlin DSL format
        match = self.KOTLIN_DEP_RE.search(line)
        if match:
            return self._create_dependency(match, line_number)

        return None

    def _create_dependency(self, match: re.Match, line_number: int) -> Dependency:
        """Create a Dependency from a regex match."""
        group = match.group("group")
        artifact = match.group("artifact")
        version = match.group("version")

        # For Maven/Gradle, the package name is typically group:artifact
        name = f"{group}:{artifact}"

        return Dependency(
            name=name,
            version=version,
            version_spec=f"={version}",
            line_number=line_number,
            ecosystem="Maven",  # Gradle uses Maven Central
        )

    @classmethod
    def supported_filenames(cls) -> list[str]:
        """Return supported filenames."""
        return [
            "build.gradle",
            "build.gradle.kts",
        ]
