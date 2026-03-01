"""Maven pom.xml parser."""

import re
import xml.etree.ElementTree as ET
from typing import Optional

from security_use.parsers.base import Dependency, DependencyParser


class MavenParser(DependencyParser):
    """Parser for Maven pom.xml files."""

    # Maven namespace
    MAVEN_NS = "{http://maven.apache.org/POM/4.0.0}"

    def parse(self, content: str) -> list[Dependency]:
        """Parse Maven pom.xml content.

        Args:
            content: The pom.xml file content.

        Returns:
            List of dependencies found.
        """
        dependencies = []

        try:
            # Remove namespace for easier parsing
            content_clean = re.sub(r'\sxmlns="[^"]+"', '', content, count=1)
            root = ET.fromstring(content_clean)
        except ET.ParseError:
            return dependencies

        # Extract properties for variable substitution
        properties = self._extract_properties(root)

        # Find all dependency elements
        for dep_elem in root.iter("dependency"):
            group_id = self._get_text(dep_elem, "groupId")
            artifact_id = self._get_text(dep_elem, "artifactId")
            version = self._get_text(dep_elem, "version")

            if not group_id or not artifact_id:
                continue

            # Resolve property references like ${project.version}
            if version:
                version = self._resolve_properties(version, properties)

            # Skip if version still has unresolved properties
            if version and "${" in version:
                continue

            # Create Maven coordinate as package name
            package_name = f"{group_id}:{artifact_id}"

            dependencies.append(
                Dependency(
                    name=package_name,
                    version=version,
                    extras=None,
                    source="pom.xml",
                    ecosystem="Maven",
                )
            )

        return dependencies

    def _extract_properties(self, root: ET.Element) -> dict[str, str]:
        """Extract properties from pom.xml for variable substitution."""
        properties = {}

        # Get project version
        version_elem = root.find("version")
        if version_elem is not None and version_elem.text:
            properties["project.version"] = version_elem.text

        # Get properties section
        props_elem = root.find("properties")
        if props_elem is not None:
            for prop in props_elem:
                tag = prop.tag.replace(self.MAVEN_NS, "")
                if prop.text:
                    properties[tag] = prop.text

        return properties

    def _resolve_properties(self, value: str, properties: dict[str, str]) -> str:
        """Resolve ${property} references in a value."""
        pattern = r"\$\{([^}]+)\}"

        def replace(match: re.Match) -> str:
            prop_name = match.group(1)
            return properties.get(prop_name, match.group(0))

        return re.sub(pattern, replace, value)

    def _get_text(self, elem: ET.Element, tag: str) -> Optional[str]:
        """Get text content of a child element."""
        child = elem.find(tag)
        if child is not None and child.text:
            return child.text.strip()
        return None

    @classmethod
    def supported_filenames(cls) -> list[str]:
        """Return supported filenames."""
        return ["pom.xml"]
