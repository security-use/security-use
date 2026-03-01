"""Parser for .NET project files (*.csproj, packages.config)."""

import re
import xml.etree.ElementTree as ET
from typing import Optional

from security_use.parsers.base import Dependency, DependencyParser


class CsprojParser(DependencyParser):
    """Parser for .NET .csproj and .fsproj files."""

    def parse(self, content: str) -> list[Dependency]:
        """Parse .csproj/.fsproj content."""
        dependencies = []

        try:
            root = ET.fromstring(content)
        except ET.ParseError:
            return dependencies

        # Find PackageReference elements
        for item_group in root.iter():
            if item_group.tag == "PackageReference":
                name = item_group.get("Include")
                version = item_group.get("Version")

                if name:
                    # Version might be in a child element
                    if not version:
                        version_elem = item_group.find("Version")
                        if version_elem is not None:
                            version = version_elem.text

                    dependencies.append(
                        Dependency(
                            name=name,
                            version=version,
                            version_spec=f"={version}" if version else None,
                            ecosystem="NuGet",
                        )
                    )

        return dependencies

    @classmethod
    def supported_filenames(cls) -> list[str]:
        """Return supported filenames."""
        return [
            "*.csproj",
            "*.fsproj",
            "*.vbproj",
            "Directory.Packages.props",
        ]


class PackagesConfigParser(DependencyParser):
    """Parser for NuGet packages.config files."""

    def parse(self, content: str) -> list[Dependency]:
        """Parse packages.config content."""
        dependencies = []

        try:
            root = ET.fromstring(content)
        except ET.ParseError:
            return dependencies

        # Find package elements
        for package in root.iter("package"):
            name = package.get("id")
            version = package.get("version")

            if name:
                dependencies.append(
                    Dependency(
                        name=name,
                        version=version,
                        version_spec=f"={version}" if version else None,
                        ecosystem="NuGet",
                    )
                )

        return dependencies

    @classmethod
    def supported_filenames(cls) -> list[str]:
        """Return supported filenames."""
        return ["packages.config"]
