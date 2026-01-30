"""SBOM generator for creating CycloneDX and SPDX documents."""

import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional

from security_use.dependency_scanner import DependencyScanner
from security_use.parsers.base import Dependency
from security_use.sbom.models import SBOMComponent, SBOMFormat, SBOMOutput


class SBOMGenerator:
    """Generate Software Bill of Materials in various formats."""

    # Ecosystem to PURL type mapping
    PURL_TYPES = {
        "PyPI": "pypi",
        "npm": "npm",
        "Maven": "maven",
        "NuGet": "nuget",
        "Packagist": "composer",
        "conda": "conda",
    }

    def __init__(self) -> None:
        """Initialize the SBOM generator."""
        self.scanner = DependencyScanner()

    def generate(
        self,
        path: Path,
        format: SBOMFormat = SBOMFormat.CYCLONEDX_JSON,
        include_vulnerabilities: bool = False,
    ) -> SBOMOutput:
        """Generate an SBOM for the given path.

        Args:
            path: Path to the project directory.
            format: Output format for the SBOM.
            include_vulnerabilities: Include vulnerability information (VEX).

        Returns:
            SBOMOutput containing the generated SBOM.
        """
        # Scan for dependencies
        result = self.scanner.scan_path(path)

        # Convert to SBOM components
        components = self._create_components(result.scanned_files, include_vulnerabilities)

        # Generate output in requested format
        if format == SBOMFormat.CYCLONEDX_JSON:
            content = self._generate_cyclonedx_json(components, path)
        elif format == SBOMFormat.CYCLONEDX_XML:
            content = self._generate_cyclonedx_xml(components, path)
        elif format == SBOMFormat.SPDX_JSON:
            content = self._generate_spdx_json(components, path)
        elif format == SBOMFormat.SPDX_TV:
            content = self._generate_spdx_tv(components, path)
        else:
            raise ValueError(f"Unsupported format: {format}")

        return SBOMOutput(
            format=format,
            content=content,
            component_count=len(components),
        )

    def _create_components(
        self,
        scanned_files: list[str],
        include_vulnerabilities: bool = False,
    ) -> list[SBOMComponent]:
        """Create SBOM components from scanned files."""
        components: list[SBOMComponent] = []
        seen: set[tuple[str, str]] = set()

        for file_path in scanned_files:
            try:
                path = Path(file_path)
                content = path.read_text(encoding="utf-8")
                dependencies = self.scanner.parse_dependencies(content, path.name)

                for dep in dependencies:
                    if dep.version is None:
                        continue

                    key = (dep.name.lower(), dep.version)
                    if key in seen:
                        continue
                    seen.add(key)

                    component = SBOMComponent(
                        name=dep.name,
                        version=dep.version,
                        ecosystem=dep.ecosystem,
                        purl=self._create_purl(dep),
                    )
                    components.append(component)

            except Exception:
                continue

        return components

    def _create_purl(self, dep: Dependency) -> str:
        """Create a Package URL (PURL) for a dependency."""
        purl_type = self.PURL_TYPES.get(dep.ecosystem, "generic")

        # Handle scoped packages (e.g., @scope/package for npm)
        if dep.name.startswith("@"):
            # npm scoped package
            parts = dep.name.split("/")
            namespace = parts[0][1:]  # Remove @
            name = parts[1] if len(parts) > 1 else parts[0]
            return f"pkg:{purl_type}/{namespace}/{name}@{dep.version}"

        # Handle Maven coordinates (group:artifact)
        if ":" in dep.name:
            parts = dep.name.split(":")
            group = parts[0]
            artifact = parts[1] if len(parts) > 1 else parts[0]
            return f"pkg:{purl_type}/{group}/{artifact}@{dep.version}"

        return f"pkg:{purl_type}/{dep.name}@{dep.version}"

    def _generate_cyclonedx_json(
        self,
        components: list[SBOMComponent],
        path: Path,
    ) -> str:
        """Generate CycloneDX 1.5 JSON format."""
        bom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "tools": [
                    {
                        "vendor": "security-use",
                        "name": "security-use",
                        "version": "0.2.8",
                    }
                ],
                "component": {
                    "type": "application",
                    "name": path.name,
                    "version": "0.0.0",
                },
            },
            "components": [
                {
                    "type": "library",
                    "name": c.name,
                    "version": c.version,
                    "purl": c.purl,
                    "bom-ref": c.purl,
                }
                for c in components
            ],
        }

        return json.dumps(bom, indent=2)

    def _generate_cyclonedx_xml(
        self,
        components: list[SBOMComponent],
        path: Path,
    ) -> str:
        """Generate CycloneDX 1.5 XML format."""
        lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<bom xmlns="http://cyclonedx.org/schema/bom/1.5"',
            f'     serialNumber="urn:uuid:{uuid.uuid4()}"',
            '     version="1">',
            "  <metadata>",
            f"    <timestamp>{datetime.utcnow().isoformat()}Z</timestamp>",
            "    <tools>",
            "      <tool>",
            "        <vendor>security-use</vendor>",
            "        <name>security-use</name>",
            "        <version>0.2.8</version>",
            "      </tool>",
            "    </tools>",
            "    <component type=\"application\">",
            f"      <name>{self._xml_escape(path.name)}</name>",
            "      <version>0.0.0</version>",
            "    </component>",
            "  </metadata>",
            "  <components>",
        ]

        for c in components:
            lines.extend([
                f'    <component type="library" bom-ref="{self._xml_escape(c.purl or c.name)}">',
                f"      <name>{self._xml_escape(c.name)}</name>",
                f"      <version>{self._xml_escape(c.version)}</version>",
            ])
            if c.purl:
                lines.append(f"      <purl>{self._xml_escape(c.purl)}</purl>")
            lines.append("    </component>")

        lines.extend([
            "  </components>",
            "</bom>",
        ])

        return "\n".join(lines)

    def _generate_spdx_json(
        self,
        components: list[SBOMComponent],
        path: Path,
    ) -> str:
        """Generate SPDX 2.3 JSON format."""
        spdx_id = f"SPDXRef-DOCUMENT"
        doc_namespace = f"https://security-use.dev/sbom/{uuid.uuid4()}"

        packages = []
        relationships = []

        # Root package
        root_spdx_id = "SPDXRef-RootPackage"
        packages.append({
            "SPDXID": root_spdx_id,
            "name": path.name,
            "versionInfo": "0.0.0",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
        })

        relationships.append({
            "spdxElementId": spdx_id,
            "relatedSpdxElement": root_spdx_id,
            "relationshipType": "DESCRIBES",
        })

        for i, c in enumerate(components):
            pkg_spdx_id = f"SPDXRef-Package-{i}"
            packages.append({
                "SPDXID": pkg_spdx_id,
                "name": c.name,
                "versionInfo": c.version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": c.purl,
                    }
                ] if c.purl else [],
            })

            relationships.append({
                "spdxElementId": root_spdx_id,
                "relatedSpdxElement": pkg_spdx_id,
                "relationshipType": "DEPENDS_ON",
            })

        doc = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": spdx_id,
            "name": f"{path.name} SBOM",
            "documentNamespace": doc_namespace,
            "creationInfo": {
                "created": datetime.utcnow().isoformat() + "Z",
                "creators": ["Tool: security-use-0.2.8"],
            },
            "packages": packages,
            "relationships": relationships,
        }

        return json.dumps(doc, indent=2)

    def _generate_spdx_tv(
        self,
        components: list[SBOMComponent],
        path: Path,
    ) -> str:
        """Generate SPDX 2.3 tag-value format."""
        doc_namespace = f"https://security-use.dev/sbom/{uuid.uuid4()}"
        timestamp = datetime.utcnow().isoformat() + "Z"

        lines = [
            "SPDXVersion: SPDX-2.3",
            "DataLicense: CC0-1.0",
            "SPDXID: SPDXRef-DOCUMENT",
            f"DocumentName: {path.name} SBOM",
            f"DocumentNamespace: {doc_namespace}",
            "Creator: Tool: security-use-0.2.8",
            f"Created: {timestamp}",
            "",
            "##### Root Package",
            "",
            "PackageName: " + path.name,
            "SPDXID: SPDXRef-RootPackage",
            "PackageVersion: 0.0.0",
            "PackageDownloadLocation: NOASSERTION",
            "FilesAnalyzed: false",
            "",
            "Relationship: SPDXRef-DOCUMENT DESCRIBES SPDXRef-RootPackage",
            "",
        ]

        for i, c in enumerate(components):
            pkg_id = f"SPDXRef-Package-{i}"
            lines.extend([
                f"##### Package: {c.name}",
                "",
                f"PackageName: {c.name}",
                f"SPDXID: {pkg_id}",
                f"PackageVersion: {c.version}",
                "PackageDownloadLocation: NOASSERTION",
                "FilesAnalyzed: false",
            ])
            if c.purl:
                lines.append(f"ExternalRef: PACKAGE-MANAGER purl {c.purl}")
            lines.extend([
                "",
                f"Relationship: SPDXRef-RootPackage DEPENDS_ON {pkg_id}",
                "",
            ])

        return "\n".join(lines)

    def _xml_escape(self, s: str) -> str:
        """Escape special characters for XML."""
        return (
            s.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&apos;")
        )
