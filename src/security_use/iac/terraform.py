"""Terraform HCL2 parser."""

import re
from typing import Any, Optional

import hcl2

from security_use.iac.base import IaCParser, IaCResource, ParseResult


class TerraformParser(IaCParser):
    """Parser for Terraform .tf files (HCL2 format)."""

    # Resource type to provider mapping
    PROVIDER_PREFIXES = {
        "aws_": "aws",
        "azurerm_": "azure",
        "google_": "gcp",
        "kubernetes_": "kubernetes",
        "helm_": "helm",
        "docker_": "docker",
    }

    def parse(self, content: str, file_path: str = "<string>") -> ParseResult:
        """Parse Terraform HCL2 content.

        Args:
            content: HCL2 file content.
            file_path: Path to the file.

        Returns:
            ParseResult with resources and any errors.
        """
        result = ParseResult()

        try:
            # Parse HCL2
            parsed = hcl2.loads(content)
        except Exception as e:
            result.errors.append(f"Failed to parse {file_path}: {e}")
            return result

        # Extract resources
        for resource_block in parsed.get("resource", []):
            for resource_type, instances in resource_block.items():
                # instances is a dict: {resource_name: config, ...}
                for resource_name, config in instances.items():
                    line_number = self._find_resource_line(
                        content, resource_type, resource_name
                    )

                    resource = IaCResource(
                        resource_type=resource_type,
                        name=resource_name,
                        config=config if isinstance(config, dict) else {},
                        file_path=file_path,
                        line_number=line_number,
                        provider=self._get_provider(resource_type),
                    )
                    result.resources.append(resource)

        # Extract data sources
        for data_block in parsed.get("data", []):
            for data_type, instances in data_block.items():
                # instances is a dict: {data_name: config, ...}
                for data_name, config in instances.items():
                    line_number = self._find_data_line(
                        content, data_type, data_name
                    )

                    resource = IaCResource(
                        resource_type=f"data.{data_type}",
                        name=data_name,
                        config=config if isinstance(config, dict) else {},
                        file_path=file_path,
                        line_number=line_number,
                        provider=self._get_provider(data_type),
                    )
                    result.resources.append(resource)

        # Extract variables
        for var_block in parsed.get("variable", []):
            for var_name, var_config in var_block.items():
                result.variables[var_name] = var_config

        # Extract outputs
        for output_block in parsed.get("output", []):
            for output_name, output_config in output_block.items():
                result.outputs[output_name] = output_config

        return result

    def _find_resource_line(
        self, content: str, resource_type: str, resource_name: str
    ) -> int:
        """Find the line number where a resource is defined."""
        pattern = rf'resource\s+"{re.escape(resource_type)}"\s+"{re.escape(resource_name)}"'
        return self._find_pattern_line(content, pattern)

    def _find_data_line(
        self, content: str, data_type: str, data_name: str
    ) -> int:
        """Find the line number where a data source is defined."""
        pattern = rf'data\s+"{re.escape(data_type)}"\s+"{re.escape(data_name)}"'
        return self._find_pattern_line(content, pattern)

    def _find_pattern_line(self, content: str, pattern: str) -> int:
        """Find line number matching a pattern."""
        lines = content.split("\n")
        for i, line in enumerate(lines, start=1):
            if re.search(pattern, line):
                return i
        return 1  # Default to line 1 if not found

    def _get_provider(self, resource_type: str) -> str:
        """Determine provider from resource type."""
        for prefix, provider in self.PROVIDER_PREFIXES.items():
            if resource_type.startswith(prefix):
                return provider
        return "unknown"

    @classmethod
    def supported_extensions(cls) -> list[str]:
        """Return supported file extensions."""
        return [".tf"]


class TerraformPlanParser(IaCParser):
    """Parser for Terraform plan JSON output."""

    def parse(self, content: str, file_path: str = "<string>") -> ParseResult:
        """Parse Terraform plan JSON.

        Args:
            content: JSON plan output.
            file_path: Path to the file.

        Returns:
            ParseResult with planned resources.
        """
        import json

        result = ParseResult()

        try:
            plan = json.loads(content)
        except json.JSONDecodeError as e:
            result.errors.append(f"Failed to parse {file_path}: {e}")
            return result

        # Extract planned resources from resource_changes
        for change in plan.get("resource_changes", []):
            if change.get("change", {}).get("actions", []) == ["no-op"]:
                continue

            resource_type = change.get("type", "unknown")
            resource_name = change.get("name", "unknown")

            # Get the planned values
            after = change.get("change", {}).get("after", {})

            resource = IaCResource(
                resource_type=resource_type,
                name=resource_name,
                config=after if isinstance(after, dict) else {},
                file_path=file_path,
                line_number=1,
                provider=change.get("provider_name", "unknown").split("/")[-1],
            )
            result.resources.append(resource)

        return result

    @classmethod
    def supported_extensions(cls) -> list[str]:
        """Return supported file extensions."""
        return [".tfplan.json", ".tfplan"]
