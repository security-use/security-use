"""CloudFormation template parser."""

import json
import re
from typing import Any

import yaml

from security_use.iac.base import IaCParser, IaCResource, ParseResult


# Custom YAML loader that handles CloudFormation intrinsic functions
class CloudFormationLoader(yaml.SafeLoader):
    """YAML loader that handles CloudFormation intrinsic function tags."""

    pass


def _construct_cfn_tag(loader: yaml.SafeLoader, tag_suffix: str, node: yaml.Node) -> dict:
    """Construct a dict representing a CloudFormation intrinsic function."""
    if isinstance(node, yaml.ScalarNode):
        value = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node)
    elif isinstance(node, yaml.MappingNode):
        value = loader.construct_mapping(node)
    else:
        value = None
    return {f"Fn::{tag_suffix}": value}


def _construct_ref(loader: yaml.SafeLoader, node: yaml.Node) -> dict:
    """Construct a Ref intrinsic function."""
    return {"Ref": loader.construct_scalar(node)}


# Register CloudFormation intrinsic function tags
CloudFormationLoader.add_constructor("!Ref", _construct_ref)
CloudFormationLoader.add_constructor("!GetAtt", lambda loader, node: _construct_cfn_tag(loader, "GetAtt", node))
CloudFormationLoader.add_constructor("!Sub", lambda loader, node: _construct_cfn_tag(loader, "Sub", node))
CloudFormationLoader.add_constructor("!Join", lambda loader, node: _construct_cfn_tag(loader, "Join", node))
CloudFormationLoader.add_constructor("!If", lambda loader, node: _construct_cfn_tag(loader, "If", node))
CloudFormationLoader.add_constructor("!Equals", lambda loader, node: _construct_cfn_tag(loader, "Equals", node))
CloudFormationLoader.add_constructor("!And", lambda loader, node: _construct_cfn_tag(loader, "And", node))
CloudFormationLoader.add_constructor("!Or", lambda loader, node: _construct_cfn_tag(loader, "Or", node))
CloudFormationLoader.add_constructor("!Not", lambda loader, node: _construct_cfn_tag(loader, "Not", node))
CloudFormationLoader.add_constructor(
    "!Condition", lambda loader, node: _construct_cfn_tag(loader, "Condition", node)
)
CloudFormationLoader.add_constructor(
    "!FindInMap", lambda loader, node: _construct_cfn_tag(loader, "FindInMap", node)
)
CloudFormationLoader.add_constructor("!Base64", lambda loader, node: _construct_cfn_tag(loader, "Base64", node))
CloudFormationLoader.add_constructor("!Cidr", lambda loader, node: _construct_cfn_tag(loader, "Cidr", node))
CloudFormationLoader.add_constructor("!GetAZs", lambda loader, node: _construct_cfn_tag(loader, "GetAZs", node))
CloudFormationLoader.add_constructor(
    "!ImportValue", lambda loader, node: _construct_cfn_tag(loader, "ImportValue", node)
)
CloudFormationLoader.add_constructor("!Select", lambda loader, node: _construct_cfn_tag(loader, "Select", node))
CloudFormationLoader.add_constructor("!Split", lambda loader, node: _construct_cfn_tag(loader, "Split", node))
CloudFormationLoader.add_constructor(
    "!Transform", lambda loader, node: _construct_cfn_tag(loader, "Transform", node)
)


class CloudFormationParser(IaCParser):
    """Parser for AWS CloudFormation templates (YAML/JSON)."""

    def parse(self, content: str, file_path: str = "<string>") -> ParseResult:
        """Parse CloudFormation template.

        Args:
            content: Template content (YAML or JSON).
            file_path: Path to the file.

        Returns:
            ParseResult with resources and any errors.
        """
        result = ParseResult()

        # Determine format and parse
        template = self._parse_template(content, file_path)
        if template is None:
            result.errors.append(f"Failed to parse {file_path}: Invalid YAML/JSON")
            return result

        # Validate it's a CloudFormation template
        if not self._is_cloudformation(template):
            result.errors.append(f"{file_path} is not a valid CloudFormation template")
            return result

        # Extract resources
        resources = template.get("Resources", {})
        for resource_name, resource_def in resources.items():
            resource_type = resource_def.get("Type", "Unknown")
            properties = resource_def.get("Properties", {})

            line_number = self._find_resource_line(content, resource_name)

            resource = IaCResource(
                resource_type=resource_type,
                name=resource_name,
                config=properties,
                file_path=file_path,
                line_number=line_number,
                provider="aws",
            )
            result.resources.append(resource)

        # Extract parameters as variables
        for param_name, param_def in template.get("Parameters", {}).items():
            result.variables[param_name] = param_def

        # Extract outputs
        for output_name, output_def in template.get("Outputs", {}).items():
            result.outputs[output_name] = output_def

        return result

    def _parse_template(self, content: str, file_path: str) -> dict[str, Any] | None:
        """Parse template content as YAML or JSON."""
        # Try YAML first with CloudFormation-aware loader
        try:
            template = yaml.load(content, Loader=CloudFormationLoader)
            if isinstance(template, dict):
                return template
        except yaml.YAMLError:
            pass

        # Try JSON explicitly
        try:
            template = json.loads(content)
            if isinstance(template, dict):
                return template
        except json.JSONDecodeError:
            pass

        return None

    def _is_cloudformation(self, template: dict[str, Any]) -> bool:
        """Check if the template is a valid CloudFormation template."""
        # Must have either Resources or AWSTemplateFormatVersion
        if "Resources" in template:
            return True
        if "AWSTemplateFormatVersion" in template:
            return True
        return False

    def _find_resource_line(self, content: str, resource_name: str) -> int:
        """Find the line number where a resource is defined."""
        lines = content.split("\n")
        for i, line in enumerate(lines, start=1):
            # Match YAML style: "ResourceName:" at start of line
            if re.match(rf"^\s*{re.escape(resource_name)}\s*:", line):
                return i
            # Match JSON style: "ResourceName": {
            if re.search(rf'"{re.escape(resource_name)}"\s*:\s*\{{', line):
                return i
        return 1

    @classmethod
    def supported_extensions(cls) -> list[str]:
        """Return supported file extensions."""
        return [".yaml", ".yml", ".json", ".template"]


class SAMParser(CloudFormationParser):
    """Parser for AWS SAM (Serverless Application Model) templates.

    SAM is a superset of CloudFormation with additional resource types.
    """

    def _is_cloudformation(self, template: dict[str, Any]) -> bool:
        """Check if the template is a valid SAM or CloudFormation template."""
        # SAM templates have Transform: AWS::Serverless
        if "Transform" in template:
            transform = template["Transform"]
            if isinstance(transform, str) and "AWS::Serverless" in transform:
                return True
            if isinstance(transform, list) and any("AWS::Serverless" in t for t in transform):
                return True

        # Fall back to CloudFormation check
        return super()._is_cloudformation(template)


class CDKOutputParser(IaCParser):
    """Parser for AWS CDK synthesized CloudFormation templates."""

    def parse(self, content: str, file_path: str = "<string>") -> ParseResult:
        """Parse CDK output (CloudFormation JSON).

        Args:
            content: Synthesized CloudFormation template.
            file_path: Path to the file.

        Returns:
            ParseResult with resources.
        """
        # CDK outputs CloudFormation JSON, so delegate to CloudFormation parser
        cf_parser = CloudFormationParser()
        result = cf_parser.parse(content, file_path)

        # Mark resources as CDK-generated
        for resource in result.resources:
            resource.config["__cdk_generated"] = True

        return result

    @classmethod
    def supported_extensions(cls) -> list[str]:
        """Return supported file extensions."""
        return [".template.json"]
