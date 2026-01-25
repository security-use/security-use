"""IaC scanner for detecting security misconfigurations."""

from pathlib import Path
from typing import Optional

from security_use.models import IaCFinding, ScanResult
from security_use.iac.base import IaCParser, IaCResource
from security_use.iac.terraform import TerraformParser
from security_use.iac.cloudformation import CloudFormationParser
from security_use.iac.rules.registry import get_registry


class IaCScanner:
    """Scanner for Infrastructure as Code files."""

    # File extensions to parser mapping
    PARSERS: dict[str, type[IaCParser]] = {
        ".tf": TerraformParser,
        ".yaml": CloudFormationParser,
        ".yml": CloudFormationParser,
        ".json": CloudFormationParser,
        ".template": CloudFormationParser,
    }

    # Patterns for identifying IaC files
    IAC_FILE_PATTERNS = [
        "*.tf",
        "*.yaml",
        "*.yml",
        "*.json",
        "**/terraform/**/*.tf",
        "**/cloudformation/**/*.yaml",
        "**/cloudformation/**/*.yml",
        "**/cdk.out/**/*.json",
    ]

    def __init__(self) -> None:
        """Initialize the IaC scanner."""
        self._registry = get_registry()

    def scan_path(self, path: Path) -> ScanResult:
        """Scan a path for IaC security issues.

        Args:
            path: File or directory path to scan.

        Returns:
            ScanResult containing IaC findings.
        """
        result = ScanResult()

        if path.is_file():
            files = [path]
        else:
            files = self._find_iac_files(path)

        for file_path in files:
            try:
                content = file_path.read_text(encoding="utf-8")
                file_result = self.scan_content(content, str(file_path))
                result.iac_findings.extend(file_result.iac_findings)
                result.scanned_files.append(str(file_path))
                result.errors.extend(file_result.errors)
            except Exception as e:
                result.errors.append(f"Error scanning {file_path}: {e}")

        return result

    def scan_content(self, content: str, file_path: str) -> ScanResult:
        """Scan IaC file content for security issues.

        Args:
            content: The file content to scan.
            file_path: Path to the file (for parser selection and reporting).

        Returns:
            ScanResult containing IaC findings.
        """
        result = ScanResult()

        # Get appropriate parser
        parser = self._get_parser(file_path)
        if parser is None:
            return result

        # Parse the file
        parse_result = parser.parse(content, file_path)
        result.errors.extend(parse_result.errors)

        if not parse_result.resources:
            return result

        # Evaluate rules against resources
        findings = self._evaluate_resources(parse_result.resources, file_path)
        result.iac_findings = findings

        return result

    def _evaluate_resources(
        self, resources: list[IaCResource], file_path: str
    ) -> list[IaCFinding]:
        """Evaluate security rules against resources.

        Args:
            resources: List of parsed IaC resources.
            file_path: Path to the source file.

        Returns:
            List of IaC findings.
        """
        findings = []
        rules = self._registry.get_all()

        for resource in resources:
            for rule in rules:
                if rule.applies_to(resource):
                    rule_result = rule.evaluate(resource)
                    if not rule_result.passed:
                        finding = IaCFinding(
                            rule_id=rule_result.rule_id,
                            title=rule_result.title,
                            severity=rule_result.severity,
                            resource_type=resource.resource_type,
                            resource_name=resource.name,
                            file_path=file_path,
                            line_number=resource.line_number,
                            description=rule_result.description,
                            remediation=rule_result.remediation,
                            fix_code=rule_result.fix_code,
                        )
                        findings.append(finding)

        return findings

    def _find_iac_files(self, directory: Path) -> list[Path]:
        """Find all IaC files in a directory.

        Args:
            directory: Directory to search.

        Returns:
            List of IaC file paths.
        """
        files = []

        # Find Terraform files
        files.extend(directory.rglob("*.tf"))

        # Find CloudFormation files (exclude node_modules, etc.)
        for ext in [".yaml", ".yml", ".json"]:
            for file_path in directory.rglob(f"*{ext}"):
                # Skip common non-IaC directories
                if self._should_skip_path(file_path):
                    continue

                # Check if it looks like a CloudFormation template
                if self._is_likely_cloudformation(file_path):
                    files.append(file_path)

        return files

    def _should_skip_path(self, path: Path) -> bool:
        """Check if a path should be skipped."""
        skip_dirs = {
            "node_modules",
            ".git",
            ".terraform",
            "__pycache__",
            "venv",
            ".venv",
            "dist",
            "build",
        }

        for part in path.parts:
            if part in skip_dirs:
                return True
        return False

    def _is_likely_cloudformation(self, path: Path) -> bool:
        """Check if a file is likely a CloudFormation template."""
        # Check common CloudFormation directory names
        cf_dirs = {"cloudformation", "cfn", "templates", "cdk.out"}
        if any(d in str(path).lower() for d in cf_dirs):
            return True

        # Check filename patterns
        name = path.name.lower()
        if any(
            pattern in name
            for pattern in ["template", "stack", "cloudformation", "cfn"]
        ):
            return True

        # For JSON/YAML files in root, we'd need to peek at content
        # to determine if it's CloudFormation
        return False

    def _get_parser(self, file_path: str) -> Optional[IaCParser]:
        """Get the appropriate parser for a file.

        Args:
            file_path: Path to the file.

        Returns:
            Parser instance or None if unsupported.
        """
        path = Path(file_path)
        suffix = path.suffix.lower()

        parser_class = self.PARSERS.get(suffix)
        if parser_class:
            return parser_class()

        return None
