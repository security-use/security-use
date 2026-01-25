"""Vulnerability report generators."""

import json
from abc import ABC, abstractmethod
from typing import Any, Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from security_use.models import ScanResult, Severity, Vulnerability, IaCFinding


class ReportGenerator(ABC):
    """Abstract base class for report generators."""

    @abstractmethod
    def generate(self, result: ScanResult) -> str:
        """Generate a report from scan results.

        Args:
            result: The scan results to report.

        Returns:
            Formatted report as a string.
        """
        pass


class JSONReporter(ReportGenerator):
    """Generate JSON format reports."""

    def __init__(self, indent: int = 2) -> None:
        """Initialize JSON reporter.

        Args:
            indent: JSON indentation level.
        """
        self.indent = indent

    def generate(self, result: ScanResult) -> str:
        """Generate JSON report."""
        return json.dumps(result.to_dict(), indent=self.indent)


class TableReporter(ReportGenerator):
    """Generate rich table format reports for CLI output."""

    SEVERITY_COLORS = {
        Severity.CRITICAL: "red bold",
        Severity.HIGH: "red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "blue",
        Severity.UNKNOWN: "dim",
    }

    def __init__(self, show_details: bool = True) -> None:
        """Initialize table reporter.

        Args:
            show_details: Whether to show full details or summary only.
        """
        self.show_details = show_details
        self.console = Console(record=True, force_terminal=True)

    def generate(self, result: ScanResult) -> str:
        """Generate table report."""
        # Render to console buffer
        self._render_summary(result)

        if result.vulnerabilities:
            self._render_vulnerabilities(result.vulnerabilities)

        if result.iac_findings:
            self._render_iac_findings(result.iac_findings)

        if result.errors:
            # Separate parse/unsupported file errors from real errors
            unsupported = [e for e in result.errors if "Failed to parse" in e or "not a valid" in e]
            real_errors = [e for e in result.errors if e not in unsupported]

            if unsupported:
                self._render_unsupported(unsupported)
            if real_errors:
                self._render_errors(real_errors)

        return self.console.export_text()

    def _render_summary(self, result: ScanResult) -> None:
        """Render summary panel."""
        severity_counts = self._count_by_severity(result)

        summary_text = Text()
        summary_text.append(f"Total Issues: {result.total_issues}\n")
        summary_text.append(f"Files Scanned: {len(result.scanned_files)}\n\n")

        summary_text.append("By Severity:\n", style="bold")
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            count = severity_counts.get(severity, 0)
            color = self.SEVERITY_COLORS[severity]
            summary_text.append(f"  {severity.value}: ", style=color)
            summary_text.append(f"{count}\n")

        panel = Panel(
            summary_text,
            title="Security Scan Summary",
            border_style="blue",
        )
        self.console.print(panel)

    def _render_vulnerabilities(self, vulns: list[Vulnerability]) -> None:
        """Render vulnerabilities table."""
        table = Table(
            title="Dependency Vulnerabilities",
            show_header=True,
            header_style="bold cyan",
        )

        table.add_column("Severity", width=10)
        table.add_column("Package", width=20)
        table.add_column("Version", width=12)
        table.add_column("CVE ID", width=20)
        table.add_column("Fix Version", width=12)

        if self.show_details:
            table.add_column("Title", width=40)

        for vuln in sorted(vulns, key=lambda v: self._severity_order(v.severity)):
            color = self.SEVERITY_COLORS[vuln.severity]
            row = [
                Text(vuln.severity.value, style=color),
                vuln.package,
                vuln.installed_version,
                vuln.id,
                vuln.fixed_version or "N/A",
            ]
            if self.show_details:
                row.append(vuln.title[:40] if len(vuln.title) > 40 else vuln.title)

            table.add_row(*row)

        self.console.print(table)

    def _render_iac_findings(self, findings: list[IaCFinding]) -> None:
        """Render IaC findings table."""
        table = Table(
            title="Infrastructure as Code Findings",
            show_header=True,
            header_style="bold cyan",
        )

        table.add_column("Severity", width=10)
        table.add_column("Rule ID", width=15)
        table.add_column("Resource", width=25)
        table.add_column("File", width=30)
        table.add_column("Line", width=6)

        if self.show_details:
            table.add_column("Title", width=35)

        for finding in sorted(findings, key=lambda f: self._severity_order(f.severity)):
            color = self.SEVERITY_COLORS[finding.severity]
            row = [
                Text(finding.severity.value, style=color),
                finding.rule_id,
                finding.resource_name[:25] if len(finding.resource_name) > 25 else finding.resource_name,
                finding.file_path[-30:] if len(finding.file_path) > 30 else finding.file_path,
                str(finding.line_number),
            ]
            if self.show_details:
                row.append(finding.title[:35] if len(finding.title) > 35 else finding.title)

            table.add_row(*row)

        self.console.print(table)

    def _render_unsupported(self, files: list[str]) -> None:
        """Render unsupported files panel."""
        text = Text()
        for item in files:
            # Extract just the filename from the error message
            if "Failed to parse" in item:
                filename = item.replace("Failed to parse ", "").replace(": Invalid YAML/JSON", "")
                text.append(f"• {filename}\n", style="dim")
            elif "not a valid" in item:
                filename = item.split(" is not")[0]
                text.append(f"• {filename}\n", style="dim")
            else:
                text.append(f"• {item}\n", style="dim")

        panel = Panel(
            text,
            title="Unsupported Files (skipped)",
            border_style="dim",
        )
        self.console.print(panel)

    def _render_errors(self, errors: list[str]) -> None:
        """Render errors panel."""
        error_text = Text()
        for error in errors:
            error_text.append(f"• {error}\n", style="red")

        panel = Panel(
            error_text,
            title="Errors",
            border_style="red",
        )
        self.console.print(panel)

    def _count_by_severity(self, result: ScanResult) -> dict[Severity, int]:
        """Count issues by severity."""
        counts: dict[Severity, int] = {}

        for vuln in result.vulnerabilities:
            counts[vuln.severity] = counts.get(vuln.severity, 0) + 1

        for finding in result.iac_findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1

        return counts

    def _severity_order(self, severity: Severity) -> int:
        """Get severity order for sorting (lower = more severe)."""
        order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.UNKNOWN: 4,
        }
        return order.get(severity, 5)


class SARIFReporter(ReportGenerator):
    """Generate SARIF (Static Analysis Results Interchange Format) reports.

    SARIF is a standard format for static analysis tools that integrates
    with VS Code, GitHub, and other tools.
    """

    SARIF_VERSION = "2.1.0"
    SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

    def __init__(self, tool_name: str = "security-use", tool_version: str = "0.1.0") -> None:
        """Initialize SARIF reporter.

        Args:
            tool_name: Name of the scanning tool.
            tool_version: Version of the scanning tool.
        """
        self.tool_name = tool_name
        self.tool_version = tool_version

    def generate(self, result: ScanResult) -> str:
        """Generate SARIF report."""
        sarif = {
            "$schema": self.SCHEMA,
            "version": self.SARIF_VERSION,
            "runs": [self._create_run(result)],
        }
        return json.dumps(sarif, indent=2)

    def _create_run(self, result: ScanResult) -> dict[str, Any]:
        """Create a SARIF run object."""
        rules: list[dict[str, Any]] = []
        results: list[dict[str, Any]] = []

        # Add vulnerability rules and results
        for vuln in result.vulnerabilities:
            rule = self._create_vulnerability_rule(vuln)
            if not any(r["id"] == rule["id"] for r in rules):
                rules.append(rule)
            results.append(self._create_vulnerability_result(vuln))

        # Add IaC finding rules and results
        for finding in result.iac_findings:
            rule = self._create_iac_rule(finding)
            if not any(r["id"] == rule["id"] for r in rules):
                rules.append(rule)
            results.append(self._create_iac_result(finding))

        return {
            "tool": {
                "driver": {
                    "name": self.tool_name,
                    "version": self.tool_version,
                    "informationUri": "https://github.com/security-use/security-use",
                    "rules": rules,
                }
            },
            "results": results,
        }

    def _create_vulnerability_rule(self, vuln: Vulnerability) -> dict[str, Any]:
        """Create a SARIF rule for a vulnerability."""
        return {
            "id": vuln.id,
            "name": f"VulnerablePackage/{vuln.package}",
            "shortDescription": {"text": vuln.title},
            "fullDescription": {"text": vuln.description or vuln.title},
            "helpUri": vuln.references[0] if vuln.references else None,
            "defaultConfiguration": {
                "level": self._severity_to_sarif_level(vuln.severity)
            },
            "properties": {
                "security-severity": str(vuln.cvss_score) if vuln.cvss_score else "0.0"
            },
        }

    def _create_vulnerability_result(self, vuln: Vulnerability) -> dict[str, Any]:
        """Create a SARIF result for a vulnerability."""
        message = f"{vuln.package}@{vuln.installed_version} has a known vulnerability ({vuln.id})"
        if vuln.fixed_version:
            message += f". Update to version {vuln.fixed_version} to fix."

        return {
            "ruleId": vuln.id,
            "level": self._severity_to_sarif_level(vuln.severity),
            "message": {"text": message},
            "locations": [],  # Dependency vulnerabilities don't have specific locations
        }

    def _create_iac_rule(self, finding: IaCFinding) -> dict[str, Any]:
        """Create a SARIF rule for an IaC finding."""
        return {
            "id": finding.rule_id,
            "name": finding.title.replace(" ", ""),
            "shortDescription": {"text": finding.title},
            "fullDescription": {"text": finding.description},
            "help": {"text": finding.remediation},
            "defaultConfiguration": {
                "level": self._severity_to_sarif_level(finding.severity)
            },
        }

    def _create_iac_result(self, finding: IaCFinding) -> dict[str, Any]:
        """Create a SARIF result for an IaC finding."""
        return {
            "ruleId": finding.rule_id,
            "level": self._severity_to_sarif_level(finding.severity),
            "message": {"text": finding.title},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.file_path},
                        "region": {
                            "startLine": finding.line_number,
                            "startColumn": 1,
                        },
                    }
                }
            ],
        }

    def _severity_to_sarif_level(self, severity: Severity) -> str:
        """Convert severity to SARIF level."""
        mapping = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.UNKNOWN: "none",
        }
        return mapping.get(severity, "none")


def create_reporter(
    format: str,
    show_details: bool = True,
    tool_name: str = "security-use",
    tool_version: str = "0.1.0",
) -> ReportGenerator:
    """Create a reporter for the specified format.

    Args:
        format: Output format ('json', 'table', 'sarif').
        show_details: Whether to show full details (for table format).
        tool_name: Tool name (for SARIF format).
        tool_version: Tool version (for SARIF format).

    Returns:
        Appropriate ReportGenerator instance.

    Raises:
        ValueError: If format is not supported.
    """
    if format == "json":
        return JSONReporter()
    elif format == "table":
        return TableReporter(show_details=show_details)
    elif format == "sarif":
        return SARIFReporter(tool_name=tool_name, tool_version=tool_version)
    else:
        raise ValueError(f"Unsupported format: {format}. Use 'json', 'table', or 'sarif'.")
