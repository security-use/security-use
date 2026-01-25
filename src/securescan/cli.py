"""Command-line interface for securescan."""

import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console

from securescan import __version__
from securescan.models import Severity, ScanResult
from securescan.reporter import create_reporter


console = Console()


def _get_severity_threshold(severity: str) -> Severity:
    """Convert severity string to Severity enum."""
    mapping = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
    }
    return mapping.get(severity.lower(), Severity.LOW)


def _filter_by_severity(result: ScanResult, threshold: Severity) -> ScanResult:
    """Filter results to only include issues at or above severity threshold."""
    severity_order = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.UNKNOWN: 4,
    }
    threshold_order = severity_order[threshold]

    filtered = ScanResult(
        scanned_files=result.scanned_files,
        errors=result.errors,
    )

    filtered.vulnerabilities = [
        v for v in result.vulnerabilities
        if severity_order.get(v.severity, 4) <= threshold_order
    ]

    filtered.iac_findings = [
        f for f in result.iac_findings
        if severity_order.get(f.severity, 4) <= threshold_order
    ]

    return filtered


def _output_result(
    result: ScanResult,
    format: str,
    output: Optional[str],
) -> None:
    """Output scan results in the specified format."""
    reporter = create_reporter(format)
    report = reporter.generate(result)

    if output:
        Path(output).write_text(report, encoding="utf-8")
        console.print(f"[green]Report written to {output}[/green]")
    else:
        if format == "json" or format == "sarif":
            click.echo(report)
        else:
            # Table format already outputs via rich
            console.print(report)


@click.group()
@click.version_option(version=__version__, prog_name="securescan")
def main() -> None:
    """SecureScan - Security scanning tool for dependencies and IaC."""
    pass


@main.group()
def scan() -> None:
    """Scan for security vulnerabilities."""
    pass


@scan.command("deps")
@click.argument("path", type=click.Path(exists=True), default=".")
@click.option(
    "--format", "-f",
    type=click.Choice(["json", "table", "sarif"]),
    default="table",
    help="Output format",
)
@click.option(
    "--severity", "-s",
    type=click.Choice(["critical", "high", "medium", "low"]),
    default="low",
    help="Minimum severity to report",
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    help="Write output to file",
)
def scan_deps(path: str, format: str, severity: str, output: Optional[str]) -> None:
    """Scan dependencies for known vulnerabilities.

    PATH is the file or directory to scan (default: current directory).
    """
    from securescan.dependency_scanner import DependencyScanner

    console.print(f"[blue]Scanning dependencies in {path}...[/blue]")

    scanner = DependencyScanner()
    result = scanner.scan_path(Path(path))

    # Filter by severity
    threshold = _get_severity_threshold(severity)
    result = _filter_by_severity(result, threshold)

    # Output results
    _output_result(result, format, output)

    # Exit with error code if vulnerabilities found
    if result.vulnerabilities:
        console.print(
            f"\n[red]Found {len(result.vulnerabilities)} vulnerability(ies)[/red]"
        )
        sys.exit(1)
    else:
        console.print("\n[green]No vulnerabilities found[/green]")


@scan.command("iac")
@click.argument("path", type=click.Path(exists=True), default=".")
@click.option(
    "--format", "-f",
    type=click.Choice(["json", "table", "sarif"]),
    default="table",
    help="Output format",
)
@click.option(
    "--severity", "-s",
    type=click.Choice(["critical", "high", "medium", "low"]),
    default="low",
    help="Minimum severity to report",
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    help="Write output to file",
)
def scan_iac(path: str, format: str, severity: str, output: Optional[str]) -> None:
    """Scan Infrastructure as Code for security misconfigurations.

    PATH is the file or directory to scan (default: current directory).
    """
    from securescan.iac_scanner import IaCScanner

    console.print(f"[blue]Scanning IaC files in {path}...[/blue]")

    scanner = IaCScanner()
    result = scanner.scan_path(Path(path))

    # Filter by severity
    threshold = _get_severity_threshold(severity)
    result = _filter_by_severity(result, threshold)

    # Output results
    _output_result(result, format, output)

    # Exit with error code if findings found
    if result.iac_findings:
        console.print(
            f"\n[red]Found {len(result.iac_findings)} security issue(s)[/red]"
        )
        sys.exit(1)
    else:
        console.print("\n[green]No security issues found[/green]")


@scan.command("all")
@click.argument("path", type=click.Path(exists=True), default=".")
@click.option(
    "--format", "-f",
    type=click.Choice(["json", "table", "sarif"]),
    default="table",
    help="Output format",
)
@click.option(
    "--severity", "-s",
    type=click.Choice(["critical", "high", "medium", "low"]),
    default="low",
    help="Minimum severity to report",
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    help="Write output to file",
)
def scan_all(path: str, format: str, severity: str, output: Optional[str]) -> None:
    """Scan both dependencies and IaC for security issues.

    PATH is the file or directory to scan (default: current directory).
    """
    from securescan.dependency_scanner import DependencyScanner
    from securescan.iac_scanner import IaCScanner

    console.print(f"[blue]Scanning {path} for all security issues...[/blue]")

    # Combined result
    result = ScanResult()

    # Scan dependencies
    dep_scanner = DependencyScanner()
    dep_result = dep_scanner.scan_path(Path(path))
    result.vulnerabilities = dep_result.vulnerabilities
    result.scanned_files.extend(dep_result.scanned_files)
    result.errors.extend(dep_result.errors)

    # Scan IaC
    iac_scanner = IaCScanner()
    iac_result = iac_scanner.scan_path(Path(path))
    result.iac_findings = iac_result.iac_findings
    result.scanned_files.extend(iac_result.scanned_files)
    result.errors.extend(iac_result.errors)

    # Filter by severity
    threshold = _get_severity_threshold(severity)
    result = _filter_by_severity(result, threshold)

    # Output results
    _output_result(result, format, output)

    # Exit with error code if issues found
    if result.total_issues > 0:
        console.print(f"\n[red]Found {result.total_issues} security issue(s)[/red]")
        sys.exit(1)
    else:
        console.print("\n[green]No security issues found[/green]")


@main.command()
@click.argument("path", type=click.Path(exists=True), default=".")
@click.option(
    "--dry-run",
    is_flag=True,
    help="Show what would be fixed without making changes",
)
def fix(path: str, dry_run: bool) -> None:
    """Auto-fix dependency vulnerabilities by updating versions.

    PATH is the file or directory to scan and fix (default: current directory).
    """
    from securescan.dependency_scanner import DependencyScanner

    console.print(f"[blue]Scanning dependencies in {path}...[/blue]")

    scanner = DependencyScanner()
    result = scanner.scan_path(Path(path))

    if not result.vulnerabilities:
        console.print("[green]No vulnerabilities found - nothing to fix[/green]")
        return

    # Group vulnerabilities by package
    package_fixes: dict[str, tuple[str, str]] = {}
    for vuln in result.vulnerabilities:
        if vuln.fixed_version and vuln.package not in package_fixes:
            package_fixes[vuln.package] = (vuln.installed_version, vuln.fixed_version)

    if not package_fixes:
        console.print("[yellow]No automatic fixes available for found vulnerabilities[/yellow]")
        return

    console.print(f"\n[bold]Found {len(package_fixes)} package(s) to update:[/bold]\n")

    for package, (current, fixed) in package_fixes.items():
        console.print(f"  • {package}: {current} → {fixed}")

    if dry_run:
        console.print("\n[yellow]Dry run - no changes made[/yellow]")
        return

    # Apply fixes
    console.print("\n[blue]Applying fixes...[/blue]")

    for file_path in result.scanned_files:
        path_obj = Path(file_path)
        if path_obj.suffix == ".txt" or path_obj.name == "requirements.txt":
            _fix_requirements_file(path_obj, package_fixes)

    console.print("[green]Fixes applied successfully[/green]")


def _fix_requirements_file(
    file_path: Path,
    fixes: dict[str, tuple[str, str]],
) -> None:
    """Apply fixes to a requirements.txt file."""
    import re

    content = file_path.read_text(encoding="utf-8")
    lines = content.splitlines()
    modified = False

    for i, line in enumerate(lines):
        for package, (current, fixed) in fixes.items():
            # Match package==version pattern
            pattern = rf'^{re.escape(package)}==({re.escape(current)})'
            match = re.match(pattern, line, re.IGNORECASE)
            if match:
                lines[i] = f"{package}=={fixed}"
                modified = True
                console.print(f"  [green]Updated {package} in {file_path}[/green]")

    if modified:
        file_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


@main.command()
def version() -> None:
    """Show version information."""
    click.echo(f"securescan version {__version__}")


if __name__ == "__main__":
    main()
