"""Command-line interface for security-use."""

import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console

from security_use import __version__
from security_use.models import Severity, ScanResult
from security_use.reporter import create_reporter


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


def _get_git_info(path: str) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Get git repository info (repo name, branch, commit) for the given path."""
    import subprocess

    # Resolve to absolute path and find the directory
    scan_path = Path(path).resolve()
    if scan_path.is_file():
        scan_path = scan_path.parent

    try:
        # Get repo name from remote URL
        result = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            capture_output=True, text=True, timeout=5,
            cwd=str(scan_path)
        )
        repo_name = None
        if result.returncode == 0:
            url = result.stdout.strip()
            # Extract repo name from URL
            if url.endswith(".git"):
                url = url[:-4]
            repo_name = url.split("/")[-1]

        # Get current branch
        result = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True, text=True, timeout=5,
            cwd=str(scan_path)
        )
        branch = result.stdout.strip() if result.returncode == 0 else None

        # Get current commit SHA
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=5,
            cwd=str(scan_path)
        )
        commit = result.stdout.strip() if result.returncode == 0 else None

        return repo_name, branch, commit
    except Exception:
        return None, None, None


def _auto_upload_results(result: ScanResult, scan_type: str, path: str) -> None:
    """Automatically upload scan results to dashboard if authenticated."""
    from security_use.auth import AuthConfig, DashboardClient, OAuthError

    config = AuthConfig()
    if not config.is_authenticated:
        return  # Silently skip if not authenticated

    try:
        client = DashboardClient(config)
        repo_name, branch, commit = _get_git_info(path)

        # Use path as repo name if git info not available
        if not repo_name:
            repo_name = Path(path).resolve().name

        response = client.upload_scan(
            result=result,
            scan_type=scan_type,
            repo_name=repo_name,
            branch=branch,
            commit_sha=commit,
        )

        summary = response.get("summary", {})
        total = summary.get("total", result.total_issues)
        console.print(f"\n[dim]Results synced to dashboard ({total} finding(s))[/dim]")

    except OAuthError:
        # Silently ignore auth errors - user might have expired token
        pass
    except Exception:
        # Don't fail the scan if upload fails
        pass


@click.group()
@click.version_option(version=__version__, prog_name="security-use")
def main() -> None:
    """security-use - Security scanning tool for dependencies and IaC."""
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
    from security_use.dependency_scanner import DependencyScanner

    is_machine_format = format in ("json", "sarif")

    if not is_machine_format:
        console.print(f"[blue]Scanning dependencies in {path}...[/blue]")

    scanner = DependencyScanner()
    result = scanner.scan_path(Path(path))

    # Filter by severity
    threshold = _get_severity_threshold(severity)
    result = _filter_by_severity(result, threshold)

    # Output results
    _output_result(result, format, output)

    # Auto-upload to dashboard if authenticated
    if not is_machine_format:
        _auto_upload_results(result, "deps", path)

    # Exit with error code if vulnerabilities found
    if result.vulnerabilities:
        if not is_machine_format:
            console.print(
                f"\n[red]Found {len(result.vulnerabilities)} vulnerability(ies)[/red]"
            )
        sys.exit(1)
    else:
        if not is_machine_format:
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
@click.option(
    "--compliance", "-c",
    type=click.Choice(["soc2", "hipaa", "pci-dss", "nist-800-53", "cis-aws", "cis-azure", "cis-gcp", "cis-kubernetes", "iso-27001"]),
    help="Filter by compliance framework",
)
def scan_iac(path: str, format: str, severity: str, output: Optional[str], compliance: Optional[str]) -> None:
    """Scan Infrastructure as Code for security misconfigurations.

    PATH is the file or directory to scan (default: current directory).
    """
    from security_use.iac_scanner import IaCScanner
    from security_use.compliance import ComplianceMapper, ComplianceFramework

    is_machine_format = format in ("json", "sarif")

    if not is_machine_format:
        console.print(f"[blue]Scanning IaC files in {path}...[/blue]")

    scanner = IaCScanner()
    result = scanner.scan_path(Path(path))

    # Filter by severity
    threshold = _get_severity_threshold(severity)
    result = _filter_by_severity(result, threshold)

    # Filter by compliance framework if specified
    if compliance:
        framework_map = {
            "soc2": ComplianceFramework.SOC2,
            "hipaa": ComplianceFramework.HIPAA,
            "pci-dss": ComplianceFramework.PCI_DSS,
            "nist-800-53": ComplianceFramework.NIST_800_53,
            "cis-aws": ComplianceFramework.CIS_AWS,
            "cis-azure": ComplianceFramework.CIS_AZURE,
            "cis-gcp": ComplianceFramework.CIS_GCP,
            "cis-kubernetes": ComplianceFramework.CIS_K8S,
            "iso-27001": ComplianceFramework.ISO_27001,
        }
        mapper = ComplianceMapper()
        framework = framework_map[compliance]

        # Filter findings to those with compliance mappings
        compliance_findings = mapper.get_findings_by_framework(result.iac_findings, framework)
        compliance_rule_ids = {f.rule_id for f in compliance_findings}
        result.iac_findings = [f for f in result.iac_findings if f.rule_id in compliance_rule_ids]

        if not is_machine_format:
            console.print(f"[dim]Filtered by {compliance.upper()} compliance[/dim]")

    # Output results
    _output_result(result, format, output)

    # Auto-upload to dashboard if authenticated
    if not is_machine_format:
        _auto_upload_results(result, "iac", path)

    # Exit with error code if findings found
    if result.iac_findings:
        if not is_machine_format:
            console.print(
                f"\n[red]Found {len(result.iac_findings)} security issue(s)[/red]"
            )
        sys.exit(1)
    else:
        if not is_machine_format:
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
    from security_use.dependency_scanner import DependencyScanner
    from security_use.iac_scanner import IaCScanner

    is_machine_format = format in ("json", "sarif")

    if not is_machine_format:
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

    # Auto-upload to dashboard if authenticated (use "deps" as primary type for combined scan)
    if not is_machine_format:
        _auto_upload_results(result, "deps", path)

    # Exit with error code if issues found
    if result.total_issues > 0:
        if not is_machine_format:
            console.print(f"\n[red]Found {result.total_issues} security issue(s)[/red]")
        sys.exit(1)
    else:
        if not is_machine_format:
            console.print("\n[green]No security issues found[/green]")


@main.command()
@click.argument("path", type=click.Path(exists=True), default=".")
@click.option(
    "--dry-run",
    is_flag=True,
    help="Show what would be fixed without making changes",
)
@click.option(
    "--deps-only",
    is_flag=True,
    help="Only fix dependency vulnerabilities",
)
@click.option(
    "--iac-only",
    is_flag=True,
    help="Only fix IaC misconfigurations",
)
def fix(path: str, dry_run: bool, deps_only: bool, iac_only: bool) -> None:
    """Auto-fix security vulnerabilities and IaC misconfigurations.

    PATH is the file or directory to scan and fix (default: current directory).
    """
    from security_use.dependency_scanner import DependencyScanner
    from security_use.iac_scanner import IaCScanner
    from security_use.fixers.iac_fixer import IaCFixer

    fix_deps = not iac_only
    fix_iac = not deps_only

    total_fixes = 0

    # Fix dependency vulnerabilities
    if fix_deps:
        console.print(f"[blue]Scanning dependencies in {path}...[/blue]")

        dep_scanner = DependencyScanner()
        dep_result = dep_scanner.scan_path(Path(path))

        if dep_result.vulnerabilities:
            # Group vulnerabilities by package
            package_fixes: dict[str, tuple[str, str]] = {}
            for vuln in dep_result.vulnerabilities:
                if vuln.fixed_version and vuln.package not in package_fixes:
                    package_fixes[vuln.package] = (vuln.installed_version, vuln.fixed_version)

            if package_fixes:
                console.print(f"\n[bold]Found {len(package_fixes)} package(s) to update:[/bold]\n")

                for package, (current, fixed) in package_fixes.items():
                    console.print(f"  • {package}: {current} → {fixed}")

                if not dry_run:
                    console.print("\n[blue]Applying dependency fixes...[/blue]")
                    for file_path in dep_result.scanned_files:
                        path_obj = Path(file_path)
                        if path_obj.suffix == ".txt" or path_obj.name == "requirements.txt":
                            _fix_requirements_file(path_obj, package_fixes)
                    total_fixes += len(package_fixes)
            else:
                console.print("[yellow]No automatic fixes available for dependency vulnerabilities[/yellow]")
        else:
            console.print("[green]No dependency vulnerabilities found[/green]")

    # Fix IaC misconfigurations
    if fix_iac:
        console.print(f"\n[blue]Scanning IaC files in {path}...[/blue]")

        iac_scanner = IaCScanner()
        iac_result = iac_scanner.scan_path(Path(path))

        if iac_result.iac_findings:
            iac_fixer = IaCFixer()

            # Filter findings that have available fixes
            fixable_findings = [
                f for f in iac_result.iac_findings
                if iac_fixer.has_fix(f.rule_id)
            ]

            if fixable_findings:
                # Deduplicate findings by (file_path, rule_id, resource_name)
                seen_fixes: set[tuple[str, str, str]] = set()
                unique_findings = []
                for finding in fixable_findings:
                    key = (finding.file_path, finding.rule_id, finding.resource_name)
                    if key not in seen_fixes:
                        seen_fixes.add(key)
                        unique_findings.append(finding)

                console.print(f"\n[bold]Found {len(unique_findings)} IaC issue(s) to fix:[/bold]\n")

                for finding in unique_findings:
                    console.print(f"  • [{finding.rule_id}] {finding.title}")
                    console.print(f"    {finding.file_path}:{finding.line_number} ({finding.resource_name})")

                if not dry_run:
                    console.print("\n[blue]Applying IaC fixes...[/blue]")

                    for finding in unique_findings:
                        result = iac_fixer.fix_finding(
                            file_path=finding.file_path,
                            rule_id=finding.rule_id,
                            resource_name=finding.resource_name,
                            line_number=finding.line_number,
                            auto_apply=True,
                        )

                        if result.success:
                            console.print(f"  [green]Fixed {finding.rule_id} in {finding.file_path}[/green]")
                            console.print(f"    {result.explanation}")
                            total_fixes += 1
                        else:
                            console.print(f"  [yellow]Could not fix {finding.rule_id}: {result.error}[/yellow]")
            else:
                console.print("[yellow]No automatic fixes available for IaC findings[/yellow]")

            # Report unfixable findings
            unfixable = [f for f in iac_result.iac_findings if not iac_fixer.has_fix(f.rule_id)]
            if unfixable:
                console.print(f"\n[yellow]{len(unfixable)} IaC finding(s) require manual remediation:[/yellow]")
                for finding in unfixable:
                    console.print(f"  • [{finding.rule_id}] {finding.title}")
        else:
            console.print("[green]No IaC misconfigurations found[/green]")

    # Summary
    if dry_run:
        console.print("\n[yellow]Dry run - no changes made[/yellow]")
    elif total_fixes > 0:
        console.print(f"\n[green]Successfully applied {total_fixes} fix(es)[/green]")
    else:
        console.print("\n[yellow]No fixes were applied[/yellow]")


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
    click.echo(f"security-use version {__version__}")


# =============================================================================
# CI/CD Command
# =============================================================================


@main.command()
@click.argument("path", type=click.Path(exists=True), default=".")
@click.option(
    "--fail-on", "-f",
    type=click.Choice(["critical", "high", "medium", "low"]),
    default="high",
    help="Minimum severity to fail on",
)
@click.option(
    "--output", "-o",
    type=click.Choice(["sarif", "json", "table", "minimal"]),
    default="minimal",
    help="Output format",
)
@click.option(
    "--sarif-file",
    type=click.Path(),
    help="Write SARIF output to file",
)
@click.option(
    "--deps-only",
    is_flag=True,
    help="Only scan dependencies",
)
@click.option(
    "--iac-only",
    is_flag=True,
    help="Only scan IaC files",
)
def ci(path: str, fail_on: str, output: str, sarif_file: Optional[str], deps_only: bool, iac_only: bool) -> None:
    """Run security scan optimized for CI/CD pipelines.

    Designed for non-interactive CI environments with minimal output
    and clear exit codes:
      - Exit 0: No issues found at or above severity threshold
      - Exit 1: Issues found at or above severity threshold
      - Exit 2: Scan error

    PATH is the directory to scan (default: current directory).
    """
    from security_use.dependency_scanner import DependencyScanner
    from security_use.iac_scanner import IaCScanner

    try:
        result = ScanResult()

        # Scan dependencies
        if not iac_only:
            dep_scanner = DependencyScanner()
            dep_result = dep_scanner.scan_path(Path(path))
            result.vulnerabilities = dep_result.vulnerabilities
            result.scanned_files.extend(dep_result.scanned_files)
            result.errors.extend(dep_result.errors)

        # Scan IaC
        if not deps_only:
            iac_scanner = IaCScanner()
            iac_result = iac_scanner.scan_path(Path(path))
            result.iac_findings = iac_result.iac_findings
            result.scanned_files.extend(iac_result.scanned_files)
            result.errors.extend(iac_result.errors)

        # Filter by severity
        threshold = _get_severity_threshold(fail_on)
        filtered_result = _filter_by_severity(result, threshold)

        # Write SARIF if requested
        if sarif_file:
            reporter = create_reporter("sarif")
            sarif_content = reporter.generate(result)  # Full results for SARIF
            Path(sarif_file).write_text(sarif_content, encoding="utf-8")

        # Output based on format
        if output == "minimal":
            # Minimal output for CI logs
            total = filtered_result.total_issues
            if total > 0:
                click.echo(f"FAILED: {total} issue(s) at {fail_on.upper()} or above")
                click.echo(f"  Vulnerabilities: {len(filtered_result.vulnerabilities)}")
                click.echo(f"  IaC Findings: {len(filtered_result.iac_findings)}")
            else:
                click.echo(f"PASSED: No issues at {fail_on.upper()} or above")
        elif output == "table":
            _output_result(result, "table", None)
        else:
            reporter = create_reporter(output)
            click.echo(reporter.generate(result))

        # Exit with appropriate code
        if filtered_result.total_issues > 0:
            sys.exit(1)
        sys.exit(0)

    except Exception as e:
        click.echo(f"ERROR: {e}", err=True)
        sys.exit(2)


# =============================================================================
# Authentication Commands
# =============================================================================


@main.group()
def auth() -> None:
    """Authenticate with SecurityUse dashboard."""
    pass


@auth.command("login")
@click.option(
    "--no-browser",
    is_flag=True,
    help="Don't automatically open the browser",
)
def auth_login(no_browser: bool) -> None:
    """Log in to SecurityUse dashboard.

    This will open your browser to authenticate with security-use.dev.
    After authentication, scan results can be synced to your dashboard.
    """
    from security_use.auth import OAuthFlow, OAuthError, AuthConfig

    config = AuthConfig()

    if config.is_authenticated:
        console.print(f"[yellow]Already logged in as {config.user.email if config.user else 'unknown'}[/yellow]")
        console.print("Run 'security-use auth logout' first to log in as a different user.")
        return

    oauth = OAuthFlow(config)

    try:
        # Request device code
        console.print("[blue]Requesting authorization...[/blue]")
        device_code = oauth.request_device_code()

        # Show user code
        console.print(f"\n[bold]Your authorization code:[/bold] [cyan]{device_code.user_code}[/cyan]")
        console.print(f"\nOpen this URL to authenticate:")
        console.print(f"[link={device_code.verification_uri}]{device_code.verification_uri}[/link]")

        if not no_browser:
            import webbrowser
            verification_url = (
                device_code.verification_uri_complete
                or f"{device_code.verification_uri}?user_code={device_code.user_code}"
            )
            console.print("\n[dim]Opening browser...[/dim]")
            webbrowser.open(verification_url)

        console.print("\n[dim]Waiting for authorization (press Ctrl+C to cancel)...[/dim]")

        def on_status(msg: str) -> None:
            console.print(f"[dim]{msg}[/dim]", end="\r")

        # Poll for token
        token = oauth.poll_for_token(device_code, on_status)

        # Get user info
        try:
            user = oauth.get_user_info(token)
            config.save_token(token, user)
            console.print(f"\n[green]Successfully logged in as {user.email}[/green]")
            if user.org_name:
                console.print(f"[dim]Organization: {user.org_name}[/dim]")
        except OAuthError:
            config.save_token(token)
            console.print("\n[green]Successfully logged in[/green]")

        console.print("\nYou can now sync scan results to your dashboard:")
        console.print("  security-use scan all ./project --sync")

    except OAuthError as e:
        console.print(f"\n[red]Authentication failed: {e}[/red]")
        sys.exit(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Authentication cancelled[/yellow]")
        sys.exit(1)


@auth.command("logout")
def auth_logout() -> None:
    """Log out from SecurityUse dashboard.

    This will clear your stored credentials.
    """
    from security_use.auth import AuthConfig

    config = AuthConfig()

    if not config.is_authenticated:
        console.print("[yellow]Not currently logged in[/yellow]")
        return

    user_email = config.user.email if config.user else "unknown"
    config.clear()
    console.print(f"[green]Successfully logged out from {user_email}[/green]")


@auth.command("status")
def auth_status() -> None:
    """Check authentication status.

    Shows whether you're logged in and account details.
    """
    from security_use.auth import AuthConfig, get_config_dir

    config = AuthConfig()

    if config.is_authenticated:
        console.print("[green]Logged in[/green]")
        if config.user:
            console.print(f"  Email: {config.user.email}")
            if config.user.name:
                console.print(f"  Name: {config.user.name}")
            if config.user.org_name:
                console.print(f"  Organization: {config.user.org_name}")
        if config.token and config.token.expires_at:
            console.print(f"  Token expires: {config.token.expires_at}")
    else:
        console.print("[yellow]Not logged in[/yellow]")
        console.print("\nRun 'security-use auth login' to authenticate.")

    console.print(f"\n[dim]Config directory: {get_config_dir()}[/dim]")


@auth.command("token")
def auth_token() -> None:
    """Print the current access token.

    Useful for integrations that need the token directly.
    """
    from security_use.auth import AuthConfig

    config = AuthConfig()

    if not config.is_authenticated:
        console.print("[red]Not logged in[/red]", err=True)
        sys.exit(1)

    token = config.get_access_token()
    if token:
        click.echo(token)
    else:
        console.print("[red]No valid token available[/red]", err=True)
        sys.exit(1)


# =============================================================================
# SBOM Commands
# =============================================================================


@main.group()
def sbom() -> None:
    """Generate Software Bill of Materials (SBOM)."""
    pass


@sbom.command("generate")
@click.argument("path", type=click.Path(exists=True), default=".")
@click.option(
    "--format", "-f",
    type=click.Choice(["cyclonedx-json", "cyclonedx-xml", "spdx-json", "spdx-tv"]),
    default="cyclonedx-json",
    help="Output format",
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    help="Write output to file",
)
@click.option(
    "--include-vulns",
    is_flag=True,
    help="Include vulnerability information (VEX)",
)
def sbom_generate(path: str, format: str, output: Optional[str], include_vulns: bool) -> None:
    """Generate an SBOM for the project.

    Scans dependency files and generates a Software Bill of Materials
    in CycloneDX or SPDX format.

    PATH is the directory to scan (default: current directory).
    """
    from security_use.sbom import SBOMGenerator, SBOMFormat

    format_map = {
        "cyclonedx-json": SBOMFormat.CYCLONEDX_JSON,
        "cyclonedx-xml": SBOMFormat.CYCLONEDX_XML,
        "spdx-json": SBOMFormat.SPDX_JSON,
        "spdx-tv": SBOMFormat.SPDX_TV,
    }

    console.print(f"[blue]Generating SBOM for {path}...[/blue]")

    generator = SBOMGenerator()
    result = generator.generate(
        Path(path),
        format=format_map[format],
        include_vulnerabilities=include_vulns,
    )

    if output:
        Path(output).write_text(result.content, encoding="utf-8")
        console.print(f"[green]SBOM written to {output}[/green]")
        console.print(f"  Format: {format}")
        console.print(f"  Components: {result.component_count}")
    else:
        click.echo(result.content)


@sbom.command("enrich")
@click.argument("sbom_file", type=click.Path(exists=True))
@click.option(
    "--output", "-o",
    type=click.Path(),
    help="Write enriched SBOM to file",
)
def sbom_enrich(sbom_file: str, output: Optional[str]) -> None:
    """Enrich an existing SBOM with vulnerability data.

    Adds VEX (Vulnerability Exploitability eXchange) information
    to an existing SBOM file.

    SBOM_FILE is the path to the existing SBOM.
    """
    import json

    console.print(f"[blue]Enriching SBOM: {sbom_file}...[/blue]")

    # Read existing SBOM
    content = Path(sbom_file).read_text(encoding="utf-8")

    try:
        sbom_data = json.loads(content)
    except json.JSONDecodeError:
        console.print("[red]Error: Only JSON SBOM files can be enriched[/red]")
        sys.exit(1)

    # TODO: Add vulnerability enrichment logic
    # This would query OSV for each component and add VEX data

    console.print("[yellow]SBOM enrichment not yet implemented[/yellow]")


# =============================================================================
# Sync Command
# =============================================================================


@main.command()
@click.argument("path", type=click.Path(exists=True), default=".")
@click.option(
    "--project", "-p",
    help="Project name for the dashboard",
)
@click.option(
    "--severity", "-s",
    type=click.Choice(["critical", "high", "medium", "low"]),
    default="low",
    help="Minimum severity to report",
)
def sync(path: str, project: Optional[str], severity: str) -> None:
    """Scan and sync results to SecurityUse dashboard.

    This command scans the project and uploads the results to your
    dashboard at security-use.dev.

    Requires authentication. Run 'security-use auth login' first.
    """
    from security_use.dependency_scanner import DependencyScanner
    from security_use.iac_scanner import IaCScanner
    from security_use.auth import AuthConfig, DashboardClient, OAuthError

    config = AuthConfig()

    if not config.is_authenticated:
        console.print("[red]Not logged in. Run 'security-use auth login' first.[/red]")
        sys.exit(1)

    console.print(f"[blue]Scanning {path}...[/blue]")

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

    # Try to get git info
    branch = None
    commit = None
    try:
        import subprocess
        branch = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True, text=True, cwd=path
        ).stdout.strip() or None
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True, text=True, cwd=path
        ).stdout.strip() or None
    except Exception:
        pass

    # Determine project name
    project_name = project or Path(path).resolve().name

    console.print(f"\n[bold]Scan Summary:[/bold]")
    console.print(f"  Vulnerabilities: {len(result.vulnerabilities)}")
    console.print(f"  IaC Findings: {len(result.iac_findings)}")
    console.print(f"  Files Scanned: {len(result.scanned_files)}")

    # Upload to dashboard
    console.print(f"\n[blue]Uploading to dashboard...[/blue]")

    try:
        client = DashboardClient(config)
        response = client.upload_scan(
            result=result,
            project_name=project_name,
            project_path=str(Path(path).resolve()),
            branch=branch,
            commit=commit,
        )

        console.print(f"[green]Scan uploaded successfully![/green]")

        if "scan_id" in response:
            console.print(f"  Scan ID: {response['scan_id']}")
        if "url" in response:
            console.print(f"\n  View results: [link={response['url']}]{response['url']}[/link]")
        elif "dashboard_url" in response:
            console.print(f"\n  View results: [link={response['dashboard_url']}]{response['dashboard_url']}[/link]")

    except OAuthError as e:
        console.print(f"[red]Failed to upload: {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
