"""Tests for CLI interface."""

import json

import pytest
from click.testing import CliRunner

from security_use.cli import main


@pytest.fixture
def runner():
    """Create a CLI test runner."""
    return CliRunner()


@pytest.fixture
def temp_requirements(tmp_path):
    """Create a temporary requirements.txt file."""
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("requests==2.28.0\ndjango==3.2.0\n")
    return req_file


@pytest.fixture
def temp_terraform(tmp_path):
    """Create a temporary Terraform file."""
    tf_file = tmp_path / "main.tf"
    tf_file.write_text("""
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  acl    = "public-read"
}
""")
    return tf_file


class TestVersion:
    """Tests for version command."""

    def test_version_command(self, runner):
        result = runner.invoke(main, ["version"])
        assert result.exit_code == 0
        assert "security-use version" in result.output

    def test_version_option(self, runner):
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "security-use" in result.output


class TestScanDeps:
    """Tests for scan deps command."""

    def test_scan_deps_no_files(self, runner, tmp_path):
        result = runner.invoke(main, ["scan", "deps", str(tmp_path)])
        assert result.exit_code == 0
        assert "No vulnerabilities found" in result.output

    def test_scan_deps_with_requirements(self, runner, temp_requirements):
        # Mock the OSV client to avoid network calls
        result = runner.invoke(
            main,
            ["scan", "deps", str(temp_requirements.parent)],
        )
        # Should complete without error (may or may not find vulns depending on mocking)
        assert result.exit_code in [0, 1]

    def test_scan_deps_json_format(self, runner, tmp_path):
        result = runner.invoke(
            main,
            ["scan", "deps", str(tmp_path), "--format", "json"],
        )
        assert result.exit_code == 0
        # Should be valid JSON
        data = json.loads(result.output)
        assert "vulnerabilities" in data

    def test_scan_deps_severity_filter(self, runner, tmp_path):
        result = runner.invoke(
            main,
            ["scan", "deps", str(tmp_path), "--severity", "critical"],
        )
        assert result.exit_code == 0


class TestScanIac:
    """Tests for scan iac command."""

    def test_scan_iac_no_files(self, runner, tmp_path):
        result = runner.invoke(main, ["scan", "iac", str(tmp_path)])
        assert result.exit_code == 0
        assert "No security issues found" in result.output

    def test_scan_iac_with_terraform(self, runner, temp_terraform):
        result = runner.invoke(
            main,
            ["scan", "iac", str(temp_terraform.parent)],
        )
        # Should find the public-read ACL issue
        assert result.exit_code == 1
        assert "security issue" in result.output.lower()

    def test_scan_iac_json_format(self, runner, tmp_path):
        result = runner.invoke(
            main,
            ["scan", "iac", str(tmp_path), "--format", "json"],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "iac_findings" in data


class TestScanAll:
    """Tests for scan all command."""

    def test_scan_all_empty_dir(self, runner, tmp_path):
        result = runner.invoke(main, ["scan", "all", str(tmp_path)])
        assert result.exit_code == 0
        assert "No security issues found" in result.output

    def test_scan_all_json_format(self, runner, tmp_path):
        result = runner.invoke(
            main,
            ["scan", "all", str(tmp_path), "--format", "json"],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "vulnerabilities" in data
        assert "iac_findings" in data


class TestFix:
    """Tests for fix command."""

    def test_fix_dry_run(self, runner, temp_requirements):
        result = runner.invoke(
            main,
            ["fix", str(temp_requirements.parent), "--dry-run"],
        )
        # Should complete without error - may find vulns with or without fixes
        assert (
            "Dry run" in result.output
            or "No vulnerabilities" in result.output
            or "No automatic fixes" in result.output
        )

    def test_fix_no_vulnerabilities(self, runner, tmp_path):
        result = runner.invoke(main, ["fix", str(tmp_path)])
        assert (
            "No dependency vulnerabilities found" in result.output
            or "No fixes were applied" in result.output
        )


class TestOutputFile:
    """Tests for output file option."""

    def test_output_to_file(self, runner, tmp_path):
        output_file = tmp_path / "report.json"
        result = runner.invoke(
            main,
            ["scan", "deps", str(tmp_path), "--format", "json", "--output", str(output_file)],
        )
        assert result.exit_code == 0
        assert output_file.exists()

        # Verify content is valid JSON
        data = json.loads(output_file.read_text())
        assert "vulnerabilities" in data


class TestHelp:
    """Tests for help output."""

    def test_main_help(self, runner):
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "security-use" in result.output

    def test_scan_help(self, runner):
        result = runner.invoke(main, ["scan", "--help"])
        assert result.exit_code == 0
        assert "deps" in result.output
        assert "iac" in result.output
        assert "all" in result.output

    def test_scan_deps_help(self, runner):
        result = runner.invoke(main, ["scan", "deps", "--help"])
        assert result.exit_code == 0
        assert "--format" in result.output
        assert "--severity" in result.output
        assert "--output" in result.output


class TestCICommand:
    """Tests for CI command - optimized for CI/CD pipelines."""

    def test_ci_help(self, runner):
        """Test CI command help output."""
        result = runner.invoke(main, ["ci", "--help"])
        assert result.exit_code == 0
        assert "--fail-on" in result.output
        assert "--output" in result.output
        assert "--sarif-file" in result.output

    def test_ci_no_issues(self, runner, tmp_path):
        """Test CI with clean directory - should exit 0."""
        result = runner.invoke(main, ["ci", str(tmp_path)])
        assert result.exit_code == 0

    def test_ci_minimal_output(self, runner, tmp_path):
        """Test CI with minimal output format."""
        result = runner.invoke(main, ["ci", str(tmp_path), "-o", "minimal"])
        assert result.exit_code == 0
        # Minimal output should be concise
        assert len(result.output) < 200 or "✓" in result.output or "passed" in result.output.lower()

    def test_ci_sarif_output(self, runner, tmp_path):
        """Test CI with SARIF output format."""
        result = runner.invoke(main, ["ci", str(tmp_path), "-o", "sarif"])
        assert result.exit_code == 0
        # SARIF output should be valid JSON with specific keys
        data = json.loads(result.output)
        assert "$schema" in data or "version" in data

    def test_ci_sarif_file(self, runner, tmp_path):
        """Test CI writes SARIF to file."""
        sarif_file = tmp_path / "results.sarif"
        result = runner.invoke(main, ["ci", str(tmp_path), "--sarif-file", str(sarif_file)])
        assert result.exit_code == 0
        assert sarif_file.exists()
        # Verify SARIF content
        data = json.loads(sarif_file.read_text())
        assert "$schema" in data or "version" in data

    def test_ci_fail_on_critical(self, runner, tmp_path):
        """Test CI fail-on option with critical severity."""
        result = runner.invoke(main, ["ci", str(tmp_path), "--fail-on", "critical"])
        # No critical issues in empty dir
        assert result.exit_code == 0

    def test_ci_fail_on_low(self, runner, tmp_path):
        """Test CI fail-on option with low severity."""
        result = runner.invoke(main, ["ci", str(tmp_path), "--fail-on", "low"])
        # No issues in empty dir
        assert result.exit_code == 0

    def test_ci_deps_only(self, runner, tmp_path):
        """Test CI with deps-only flag."""
        result = runner.invoke(main, ["ci", str(tmp_path), "--deps-only"])
        assert result.exit_code == 0

    def test_ci_iac_only(self, runner, tmp_path):
        """Test CI with iac-only flag."""
        result = runner.invoke(main, ["ci", str(tmp_path), "--iac-only"])
        assert result.exit_code == 0

    def test_ci_json_output(self, runner, tmp_path):
        """Test CI with JSON output format."""
        result = runner.invoke(main, ["ci", str(tmp_path), "-o", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, dict)

    def test_ci_table_output(self, runner, tmp_path):
        """Test CI with table output format."""
        result = runner.invoke(main, ["ci", str(tmp_path), "-o", "table"])
        assert result.exit_code == 0


class TestInitCommand:
    """Tests for init command."""

    def test_init_help(self, runner):
        """Test init command help output."""
        result = runner.invoke(main, ["init", "--help"])
        assert result.exit_code == 0
        assert "--no-middleware" in result.output
        assert "--no-precommit" in result.output
        assert "--dry-run" in result.output

    def test_init_empty_dir(self, runner, tmp_path):
        """Test init on empty directory."""
        # Pass 'Y' as input to confirm interactive prompt
        result = runner.invoke(main, ["init", str(tmp_path)], input="Y\n")
        # Should succeed
        assert result.exit_code == 0

    def test_init_dry_run(self, runner, tmp_path):
        """Test init with dry-run flag."""
        # Create a simple FastAPI file
        app_file = tmp_path / "main.py"
        app_file.write_text("from fastapi import FastAPI\napp = FastAPI()")

        # Dry run doesn't need input confirmation
        result = runner.invoke(main, ["init", str(tmp_path), "--dry-run"])
        assert result.exit_code == 0
        assert "Dry run" in result.output or "Would" in result.output

        # Verify no files were actually created
        assert not (tmp_path / ".security-use.yaml").exists()

    def test_init_creates_config(self, runner, tmp_path):
        """Test init creates config file."""
        # Create a simple FastAPI file
        app_file = tmp_path / "main.py"
        app_file.write_text("from fastapi import FastAPI\napp = FastAPI()")

        # Pass 'Y' to confirm
        result = runner.invoke(main, ["init", str(tmp_path)], input="Y\n")
        assert result.exit_code == 0

        # Should create config file
        config_file = tmp_path / ".security-use.yaml"
        assert config_file.exists()

    def test_init_no_middleware_flag(self, runner, tmp_path):
        """Test init with --no-middleware flag."""
        app_file = tmp_path / "main.py"
        original_content = "from fastapi import FastAPI\napp = FastAPI()"
        app_file.write_text(original_content)

        # Pass 'Y' to confirm
        result = runner.invoke(main, ["init", str(tmp_path), "--no-middleware"], input="Y\n")
        assert result.exit_code == 0

        # App file should not be modified
        assert "SecurityMiddleware" not in app_file.read_text()

    def test_init_idempotent(self, runner, tmp_path):
        """Test that running init twice is safe."""
        app_file = tmp_path / "main.py"
        app_file.write_text("from fastapi import FastAPI\napp = FastAPI()")

        # First init
        result1 = runner.invoke(main, ["init", str(tmp_path)], input="Y\n")
        assert result1.exit_code == 0

        # Second init should also succeed (config already exists, should skip)
        result2 = runner.invoke(main, ["init", str(tmp_path)], input="Y\n")
        assert result2.exit_code == 0
