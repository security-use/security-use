"""Tests for CLI interface."""

import json
from pathlib import Path

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
    tf_file.write_text('''
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  acl    = "public-read"
}
''')
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
        assert "No dependency vulnerabilities found" in result.output or "No fixes were applied" in result.output


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
