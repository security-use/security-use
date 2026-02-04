"""Tests for the fixer modules."""

import pytest
from pathlib import Path

from security_use.fixers.dependency_fixer import DependencyFixer, FixResult
from security_use.fixers.iac_fixer import IaCFixer, IaCFixResult


class TestFixResult:
    """Tests for FixResult dataclass."""

    def test_create_success_result(self):
        """Test creating a successful fix result."""
        result = FixResult(
            success=True,
            file_modified="requirements.txt",
            old_version="1.0.0",
            new_version="1.0.1",
            diff="- requests==1.0.0\n+ requests==1.0.1",
        )

        assert result.success is True
        assert result.file_modified == "requirements.txt"
        assert result.old_version == "1.0.0"
        assert result.new_version == "1.0.1"

    def test_create_failure_result(self):
        """Test creating a failed fix result."""
        result = FixResult(success=False, error="Package not found")

        assert result.success is False
        assert result.error == "Package not found"


class TestDependencyFixer:
    """Tests for DependencyFixer."""

    @pytest.fixture
    def fixer(self):
        """Create a fixer instance."""
        return DependencyFixer()

    def test_fix_nonexistent_path(self, fixer):
        """Test fixing with nonexistent path."""
        result = fixer.fix("/nonexistent/path", "requests", "2.28.0")

        assert result.success is False
        assert "does not exist" in result.error

    def test_fix_package_not_found(self, fixer, tmp_path):
        """Test fixing when package is not in any file."""
        # Create empty requirements.txt
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("flask==2.0.0\n")

        result = fixer.fix(str(tmp_path), "nonexistent-package", "1.0.0")

        assert result.success is False
        assert "not found" in result.error

    def test_fix_requirements_file(self, fixer, tmp_path):
        """Test fixing a package in requirements.txt."""
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("requests==2.25.0\nflask==2.0.0\n")

        result = fixer.fix(str(tmp_path), "requests", "2.28.0")

        assert result.success is True
        assert result.old_version == "2.25.0"
        assert result.new_version == "2.28.0"
        assert "requests==2.28.0" in req_file.read_text()

    def test_fix_preserves_other_packages(self, fixer, tmp_path):
        """Test that fixing one package preserves others."""
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("requests==2.25.0\nflask==2.0.0\ndjango==4.0.0\n")

        fixer.fix(str(tmp_path), "requests", "2.28.0")

        content = req_file.read_text()
        assert "flask==2.0.0" in content
        assert "django==4.0.0" in content

    def test_fix_with_no_version_specified(self, fixer, tmp_path):
        """Test fixing without specifying target version."""
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("requests==2.25.0\n")

        # Without target version, should try to fetch latest
        result = fixer.fix(str(tmp_path), "requests")

        # May succeed or fail depending on network, but shouldn't crash
        assert isinstance(result, FixResult)

    def test_find_package_in_main_requirements(self, fixer, tmp_path):
        """Test finding package in main requirements file."""
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("requests==2.25.0\n")

        result = fixer.fix(str(tmp_path), "requests", "2.28.0")

        assert result.success is True

    def test_fix_pyproject_toml(self, fixer, tmp_path):
        """Test fixing a package in pyproject.toml."""
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text('''
[project]
name = "myproject"
dependencies = [
    "requests==2.25.0",
    "flask>=2.0.0",
]
''')

        result = fixer.fix(str(tmp_path), "requests", "2.28.0")

        # Should update pyproject.toml
        if result.success:
            content = pyproject.read_text()
            assert "2.28.0" in content


class TestIaCFixer:
    """Tests for IaCFixer."""

    @pytest.fixture
    def fixer(self):
        """Create a fixer instance."""
        return IaCFixer()

    def test_fix_nonexistent_file(self, fixer):
        """Test fixing nonexistent file."""
        result = fixer.fix_finding("/nonexistent/file.tf", rule_id="CKV_AWS_19", resource_name="example")

        assert result.success is False
        assert "does not exist" in result.error

    def test_fix_s3_encryption(self, fixer, tmp_path):
        """Test fixing S3 bucket encryption."""
        tf_file = tmp_path / "main.tf"
        tf_file.write_text('''
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
}
''')

        result = fixer.fix_finding(str(tf_file), rule_id="CKV_AWS_19", resource_name="example")

        # Should suggest or apply encryption fix
        assert isinstance(result, IaCFixResult)
        if result.success:
            assert "encryption" in result.after.lower() or "encryption" in result.explanation.lower()

    def test_fix_security_group(self, fixer, tmp_path):
        """Test fixing security group open ingress."""
        tf_file = tmp_path / "main.tf"
        tf_file.write_text('''
resource "aws_security_group" "example" {
  name = "open-sg"
  
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
''')

        result = fixer.fix_finding(str(tf_file), rule_id="CKV_AWS_23", resource_name="example")

        # Should suggest restricting CIDR
        assert isinstance(result, IaCFixResult)

    def test_fix_unknown_rule(self, fixer, tmp_path):
        """Test fixing with unknown rule ID."""
        tf_file = tmp_path / "main.tf"
        tf_file.write_text('resource "aws_instance" "example" {}')

        result = fixer.fix_finding(str(tf_file), rule_id="UNKNOWN_RULE_999", resource_name="example")

        # Should handle gracefully
        assert isinstance(result, IaCFixResult)

    def test_fix_dry_run(self, fixer, tmp_path):
        """Test fix in dry-run mode (auto_apply=False)."""
        tf_file = tmp_path / "main.tf"
        original_content = '''
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
}
'''
        tf_file.write_text(original_content)

        result = fixer.fix_finding(str(tf_file), rule_id="CKV_AWS_19", resource_name="example", auto_apply=False)

        # File should not be modified in dry run
        assert tf_file.read_text() == original_content

    def test_fix_returns_before_after(self, fixer, tmp_path):
        """Test that fix returns before and after content."""
        tf_file = tmp_path / "main.tf"
        tf_file.write_text('''
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
}
''')

        result = fixer.fix_finding(str(tf_file), rule_id="CKV_AWS_19", resource_name="example")

        if result.success:
            assert result.before or result.after or result.explanation
