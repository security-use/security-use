"""Tests for the main scanner module."""

import pytest

from security_use import scan_dependencies, scan_iac
from security_use.models import Severity


class TestScanIaCFileContent:
    """Tests for scan_iac with file_content parameter."""

    def test_scan_terraform_content(self):
        """Test scanning Terraform content directly."""
        content = '''
resource "aws_s3_bucket" "test" {
  bucket = "my-test-bucket"
}
'''
        result = scan_iac(file_content=content, file_type="terraform")

        # Should find at least the missing encryption finding
        assert len(result.iac_findings) >= 1
        assert any(f.rule_id == "CKV_AWS_19" for f in result.iac_findings)

    def test_scan_terraform_with_public_acl(self):
        """Test detecting public S3 bucket ACL."""
        content = '''
resource "aws_s3_bucket" "public" {
  bucket = "public-bucket"
}

resource "aws_s3_bucket_acl" "public" {
  bucket = aws_s3_bucket.public.id
  acl    = "public-read"
}
'''
        result = scan_iac(file_content=content, file_type="terraform")

        # Should find public access violation
        assert any(f.rule_id == "CKV_AWS_20" for f in result.iac_findings)

    def test_scan_terraform_file_type_variations(self):
        """Test various file_type values for Terraform."""
        content = '''
resource "aws_s3_bucket" "test" {
  bucket = "test-bucket"
}
'''
        # Test different file_type values
        for file_type in ["terraform", "tf", "TERRAFORM", "TF", "Terraform"]:
            result = scan_iac(file_content=content, file_type=file_type)
            assert len(result.iac_findings) >= 1, f"Failed for file_type={file_type}"

    def test_scan_terraform_default_file_type(self):
        """Test that default file_type is terraform."""
        content = '''
resource "aws_s3_bucket" "test" {
  bucket = "test-bucket"
}
'''
        result = scan_iac(file_content=content)  # No file_type specified
        assert len(result.iac_findings) >= 1

    def test_scan_cloudformation_content(self):
        """Test scanning CloudFormation content directly."""
        content = '''
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: my-cf-bucket
'''
        result = scan_iac(file_content=content, file_type="cloudformation")

        # Should parse and potentially find findings
        assert result is not None
        assert len(result.errors) == 0

    def test_scan_cloudformation_file_type_variations(self):
        """Test various file_type values for CloudFormation."""
        content = '''
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
'''
        for file_type in ["cloudformation", "cfn", "yaml", "yml"]:
            result = scan_iac(file_content=content, file_type=file_type)
            assert result is not None, f"Failed for file_type={file_type}"
            assert len(result.errors) == 0, f"Errors for file_type={file_type}: {result.errors}"

    def test_scan_empty_content(self):
        """Test scanning empty content."""
        result = scan_iac(file_content="", file_type="terraform")
        assert result is not None
        assert len(result.iac_findings) == 0

    def test_scan_invalid_terraform_content(self):
        """Test scanning invalid Terraform content."""
        content = "this is not valid terraform syntax { { {"
        result = scan_iac(file_content=content, file_type="terraform")

        # Should return empty findings but capture errors
        assert result is not None


class TestScanDependenciesFileContent:
    """Tests for scan_dependencies with file_content parameter."""

    def test_scan_requirements_content(self):
        """Test scanning requirements.txt content directly."""
        content = """
flask==2.0.1
requests>=2.25.0
"""
        result = scan_dependencies(file_content=content, file_type="requirements.txt")

        # Should find vulnerabilities in flask 2.0.1
        assert result is not None
        # Flask 2.0.1 has known vulnerabilities
        flask_vulns = [v for v in result.vulnerabilities if v.package == "flask"]
        assert len(flask_vulns) > 0

    def test_scan_requirements_default_file_type(self):
        """Test that default file_type is requirements.txt."""
        content = "flask==2.0.1"
        result = scan_dependencies(file_content=content)  # No file_type specified
        assert result is not None


class TestScanIaCPath:
    """Tests for scan_iac with path parameter."""

    def test_scan_path_still_works(self, tmp_path):
        """Ensure path-based scanning still works after the fix."""
        tf_file = tmp_path / "main.tf"
        tf_file.write_text('''
resource "aws_s3_bucket" "test" {
  bucket = "test-bucket"
}
''')
        result = scan_iac(path=str(tmp_path))

        assert len(result.iac_findings) >= 1
        assert len(result.scanned_files) == 1
