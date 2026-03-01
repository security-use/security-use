"""Tests for IaC fixer functionality."""

import re

import pytest

from security_use.fixers.iac_fixer import IAC_FIXES, IaCFixer


class TestIaCFixerReplacements:
    """Tests for IaC fixer replacement strings."""

    def test_security_group_replacement_has_no_todo(self):
        """CKV_AWS_23 replacement should not contain TODO."""
        replacement = IAC_FIXES["CKV_AWS_23"]["replacement"]
        assert "TODO" not in replacement
        assert "10.0.0.0/8" in replacement

    def test_iam_policy_replacement_has_no_todo(self):
        """CKV_AWS_40 replacement should not contain TODO."""
        replacement = IAC_FIXES["CKV_AWS_40"]["replacement"]
        assert "TODO" not in replacement
        assert "s3:GetObject" in replacement

    def test_no_remaining_todos_in_fixes(self):
        """No fix replacement strings should contain TODO."""
        for rule_id, fix_info in IAC_FIXES.items():
            if "replacement" in fix_info:
                assert "TODO" not in fix_info["replacement"], (
                    f"Rule {rule_id} replacement still contains TODO"
                )


class TestIaCFixerApply:
    """Tests for IaC fixer applying fixes."""

    def test_fix_security_group_cidr(self, tmp_path):
        """Test fixing security group with 0.0.0.0/0 CIDR."""
        tf_file = tmp_path / "sg.tf"
        tf_file.write_text('''
resource "aws_security_group" "allow_all" {
  ingress {
    cidr_blocks = ["0.0.0.0/0"]
  }
}
''')
        fixer = IaCFixer()
        result = fixer.fix_finding(
            file_path=str(tf_file),
            rule_id="CKV_AWS_23",
            resource_name="allow_all",
        )
        assert result.success
        fixed_content = tf_file.read_text()
        assert "10.0.0.0/8" in fixed_content
        assert "0.0.0.0/0" not in fixed_content
        assert "TODO" not in fixed_content

    def test_fix_iam_wildcard_action(self, tmp_path):
        """Test fixing IAM policy with wildcard action."""
        policy_file = tmp_path / "iam.json"
        policy_file.write_text('''{
  "Statement": [{
    "Effect": "Allow",
    "Action": "*",
    "Resource": "*"
  }]
}''')
        fixer = IaCFixer()
        result = fixer.fix_finding(
            file_path=str(policy_file),
            rule_id="CKV_AWS_40",
            resource_name="admin_policy",
        )
        assert result.success
        fixed_content = policy_file.read_text()
        assert "s3:GetObject" in fixed_content
        assert '"Action": "*"' not in fixed_content.replace(" ", "")
        assert "TODO" not in fixed_content

    def test_fix_s3_public_acl(self, tmp_path):
        """Test fixing S3 bucket public ACL."""
        tf_file = tmp_path / "s3.tf"
        tf_file.write_text('''
resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
  acl    = "public-read"
}
''')
        fixer = IaCFixer()
        result = fixer.fix_finding(
            file_path=str(tf_file),
            rule_id="CKV_AWS_20",
            resource_name="data",
        )
        assert result.success
        fixed_content = tf_file.read_text()
        assert '"private"' in fixed_content
        assert "public-read" not in fixed_content

    def test_fix_nonexistent_file(self):
        """Test fixing a non-existent file returns error."""
        fixer = IaCFixer()
        result = fixer.fix_finding(
            file_path="/nonexistent/path.tf",
            rule_id="CKV_AWS_20",
            resource_name="test",
        )
        assert not result.success
        assert "does not exist" in result.error

    def test_fix_unsupported_rule(self, tmp_path):
        """Test fixing with an unsupported rule returns error."""
        tf_file = tmp_path / "test.tf"
        tf_file.write_text("resource {}")
        fixer = IaCFixer()
        result = fixer.fix_finding(
            file_path=str(tf_file),
            rule_id="UNSUPPORTED_RULE",
            resource_name="test",
        )
        assert not result.success

    def test_has_fix(self):
        """Test has_fix for known and unknown rules."""
        fixer = IaCFixer()
        assert fixer.has_fix("CKV_AWS_20")
        assert fixer.has_fix("CKV_AWS_23")
        assert fixer.has_fix("CKV_AWS_40")
        assert not fixer.has_fix("UNKNOWN_RULE")

    def test_get_available_fixes(self):
        """Test listing available fixes."""
        fixer = IaCFixer()
        fixes = fixer.get_available_fixes()
        assert isinstance(fixes, list)
        assert "CKV_AWS_20" in fixes
        assert "CKV_AWS_23" in fixes
