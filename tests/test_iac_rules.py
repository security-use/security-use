"""Tests for IaC security rules."""

import pytest

from security_use.models import Severity
from security_use.iac.base import IaCResource
from security_use.iac.rules.registry import RuleRegistry, get_registry
from security_use.iac.rules.aws import (
    S3BucketEncryptionRule,
    S3BucketPublicAccessRule,
    SecurityGroupOpenIngressRule,
    RDSEncryptionRule,
    EBSEncryptionRule,
)


class TestS3BucketEncryptionRule:
    """Tests for S3 encryption rule."""

    def test_bucket_with_encryption_passes(self):
        resource = IaCResource(
            resource_type="aws_s3_bucket",
            name="encrypted_bucket",
            config={
                "server_side_encryption_configuration": {
                    "rule": {
                        "apply_server_side_encryption_by_default": {
                            "sse_algorithm": "AES256"
                        }
                    }
                }
            },
            file_path="main.tf",
            line_number=1,
            provider="aws",
        )

        rule = S3BucketEncryptionRule()
        result = rule.evaluate(resource)

        assert result.passed is True
        assert result.rule_id == "CKV_AWS_19"

    def test_bucket_without_encryption_fails(self):
        resource = IaCResource(
            resource_type="aws_s3_bucket",
            name="unencrypted_bucket",
            config={"bucket": "my-bucket"},
            file_path="main.tf",
            line_number=1,
            provider="aws",
        )

        rule = S3BucketEncryptionRule()
        result = rule.evaluate(resource)

        assert result.passed is False
        assert result.fix_code is not None
        assert "server_side_encryption" in result.fix_code

    def test_cloudformation_bucket_with_encryption_passes(self):
        resource = IaCResource(
            resource_type="AWS::S3::Bucket",
            name="EncryptedBucket",
            config={
                "BucketEncryption": {
                    "ServerSideEncryptionConfiguration": [
                        {
                            "ServerSideEncryptionByDefault": {
                                "SSEAlgorithm": "AES256"
                            }
                        }
                    ]
                }
            },
            file_path="template.yaml",
            line_number=1,
            provider="aws",
        )

        rule = S3BucketEncryptionRule()
        result = rule.evaluate(resource)

        assert result.passed is True


class TestS3BucketPublicAccessRule:
    """Tests for S3 public access rule."""

    def test_private_bucket_passes(self):
        resource = IaCResource(
            resource_type="aws_s3_bucket",
            name="private_bucket",
            config={"acl": "private"},
            file_path="main.tf",
            line_number=1,
            provider="aws",
        )

        rule = S3BucketPublicAccessRule()
        result = rule.evaluate(resource)

        assert result.passed is True

    def test_public_read_bucket_fails(self):
        resource = IaCResource(
            resource_type="aws_s3_bucket",
            name="public_bucket",
            config={"acl": "public-read"},
            file_path="main.tf",
            line_number=1,
            provider="aws",
        )

        rule = S3BucketPublicAccessRule()
        result = rule.evaluate(resource)

        assert result.passed is False
        assert result.severity == Severity.CRITICAL
        assert result.fix_code == 'acl = "private"'

    def test_cloudformation_public_bucket_fails(self):
        resource = IaCResource(
            resource_type="AWS::S3::Bucket",
            name="PublicBucket",
            config={"AccessControl": "PublicRead"},
            file_path="template.yaml",
            line_number=1,
            provider="aws",
        )

        rule = S3BucketPublicAccessRule()
        result = rule.evaluate(resource)

        assert result.passed is False


class TestSecurityGroupOpenIngressRule:
    """Tests for security group ingress rule."""

    def test_restricted_ingress_passes(self):
        resource = IaCResource(
            resource_type="aws_security_group",
            name="restricted_sg",
            config={
                "ingress": [
                    {
                        "from_port": 22,
                        "to_port": 22,
                        "cidr_blocks": ["10.0.0.0/8"],
                    }
                ]
            },
            file_path="main.tf",
            line_number=1,
            provider="aws",
        )

        rule = SecurityGroupOpenIngressRule()
        result = rule.evaluate(resource)

        assert result.passed is True

    def test_open_ssh_fails(self):
        resource = IaCResource(
            resource_type="aws_security_group",
            name="open_sg",
            config={
                "ingress": [
                    {
                        "from_port": 22,
                        "to_port": 22,
                        "cidr_blocks": ["0.0.0.0/0"],
                    }
                ]
            },
            file_path="main.tf",
            line_number=1,
            provider="aws",
        )

        rule = SecurityGroupOpenIngressRule()
        result = rule.evaluate(resource)

        assert result.passed is False
        assert result.severity == Severity.HIGH

    def test_open_rdp_fails(self):
        resource = IaCResource(
            resource_type="aws_security_group",
            name="open_sg",
            config={
                "ingress": [
                    {
                        "from_port": 3389,
                        "to_port": 3389,
                        "cidr_blocks": ["0.0.0.0/0"],
                    }
                ]
            },
            file_path="main.tf",
            line_number=1,
            provider="aws",
        )

        rule = SecurityGroupOpenIngressRule()
        result = rule.evaluate(resource)

        assert result.passed is False


class TestRDSEncryptionRule:
    """Tests for RDS encryption rule."""

    def test_encrypted_rds_passes(self):
        resource = IaCResource(
            resource_type="aws_db_instance",
            name="encrypted_db",
            config={"storage_encrypted": True},
            file_path="main.tf",
            line_number=1,
            provider="aws",
        )

        rule = RDSEncryptionRule()
        result = rule.evaluate(resource)

        assert result.passed is True

    def test_unencrypted_rds_fails(self):
        resource = IaCResource(
            resource_type="aws_db_instance",
            name="unencrypted_db",
            config={"storage_encrypted": False},
            file_path="main.tf",
            line_number=1,
            provider="aws",
        )

        rule = RDSEncryptionRule()
        result = rule.evaluate(resource)

        assert result.passed is False
        assert result.fix_code == "storage_encrypted = true"


class TestEBSEncryptionRule:
    """Tests for EBS encryption rule."""

    def test_encrypted_ebs_passes(self):
        resource = IaCResource(
            resource_type="aws_ebs_volume",
            name="encrypted_vol",
            config={"encrypted": True},
            file_path="main.tf",
            line_number=1,
            provider="aws",
        )

        rule = EBSEncryptionRule()
        result = rule.evaluate(resource)

        assert result.passed is True

    def test_unencrypted_ebs_fails(self):
        resource = IaCResource(
            resource_type="aws_ebs_volume",
            name="unencrypted_vol",
            config={},
            file_path="main.tf",
            line_number=1,
            provider="aws",
        )

        rule = EBSEncryptionRule()
        result = rule.evaluate(resource)

        assert result.passed is False


class TestRuleRegistry:
    """Tests for rule registry."""

    def test_register_and_get_rule(self):
        registry = RuleRegistry()
        rule = S3BucketEncryptionRule()
        registry.register(rule)

        retrieved = registry.get("CKV_AWS_19")
        assert retrieved is rule

    def test_get_nonexistent_rule(self):
        registry = RuleRegistry()
        assert registry.get("NONEXISTENT") is None

    def test_get_all_rules(self):
        registry = RuleRegistry()
        registry.register(S3BucketEncryptionRule())
        registry.register(S3BucketPublicAccessRule())

        rules = registry.get_all()
        assert len(rules) == 2

    def test_get_for_resource(self):
        registry = RuleRegistry()
        registry.register(S3BucketEncryptionRule())
        registry.register(S3BucketPublicAccessRule())
        registry.register(RDSEncryptionRule())

        s3_rules = registry.get_for_resource("aws_s3_bucket")
        assert len(s3_rules) == 2

        rds_rules = registry.get_for_resource("aws_db_instance")
        assert len(rds_rules) == 1

    def test_global_registry(self):
        registry = get_registry()
        rules = registry.get_all()

        # Should have default rules registered
        assert len(rules) >= 8
        assert registry.get("CKV_AWS_19") is not None
        assert registry.get("CKV_AWS_20") is not None


class TestRuleBase:
    """Tests for Rule base class functionality."""

    def test_applies_to_matching_resource(self):
        rule = S3BucketEncryptionRule()
        resource = IaCResource(
            resource_type="aws_s3_bucket",
            name="test",
            config={},
            file_path="main.tf",
            line_number=1,
        )

        assert rule.applies_to(resource) is True

    def test_applies_to_non_matching_resource(self):
        rule = S3BucketEncryptionRule()
        resource = IaCResource(
            resource_type="aws_ec2_instance",
            name="test",
            config={},
            file_path="main.tf",
            line_number=1,
        )

        assert rule.applies_to(resource) is False
