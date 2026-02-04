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


class TestALBAccessLogsRule:
    """Tests for ALB access logs rule."""

    def test_alb_with_access_logs_passes(self):
        from security_use.iac.rules.aws import ALBAccessLogsRule

        resource = IaCResource(
            resource_type="aws_lb",
            name="my_alb",
            config={
                "access_logs": {
                    "bucket": "my-logs-bucket",
                    "enabled": True,
                }
            },
            file_path="main.tf",
            line_number=1,
            provider="aws",
        )

        rule = ALBAccessLogsRule()
        result = rule.evaluate(resource)
        assert result.passed is True

    def test_alb_without_access_logs_fails(self):
        from security_use.iac.rules.aws import ALBAccessLogsRule

        resource = IaCResource(
            resource_type="aws_lb",
            name="my_alb",
            config={"name": "my-alb"},
            file_path="main.tf",
            line_number=1,
            provider="aws",
        )

        rule = ALBAccessLogsRule()
        result = rule.evaluate(resource)
        assert result.passed is False
        assert result.fix_code is not None
        assert "access_logs" in result.fix_code


class TestSNSTopicEncryptionRule:
    """Tests for SNS topic encryption rule."""

    def test_sns_with_encryption_passes(self):
        from security_use.iac.rules.aws import SNSTopicEncryptionRule

        resource = IaCResource(
            resource_type="aws_sns_topic",
            name="my_topic",
            config={
                "kms_master_key_id": "alias/aws/sns",
            },
            file_path="main.tf",
            line_number=1,
            provider="aws",
        )

        rule = SNSTopicEncryptionRule()
        result = rule.evaluate(resource)
        assert result.passed is True

    def test_sns_without_encryption_fails(self):
        from security_use.iac.rules.aws import SNSTopicEncryptionRule

        resource = IaCResource(
            resource_type="aws_sns_topic",
            name="my_topic",
            config={"name": "my-topic"},
            file_path="main.tf",
            line_number=1,
            provider="aws",
        )

        rule = SNSTopicEncryptionRule()
        result = rule.evaluate(resource)
        assert result.passed is False


class TestSQSQueueEncryptionRule:
    """Tests for SQS queue encryption rule."""

    def test_sqs_with_kms_encryption_passes(self):
        from security_use.iac.rules.aws import SQSQueueEncryptionRule

        resource = IaCResource(
            resource_type="aws_sqs_queue",
            name="my_queue",
            config={
                "kms_master_key_id": "alias/aws/sqs",
            },
            file_path="main.tf",
            line_number=1,
            provider="aws",
        )

        rule = SQSQueueEncryptionRule()
        result = rule.evaluate(resource)
        assert result.passed is True

    def test_sqs_with_sse_encryption_passes(self):
        from security_use.iac.rules.aws import SQSQueueEncryptionRule

        resource = IaCResource(
            resource_type="aws_sqs_queue",
            name="my_queue",
            config={
                "sqs_managed_sse_enabled": True,
            },
            file_path="main.tf",
            line_number=1,
            provider="aws",
        )

        rule = SQSQueueEncryptionRule()
        result = rule.evaluate(resource)
        assert result.passed is True

    def test_sqs_without_encryption_fails(self):
        from security_use.iac.rules.aws import SQSQueueEncryptionRule

        resource = IaCResource(
            resource_type="aws_sqs_queue",
            name="my_queue",
            config={"name": "my-queue"},
            file_path="main.tf",
            line_number=1,
            provider="aws",
        )

        rule = SQSQueueEncryptionRule()
        result = rule.evaluate(resource)
        assert result.passed is False


class TestLambdaVPCRule:
    """Tests for Lambda VPC rule."""

    def test_lambda_with_vpc_passes(self):
        from security_use.iac.rules.aws import LambdaVPCRule

        resource = IaCResource(
            resource_type="aws_lambda_function",
            name="my_function",
            config={
                "vpc_config": {
                    "subnet_ids": ["subnet-123"],
                    "security_group_ids": ["sg-123"],
                }
            },
            file_path="main.tf",
            line_number=1,
            provider="aws",
        )

        rule = LambdaVPCRule()
        result = rule.evaluate(resource)
        assert result.passed is True

    def test_lambda_without_vpc_fails(self):
        from security_use.iac.rules.aws import LambdaVPCRule

        resource = IaCResource(
            resource_type="aws_lambda_function",
            name="my_function",
            config={"function_name": "my-function"},
            file_path="main.tf",
            line_number=1,
            provider="aws",
        )

        rule = LambdaVPCRule()
        result = rule.evaluate(resource)
        assert result.passed is False
        assert result.fix_code is not None
        assert "vpc_config" in result.fix_code


class TestAzureAppServiceHTTPSRule:
    """Tests for Azure App Service HTTPS rule."""

    def test_app_service_with_https_passes(self):
        from security_use.iac.rules.azure import AzureAppServiceHTTPSRule

        resource = IaCResource(
            resource_type="azurerm_app_service",
            name="my_app",
            config={"https_only": True},
            file_path="main.tf",
            line_number=1,
            provider="azure",
        )

        rule = AzureAppServiceHTTPSRule()
        result = rule.evaluate(resource)
        assert result.passed is True

    def test_app_service_without_https_fails(self):
        from security_use.iac.rules.azure import AzureAppServiceHTTPSRule

        resource = IaCResource(
            resource_type="azurerm_app_service",
            name="my_app",
            config={"name": "my-app"},
            file_path="main.tf",
            line_number=1,
            provider="azure",
        )

        rule = AzureAppServiceHTTPSRule()
        result = rule.evaluate(resource)
        assert result.passed is False
        assert "https_only" in result.fix_code


class TestAzureStorageHTTPSRule:
    """Tests for Azure Storage HTTPS rule."""

    def test_storage_with_https_passes(self):
        from security_use.iac.rules.azure import AzureStorageHTTPSRule

        resource = IaCResource(
            resource_type="azurerm_storage_account",
            name="my_storage",
            config={"enable_https_traffic_only": True},
            file_path="main.tf",
            line_number=1,
            provider="azure",
        )

        rule = AzureStorageHTTPSRule()
        result = rule.evaluate(resource)
        assert result.passed is True

    def test_storage_without_https_fails(self):
        from security_use.iac.rules.azure import AzureStorageHTTPSRule

        resource = IaCResource(
            resource_type="azurerm_storage_account",
            name="my_storage",
            config={"enable_https_traffic_only": False},
            file_path="main.tf",
            line_number=1,
            provider="azure",
        )

        rule = AzureStorageHTTPSRule()
        result = rule.evaluate(resource)
        assert result.passed is False


class TestAzureFunctionAppHTTPSRule:
    """Tests for Azure Function App HTTPS rule."""

    def test_function_app_with_https_passes(self):
        from security_use.iac.rules.azure import AzureFunctionAppHTTPSRule

        resource = IaCResource(
            resource_type="azurerm_function_app",
            name="my_func",
            config={"https_only": True},
            file_path="main.tf",
            line_number=1,
            provider="azure",
        )

        rule = AzureFunctionAppHTTPSRule()
        result = rule.evaluate(resource)
        assert result.passed is True

    def test_function_app_without_https_fails(self):
        from security_use.iac.rules.azure import AzureFunctionAppHTTPSRule

        resource = IaCResource(
            resource_type="azurerm_function_app",
            name="my_func",
            config={"name": "my-func"},
            file_path="main.tf",
            line_number=1,
            provider="azure",
        )

        rule = AzureFunctionAppHTTPSRule()
        result = rule.evaluate(resource)
        assert result.passed is False


class TestGKEPrivateClusterRule:
    """Tests for GKE private cluster rule."""

    def test_gke_with_private_nodes_passes(self):
        from security_use.iac.rules.gcp import GKEPrivateClusterRule

        resource = IaCResource(
            resource_type="google_container_cluster",
            name="my_cluster",
            config={
                "private_cluster_config": {
                    "enable_private_nodes": True,
                }
            },
            file_path="main.tf",
            line_number=1,
            provider="gcp",
        )

        rule = GKEPrivateClusterRule()
        result = rule.evaluate(resource)
        assert result.passed is True

    def test_gke_without_private_nodes_fails(self):
        from security_use.iac.rules.gcp import GKEPrivateClusterRule

        resource = IaCResource(
            resource_type="google_container_cluster",
            name="my_cluster",
            config={"name": "my-cluster"},
            file_path="main.tf",
            line_number=1,
            provider="gcp",
        )

        rule = GKEPrivateClusterRule()
        result = rule.evaluate(resource)
        assert result.passed is False
        assert "private_cluster_config" in result.fix_code


class TestGCPCloudSQLSSLRule:
    """Tests for GCP Cloud SQL SSL rule."""

    def test_sql_with_ssl_passes(self):
        from security_use.iac.rules.gcp import GCPCloudSQLSSLRule

        resource = IaCResource(
            resource_type="google_sql_database_instance",
            name="my_db",
            config={
                "settings": {
                    "ip_configuration": {
                        "require_ssl": True,
                    }
                }
            },
            file_path="main.tf",
            line_number=1,
            provider="gcp",
        )

        rule = GCPCloudSQLSSLRule()
        result = rule.evaluate(resource)
        assert result.passed is True

    def test_sql_without_ssl_fails(self):
        from security_use.iac.rules.gcp import GCPCloudSQLSSLRule

        resource = IaCResource(
            resource_type="google_sql_database_instance",
            name="my_db",
            config={"settings": {}},
            file_path="main.tf",
            line_number=1,
            provider="gcp",
        )

        rule = GCPCloudSQLSSLRule()
        result = rule.evaluate(resource)
        assert result.passed is False


class TestGCPComputeSSHKeysRule:
    """Tests for GCP Compute SSH keys rule."""

    def test_compute_blocking_project_keys_passes(self):
        from security_use.iac.rules.gcp import GCPComputeSSHKeysRule

        resource = IaCResource(
            resource_type="google_compute_instance",
            name="my_vm",
            config={
                "metadata": {
                    "block-project-ssh-keys": "true",
                }
            },
            file_path="main.tf",
            line_number=1,
            provider="gcp",
        )

        rule = GCPComputeSSHKeysRule()
        result = rule.evaluate(resource)
        assert result.passed is True

    def test_compute_allowing_project_keys_fails(self):
        from security_use.iac.rules.gcp import GCPComputeSSHKeysRule

        resource = IaCResource(
            resource_type="google_compute_instance",
            name="my_vm",
            config={"name": "my-vm"},
            file_path="main.tf",
            line_number=1,
            provider="gcp",
        )

        rule = GCPComputeSSHKeysRule()
        result = rule.evaluate(resource)
        assert result.passed is False


class TestK8sAllowPrivilegeEscalationRule:
    """Tests for K8s allow privilege escalation rule."""

    def test_pod_disallowing_escalation_passes(self):
        from security_use.iac.rules.kubernetes import K8sAllowPrivilegeEscalationRule

        resource = IaCResource(
            resource_type="kubernetes_pod",
            name="my_pod",
            config={
                "spec": {
                    "containers": [{
                        "name": "app",
                        "securityContext": {
                            "allowPrivilegeEscalation": False,
                        }
                    }]
                }
            },
            file_path="pod.yaml",
            line_number=1,
        )

        rule = K8sAllowPrivilegeEscalationRule()
        result = rule.evaluate(resource)
        assert result.passed is True

    def test_pod_allowing_escalation_fails(self):
        from security_use.iac.rules.kubernetes import K8sAllowPrivilegeEscalationRule

        resource = IaCResource(
            resource_type="kubernetes_pod",
            name="my_pod",
            config={
                "spec": {
                    "containers": [{
                        "name": "app",
                        "securityContext": {
                            "allowPrivilegeEscalation": True,
                        }
                    }]
                }
            },
            file_path="pod.yaml",
            line_number=1,
        )

        rule = K8sAllowPrivilegeEscalationRule()
        result = rule.evaluate(resource)
        assert result.passed is False


class TestK8sHostPathVolumeRule:
    """Tests for K8s hostPath volume rule."""

    def test_pod_without_hostpath_passes(self):
        from security_use.iac.rules.kubernetes import K8sHostPathVolumeRule

        resource = IaCResource(
            resource_type="kubernetes_pod",
            name="my_pod",
            config={
                "spec": {
                    "volumes": [{
                        "name": "data",
                        "persistentVolumeClaim": {
                            "claimName": "my-pvc"
                        }
                    }]
                }
            },
            file_path="pod.yaml",
            line_number=1,
        )

        rule = K8sHostPathVolumeRule()
        result = rule.evaluate(resource)
        assert result.passed is True

    def test_pod_with_hostpath_fails(self):
        from security_use.iac.rules.kubernetes import K8sHostPathVolumeRule

        resource = IaCResource(
            resource_type="kubernetes_pod",
            name="my_pod",
            config={
                "spec": {
                    "volumes": [{
                        "name": "host-data",
                        "hostPath": {
                            "path": "/var/log"
                        }
                    }]
                }
            },
            file_path="pod.yaml",
            line_number=1,
        )

        rule = K8sHostPathVolumeRule()
        result = rule.evaluate(resource)
        assert result.passed is False
        assert "PersistentVolumeClaim" in result.fix_code
