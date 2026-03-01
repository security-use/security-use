"""AWS security rules for IaC scanning."""

from security_use.models import Severity
from security_use.iac.base import IaCResource
from security_use.iac.rules.base import Rule, RuleResult


class S3BucketEncryptionRule(Rule):
    """Check that S3 buckets have server-side encryption enabled."""

    RULE_ID = "CKV_AWS_19"
    TITLE = "S3 bucket without encryption"
    SEVERITY = Severity.HIGH
    DESCRIPTION = (
        "S3 bucket does not have server-side encryption enabled. "
        "Data at rest should be encrypted to protect sensitive information."
    )
    REMEDIATION = (
        "Enable server-side encryption using SSE-S3, SSE-KMS, or SSE-C. "
        "Add a server_side_encryption_configuration block to the bucket."
    )
    RESOURCE_TYPES = ["aws_s3_bucket", "AWS::S3::Bucket"]

    def evaluate(self, resource: IaCResource) -> RuleResult:
        """Check if S3 bucket has encryption enabled."""
        has_encryption = False

        # Terraform: Check for server_side_encryption_configuration
        if "server_side_encryption_configuration" in resource.config:
            has_encryption = True

        # CloudFormation: Check for BucketEncryption
        if "BucketEncryption" in resource.config:
            has_encryption = True

        fix_code = None
        if not has_encryption:
            if resource.provider == "aws":
                fix_code = '''server_side_encryption_configuration {
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}'''

        return self._create_result(has_encryption, resource, fix_code)


class S3BucketPublicAccessRule(Rule):
    """Check that S3 buckets do not allow public access."""

    RULE_ID = "CKV_AWS_20"
    TITLE = "S3 bucket with public access"
    SEVERITY = Severity.CRITICAL
    DESCRIPTION = (
        "S3 bucket allows public access. This can lead to data exposure "
        "and security breaches."
    )
    REMEDIATION = (
        "Set the bucket ACL to 'private' and enable block public access settings. "
        "Remove any bucket policies that grant public access."
    )
    RESOURCE_TYPES = ["aws_s3_bucket", "AWS::S3::Bucket"]

    PUBLIC_ACLS = ["public-read", "public-read-write", "authenticated-read"]

    def evaluate(self, resource: IaCResource) -> RuleResult:
        """Check if S3 bucket has public access."""
        has_public_access = False

        # Check ACL
        acl = resource.get_config("acl", default="private")
        if acl in self.PUBLIC_ACLS:
            has_public_access = True

        # CloudFormation: Check AccessControl
        access_control = resource.get_config("AccessControl", default="Private")
        if access_control in ["PublicRead", "PublicReadWrite", "AuthenticatedRead"]:
            has_public_access = True

        fix_code = None
        if has_public_access:
            fix_code = 'acl = "private"'

        return self._create_result(not has_public_access, resource, fix_code)


class SecurityGroupOpenIngressRule(Rule):
    """Check that security groups don't allow unrestricted ingress on sensitive ports."""

    RULE_ID = "CKV_AWS_23"
    TITLE = "Security group allows unrestricted ingress"
    SEVERITY = Severity.HIGH
    DESCRIPTION = (
        "Security group allows ingress from 0.0.0.0/0 on sensitive ports. "
        "This exposes services to the entire internet."
    )
    REMEDIATION = (
        "Restrict ingress rules to specific IP ranges or security groups. "
        "Avoid using 0.0.0.0/0 as the source CIDR."
    )
    RESOURCE_TYPES = ["aws_security_group", "AWS::EC2::SecurityGroup"]

    SENSITIVE_PORTS = [22, 3389, 3306, 5432, 1433, 27017, 6379, 11211]

    def evaluate(self, resource: IaCResource) -> RuleResult:
        """Check if security group has open ingress on sensitive ports."""
        has_open_ingress = False

        # Terraform format
        ingress_rules = resource.get_config("ingress", default=[])
        if isinstance(ingress_rules, list):
            for rule in ingress_rules:
                if self._is_open_rule(rule):
                    has_open_ingress = True
                    break

        # CloudFormation format
        sg_ingress = resource.get_config("SecurityGroupIngress", default=[])
        if isinstance(sg_ingress, list):
            for rule in sg_ingress:
                if self._is_open_cfn_rule(rule):
                    has_open_ingress = True
                    break

        fix_code = None
        if has_open_ingress:
            fix_code = "# Restrict cidr_blocks to specific IP ranges instead of 0.0.0.0/0"

        return self._create_result(not has_open_ingress, resource, fix_code)

    def _is_open_rule(self, rule: dict) -> bool:
        """Check if a Terraform ingress rule is open to the world."""
        cidr_blocks = rule.get("cidr_blocks", [])
        if "0.0.0.0/0" not in cidr_blocks and "::/0" not in cidr_blocks:
            return False

        from_port = rule.get("from_port", 0)
        to_port = rule.get("to_port", 65535)

        # Check if any sensitive port is in the range
        for port in self.SENSITIVE_PORTS:
            if from_port <= port <= to_port:
                return True

        return False

    def _is_open_cfn_rule(self, rule: dict) -> bool:
        """Check if a CloudFormation ingress rule is open to the world."""
        cidr = rule.get("CidrIp", "")
        cidr_v6 = rule.get("CidrIpv6", "")
        if cidr != "0.0.0.0/0" and cidr_v6 != "::/0":
            return False

        from_port = rule.get("FromPort", 0)
        to_port = rule.get("ToPort", 65535)

        for port in self.SENSITIVE_PORTS:
            if from_port <= port <= to_port:
                return True

        return False


class IAMUserMFARule(Rule):
    """Check that IAM users have MFA enabled."""

    RULE_ID = "CKV_AWS_14"
    TITLE = "IAM user without MFA"
    SEVERITY = Severity.MEDIUM
    DESCRIPTION = (
        "IAM user does not have MFA enabled. MFA provides an additional "
        "layer of security for user authentication."
    )
    REMEDIATION = (
        "Enable MFA for all IAM users with console access. "
        "Use virtual MFA devices or hardware tokens."
    )
    RESOURCE_TYPES = ["aws_iam_user", "AWS::IAM::User"]

    def evaluate(self, resource: IaCResource) -> RuleResult:
        """Check if IAM user has MFA configured."""
        # For Terraform, we'd check for associated aws_iam_user_mfa_device
        # For CloudFormation, MFA is typically configured separately
        # This is a best-effort check

        # If the user has login profile (console access), MFA should be required
        has_login_profile = "login_profile" in resource.config or "LoginProfile" in resource.config

        # We can't definitively check MFA from the resource alone
        # Flag users with console access as needing review
        if has_login_profile:
            return self._create_result(
                False,
                resource,
                fix_code="# Ensure MFA is configured for this user",
            )

        return self._create_result(True, resource)


class RDSEncryptionRule(Rule):
    """Check that RDS instances have encryption enabled."""

    RULE_ID = "CKV_AWS_16"
    TITLE = "RDS instance without encryption"
    SEVERITY = Severity.HIGH
    DESCRIPTION = (
        "RDS instance does not have encryption at rest enabled. "
        "Database data should be encrypted to protect sensitive information."
    )
    REMEDIATION = (
        "Enable encryption at rest for the RDS instance. "
        "Set storage_encrypted = true (Terraform) or StorageEncrypted: true (CloudFormation)."
    )
    RESOURCE_TYPES = ["aws_db_instance", "AWS::RDS::DBInstance"]

    def evaluate(self, resource: IaCResource) -> RuleResult:
        """Check if RDS instance has encryption enabled."""
        # Terraform
        storage_encrypted = resource.get_config("storage_encrypted", default=False)

        # CloudFormation
        if not storage_encrypted:
            storage_encrypted = resource.get_config("StorageEncrypted", default=False)

        fix_code = None
        if not storage_encrypted:
            fix_code = "storage_encrypted = true"

        return self._create_result(bool(storage_encrypted), resource, fix_code)


class EBSEncryptionRule(Rule):
    """Check that EBS volumes have encryption enabled."""

    RULE_ID = "CKV_AWS_3"
    TITLE = "EBS volume without encryption"
    SEVERITY = Severity.HIGH
    DESCRIPTION = (
        "EBS volume does not have encryption enabled. "
        "Data on EBS volumes should be encrypted at rest."
    )
    REMEDIATION = (
        "Enable encryption for the EBS volume. "
        "Set encrypted = true (Terraform) or Encrypted: true (CloudFormation)."
    )
    RESOURCE_TYPES = ["aws_ebs_volume", "AWS::EC2::Volume"]

    def evaluate(self, resource: IaCResource) -> RuleResult:
        """Check if EBS volume has encryption enabled."""
        # Terraform
        encrypted = resource.get_config("encrypted", default=False)

        # CloudFormation
        if not encrypted:
            encrypted = resource.get_config("Encrypted", default=False)

        fix_code = None
        if not encrypted:
            fix_code = "encrypted = true"

        return self._create_result(bool(encrypted), resource, fix_code)


class CloudTrailEnabledRule(Rule):
    """Check that CloudTrail is properly configured."""

    RULE_ID = "CKV_AWS_35"
    TITLE = "CloudTrail not logging all events"
    SEVERITY = Severity.MEDIUM
    DESCRIPTION = (
        "CloudTrail is not configured to log all management events. "
        "Complete audit logging is essential for security monitoring."
    )
    REMEDIATION = (
        "Enable CloudTrail with is_multi_region_trail = true and "
        "include_global_service_events = true."
    )
    RESOURCE_TYPES = ["aws_cloudtrail", "AWS::CloudTrail::Trail"]

    def evaluate(self, resource: IaCResource) -> RuleResult:
        """Check if CloudTrail is properly configured."""
        is_multi_region = resource.get_config("is_multi_region_trail", default=False)
        include_global = resource.get_config("include_global_service_events", default=False)

        # CloudFormation
        if not is_multi_region:
            is_multi_region = resource.get_config("IsMultiRegionTrail", default=False)
        if not include_global:
            include_global = resource.get_config("IncludeGlobalServiceEvents", default=False)

        passed = is_multi_region and include_global

        fix_code = None
        if not passed:
            fix_code = "is_multi_region_trail = true\ninclude_global_service_events = true"

        return self._create_result(passed, resource, fix_code)


class VPCFlowLogsRule(Rule):
    """Check that VPC flow logs are enabled."""

    RULE_ID = "CKV_AWS_12"
    TITLE = "VPC without flow logs"
    SEVERITY = Severity.MEDIUM
    DESCRIPTION = (
        "VPC does not have flow logs enabled. Flow logs provide visibility "
        "into network traffic for security analysis and troubleshooting."
    )
    REMEDIATION = (
        "Enable VPC flow logs by creating an aws_flow_log resource "
        "(Terraform) or AWS::EC2::FlowLog (CloudFormation)."
    )
    RESOURCE_TYPES = ["aws_vpc", "AWS::EC2::VPC"]

    def evaluate(self, resource: IaCResource) -> RuleResult:
        """Check if VPC has flow logs.

        Note: This is a best-effort check. Flow logs are typically
        defined as separate resources, so we flag VPCs for review.
        """
        # VPCs should have associated flow logs
        # We can't verify this from the VPC resource alone
        # Return a warning to encourage flow log configuration

        fix_code = '''resource "aws_flow_log" "example" {
  vpc_id                   = aws_vpc.example.id
  traffic_type             = "ALL"
  log_destination_type     = "cloud-watch-logs"
  log_destination          = aws_cloudwatch_log_group.example.arn
  iam_role_arn             = aws_iam_role.example.arn
}'''

        # Default to warning (not passed) to encourage flow logs
        return self._create_result(False, resource, fix_code)
