"""IaC security rules."""

from security_use.iac.rules.base import Rule, RuleResult
from security_use.iac.rules.registry import RuleRegistry, get_registry
from security_use.iac.rules.aws import (
    ALBAccessLogsRule,
    CloudTrailEnabledRule,
    EBSEncryptionRule,
    IAMUserMFARule,
    LambdaVPCRule,
    RDSEncryptionRule,
    S3BucketEncryptionRule,
    S3BucketPublicAccessRule,
    SecurityGroupOpenIngressRule,
    SNSTopicEncryptionRule,
    SQSQueueEncryptionRule,
    VPCFlowLogsRule,
)

__all__ = [
    "Rule",
    "RuleResult",
    "RuleRegistry",
    "get_registry",
    "ALBAccessLogsRule",
    "CloudTrailEnabledRule",
    "EBSEncryptionRule",
    "IAMUserMFARule",
    "LambdaVPCRule",
    "RDSEncryptionRule",
    "S3BucketEncryptionRule",
    "S3BucketPublicAccessRule",
    "SecurityGroupOpenIngressRule",
    "SNSTopicEncryptionRule",
    "SQSQueueEncryptionRule",
    "VPCFlowLogsRule",
]
