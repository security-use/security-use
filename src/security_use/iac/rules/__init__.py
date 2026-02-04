"""IaC security rules."""

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
from security_use.iac.rules.azure import (
    AzureActivityLogRetentionRule,
    AzureAppServiceHTTPSRule,
    AzureFunctionAppHTTPSRule,
    AzureKeyVaultSoftDeleteRule,
    AzureNSGOpenIngressRule,
    AzureSQLEncryptionRule,
    AzureStorageEncryptionRule,
    AzureStorageHTTPSRule,
    AzureStoragePublicAccessRule,
)
from security_use.iac.rules.base import Rule, RuleResult
from security_use.iac.rules.registry import RuleRegistry, get_registry

__all__ = [
    "Rule",
    "RuleResult",
    "RuleRegistry",
    "get_registry",
    # AWS Rules
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
    # Azure Rules
    "AzureActivityLogRetentionRule",
    "AzureAppServiceHTTPSRule",
    "AzureFunctionAppHTTPSRule",
    "AzureKeyVaultSoftDeleteRule",
    "AzureNSGOpenIngressRule",
    "AzureSQLEncryptionRule",
    "AzureStorageEncryptionRule",
    "AzureStorageHTTPSRule",
    "AzureStoragePublicAccessRule",
]
