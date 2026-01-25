"""IaC security rules."""

from securescan.iac.rules.base import Rule, RuleResult
from securescan.iac.rules.registry import RuleRegistry, get_registry
from securescan.iac.rules.aws import (
    S3BucketEncryptionRule,
    S3BucketPublicAccessRule,
    SecurityGroupOpenIngressRule,
    IAMUserMFARule,
    RDSEncryptionRule,
    EBSEncryptionRule,
    CloudTrailEnabledRule,
    VPCFlowLogsRule,
)

__all__ = [
    "Rule",
    "RuleResult",
    "RuleRegistry",
    "get_registry",
    "S3BucketEncryptionRule",
    "S3BucketPublicAccessRule",
    "SecurityGroupOpenIngressRule",
    "IAMUserMFARule",
    "RDSEncryptionRule",
    "EBSEncryptionRule",
    "CloudTrailEnabledRule",
    "VPCFlowLogsRule",
]
