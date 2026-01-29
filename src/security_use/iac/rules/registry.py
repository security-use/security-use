"""Rule registry for managing security rules."""

from typing import Optional, Type

from security_use.iac.rules.base import Rule


class RuleRegistry:
    """Registry for IaC security rules."""

    def __init__(self) -> None:
        """Initialize the rule registry."""
        self._rules: dict[str, Rule] = {}

    def register(self, rule: Rule) -> None:
        """Register a rule.

        Args:
            rule: Rule instance to register.
        """
        self._rules[rule.RULE_ID] = rule

    def register_class(self, rule_class: Type[Rule]) -> None:
        """Register a rule class (instantiates it).

        Args:
            rule_class: Rule class to register.
        """
        rule = rule_class()
        self.register(rule)

    def get(self, rule_id: str) -> Optional[Rule]:
        """Get a rule by ID.

        Args:
            rule_id: The rule ID.

        Returns:
            Rule instance or None if not found.
        """
        return self._rules.get(rule_id)

    def get_all(self) -> list[Rule]:
        """Get all registered rules.

        Returns:
            List of all registered rules.
        """
        return list(self._rules.values())

    def get_for_resource(self, resource_type: str) -> list[Rule]:
        """Get rules that apply to a resource type.

        Args:
            resource_type: The resource type to match.

        Returns:
            List of applicable rules.
        """
        from security_use.iac.base import IaCResource

        # Create a dummy resource to check applicability
        dummy = IaCResource(
            resource_type=resource_type,
            name="",
            config={},
            file_path="",
            line_number=0,
        )

        return [rule for rule in self._rules.values() if rule.applies_to(dummy)]

    def clear(self) -> None:
        """Clear all registered rules."""
        self._rules.clear()


# Global registry instance
_registry: Optional[RuleRegistry] = None


def get_registry() -> RuleRegistry:
    """Get the global rule registry.

    Returns:
        The global RuleRegistry instance.
    """
    global _registry
    if _registry is None:
        _registry = RuleRegistry()
        _register_default_rules(_registry)
    return _registry


def _register_default_rules(registry: RuleRegistry) -> None:
    """Register all default rules."""
    # AWS Rules
    from security_use.iac.rules.aws import (
        S3BucketEncryptionRule,
        S3BucketPublicAccessRule,
        SecurityGroupOpenIngressRule,
        IAMUserMFARule,
        RDSEncryptionRule,
        EBSEncryptionRule,
        CloudTrailEnabledRule,
        VPCFlowLogsRule,
    )

    registry.register_class(S3BucketEncryptionRule)
    registry.register_class(S3BucketPublicAccessRule)
    registry.register_class(SecurityGroupOpenIngressRule)
    registry.register_class(IAMUserMFARule)
    registry.register_class(RDSEncryptionRule)
    registry.register_class(EBSEncryptionRule)
    registry.register_class(CloudTrailEnabledRule)
    registry.register_class(VPCFlowLogsRule)

    # Azure Rules
    from security_use.iac.rules.azure import (
        AzureStoragePublicAccessRule,
        AzureStorageEncryptionRule,
        AzureNSGOpenIngressRule,
        AzureSQLEncryptionRule,
        AzureKeyVaultSoftDeleteRule,
        AzureActivityLogRetentionRule,
    )

    registry.register_class(AzureStoragePublicAccessRule)
    registry.register_class(AzureStorageEncryptionRule)
    registry.register_class(AzureNSGOpenIngressRule)
    registry.register_class(AzureSQLEncryptionRule)
    registry.register_class(AzureKeyVaultSoftDeleteRule)
    registry.register_class(AzureActivityLogRetentionRule)

    # GCP Rules
    from security_use.iac.rules.gcp import (
        GCSBucketPublicAccessRule,
        GCSBucketEncryptionRule,
        GCPFirewallOpenIngressRule,
        GCPCloudSQLEncryptionRule,
        GCPKMSKeyRotationRule,
        GCPServiceAccountKeyRule,
        GCPAuditLoggingRule,
    )

    registry.register_class(GCSBucketPublicAccessRule)
    registry.register_class(GCSBucketEncryptionRule)
    registry.register_class(GCPFirewallOpenIngressRule)
    registry.register_class(GCPCloudSQLEncryptionRule)
    registry.register_class(GCPKMSKeyRotationRule)
    registry.register_class(GCPServiceAccountKeyRule)
    registry.register_class(GCPAuditLoggingRule)

    # Kubernetes Rules
    from security_use.iac.rules.kubernetes import (
        K8sRunAsRootRule,
        K8sPrivilegedContainerRule,
        K8sResourceLimitsRule,
        K8sHostNetworkRule,
        K8sSecretsEnvVarsRule,
        K8sReadOnlyRootFilesystemRule,
        K8sNetworkPolicyRule,
    )

    registry.register_class(K8sRunAsRootRule)
    registry.register_class(K8sPrivilegedContainerRule)
    registry.register_class(K8sResourceLimitsRule)
    registry.register_class(K8sHostNetworkRule)
    registry.register_class(K8sSecretsEnvVarsRule)
    registry.register_class(K8sReadOnlyRootFilesystemRule)
    registry.register_class(K8sNetworkPolicyRule)
