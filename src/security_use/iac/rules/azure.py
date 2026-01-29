"""Azure security rules for IaC scanning."""

from security_use.models import Severity
from security_use.iac.base import IaCResource
from security_use.iac.rules.base import Rule, RuleResult


class AzureStoragePublicAccessRule(Rule):
    """Check that Azure Storage accounts do not allow public access."""

    RULE_ID = "CKV_AZURE_19"
    TITLE = "Storage account with public access"
    SEVERITY = Severity.CRITICAL
    DESCRIPTION = (
        "Azure Storage account allows public access. This can expose "
        "sensitive data to unauthorized users."
    )
    REMEDIATION = (
        "Set allow_blob_public_access to false and configure private endpoints."
    )
    RESOURCE_TYPES = ["azurerm_storage_account", "Microsoft.Storage/storageAccounts"]

    def evaluate(self, resource: IaCResource) -> RuleResult:
        """Check if Storage account allows public access."""
        # Terraform
        allow_public = resource.get_config("allow_blob_public_access", default=True)

        # ARM template
        if allow_public:
            properties = resource.get_config("properties", default={})
            allow_public = properties.get("allowBlobPublicAccess", True)

        fix_code = None
        if allow_public:
            fix_code = "allow_blob_public_access = false"

        return self._create_result(not allow_public, resource, fix_code)


class AzureStorageEncryptionRule(Rule):
    """Check that Azure Storage accounts have encryption enabled."""

    RULE_ID = "CKV_AZURE_3"
    TITLE = "Storage account without encryption"
    SEVERITY = Severity.HIGH
    DESCRIPTION = (
        "Azure Storage account does not have encryption at rest enabled. "
        "Data should be encrypted to protect sensitive information."
    )
    REMEDIATION = (
        "Enable blob encryption services and configure customer-managed keys."
    )
    RESOURCE_TYPES = ["azurerm_storage_account", "Microsoft.Storage/storageAccounts"]

    def evaluate(self, resource: IaCResource) -> RuleResult:
        """Check if Storage account has encryption enabled."""
        has_encryption = False

        # Terraform
        blob_properties = resource.get_config("blob_properties", default={})
        if blob_properties:
            has_encryption = True

        # ARM template - encryption is enabled by default since 2017
        properties = resource.get_config("properties", default={})
        encryption = properties.get("encryption", {})
        if encryption.get("services", {}).get("blob", {}).get("enabled"):
            has_encryption = True

        # Check for minimum TLS version
        min_tls = resource.get_config("min_tls_version", default="")
        if min_tls == "TLS1_2":
            has_encryption = True

        return self._create_result(has_encryption, resource)


class AzureNSGOpenIngressRule(Rule):
    """Check that Azure NSG doesn't allow unrestricted ingress."""

    RULE_ID = "CKV_AZURE_9"
    TITLE = "NSG allows unrestricted inbound traffic"
    SEVERITY = Severity.HIGH
    DESCRIPTION = (
        "Network Security Group allows inbound traffic from 0.0.0.0/0 or * "
        "on sensitive ports. This exposes services to the entire internet."
    )
    REMEDIATION = (
        "Restrict source addresses to specific IP ranges or Azure service tags. "
        "Avoid using * or 0.0.0.0/0 as the source."
    )
    RESOURCE_TYPES = [
        "azurerm_network_security_rule",
        "azurerm_network_security_group",
        "Microsoft.Network/networkSecurityGroups",
    ]

    SENSITIVE_PORTS = ["22", "3389", "3306", "5432", "1433", "27017", "6379"]

    def evaluate(self, resource: IaCResource) -> RuleResult:
        """Check if NSG has open ingress on sensitive ports."""
        has_open_ingress = False

        # Terraform: Check security_rule blocks
        rules = resource.get_config("security_rule", default=[])
        if isinstance(rules, list):
            for rule in rules:
                if self._is_open_rule(rule):
                    has_open_ingress = True
                    break

        # Standalone security rule
        if resource.resource_type == "azurerm_network_security_rule":
            if self._is_open_rule(resource.config):
                has_open_ingress = True

        fix_code = None
        if has_open_ingress:
            fix_code = "# Restrict source_address_prefix to specific IP ranges"

        return self._create_result(not has_open_ingress, resource, fix_code)

    def _is_open_rule(self, rule: dict) -> bool:
        """Check if a rule allows open inbound access."""
        direction = rule.get("direction", "").lower()
        access = rule.get("access", "").lower()
        source = rule.get("source_address_prefix", "")

        if direction != "inbound" or access != "allow":
            return False

        if source not in ["*", "0.0.0.0/0", "Internet"]:
            return False

        # Check ports
        dest_port = rule.get("destination_port_range", "")
        dest_ports = rule.get("destination_port_ranges", [])

        if dest_port == "*" or "*" in dest_ports:
            return True

        for port in self.SENSITIVE_PORTS:
            if dest_port == port or port in dest_ports:
                return True

        return False


class AzureSQLEncryptionRule(Rule):
    """Check that Azure SQL databases have encryption enabled."""

    RULE_ID = "CKV_AZURE_24"
    TITLE = "SQL database without transparent data encryption"
    SEVERITY = Severity.HIGH
    DESCRIPTION = (
        "Azure SQL database does not have transparent data encryption (TDE) enabled. "
        "TDE protects data at rest by encrypting the database files."
    )
    REMEDIATION = (
        "Enable transparent data encryption for the SQL database. "
        "TDE is enabled by default for Azure SQL Database."
    )
    RESOURCE_TYPES = [
        "azurerm_mssql_database",
        "azurerm_sql_database",
        "Microsoft.Sql/servers/databases",
    ]

    def evaluate(self, resource: IaCResource) -> RuleResult:
        """Check if SQL database has TDE enabled."""
        # Terraform - check if TDE is explicitly disabled
        transparent_encryption = resource.get_config(
            "transparent_data_encryption_enabled", default=True
        )

        fix_code = None
        if not transparent_encryption:
            fix_code = "transparent_data_encryption_enabled = true"

        return self._create_result(bool(transparent_encryption), resource, fix_code)


class AzureKeyVaultSoftDeleteRule(Rule):
    """Check that Azure Key Vault has soft delete enabled."""

    RULE_ID = "CKV_AZURE_42"
    TITLE = "Key Vault without soft delete"
    SEVERITY = Severity.MEDIUM
    DESCRIPTION = (
        "Azure Key Vault does not have soft delete enabled. "
        "Soft delete protects against accidental deletion of secrets and keys."
    )
    REMEDIATION = (
        "Enable soft delete and purge protection for the Key Vault."
    )
    RESOURCE_TYPES = ["azurerm_key_vault", "Microsoft.KeyVault/vaults"]

    def evaluate(self, resource: IaCResource) -> RuleResult:
        """Check if Key Vault has soft delete enabled."""
        # Soft delete is enabled by default since Feb 2025
        soft_delete = resource.get_config("soft_delete_retention_days", default=90)
        purge_protection = resource.get_config("purge_protection_enabled", default=False)

        passed = soft_delete > 0 and purge_protection

        fix_code = None
        if not passed:
            fix_code = "soft_delete_retention_days = 90\npurge_protection_enabled = true"

        return self._create_result(passed, resource, fix_code)


class AzureActivityLogRetentionRule(Rule):
    """Check that Azure activity logs have sufficient retention."""

    RULE_ID = "CKV_AZURE_37"
    TITLE = "Activity log with insufficient retention"
    SEVERITY = Severity.MEDIUM
    DESCRIPTION = (
        "Azure activity logs do not have sufficient retention period. "
        "Logs should be retained for at least 365 days for compliance."
    )
    REMEDIATION = (
        "Configure activity log retention to at least 365 days or export to storage."
    )
    RESOURCE_TYPES = [
        "azurerm_monitor_log_profile",
        "Microsoft.Insights/logprofiles",
    ]

    def evaluate(self, resource: IaCResource) -> RuleResult:
        """Check if activity logs have sufficient retention."""
        retention = resource.get_config("retention_policy", default={})
        enabled = retention.get("enabled", False)
        days = retention.get("days", 0)

        passed = enabled and days >= 365

        fix_code = None
        if not passed:
            fix_code = '''retention_policy {
  enabled = true
  days    = 365
}'''

        return self._create_result(passed, resource, fix_code)
