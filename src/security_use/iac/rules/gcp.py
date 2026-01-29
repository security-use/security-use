"""GCP security rules for IaC scanning."""

from security_use.models import Severity
from security_use.iac.base import IaCResource
from security_use.iac.rules.base import Rule, RuleResult


class GCSBucketPublicAccessRule(Rule):
    """Check that GCS buckets do not allow public access."""

    RULE_ID = "CKV_GCP_5"
    TITLE = "Cloud Storage bucket with public access"
    SEVERITY = Severity.CRITICAL
    DESCRIPTION = (
        "Cloud Storage bucket is publicly accessible. This can expose "
        "sensitive data to unauthorized users."
    )
    REMEDIATION = (
        "Remove allUsers and allAuthenticatedUsers from bucket IAM bindings. "
        "Use uniform bucket-level access."
    )
    RESOURCE_TYPES = [
        "google_storage_bucket",
        "google_storage_bucket_iam_binding",
        "google_storage_bucket_iam_member",
    ]

    def evaluate(self, resource: IaCResource) -> RuleResult:
        """Check if GCS bucket allows public access."""
        has_public_access = False

        # Check IAM bindings
        members = resource.get_config("members", default=[])
        member = resource.get_config("member", default="")

        public_principals = ["allUsers", "allAuthenticatedUsers"]

        if any(m in members for m in public_principals):
            has_public_access = True

        if member in public_principals:
            has_public_access = True

        fix_code = None
        if has_public_access:
            fix_code = "# Remove allUsers and allAuthenticatedUsers from members"

        return self._create_result(not has_public_access, resource, fix_code)


class GCSBucketEncryptionRule(Rule):
    """Check that GCS buckets have encryption configured."""

    RULE_ID = "CKV_GCP_6"
    TITLE = "Cloud Storage bucket without customer-managed encryption"
    SEVERITY = Severity.HIGH
    DESCRIPTION = (
        "Cloud Storage bucket does not use customer-managed encryption keys (CMEK). "
        "While GCS encrypts data by default, CMEK provides additional control."
    )
    REMEDIATION = (
        "Configure a Cloud KMS key for bucket encryption."
    )
    RESOURCE_TYPES = ["google_storage_bucket"]

    def evaluate(self, resource: IaCResource) -> RuleResult:
        """Check if GCS bucket uses CMEK."""
        encryption = resource.get_config("encryption", default={})
        default_kms_key = encryption.get("default_kms_key_name")

        has_cmek = bool(default_kms_key)

        fix_code = None
        if not has_cmek:
            fix_code = '''encryption {
  default_kms_key_name = "projects/PROJECT/locations/LOCATION/keyRings/KEYRING/cryptoKeys/KEY"
}'''

        return self._create_result(has_cmek, resource, fix_code)


class GCPFirewallOpenIngressRule(Rule):
    """Check that GCP firewall rules don't allow unrestricted ingress."""

    RULE_ID = "CKV_GCP_2"
    TITLE = "Firewall rule allows unrestricted ingress"
    SEVERITY = Severity.HIGH
    DESCRIPTION = (
        "Firewall rule allows ingress from 0.0.0.0/0 on sensitive ports. "
        "This exposes services to the entire internet."
    )
    REMEDIATION = (
        "Restrict source_ranges to specific IP ranges. "
        "Avoid using 0.0.0.0/0 as the source."
    )
    RESOURCE_TYPES = ["google_compute_firewall"]

    SENSITIVE_PORTS = ["22", "3389", "3306", "5432", "1433", "27017", "6379"]

    def evaluate(self, resource: IaCResource) -> RuleResult:
        """Check if firewall rule has open ingress on sensitive ports."""
        has_open_ingress = False

        direction = resource.get_config("direction", default="INGRESS")
        if direction.upper() != "INGRESS":
            return self._create_result(True, resource)

        source_ranges = resource.get_config("source_ranges", default=[])

        if "0.0.0.0/0" not in source_ranges:
            return self._create_result(True, resource)

        # Check if sensitive ports are exposed
        allow_rules = resource.get_config("allow", default=[])
        if isinstance(allow_rules, list):
            for rule in allow_rules:
                ports = rule.get("ports", [])
                if not ports:
                    # No port restriction means all ports
                    has_open_ingress = True
                    break
                for port in ports:
                    if port in self.SENSITIVE_PORTS or "-" in str(port):
                        has_open_ingress = True
                        break

        fix_code = None
        if has_open_ingress:
            fix_code = '# Restrict source_ranges to specific IP ranges instead of ["0.0.0.0/0"]'

        return self._create_result(not has_open_ingress, resource, fix_code)


class GCPCloudSQLEncryptionRule(Rule):
    """Check that Cloud SQL instances have encryption enabled."""

    RULE_ID = "CKV_GCP_14"
    TITLE = "Cloud SQL instance without customer-managed encryption"
    SEVERITY = Severity.HIGH
    DESCRIPTION = (
        "Cloud SQL instance does not use customer-managed encryption keys (CMEK). "
        "While Cloud SQL encrypts data by default, CMEK provides additional control."
    )
    REMEDIATION = (
        "Configure a Cloud KMS key for Cloud SQL encryption."
    )
    RESOURCE_TYPES = ["google_sql_database_instance"]

    def evaluate(self, resource: IaCResource) -> RuleResult:
        """Check if Cloud SQL uses CMEK."""
        settings = resource.get_config("settings", default={})
        ip_config = settings.get("ip_configuration", {})

        # Check for encryption key
        encryption_key = resource.get_config("encryption_key_name")

        has_cmek = bool(encryption_key)

        fix_code = None
        if not has_cmek:
            fix_code = 'encryption_key_name = "projects/PROJECT/locations/LOCATION/keyRings/KEYRING/cryptoKeys/KEY"'

        return self._create_result(has_cmek, resource, fix_code)


class GCPKMSKeyRotationRule(Rule):
    """Check that Cloud KMS keys have rotation configured."""

    RULE_ID = "CKV_GCP_43"
    TITLE = "KMS key without rotation"
    SEVERITY = Severity.MEDIUM
    DESCRIPTION = (
        "Cloud KMS key does not have automatic rotation configured. "
        "Regular key rotation limits the impact of key compromise."
    )
    REMEDIATION = (
        "Configure automatic key rotation with a rotation period of 90 days or less."
    )
    RESOURCE_TYPES = ["google_kms_crypto_key"]

    def evaluate(self, resource: IaCResource) -> RuleResult:
        """Check if KMS key has rotation configured."""
        rotation_period = resource.get_config("rotation_period")

        has_rotation = bool(rotation_period)

        fix_code = None
        if not has_rotation:
            fix_code = 'rotation_period = "7776000s"  # 90 days'

        return self._create_result(has_rotation, resource, fix_code)


class GCPServiceAccountKeyRule(Rule):
    """Check that service account keys are managed properly."""

    RULE_ID = "CKV_GCP_41"
    TITLE = "Service account with user-managed keys"
    SEVERITY = Severity.MEDIUM
    DESCRIPTION = (
        "Service account has user-managed keys. User-managed keys are a security "
        "risk as they can be leaked or stolen. Prefer using attached service accounts."
    )
    REMEDIATION = (
        "Use attached service accounts or workload identity instead of user-managed keys."
    )
    RESOURCE_TYPES = ["google_service_account_key"]

    def evaluate(self, resource: IaCResource) -> RuleResult:
        """Flag user-managed service account keys."""
        # Any google_service_account_key resource is a user-managed key
        fix_code = "# Remove user-managed keys and use workload identity or attached service accounts"

        return self._create_result(False, resource, fix_code)


class GCPAuditLoggingRule(Rule):
    """Check that audit logging is enabled for GCP projects."""

    RULE_ID = "CKV_GCP_32"
    TITLE = "Audit logging not enabled"
    SEVERITY = Severity.MEDIUM
    DESCRIPTION = (
        "Audit logging is not enabled for all services. "
        "Audit logs are essential for security monitoring and compliance."
    )
    REMEDIATION = (
        "Enable audit logging for all services using google_project_iam_audit_config."
    )
    RESOURCE_TYPES = ["google_project_iam_audit_config"]

    def evaluate(self, resource: IaCResource) -> RuleResult:
        """Check if comprehensive audit logging is configured."""
        service = resource.get_config("service", default="")
        audit_log_configs = resource.get_config("audit_log_config", default=[])

        # Check if auditing all services
        if service == "allServices":
            if isinstance(audit_log_configs, list) and len(audit_log_configs) > 0:
                return self._create_result(True, resource)

        fix_code = '''resource "google_project_iam_audit_config" "all" {
  service = "allServices"
  audit_log_config {
    log_type = "ADMIN_READ"
  }
  audit_log_config {
    log_type = "DATA_READ"
  }
  audit_log_config {
    log_type = "DATA_WRITE"
  }
}'''

        return self._create_result(False, resource, fix_code)
