# Infrastructure as Code Rules Reference

SecurityUse includes 38+ rules for scanning Terraform and CloudFormation templates.

## AWS Rules (12)

| Rule ID | Description | Severity |
|---------|-------------|----------|
| CKV_AWS_3 | Ensure EBS volumes are encrypted | HIGH |
| CKV_AWS_12 | Ensure EC2 instance has detailed monitoring | LOW |
| CKV_AWS_14 | Ensure RDS instances are Multi-AZ | MEDIUM |
| CKV_AWS_16 | Ensure RDS database instances are encrypted | HIGH |
| CKV_AWS_19 | Ensure S3 bucket encryption is enabled | HIGH |
| CKV_AWS_20 | Ensure S3 bucket does not have public ACL | CRITICAL |
| CKV_AWS_23 | Ensure Security Groups don't allow unrestricted ingress | HIGH |
| CKV_AWS_26 | Ensure SNS topic encryption is enabled | MEDIUM |
| CKV_AWS_27 | Ensure SQS queue encryption is enabled | MEDIUM |
| CKV_AWS_35 | Ensure CloudTrail logs all events | MEDIUM |
| CKV_AWS_91 | Ensure ALB/ELB access logging is enabled | MEDIUM |
| CKV_AWS_117 | Ensure Lambda functions are in VPC | MEDIUM |

## Azure Rules (9)

| Rule ID | Description | Severity |
|---------|-------------|----------|
| CKV_AZURE_3 | Ensure Storage Account uses HTTPS | HIGH |
| CKV_AZURE_9 | Ensure Azure Key Vault enables soft delete | MEDIUM |
| CKV_AZURE_14 | Ensure App Service uses HTTPS | HIGH |
| CKV_AZURE_19 | Ensure Azure SQL Server audit log retention > 90 days | MEDIUM |
| CKV_AZURE_70 | Ensure Function App uses HTTPS | HIGH |
| CKV_AZURE_35 | Ensure Storage Account has secure transfer required | HIGH |
| CKV_AZURE_36 | Ensure Storage Account uses customer-managed key | MEDIUM |
| CKV_AZURE_40 | Ensure Key Vault purge protection is enabled | MEDIUM |
| CKV_AZURE_109 | Ensure App Service has client certificates enabled | LOW |

## GCP Rules (10)

| Rule ID | Description | Severity |
|---------|-------------|----------|
| CKV_GCP_2 | Ensure GCS bucket has versioning enabled | MEDIUM |
| CKV_GCP_5 | Ensure GCS bucket is not publicly accessible | CRITICAL |
| CKV_GCP_6 | Ensure Cloud SQL uses SSL | HIGH |
| CKV_GCP_11 | Ensure Cloud SQL has backups enabled | MEDIUM |
| CKV_GCP_14 | Ensure GKE cluster has shielded nodes | MEDIUM |
| CKV_GCP_18 | Ensure GKE cluster is private | HIGH |
| CKV_GCP_32 | Ensure Compute instance SSH keys are instance-specific | MEDIUM |
| CKV_GCP_37 | Ensure Cloud SQL has query insights enabled | LOW |
| CKV_GCP_39 | Ensure GCS bucket has uniform access level | MEDIUM |
| CKV_GCP_62 | Ensure Cloud SQL has audit logging | MEDIUM |

## Kubernetes Rules (9)

| Rule ID | Description | Severity |
|---------|-------------|----------|
| CKV_K8S_1 | Ensure containers don't run as root | HIGH |
| CKV_K8S_6 | Ensure API server is not publicly accessible | CRITICAL |
| CKV_K8S_8 | Ensure liveness probe is configured | LOW |
| CKV_K8S_9 | Ensure readiness probe is configured | LOW |
| CKV_K8S_11 | Ensure CPU limits are set | MEDIUM |
| CKV_K8S_12 | Ensure memory limits are set | MEDIUM |
| CKV_K8S_14 | Ensure image tag is not 'latest' | MEDIUM |
| CKV_K8S_20 | Ensure containers don't allow privilege escalation | HIGH |
| CKV_K8S_26 | Ensure hostPath volumes are not used | HIGH |

## Compliance Mappings

Rules are mapped to major compliance frameworks:

| Framework | Coverage |
|-----------|----------|
| CIS AWS Benchmark | 25+ controls |
| CIS Azure Benchmark | 15+ controls |
| CIS GCP Benchmark | 12+ controls |
| CIS Kubernetes Benchmark | 9+ controls |
| NIST 800-53 | 30+ controls |
| PCI DSS | 20+ controls |
| SOC 2 | 25+ controls |
| HIPAA | 15+ controls |

## Adding Custom Rules

See [CONTRIBUTING.md](../CONTRIBUTING.md) for instructions on adding new rules.

## Ignoring Rules

### In Configuration

```yaml
iac:
  rules:
    exclude:
      - CKV_AWS_12  # Don't require detailed monitoring
```

### Inline

```hcl
# security-use: ignore=CKV_AWS_19
resource "aws_s3_bucket" "public_assets" {
  bucket = "my-public-bucket"
}
```
