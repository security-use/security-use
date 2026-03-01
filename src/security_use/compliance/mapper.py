"""Compliance framework mapper for security rules."""

from typing import Optional

from security_use.compliance.models import (
    ComplianceControl,
    ComplianceFinding,
    ComplianceFramework,
    ComplianceMapping,
)
from security_use.models import IaCFinding


class ComplianceMapper:
    """Maps security findings to compliance framework controls."""

    # Mapping of rule IDs to compliance controls
    MAPPINGS: dict[str, list[tuple[ComplianceFramework, str, str, str]]] = {
        # AWS S3 Encryption
        "CKV_AWS_19": [
            (ComplianceFramework.SOC2, "CC6.1", "Encryption of Data at Rest",
             "Logical and physical access controls"),
            (ComplianceFramework.HIPAA, "164.312(a)(2)(iv)", "Encryption",
             "Technical safeguards for data encryption"),
            (ComplianceFramework.PCI_DSS, "3.4", "Render PAN unreadable",
             "Protect stored cardholder data"),
            (ComplianceFramework.NIST_800_53, "SC-28", "Protection of Information at Rest",
             "Protect data at rest with encryption"),
            (ComplianceFramework.CIS_AWS, "2.1.1", "Ensure S3 Bucket Encryption",
             "S3 buckets should have encryption enabled"),
            (ComplianceFramework.ISO_27001, "A.10.1.1", "Cryptographic Controls",
             "Policy on use of cryptographic controls"),
        ],
        # AWS S3 Public Access
        "CKV_AWS_20": [
            (ComplianceFramework.SOC2, "CC6.6", "Logical Access Controls",
             "Restrict access to authorized users"),
            (ComplianceFramework.HIPAA, "164.312(e)(1)", "Transmission Security",
             "Technical safeguards for access control"),
            (ComplianceFramework.PCI_DSS, "7.1", "Limit access to system components",
             "Restrict access to need-to-know basis"),
            (ComplianceFramework.NIST_800_53, "AC-3", "Access Enforcement",
             "Enforce approved authorizations"),
            (ComplianceFramework.CIS_AWS, "2.1.5", "Ensure S3 Block Public Access",
             "Block public access to S3 buckets"),
        ],
        # AWS Security Group
        "CKV_AWS_23": [
            (ComplianceFramework.SOC2, "CC6.6", "Logical Access Controls",
             "Network access restrictions"),
            (ComplianceFramework.PCI_DSS, "1.3", "Prohibit direct public access",
             "Restrict inbound and outbound traffic"),
            (ComplianceFramework.NIST_800_53, "SC-7", "Boundary Protection",
             "Monitor and control communications at boundaries"),
            (ComplianceFramework.CIS_AWS, "5.2", "Ensure VPC Security Groups",
             "Restrict unrestricted ingress"),
        ],
        # AWS RDS Encryption
        "CKV_AWS_16": [
            (ComplianceFramework.SOC2, "CC6.1", "Encryption of Data at Rest",
             "Database encryption"),
            (ComplianceFramework.HIPAA, "164.312(a)(2)(iv)", "Encryption",
             "Encrypt PHI at rest"),
            (ComplianceFramework.PCI_DSS, "3.4", "Render PAN unreadable",
             "Encrypt stored cardholder data"),
            (ComplianceFramework.NIST_800_53, "SC-28", "Protection of Information at Rest",
             "Database encryption at rest"),
            (ComplianceFramework.CIS_AWS, "2.3.1", "Ensure RDS Encryption",
             "RDS instances should be encrypted"),
        ],
        # AWS EBS Encryption
        "CKV_AWS_3": [
            (ComplianceFramework.SOC2, "CC6.1", "Encryption of Data at Rest",
             "Volume encryption"),
            (ComplianceFramework.HIPAA, "164.312(a)(2)(iv)", "Encryption",
             "Encrypt PHI on storage volumes"),
            (ComplianceFramework.PCI_DSS, "3.4", "Render PAN unreadable",
             "Encrypt stored data on volumes"),
            (ComplianceFramework.CIS_AWS, "2.2.1", "Ensure EBS Encryption",
             "EBS volumes should be encrypted"),
        ],
        # AWS IAM MFA
        "CKV_AWS_14": [
            (ComplianceFramework.SOC2, "CC6.1", "Authentication Controls",
             "Multi-factor authentication"),
            (ComplianceFramework.HIPAA, "164.312(d)", "Person or Entity Authentication",
             "Verify user identity"),
            (ComplianceFramework.PCI_DSS, "8.3", "Secure all administrative access",
             "Use MFA for all access"),
            (ComplianceFramework.NIST_800_53, "IA-2", "Identification and Authentication",
             "Multi-factor authentication"),
            (ComplianceFramework.CIS_AWS, "1.10", "Ensure MFA is enabled",
             "Enable MFA for IAM users"),
        ],
        # AWS CloudTrail
        "CKV_AWS_35": [
            (ComplianceFramework.SOC2, "CC7.2", "System Monitoring",
             "Audit logging and monitoring"),
            (ComplianceFramework.HIPAA, "164.312(b)", "Audit Controls",
             "Record and examine activity"),
            (ComplianceFramework.PCI_DSS, "10.1", "Implement audit trails",
             "Link all access to individual users"),
            (ComplianceFramework.NIST_800_53, "AU-2", "Audit Events",
             "Generate audit records"),
            (ComplianceFramework.CIS_AWS, "3.1", "Ensure CloudTrail is enabled",
             "Enable CloudTrail in all regions"),
        ],
        # AWS VPC Flow Logs
        "CKV_AWS_12": [
            (ComplianceFramework.SOC2, "CC7.2", "System Monitoring",
             "Network traffic monitoring"),
            (ComplianceFramework.PCI_DSS, "10.6", "Review logs",
             "Monitor network traffic"),
            (ComplianceFramework.NIST_800_53, "AU-12", "Audit Generation",
             "Generate audit records for network traffic"),
            (ComplianceFramework.CIS_AWS, "3.9", "Ensure VPC Flow Logs",
             "Enable VPC Flow Logs"),
        ],
        # Azure Storage Public Access
        "CKV_AZURE_19": [
            (ComplianceFramework.SOC2, "CC6.6", "Logical Access Controls",
             "Storage access controls"),
            (ComplianceFramework.CIS_AZURE, "3.7", "Ensure Storage Account Access",
             "Disable public blob access"),
        ],
        # Azure NSG
        "CKV_AZURE_9": [
            (ComplianceFramework.SOC2, "CC6.6", "Network Access Controls",
             "NSG configuration"),
            (ComplianceFramework.CIS_AZURE, "6.1", "Ensure NSG Rules",
             "Restrict unrestricted access"),
        ],
        # GCP Storage Public Access
        "CKV_GCP_5": [
            (ComplianceFramework.SOC2, "CC6.6", "Logical Access Controls",
             "Cloud Storage access controls"),
            (ComplianceFramework.CIS_GCP, "5.1", "Ensure Cloud Storage Bucket Access",
             "Remove public access"),
        ],
        # GCP Firewall
        "CKV_GCP_2": [
            (ComplianceFramework.SOC2, "CC6.6", "Network Access Controls",
             "Firewall configuration"),
            (ComplianceFramework.CIS_GCP, "3.6", "Ensure Firewall Rules",
             "Restrict unrestricted access"),
        ],
        # Kubernetes Privileged Container
        "CKV_K8S_1": [
            (ComplianceFramework.SOC2, "CC6.1", "Access Controls",
             "Container privilege restrictions"),
            (ComplianceFramework.CIS_K8S, "5.2.1", "Minimize privileged containers",
             "Do not run privileged containers"),
        ],
        # Kubernetes Run as Root
        "CKV_K8S_6": [
            (ComplianceFramework.SOC2, "CC6.1", "Access Controls",
             "Container user restrictions"),
            (ComplianceFramework.CIS_K8S, "5.2.6", "Minimize root containers",
             "Do not run containers as root"),
        ],
        # Kubernetes Resource Limits
        "CKV_K8S_11": [
            (ComplianceFramework.SOC2, "CC6.8", "System Operations",
             "Resource management"),
            (ComplianceFramework.CIS_K8S, "5.4.1", "Ensure resource limits",
             "Set CPU and memory limits"),
        ],
    }

    def get_mapping(self, rule_id: str) -> ComplianceMapping:
        """Get compliance mapping for a rule.

        Args:
            rule_id: The security rule ID.

        Returns:
            ComplianceMapping with associated controls.
        """
        mapping = ComplianceMapping(rule_id=rule_id)

        raw_mappings = self.MAPPINGS.get(rule_id, [])
        for framework, control_id, title, description in raw_mappings:
            control = ComplianceControl(
                framework=framework,
                control_id=control_id,
                title=title,
                description=description,
            )
            mapping.controls.append(control)

        return mapping

    def enrich_finding(self, finding: IaCFinding) -> ComplianceFinding:
        """Enrich an IaC finding with compliance information.

        Args:
            finding: The original IaC finding.

        Returns:
            ComplianceFinding with compliance controls.
        """
        mapping = self.get_mapping(finding.rule_id)

        return ComplianceFinding(
            rule_id=finding.rule_id,
            title=finding.title,
            severity=finding.severity.value,
            file_path=finding.file_path,
            line_number=finding.line_number,
            controls=mapping.controls,
        )

    def get_findings_by_framework(
        self,
        findings: list[IaCFinding],
        framework: ComplianceFramework,
    ) -> list[ComplianceFinding]:
        """Filter findings by compliance framework.

        Args:
            findings: List of IaC findings.
            framework: The compliance framework to filter by.

        Returns:
            List of ComplianceFindings relevant to the framework.
        """
        result = []

        for finding in findings:
            enriched = self.enrich_finding(finding)
            # Filter controls to only the requested framework
            framework_controls = [
                c for c in enriched.controls
                if c.framework == framework
            ]

            if framework_controls:
                enriched.controls = framework_controls
                result.append(enriched)

        return result

    def get_supported_frameworks(self) -> list[ComplianceFramework]:
        """Get list of supported compliance frameworks.

        Returns:
            List of supported ComplianceFramework values.
        """
        return list(ComplianceFramework)

    def get_framework_summary(
        self,
        findings: list[IaCFinding],
        framework: ComplianceFramework,
    ) -> dict[str, list[ComplianceFinding]]:
        """Group findings by control within a framework.

        Args:
            findings: List of IaC findings.
            framework: The compliance framework.

        Returns:
            Dict mapping control_id to list of findings.
        """
        by_control: dict[str, list[ComplianceFinding]] = {}

        framework_findings = self.get_findings_by_framework(findings, framework)

        for finding in framework_findings:
            for control in finding.controls:
                if control.control_id not in by_control:
                    by_control[control.control_id] = []
                by_control[control.control_id].append(finding)

        return by_control
