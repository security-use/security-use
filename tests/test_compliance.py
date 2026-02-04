"""Tests for the compliance mapping module."""

import pytest

from security_use.compliance import (
    ComplianceControl,
    ComplianceFinding,
    ComplianceFramework,
    ComplianceMapper,
    ComplianceMapping,
)
from security_use.models import IaCFinding, Severity


class TestComplianceFramework:
    """Tests for ComplianceFramework enum."""

    def test_framework_values(self):
        """Test all expected frameworks are defined."""
        expected = [
            "soc2",
            "hipaa",
            "pci-dss",
            "nist-800-53",
            "cis-aws",
            "cis-azure",
            "cis-gcp",
            "cis-kubernetes",
            "iso-27001",
        ]
        actual = [f.value for f in ComplianceFramework]
        for exp in expected:
            assert exp in actual, f"Missing framework: {exp}"

    def test_framework_from_string(self):
        """Test creating framework from string value."""
        assert ComplianceFramework("soc2") == ComplianceFramework.SOC2
        assert ComplianceFramework("hipaa") == ComplianceFramework.HIPAA
        assert ComplianceFramework("pci-dss") == ComplianceFramework.PCI_DSS


class TestComplianceControl:
    """Tests for ComplianceControl dataclass."""

    def test_create_control(self):
        """Test creating a compliance control."""
        control = ComplianceControl(
            framework=ComplianceFramework.SOC2,
            control_id="CC6.1",
            title="Encryption of Data at Rest",
            description="Logical and physical access controls",
        )

        assert control.framework == ComplianceFramework.SOC2
        assert control.control_id == "CC6.1"
        assert control.title == "Encryption of Data at Rest"

    def test_control_with_category(self):
        """Test creating control with optional category."""
        control = ComplianceControl(
            framework=ComplianceFramework.HIPAA,
            control_id="164.312",
            title="Technical Safeguards",
            description="Access controls",
            category="Security Rule",
        )

        assert control.category == "Security Rule"


class TestComplianceMapping:
    """Tests for ComplianceMapping dataclass."""

    def test_create_mapping(self):
        """Test creating a compliance mapping."""
        mapping = ComplianceMapping(rule_id="CKV_AWS_19")

        assert mapping.rule_id == "CKV_AWS_19"
        assert mapping.controls == []

    def test_mapping_with_controls(self):
        """Test mapping with controls."""
        mapping = ComplianceMapping(
            rule_id="CKV_AWS_19",
            controls=[
                ComplianceControl(
                    framework=ComplianceFramework.SOC2,
                    control_id="CC6.1",
                    title="Encryption",
                    description="Encryption controls",
                )
            ],
        )

        assert len(mapping.controls) == 1
        assert mapping.controls[0].control_id == "CC6.1"


class TestComplianceFinding:
    """Tests for ComplianceFinding dataclass."""

    def test_create_finding(self):
        """Test creating a compliance finding."""
        finding = ComplianceFinding(
            rule_id="CKV_AWS_19",
            title="S3 bucket without encryption",
            severity="HIGH",
            file_path="main.tf",
            line_number=10,
            controls=[
                ComplianceControl(
                    framework=ComplianceFramework.SOC2,
                    control_id="CC6.1",
                    title="Encryption",
                    description="Encryption controls",
                )
            ],
        )

        assert finding.rule_id == "CKV_AWS_19"
        assert len(finding.controls) == 1
        assert finding.controls[0].framework == ComplianceFramework.SOC2


class TestComplianceMapper:
    """Tests for ComplianceMapper."""

    @pytest.fixture
    def mapper(self):
        """Create a compliance mapper instance."""
        return ComplianceMapper()

    @pytest.fixture
    def sample_finding(self):
        """Create a sample IaC finding."""
        return IaCFinding(
            rule_id="CKV_AWS_19",
            title="S3 bucket without encryption",
            description="S3 bucket is not encrypted",
            severity=Severity.HIGH,
            resource_type="aws_s3_bucket",
            resource_name="example",
            file_path="main.tf",
            line_number=10,
            remediation="Enable server-side encryption",
        )

    @pytest.fixture
    def sample_findings(self):
        """Create multiple sample IaC findings."""
        return [
            IaCFinding(
                rule_id="CKV_AWS_19",
                title="S3 bucket without encryption",
                description="S3 bucket is not encrypted",
                severity=Severity.HIGH,
                resource_type="aws_s3_bucket",
                resource_name="example",
                file_path="main.tf",
                line_number=10,
                remediation="Enable server-side encryption",
            ),
            IaCFinding(
                rule_id="CKV_AWS_20",
                title="S3 bucket publicly accessible",
                description="S3 bucket is public",
                severity=Severity.CRITICAL,
                resource_type="aws_s3_bucket",
                resource_name="public_bucket",
                file_path="main.tf",
                line_number=15,
                remediation="Block public access",
            ),
        ]

    def test_get_mapping_known_rule(self, mapper):
        """Test getting mapping for a known rule."""
        mapping = mapper.get_mapping("CKV_AWS_19")

        assert mapping.rule_id == "CKV_AWS_19"
        assert len(mapping.controls) > 0

        # Should include SOC2 control
        soc2_controls = [c for c in mapping.controls if c.framework == ComplianceFramework.SOC2]
        assert len(soc2_controls) > 0
        assert soc2_controls[0].control_id == "CC6.1"

    def test_get_mapping_unknown_rule(self, mapper):
        """Test getting mapping for an unknown rule."""
        mapping = mapper.get_mapping("UNKNOWN_RULE_123")

        assert mapping.rule_id == "UNKNOWN_RULE_123"
        assert len(mapping.controls) == 0

    def test_get_mapping_multiple_frameworks(self, mapper):
        """Test that a rule can map to multiple frameworks."""
        mapping = mapper.get_mapping("CKV_AWS_19")

        frameworks = set(c.framework for c in mapping.controls)
        # CKV_AWS_19 should map to multiple frameworks
        assert len(frameworks) >= 3

    def test_enrich_finding(self, mapper, sample_finding):
        """Test enriching a finding with compliance info."""
        enriched = mapper.enrich_finding(sample_finding)

        assert enriched.rule_id == sample_finding.rule_id
        assert enriched.title == sample_finding.title
        assert enriched.severity == sample_finding.severity.value
        assert len(enriched.controls) > 0

    def test_enrich_finding_preserves_location(self, mapper, sample_finding):
        """Test that enrichment preserves file location info."""
        enriched = mapper.enrich_finding(sample_finding)

        assert enriched.file_path == sample_finding.file_path
        assert enriched.line_number == sample_finding.line_number

    def test_get_findings_by_framework_soc2(self, mapper, sample_findings):
        """Test filtering findings by SOC2 framework."""
        results = mapper.get_findings_by_framework(sample_findings, ComplianceFramework.SOC2)

        assert len(results) > 0
        for finding in results:
            assert all(c.framework == ComplianceFramework.SOC2 for c in finding.controls)

    def test_get_findings_by_framework_hipaa(self, mapper, sample_findings):
        """Test filtering findings by HIPAA framework."""
        results = mapper.get_findings_by_framework(sample_findings, ComplianceFramework.HIPAA)

        assert len(results) > 0
        for finding in results:
            assert all(c.framework == ComplianceFramework.HIPAA for c in finding.controls)

    def test_get_findings_by_framework_pci_dss(self, mapper, sample_findings):
        """Test filtering findings by PCI-DSS framework."""
        results = mapper.get_findings_by_framework(sample_findings, ComplianceFramework.PCI_DSS)

        assert len(results) > 0
        for finding in results:
            assert all(c.framework == ComplianceFramework.PCI_DSS for c in finding.controls)

    def test_get_findings_no_match(self, mapper):
        """Test filtering when no findings match framework."""
        findings = [
            IaCFinding(
                rule_id="UNKNOWN_RULE",
                title="Unknown finding",
                description="Test",
                severity=Severity.LOW,
                resource_type="unknown",
                resource_name="test",
                file_path="main.tf",
                line_number=1,
                remediation="N/A",
            )
        ]

        results = mapper.get_findings_by_framework(findings, ComplianceFramework.SOC2)
        assert len(results) == 0

    def test_get_supported_frameworks(self, mapper):
        """Test getting list of supported frameworks."""
        frameworks = mapper.get_supported_frameworks()

        assert ComplianceFramework.SOC2 in frameworks
        assert ComplianceFramework.HIPAA in frameworks
        assert ComplianceFramework.PCI_DSS in frameworks
        assert ComplianceFramework.NIST_800_53 in frameworks
        assert ComplianceFramework.ISO_27001 in frameworks

    def test_get_framework_summary(self, mapper, sample_findings):
        """Test getting summary grouped by control."""
        summary = mapper.get_framework_summary(sample_findings, ComplianceFramework.SOC2)

        assert isinstance(summary, dict)
        # Should have at least one control
        assert len(summary) > 0

        # Each key should be a control ID
        for control_id, findings in summary.items():
            assert isinstance(control_id, str)
            assert isinstance(findings, list)
            assert all(isinstance(f, ComplianceFinding) for f in findings)

    def test_mappings_have_required_info(self, mapper):
        """Test that all mappings have required control info."""
        for rule_id in mapper.MAPPINGS:
            mapping = mapper.get_mapping(rule_id)
            for control in mapping.controls:
                assert control.framework is not None
                assert control.control_id
                assert control.title
                assert control.description


class TestComplianceMapperCoverage:
    """Tests for compliance mapper rule coverage."""

    @pytest.fixture
    def mapper(self):
        """Create a compliance mapper instance."""
        return ComplianceMapper()

    def test_aws_rules_coverage(self, mapper):
        """Test that common AWS rules are mapped."""
        aws_rules = ["CKV_AWS_19", "CKV_AWS_20", "CKV_AWS_21", "CKV_AWS_23"]
        for rule in aws_rules:
            mapping = mapper.get_mapping(rule)
            if rule in mapper.MAPPINGS:
                assert len(mapping.controls) > 0, f"Rule {rule} has no controls"

    def test_azure_rules_coverage(self, mapper):
        """Test that Azure rules are mapped."""
        azure_rules = ["CKV_AZURE_2", "CKV_AZURE_9"]
        for rule in azure_rules:
            if rule in mapper.MAPPINGS:
                mapping = mapper.get_mapping(rule)
                assert len(mapping.controls) > 0

    def test_gcp_rules_coverage(self, mapper):
        """Test that GCP rules are mapped."""
        gcp_rules = ["CKV_GCP_2", "CKV_GCP_5"]
        for rule in gcp_rules:
            if rule in mapper.MAPPINGS:
                mapping = mapper.get_mapping(rule)
                assert len(mapping.controls) > 0

    def test_kubernetes_rules_coverage(self, mapper):
        """Test that Kubernetes rules are mapped."""
        k8s_rules = ["CKV_K8S_1", "CKV_K8S_6", "CKV_K8S_11"]
        for rule in k8s_rules:
            if rule in mapper.MAPPINGS:
                mapping = mapper.get_mapping(rule)
                assert len(mapping.controls) > 0
