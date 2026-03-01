"""Tests for report generators."""

import json

import pytest

from security_use.models import (
    IaCFinding,
    ScanResult,
    Severity,
    Vulnerability,
)
from security_use.reporter import (
    JSONReporter,
    SARIFReporter,
    TableReporter,
    create_reporter,
)


@pytest.fixture
def sample_vulnerability():
    """Create a sample vulnerability for testing."""
    return Vulnerability(
        id="CVE-2021-1234",
        package="requests",
        installed_version="2.25.0",
        severity=Severity.HIGH,
        title="Security vulnerability in requests",
        description="A security vulnerability was found.",
        affected_versions=">=2.0.0, <2.26.0",
        fixed_version="2.26.0",
        cvss_score=7.5,
        references=["https://example.com/cve-2021-1234"],
    )


@pytest.fixture
def sample_iac_finding():
    """Create a sample IaC finding for testing."""
    return IaCFinding(
        rule_id="CKV_AWS_19",
        title="S3 bucket without encryption",
        severity=Severity.HIGH,
        resource_type="aws_s3_bucket",
        resource_name="my-bucket",
        file_path="main.tf",
        line_number=10,
        description="S3 bucket is not encrypted at rest.",
        remediation="Enable server-side encryption.",
        fix_code='server_side_encryption_configuration { ... }',
    )


@pytest.fixture
def sample_result(sample_vulnerability, sample_iac_finding):
    """Create a sample scan result for testing."""
    return ScanResult(
        vulnerabilities=[sample_vulnerability],
        iac_findings=[sample_iac_finding],
        scanned_files=["requirements.txt", "main.tf"],
        errors=[],
    )


class TestJSONReporter:
    """Tests for JSON reporter."""

    def test_generate_returns_valid_json(self, sample_result):
        reporter = JSONReporter()
        output = reporter.generate(sample_result)

        # Should be valid JSON
        data = json.loads(output)
        assert "vulnerabilities" in data
        assert "iac_findings" in data
        assert "summary" in data

    def test_generate_includes_vulnerability_details(self, sample_result):
        reporter = JSONReporter()
        output = reporter.generate(sample_result)
        data = json.loads(output)

        vuln = data["vulnerabilities"][0]
        assert vuln["id"] == "CVE-2021-1234"
        assert vuln["package"] == "requests"
        assert vuln["severity"] == "HIGH"

    def test_generate_includes_iac_details(self, sample_result):
        reporter = JSONReporter()
        output = reporter.generate(sample_result)
        data = json.loads(output)

        finding = data["iac_findings"][0]
        assert finding["rule_id"] == "CKV_AWS_19"
        assert finding["resource_name"] == "my-bucket"

    def test_generate_with_custom_indent(self):
        result = ScanResult()
        reporter = JSONReporter(indent=4)
        output = reporter.generate(result)

        # Check indentation
        lines = output.split("\n")
        assert any("    " in line for line in lines)


class TestTableReporter:
    """Tests for table reporter."""

    def test_generate_returns_string(self, sample_result):
        reporter = TableReporter()
        output = reporter.generate(sample_result)

        assert isinstance(output, str)
        assert len(output) > 0

    def test_generate_includes_summary(self, sample_result):
        reporter = TableReporter()
        output = reporter.generate(sample_result)

        assert "Security Scan Summary" in output
        assert "Total Issues" in output

    def test_generate_includes_vulnerability_table(self, sample_result):
        reporter = TableReporter()
        output = reporter.generate(sample_result)

        assert "Dependency Vulnerabilities" in output
        # Table may truncate long values, so check for partial match
        assert "CVE-2021" in output
        assert "requests" in output

    def test_generate_includes_iac_table(self, sample_result):
        reporter = TableReporter()
        output = reporter.generate(sample_result)

        assert "Infrastructure as Code Findings" in output
        # Table may truncate long values, so check for partial match
        assert "CKV_" in output or "CKV" in output

    def test_generate_empty_result(self):
        result = ScanResult()
        reporter = TableReporter()
        output = reporter.generate(result)

        assert "Total Issues: 0" in output


class TestSARIFReporter:
    """Tests for SARIF reporter."""

    def test_generate_returns_valid_json(self, sample_result):
        reporter = SARIFReporter()
        output = reporter.generate(sample_result)

        # Should be valid JSON
        data = json.loads(output)
        assert "$schema" in data
        assert "version" in data
        assert "runs" in data

    def test_generate_includes_tool_info(self, sample_result):
        reporter = SARIFReporter(tool_name="test-tool", tool_version="1.0.0")
        output = reporter.generate(sample_result)
        data = json.loads(output)

        tool = data["runs"][0]["tool"]["driver"]
        assert tool["name"] == "test-tool"
        assert tool["version"] == "1.0.0"

    def test_generate_includes_rules(self, sample_result):
        reporter = SARIFReporter()
        output = reporter.generate(sample_result)
        data = json.loads(output)

        rules = data["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 2  # One for vuln, one for IaC

        rule_ids = [r["id"] for r in rules]
        assert "CVE-2021-1234" in rule_ids
        assert "CKV_AWS_19" in rule_ids

    def test_generate_includes_results(self, sample_result):
        reporter = SARIFReporter()
        output = reporter.generate(sample_result)
        data = json.loads(output)

        results = data["runs"][0]["results"]
        assert len(results) == 2

    def test_severity_mapping(self):
        reporter = SARIFReporter()

        assert reporter._severity_to_sarif_level(Severity.CRITICAL) == "error"
        assert reporter._severity_to_sarif_level(Severity.HIGH) == "error"
        assert reporter._severity_to_sarif_level(Severity.MEDIUM) == "warning"
        assert reporter._severity_to_sarif_level(Severity.LOW) == "note"
        assert reporter._severity_to_sarif_level(Severity.UNKNOWN) == "none"


class TestCreateReporter:
    """Tests for reporter factory function."""

    def test_create_json_reporter(self):
        reporter = create_reporter("json")
        assert isinstance(reporter, JSONReporter)

    def test_create_table_reporter(self):
        reporter = create_reporter("table")
        assert isinstance(reporter, TableReporter)

    def test_create_sarif_reporter(self):
        reporter = create_reporter("sarif")
        assert isinstance(reporter, SARIFReporter)

    def test_create_invalid_format(self):
        with pytest.raises(ValueError):
            create_reporter("invalid")

    def test_create_sarif_with_options(self):
        reporter = create_reporter(
            "sarif",
            tool_name="custom-tool",
            tool_version="2.0.0",
        )
        assert isinstance(reporter, SARIFReporter)
        assert reporter.tool_name == "custom-tool"
        assert reporter.tool_version == "2.0.0"
