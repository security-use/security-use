"""Tests for SBOM enrichment CLI command."""

import json
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
from click.testing import CliRunner

from security_use.cli import main, _ecosystem_from_purl
from security_use.models import Severity, Vulnerability


@pytest.fixture
def runner():
    """Create a CLI test runner."""
    return CliRunner()


@pytest.fixture
def sample_cyclonedx_sbom(tmp_path):
    """Create a sample CycloneDX SBOM file."""
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:test",
        "version": 1,
        "components": [
            {
                "type": "library",
                "name": "requests",
                "version": "2.28.0",
                "purl": "pkg:pypi/requests@2.28.0",
                "bom-ref": "pkg:pypi/requests@2.28.0",
            },
            {
                "type": "library",
                "name": "flask",
                "version": "2.3.0",
                "purl": "pkg:pypi/flask@2.3.0",
                "bom-ref": "pkg:pypi/flask@2.3.0",
            },
        ],
    }
    sbom_file = tmp_path / "sbom.json"
    sbom_file.write_text(json.dumps(sbom, indent=2))
    return sbom_file


@pytest.fixture
def sample_spdx_sbom(tmp_path):
    """Create a sample SPDX SBOM file."""
    sbom = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "test SBOM",
        "packages": [
            {
                "SPDXID": "SPDXRef-RootPackage",
                "name": "test-app",
                "versionInfo": "0.0.0",
                "downloadLocation": "NOASSERTION",
            },
            {
                "SPDXID": "SPDXRef-Package-0",
                "name": "django",
                "versionInfo": "3.2.0",
                "downloadLocation": "NOASSERTION",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": "pkg:pypi/django@3.2.0",
                    }
                ],
            },
        ],
    }
    sbom_file = tmp_path / "sbom-spdx.json"
    sbom_file.write_text(json.dumps(sbom, indent=2))
    return sbom_file


def _make_vuln(vuln_id="CVE-2023-1234", package="requests", version="2.28.0"):
    """Helper to create a mock Vulnerability."""
    return Vulnerability(
        id=vuln_id,
        package=package,
        installed_version=version,
        severity=Severity.HIGH,
        title="Test vulnerability",
        description="A test vulnerability description",
        affected_versions=">=2.0.0, <2.31.0",
        fixed_version="2.31.0",
        cvss_score=7.5,
        references=["https://nvd.nist.gov/vuln/detail/CVE-2023-1234"],
    )


class TestEcosystemFromPurl:
    """Tests for the _ecosystem_from_purl helper."""

    def test_pypi_purl(self):
        assert _ecosystem_from_purl("pkg:pypi/requests@2.28.0") == "PyPI"

    def test_npm_purl(self):
        assert _ecosystem_from_purl("pkg:npm/express@4.18.0") == "npm"

    def test_maven_purl(self):
        assert _ecosystem_from_purl("pkg:maven/org.apache/commons@1.0") == "Maven"

    def test_cargo_purl(self):
        assert _ecosystem_from_purl("pkg:cargo/serde@1.0") == "crates.io"

    def test_unknown_purl_defaults_to_pypi(self):
        assert _ecosystem_from_purl("pkg:unknown/foo@1.0") == "PyPI"

    def test_empty_string_defaults_to_pypi(self):
        assert _ecosystem_from_purl("") == "PyPI"


class TestSBOMEnrichCycloneDX:
    """Tests for CycloneDX SBOM enrichment."""

    @patch("security_use.osv_client.OSVClient")
    def test_enrich_cyclonedx_with_vulnerabilities(self, mock_osv_class, runner, sample_cyclonedx_sbom, tmp_path):
        """Test enriching a CycloneDX SBOM adds vulnerability data."""
        mock_osv = MagicMock()
        mock_osv_class.return_value = mock_osv
        mock_osv.query_package.side_effect = lambda name, version, ecosystem: (
            [_make_vuln("CVE-2023-1234", name, version)] if name == "requests" else []
        )

        output_file = tmp_path / "enriched.json"
        result = runner.invoke(
            main,
            ["sbom", "enrich", str(sample_cyclonedx_sbom), "-o", str(output_file)],
        )

        assert result.exit_code == 0
        assert "Found 1 vulnerabilities" in result.output

        enriched = json.loads(output_file.read_text())
        assert "vulnerabilities" in enriched
        assert len(enriched["vulnerabilities"]) == 1
        vuln = enriched["vulnerabilities"][0]
        assert vuln["id"] == "CVE-2023-1234"
        assert vuln["description"] == "Test vulnerability"
        assert vuln["affects"][0]["ref"] == "pkg:pypi/requests@2.28.0"

    @patch("security_use.osv_client.OSVClient")
    def test_enrich_cyclonedx_no_vulnerabilities(self, mock_osv_class, runner, sample_cyclonedx_sbom, tmp_path):
        """Test enriching a CycloneDX SBOM with no vulnerabilities found."""
        mock_osv = MagicMock()
        mock_osv_class.return_value = mock_osv
        mock_osv.query_package.return_value = []

        output_file = tmp_path / "enriched-empty.json"
        result = runner.invoke(
            main,
            ["sbom", "enrich", str(sample_cyclonedx_sbom), "-o", str(output_file)],
        )

        assert result.exit_code == 0
        assert "Found 0 vulnerabilities" in result.output

        enriched = json.loads(output_file.read_text())
        assert enriched.get("vulnerabilities") == []


class TestSBOMEnrichSPDX:
    """Tests for SPDX SBOM enrichment."""

    @patch("security_use.osv_client.OSVClient")
    def test_enrich_spdx_with_vulnerabilities(self, mock_osv_class, runner, sample_spdx_sbom, tmp_path):
        """Test enriching an SPDX SBOM adds annotation data."""
        mock_osv = MagicMock()
        mock_osv_class.return_value = mock_osv
        mock_osv.query_package.side_effect = lambda name, version, ecosystem: (
            [_make_vuln("CVE-2023-5678", name, version)] if name == "django" else []
        )

        output_file = tmp_path / "enriched-spdx.json"
        result = runner.invoke(
            main,
            ["sbom", "enrich", str(sample_spdx_sbom), "-o", str(output_file)],
        )

        assert result.exit_code == 0
        assert "Found 1 vulnerabilities" in result.output

        enriched = json.loads(output_file.read_text())
        # Find the django package
        django_pkg = None
        for pkg in enriched["packages"]:
            if pkg["name"] == "django":
                django_pkg = pkg
                break
        assert django_pkg is not None
        assert "annotations" in django_pkg
        assert len(django_pkg["annotations"]) == 1
        assert "CVE-2023-5678" in django_pkg["annotations"][0]["comment"]


class TestSBOMEnrichErrors:
    """Tests for SBOM enrichment error handling."""

    def test_enrich_invalid_json(self, runner, tmp_path):
        """Test that invalid JSON is rejected."""
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("not valid json")

        result = runner.invoke(main, ["sbom", "enrich", str(bad_file)])
        assert result.exit_code == 1

    def test_enrich_unknown_format(self, runner, tmp_path):
        """Test that unrecognized SBOM format is rejected."""
        unknown_file = tmp_path / "unknown.json"
        unknown_file.write_text('{"foo": "bar"}')

        result = runner.invoke(main, ["sbom", "enrich", str(unknown_file)])
        assert result.exit_code == 1
