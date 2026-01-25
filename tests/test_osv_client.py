"""Tests for OSV API client."""

import pytest
from unittest.mock import Mock, patch

from security_use.osv_client import OSVClient
from security_use.models import Severity


class TestOSVClient:
    """Tests for OSV client."""

    def test_cache_key_normalization(self):
        """Test that cache keys are normalized correctly."""
        client = OSVClient()
        key1 = client._cache_key("Django", "3.2.0", "PyPI")
        key2 = client._cache_key("django", "3.2.0", "PyPI")
        key3 = client._cache_key("DJANGO", "3.2.0", "PyPI")

        assert key1 == key2 == key3

    def test_normalize_name(self):
        """Test package name normalization."""
        client = OSVClient()

        assert client._normalize_name("Django") == "django"
        assert client._normalize_name("my-package") == "my_package"
        assert client._normalize_name("my.package") == "my_package"

    def test_cache_set_and_get(self):
        """Test cache functionality."""
        client = OSVClient(cache_ttl=60)
        client._set_cached("test_key", ["value1", "value2"])

        result = client._get_cached("test_key")
        assert result == ["value1", "value2"]

    def test_cache_miss(self):
        """Test cache miss returns None."""
        client = OSVClient()
        result = client._get_cached("nonexistent_key")
        assert result is None

    def test_clear_cache(self):
        """Test cache clearing."""
        client = OSVClient()
        client._set_cached("key1", "value1")
        client._set_cached("key2", "value2")

        client.clear_cache()

        assert client._get_cached("key1") is None
        assert client._get_cached("key2") is None

    def test_context_manager(self):
        """Test context manager usage."""
        with OSVClient() as client:
            assert client is not None

    @patch("httpx.Client.post")
    def test_query_package_parses_response(self, mock_post):
        """Test that query_package parses OSV response correctly."""
        mock_response = Mock()
        mock_response.json.return_value = {
            "vulns": [
                {
                    "id": "GHSA-xxxx",
                    "aliases": ["CVE-2021-1234"],
                    "summary": "Test vulnerability",
                    "details": "Detailed description",
                    "severity": [{"type": "CVSS_V3", "score": "7.5"}],
                    "affected": [
                        {
                            "package": {"name": "requests", "ecosystem": "PyPI"},
                            "ranges": [
                                {
                                    "events": [
                                        {"introduced": "0"},
                                        {"fixed": "2.28.1"},
                                    ]
                                }
                            ],
                        }
                    ],
                    "references": [{"url": "https://example.com"}],
                }
            ]
        }
        mock_response.raise_for_status = Mock()
        mock_post.return_value = mock_response

        client = OSVClient()
        vulns = client.query_package("requests", "2.28.0")

        assert len(vulns) == 1
        assert vulns[0].id == "CVE-2021-1234"
        assert vulns[0].package == "requests"
        assert vulns[0].installed_version == "2.28.0"
        assert vulns[0].fixed_version == "2.28.1"
        assert vulns[0].severity == Severity.HIGH

    @patch("httpx.Client.get")
    @patch("httpx.Client.post")
    def test_query_batch_returns_dict(self, mock_post, mock_get):
        """Test that query_batch returns correct dictionary format."""
        # Mock batch query response (returns only IDs)
        mock_batch_response = Mock()
        mock_batch_response.json.return_value = {
            "results": [
                {"vulns": []},
                {"vulns": [{"id": "GHSA-test"}]},
            ]
        }
        mock_batch_response.raise_for_status = Mock()
        mock_post.return_value = mock_batch_response

        # Mock full vulnerability fetch response
        mock_vuln_response = Mock()
        mock_vuln_response.json.return_value = {
            "id": "GHSA-test",
            "summary": "Test vuln",
            "details": "",
            "database_specific": {"severity": "HIGH"},
            "affected": [
                {
                    "package": {"name": "django", "ecosystem": "PyPI"},
                    "ranges": [{"events": [{"introduced": "0"}]}],
                }
            ],
        }
        mock_vuln_response.raise_for_status = Mock()
        mock_get.return_value = mock_vuln_response

        client = OSVClient()
        results = client.query_batch([("requests", "2.28.0"), ("django", "3.2.0")])

        assert ("requests", "2.28.0") in results
        assert ("django", "3.2.0") in results
        assert len(results[("requests", "2.28.0")]) == 0
        assert len(results[("django", "3.2.0")]) == 1


class TestSeverityFromCVSS:
    """Tests for CVSS to severity conversion."""

    def test_critical_severity(self):
        assert Severity.from_cvss(9.0) == Severity.CRITICAL
        assert Severity.from_cvss(10.0) == Severity.CRITICAL

    def test_high_severity(self):
        assert Severity.from_cvss(7.0) == Severity.HIGH
        assert Severity.from_cvss(8.9) == Severity.HIGH

    def test_medium_severity(self):
        assert Severity.from_cvss(4.0) == Severity.MEDIUM
        assert Severity.from_cvss(6.9) == Severity.MEDIUM

    def test_low_severity(self):
        assert Severity.from_cvss(0.1) == Severity.LOW
        assert Severity.from_cvss(3.9) == Severity.LOW

    def test_unknown_severity(self):
        assert Severity.from_cvss(None) == Severity.UNKNOWN
