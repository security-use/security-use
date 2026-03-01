"""OSV API client for vulnerability database queries."""

import hashlib
import time
from dataclasses import dataclass
from typing import Any, Optional

import httpx

from security_use.models import Severity, Vulnerability


@dataclass
class CacheEntry:
    """Cache entry with TTL."""

    data: Any
    expires_at: float


class OSVClient:
    """Client for the OSV (Open Source Vulnerabilities) API.

    Documentation: https://google.github.io/osv.dev/api/
    """

    BASE_URL = "https://api.osv.dev/v1"
    CACHE_TTL = 300  # 5 minutes
    BATCH_SIZE = 1000  # Max queries per batch request

    def __init__(self, timeout: float = 30.0, cache_ttl: int = 300) -> None:
        """Initialize the OSV client.

        Args:
            timeout: HTTP request timeout in seconds.
            cache_ttl: Cache time-to-live in seconds.
        """
        self._client = httpx.Client(timeout=timeout)
        self._cache: dict[str, CacheEntry] = {}
        self.cache_ttl = cache_ttl

    def query_package(
        self, package: str, version: str, ecosystem: str = "PyPI"
    ) -> list[Vulnerability]:
        """Query vulnerabilities for a single package.

        Args:
            package: Package name.
            version: Package version.
            ecosystem: Package ecosystem (default: PyPI).

        Returns:
            List of vulnerabilities affecting this package version.
        """
        cache_key = self._cache_key(package, version, ecosystem)
        cached = self._get_cached(cache_key)
        if cached is not None:
            return cached

        payload = {
            "package": {"name": package, "ecosystem": ecosystem},
            "version": version,
        }

        try:
            response = self._client.post(f"{self.BASE_URL}/query", json=payload)
            response.raise_for_status()
            data = response.json()
        except httpx.HTTPError:
            return []

        vulns = self._parse_vulnerabilities(data.get("vulns", []), package, version)
        self._set_cached(cache_key, vulns)

        return vulns

    def query_batch(
        self,
        packages: list[tuple[str, str]],
        ecosystem: str = "PyPI",
    ) -> dict[tuple[str, str], list[Vulnerability]]:
        """Query vulnerabilities for multiple packages at once.

        Args:
            packages: List of (package_name, version) tuples.
            ecosystem: Package ecosystem (default: PyPI).

        Returns:
            Dict mapping (normalized_name, version) to list of vulnerabilities.
        """
        results: dict[tuple[str, str], list[Vulnerability]] = {}

        if not packages:
            return results

        # Check cache first
        uncached_packages = []
        for name, version in packages:
            normalized = self._normalize_name(name)
            cache_key = self._cache_key(name, version, ecosystem)
            cached = self._get_cached(cache_key)
            if cached is not None:
                results[(normalized, version)] = cached
            else:
                uncached_packages.append((name, version))

        if not uncached_packages:
            return results

        # Build batch queries
        queries = [
            {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
            for name, version in uncached_packages
        ]

        # Process in batches
        for i in range(0, len(queries), self.BATCH_SIZE):
            batch = queries[i : i + self.BATCH_SIZE]
            batch_packages = uncached_packages[i : i + self.BATCH_SIZE]

            try:
                response = self._client.post(
                    f"{self.BASE_URL}/querybatch",
                    json={"queries": batch},
                )
                response.raise_for_status()
                data = response.json()
            except httpx.HTTPError:
                # On error, skip this batch
                continue

            # Parse results - batch API returns minimal data, need to fetch full details
            for idx, result in enumerate(data.get("results", [])):
                if idx >= len(batch_packages):
                    break

                name, version = batch_packages[idx]
                normalized = self._normalize_name(name)

                # Batch API only returns IDs, fetch full vulnerability data
                vuln_ids = [v.get("id") for v in result.get("vulns", []) if v.get("id")]
                full_vulns = []
                for vuln_id in vuln_ids:
                    vuln_data = self.get_vulnerability(vuln_id)
                    if vuln_data:
                        full_vulns.append(vuln_data)

                vulns = self._parse_vulnerabilities(full_vulns, name, version)

                results[(normalized, version)] = vulns
                cache_key = self._cache_key(name, version, ecosystem)
                self._set_cached(cache_key, vulns)

        return results

    def get_vulnerability(self, vuln_id: str) -> Optional[dict[str, Any]]:
        """Get details for a specific vulnerability.

        Args:
            vuln_id: Vulnerability ID (e.g., CVE-2021-1234, GHSA-xxxx).

        Returns:
            Vulnerability details or None if not found.
        """
        cache_key = f"vuln:{vuln_id}"
        cached = self._get_cached(cache_key)
        if cached is not None:
            return cached

        try:
            response = self._client.get(f"{self.BASE_URL}/vulns/{vuln_id}")
            response.raise_for_status()
            data = response.json()
            self._set_cached(cache_key, data)
            return data
        except httpx.HTTPError:
            return None

    def get_fix_version(
        self, vulnerability_id: str, package: str, ecosystem: str = "PyPI"
    ) -> Optional[str]:
        """Get the recommended fix version for a vulnerability.

        Args:
            vulnerability_id: The vulnerability ID.
            package: Package name.
            ecosystem: Package ecosystem.

        Returns:
            Recommended version to upgrade to, or None if unknown.
        """
        vuln_data = self.get_vulnerability(vulnerability_id)
        if not vuln_data:
            return None

        # Look for fixed version in affected ranges
        for affected in vuln_data.get("affected", []):
            pkg = affected.get("package", {})
            if (
                pkg.get("name", "").lower() == package.lower()
                and pkg.get("ecosystem", "").lower() == ecosystem.lower()
            ):
                for range_info in affected.get("ranges", []):
                    for event in range_info.get("events", []):
                        if "fixed" in event:
                            return event["fixed"]

        return None

    def _parse_vulnerabilities(
        self, vulns: list[dict[str, Any]], package: str, version: str
    ) -> list[Vulnerability]:
        """Parse OSV vulnerability data into Vulnerability objects.

        Args:
            vulns: Raw vulnerability data from OSV.
            package: Package name.
            version: Package version.

        Returns:
            List of Vulnerability objects.
        """
        result = []

        for vuln in vulns:
            # Get CVE ID if available, otherwise use OSV ID
            vuln_id = vuln.get("id", "")
            aliases = vuln.get("aliases", [])
            cve_id = next((a for a in aliases if a.startswith("CVE-")), vuln_id)

            # Get severity from CVSS or severity field
            severity = self._get_severity(vuln)

            # Get fixed version
            fixed_version = self._get_fixed_version(vuln, package)

            # Get affected versions string
            affected_versions = self._get_affected_versions(vuln, package)

            result.append(
                Vulnerability(
                    id=cve_id,
                    package=package,
                    installed_version=version,
                    severity=severity,
                    title=vuln.get("summary", "Unknown vulnerability"),
                    description=vuln.get("details", ""),
                    affected_versions=affected_versions,
                    fixed_version=fixed_version,
                    cvss_score=self._get_cvss_score(vuln),
                    references=[
                        ref.get("url", "") for ref in vuln.get("references", [])
                    ],
                )
            )

        return result

    def _get_severity(self, vuln: dict[str, Any]) -> Severity:
        """Extract severity from vulnerability data."""
        # Try to get from severity field
        for sev in vuln.get("severity", []):
            if sev.get("type") == "CVSS_V3":
                score = self._parse_cvss_score(sev.get("score", ""))
                if score is not None:
                    return Severity.from_cvss(score)

        # Try database_specific severity
        db_specific = vuln.get("database_specific", {})
        severity_str = db_specific.get("severity", "").upper()
        if severity_str in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            return Severity(severity_str)

        return Severity.UNKNOWN

    def _get_cvss_score(self, vuln: dict[str, Any]) -> Optional[float]:
        """Extract CVSS score from vulnerability data."""
        for sev in vuln.get("severity", []):
            if sev.get("type") == "CVSS_V3":
                return self._parse_cvss_score(sev.get("score", ""))
        return None

    def _parse_cvss_score(self, score_str: str) -> Optional[float]:
        """Parse CVSS score from vector or score string."""
        if not score_str:
            return None

        # If it's a CVSS vector, extract the base score
        if score_str.startswith("CVSS:"):
            # For now, return None as parsing CVSS vectors is complex
            return None

        try:
            return float(score_str)
        except ValueError:
            return None

    def _get_fixed_version(
        self, vuln: dict[str, Any], package: str
    ) -> Optional[str]:
        """Extract fixed version from vulnerability data."""
        for affected in vuln.get("affected", []):
            pkg = affected.get("package", {})
            if pkg.get("name", "").lower() == package.lower():
                for range_info in affected.get("ranges", []):
                    for event in range_info.get("events", []):
                        if "fixed" in event:
                            return event["fixed"]
        return None

    def _get_affected_versions(
        self, vuln: dict[str, Any], package: str
    ) -> str:
        """Build affected versions string from vulnerability data."""
        for affected in vuln.get("affected", []):
            pkg = affected.get("package", {})
            if pkg.get("name", "").lower() == package.lower():
                versions = affected.get("versions", [])
                if versions:
                    if len(versions) <= 3:
                        return ", ".join(versions)
                    return f"{versions[0]} - {versions[-1]}"

                # Build from ranges
                ranges = []
                for range_info in affected.get("ranges", []):
                    events = range_info.get("events", [])
                    introduced = None
                    fixed = None
                    for event in events:
                        if "introduced" in event:
                            introduced = event["introduced"]
                        if "fixed" in event:
                            fixed = event["fixed"]
                    if introduced:
                        if fixed:
                            ranges.append(f">={introduced}, <{fixed}")
                        else:
                            ranges.append(f">={introduced}")
                if ranges:
                    return "; ".join(ranges)

        return "unknown"

    def _normalize_name(self, name: str) -> str:
        """Normalize package name for cache key matching."""
        return name.lower().replace("-", "_").replace(".", "_")

    def _cache_key(self, package: str, version: str, ecosystem: str) -> str:
        """Generate cache key for a package query."""
        normalized = self._normalize_name(package)
        key_str = f"{ecosystem}:{normalized}:{version}"
        return hashlib.sha256(key_str.encode()).hexdigest()[:16]

    def _get_cached(self, key: str) -> Optional[Any]:
        """Get value from cache if not expired."""
        entry = self._cache.get(key)
        if entry is None:
            return None
        if time.time() > entry.expires_at:
            del self._cache[key]
            return None
        return entry.data

    def _set_cached(self, key: str, value: Any) -> None:
        """Set value in cache with TTL."""
        self._cache[key] = CacheEntry(
            data=value,
            expires_at=time.time() + self.cache_ttl,
        )

    def clear_cache(self) -> None:
        """Clear the vulnerability cache."""
        self._cache.clear()

    def close(self) -> None:
        """Close the HTTP client."""
        self._client.close()

    def __enter__(self) -> "OSVClient":
        """Context manager entry."""
        return self

    def __exit__(self, *args: Any) -> None:
        """Context manager exit."""
        self.close()
