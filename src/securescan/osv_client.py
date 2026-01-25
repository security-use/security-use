"""OSV API client - placeholder for Issue #3."""

from typing import Optional


class OSVClient:
    """Client for the OSV vulnerability database API."""

    def get_fix_version(self, vulnerability_id: str, package: str) -> Optional[str]:
        """Get the recommended fix version for a vulnerability."""
        raise NotImplementedError("Implemented in Issue #3")
