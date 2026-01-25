"""Dashboard API client for uploading scan results."""

import platform
from typing import Optional
from datetime import datetime

import httpx

from .config import OAUTH_CONFIG, AuthConfig
from .oauth import OAuthFlow, OAuthError
from security_use import __version__
from security_use.models import ScanResult


class DashboardClient:
    """Client for the SecurityUse dashboard API."""

    def __init__(self, config: Optional[AuthConfig] = None):
        self.config = config or AuthConfig()
        self.api_url = OAUTH_CONFIG["api_url"]
        self.oauth = OAuthFlow(self.config)

    def _get_headers(self) -> dict:
        """Get request headers with authentication."""
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": f"security-use-cli/{__version__}",
        }

        token = self.config.get_access_token()
        if token:
            headers["Authorization"] = f"Bearer {token}"

        return headers

    def _ensure_authenticated(self) -> None:
        """Ensure user is authenticated, refresh token if needed."""
        if not self.config.is_authenticated:
            raise OAuthError("Not authenticated. Run 'security-use auth login' first.")

        # Try to refresh if token is expired
        if self.config.token and self.config.token.is_expired():
            if self.config.token.refresh_token:
                try:
                    new_token = self.oauth.refresh_token(self.config.token.refresh_token)
                    self.config.save_token(new_token, self.config.user)
                except OAuthError:
                    raise OAuthError(
                        "Session expired. Run 'security-use auth login' to re-authenticate."
                    )
            else:
                raise OAuthError(
                    "Session expired. Run 'security-use auth login' to re-authenticate."
                )

    def upload_scan(
        self,
        result: ScanResult,
        project_name: Optional[str] = None,
        project_path: Optional[str] = None,
        branch: Optional[str] = None,
        commit: Optional[str] = None,
    ) -> dict:
        """Upload scan results to the dashboard.

        Args:
            result: The scan result to upload.
            project_name: Optional project name.
            project_path: Optional local path that was scanned.
            branch: Optional git branch name.
            commit: Optional git commit SHA.

        Returns:
            API response with scan ID and dashboard URL.

        Raises:
            OAuthError: If not authenticated or upload fails.
        """
        self._ensure_authenticated()

        payload = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "cli_version": __version__,
            "platform": {
                "system": platform.system(),
                "release": platform.release(),
                "python": platform.python_version(),
            },
            "project": {
                "name": project_name,
                "path": project_path,
                "branch": branch,
                "commit": commit,
            },
            "summary": {
                "total_issues": result.total_issues,
                "critical_count": result.critical_count,
                "high_count": result.high_count,
                "scanned_files": len(result.scanned_files),
            },
            "vulnerabilities": [v.to_dict() for v in result.vulnerabilities],
            "iac_findings": [f.to_dict() for f in result.iac_findings],
            "scanned_files": result.scanned_files,
            "errors": result.errors,
        }

        try:
            with httpx.Client(timeout=60.0) as client:
                response = client.post(
                    f"{self.api_url}/v1/scans",
                    json=payload,
                    headers=self._get_headers(),
                )

                if response.status_code == 401:
                    raise OAuthError(
                        "Authentication failed. Run 'security-use auth login' to re-authenticate."
                    )

                if response.status_code not in (200, 201):
                    raise OAuthError(f"Failed to upload scan: {response.text}")

                return response.json()

        except httpx.RequestError as e:
            raise OAuthError(f"Network error: {e}")

    def get_scans(
        self,
        project_name: Optional[str] = None,
        limit: int = 10,
    ) -> list[dict]:
        """Get recent scans from the dashboard.

        Args:
            project_name: Optional filter by project name.
            limit: Maximum number of scans to return.

        Returns:
            List of scan summaries.

        Raises:
            OAuthError: If not authenticated or request fails.
        """
        self._ensure_authenticated()

        params = {"limit": limit}
        if project_name:
            params["project"] = project_name

        try:
            with httpx.Client(timeout=30.0) as client:
                response = client.get(
                    f"{self.api_url}/v1/scans",
                    params=params,
                    headers=self._get_headers(),
                )

                if response.status_code == 401:
                    raise OAuthError(
                        "Authentication failed. Run 'security-use auth login' to re-authenticate."
                    )

                if response.status_code != 200:
                    raise OAuthError(f"Failed to fetch scans: {response.text}")

                return response.json().get("scans", [])

        except httpx.RequestError as e:
            raise OAuthError(f"Network error: {e}")

    def get_projects(self) -> list[dict]:
        """Get list of projects for the authenticated user.

        Returns:
            List of projects.

        Raises:
            OAuthError: If not authenticated or request fails.
        """
        self._ensure_authenticated()

        try:
            with httpx.Client(timeout=30.0) as client:
                response = client.get(
                    f"{self.api_url}/v1/projects",
                    headers=self._get_headers(),
                )

                if response.status_code == 401:
                    raise OAuthError(
                        "Authentication failed. Run 'security-use auth login' to re-authenticate."
                    )

                if response.status_code != 200:
                    raise OAuthError(f"Failed to fetch projects: {response.text}")

                return response.json().get("projects", [])

        except httpx.RequestError as e:
            raise OAuthError(f"Network error: {e}")
