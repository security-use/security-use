"""OAuth device authorization flow implementation."""

import time
import webbrowser
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional, Callable

import httpx

from .config import OAUTH_CONFIG, AuthToken, UserInfo, AuthConfig


@dataclass
class DeviceCode:
    """Device code response from OAuth server."""
    device_code: str
    user_code: str
    verification_uri: str
    verification_uri_complete: Optional[str]
    expires_in: int
    interval: int

    @classmethod
    def from_dict(cls, data: dict) -> "DeviceCode":
        """Create from API response."""
        # Normalize verification URLs to use security-use.dev
        verification_uri = data["verification_uri"].replace(
            "security-use.lovable.app", "security-use.dev"
        )
        verification_uri_complete = data.get("verification_uri_complete")
        if verification_uri_complete:
            verification_uri_complete = verification_uri_complete.replace(
                "security-use.lovable.app", "security-use.dev"
            )

        return cls(
            device_code=data["device_code"],
            user_code=data["user_code"],
            verification_uri=verification_uri,
            verification_uri_complete=verification_uri_complete,
            expires_in=data.get("expires_in", 900),
            interval=data.get("interval", 5),
        )


class OAuthError(Exception):
    """OAuth authentication error."""
    pass


class OAuthFlow:
    """Handles OAuth device authorization flow."""

    def __init__(self, config: Optional[AuthConfig] = None):
        self.config = config or AuthConfig()
        self.client_id = OAUTH_CONFIG["client_id"]
        self.auth_url = OAUTH_CONFIG["auth_url"]
        self.token_url = OAUTH_CONFIG["token_url"]
        self.api_url = OAUTH_CONFIG["api_url"]
        self.scopes = OAUTH_CONFIG["scopes"]

    def request_device_code(self) -> DeviceCode:
        """Request a device code to start the authorization flow.

        Returns:
            DeviceCode with the user code and verification URL.

        Raises:
            OAuthError: If the request fails.
        """
        try:
            with httpx.Client(timeout=30.0) as client:
                response = client.post(
                    self.auth_url,
                    json={
                        "client_id": self.client_id,
                        "scope": " ".join(self.scopes),
                    },
                    headers={"Accept": "application/json"},
                )

                if response.status_code == 404:
                    raise OAuthError(
                        "OAuth server not available. The dashboard at security-use.dev "
                        "may not be configured yet."
                    )

                if response.status_code != 200:
                    raise OAuthError(f"Failed to request device code: {response.text}")

                try:
                    return DeviceCode.from_dict(response.json())
                except (ValueError, KeyError) as e:
                    raise OAuthError(
                        f"Invalid response from OAuth server: {e}"
                    )

        except httpx.RequestError as e:
            raise OAuthError(f"Network error connecting to {self.auth_url}: {e}")

    def poll_for_token(
        self,
        device_code: DeviceCode,
        on_status: Optional[Callable[[str], None]] = None,
    ) -> AuthToken:
        """Poll the token endpoint until authorization is complete.

        Args:
            device_code: The device code from request_device_code().
            on_status: Optional callback for status updates.

        Returns:
            AuthToken on successful authorization.

        Raises:
            OAuthError: If authorization fails or times out.
        """
        start_time = time.time()
        interval = device_code.interval

        with httpx.Client(timeout=30.0) as client:
            while time.time() - start_time < device_code.expires_in:
                time.sleep(interval)

                try:
                    response = client.post(
                        self.token_url,
                        json={
                            "client_id": self.client_id,
                            "device_code": device_code.device_code,
                            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                        },
                        headers={"Accept": "application/json"},
                    )

                    data = response.json()

                    if response.status_code == 200:
                        # Success - got the token
                        expires_at = None
                        if "expires_in" in data:
                            expires_at = (
                                datetime.utcnow() + timedelta(seconds=data["expires_in"])
                            ).isoformat()

                        return AuthToken(
                            access_token=data["access_token"],
                            refresh_token=data.get("refresh_token"),
                            token_type=data.get("token_type", "Bearer"),
                            expires_at=expires_at,
                            scope=data.get("scope"),
                        )

                    # Handle pending/slow_down/errors
                    error = data.get("error", "")

                    if error == "authorization_pending":
                        if on_status:
                            on_status("Waiting for authorization...")
                        continue

                    elif error == "slow_down":
                        # Increase polling interval
                        interval = data.get("interval", interval + 5)
                        if on_status:
                            on_status("Slowing down polling...")
                        continue

                    elif error == "expired_token":
                        raise OAuthError("Device code expired. Please try again.")

                    elif error == "access_denied":
                        raise OAuthError("Authorization was denied.")

                    else:
                        raise OAuthError(f"Authorization failed: {error}")

                except httpx.RequestError as e:
                    if on_status:
                        on_status(f"Network error, retrying...")
                    continue

        raise OAuthError("Authorization timed out. Please try again.")

    def get_user_info(self, token: AuthToken) -> UserInfo:
        """Fetch user information using the access token.

        Args:
            token: The auth token.

        Returns:
            UserInfo with the authenticated user's details.

        Raises:
            OAuthError: If the request fails.
        """
        try:
            with httpx.Client(timeout=30.0) as client:
                response = client.get(
                    f"{self.api_url}/user-me",
                    headers={
                        "Authorization": f"{token.token_type} {token.access_token}",
                        "Accept": "application/json",
                    },
                )

                if response.status_code == 401:
                    raise OAuthError("Invalid or expired token")

                if response.status_code != 200:
                    raise OAuthError(f"Failed to fetch user info: {response.text}")

                data = response.json()
                return UserInfo(
                    user_id=data.get("id", data.get("user_id", "unknown")),
                    email=data.get("email", "unknown"),
                    name=data.get("name"),
                    org_id=data.get("org_id"),
                    org_name=data.get("org_name"),
                )

        except httpx.RequestError as e:
            raise OAuthError(f"Network error: {e}")

    def refresh_token(self, refresh_token: str) -> AuthToken:
        """Refresh an expired access token.

        Args:
            refresh_token: The refresh token.

        Returns:
            New AuthToken.

        Raises:
            OAuthError: If refresh fails.
        """
        try:
            with httpx.Client(timeout=30.0) as client:
                response = client.post(
                    self.token_url,
                    json={
                        "client_id": self.client_id,
                        "refresh_token": refresh_token,
                        "grant_type": "refresh_token",
                    },
                    headers={"Accept": "application/json"},
                )

                if response.status_code != 200:
                    raise OAuthError("Failed to refresh token")

                data = response.json()
                expires_at = None
                if "expires_in" in data:
                    expires_at = (
                        datetime.utcnow() + timedelta(seconds=data["expires_in"])
                    ).isoformat()

                return AuthToken(
                    access_token=data["access_token"],
                    refresh_token=data.get("refresh_token", refresh_token),
                    token_type=data.get("token_type", "Bearer"),
                    expires_at=expires_at,
                    scope=data.get("scope"),
                )

        except httpx.RequestError as e:
            raise OAuthError(f"Network error: {e}")

    def login(
        self,
        open_browser: bool = True,
        on_status: Optional[Callable[[str], None]] = None,
    ) -> tuple[AuthToken, UserInfo]:
        """Perform the full device authorization flow.

        Args:
            open_browser: Whether to automatically open the browser.
            on_status: Optional callback for status updates.

        Returns:
            Tuple of (AuthToken, UserInfo).

        Raises:
            OAuthError: If authentication fails.
        """
        # Request device code
        device_code = self.request_device_code()

        # Open browser if requested
        verification_url = (
            device_code.verification_uri_complete
            or f"{device_code.verification_uri}?user_code={device_code.user_code}"
        )

        if open_browser:
            webbrowser.open(verification_url)

        # Poll for token
        token = self.poll_for_token(device_code, on_status)

        # Get user info
        try:
            user = self.get_user_info(token)
        except OAuthError:
            # If we can't get user info, create a placeholder
            user = UserInfo(user_id="unknown", email="unknown")

        # Save credentials
        self.config.save_token(token, user)

        return token, user

    def logout(self) -> None:
        """Clear stored credentials."""
        self.config.clear()
