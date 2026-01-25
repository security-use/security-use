"""Authentication configuration and token storage."""

import json
import os
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional
from datetime import datetime, timedelta


# OAuth configuration
OAUTH_CONFIG = {
    "client_id": "security-use-cli",
    "auth_url": "https://lhirdknhtzkqynfavdao.supabase.co/functions/v1/oauth-device-code",
    "token_url": "https://lhirdknhtzkqynfavdao.supabase.co/functions/v1/oauth-token",
    "api_url": "https://lhirdknhtzkqynfavdao.supabase.co/functions/v1",
    "scopes": ["read", "write", "scan:upload"],
}


def get_config_dir() -> Path:
    """Get the configuration directory path."""
    # Use XDG_CONFIG_HOME on Linux, or platform-specific defaults
    if os.name == "nt":  # Windows
        config_dir = Path(os.environ.get("APPDATA", "~")).expanduser() / "security-use"
    else:  # macOS/Linux
        xdg_config = os.environ.get("XDG_CONFIG_HOME")
        if xdg_config:
            config_dir = Path(xdg_config) / "security-use"
        else:
            config_dir = Path.home() / ".config" / "security-use"

    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir


def get_config_file() -> Path:
    """Get the configuration file path."""
    return get_config_dir() / "config.json"


def get_token_file() -> Path:
    """Get the token file path."""
    return get_config_dir() / "credentials.json"


@dataclass
class AuthToken:
    """OAuth token data."""
    access_token: str
    refresh_token: Optional[str] = None
    token_type: str = "Bearer"
    expires_at: Optional[str] = None
    scope: Optional[str] = None

    def is_expired(self) -> bool:
        """Check if the token is expired."""
        if not self.expires_at:
            return False
        try:
            expires = datetime.fromisoformat(self.expires_at)
            return datetime.utcnow() >= expires
        except ValueError:
            return False

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "AuthToken":
        """Create from dictionary."""
        return cls(
            access_token=data["access_token"],
            refresh_token=data.get("refresh_token"),
            token_type=data.get("token_type", "Bearer"),
            expires_at=data.get("expires_at"),
            scope=data.get("scope"),
        )


@dataclass
class UserInfo:
    """Authenticated user information."""
    user_id: str
    email: str
    name: Optional[str] = None
    org_id: Optional[str] = None
    org_name: Optional[str] = None

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "UserInfo":
        """Create from dictionary."""
        return cls(
            user_id=data["user_id"],
            email=data["email"],
            name=data.get("name"),
            org_id=data.get("org_id"),
            org_name=data.get("org_name"),
        )


class AuthConfig:
    """Manages authentication configuration and tokens."""

    def __init__(self):
        self._token: Optional[AuthToken] = None
        self._user: Optional[UserInfo] = None
        self._load()

    def _load(self) -> None:
        """Load credentials from file."""
        token_file = get_token_file()
        if token_file.exists():
            try:
                data = json.loads(token_file.read_text())
                if "token" in data:
                    self._token = AuthToken.from_dict(data["token"])
                if "user" in data:
                    self._user = UserInfo.from_dict(data["user"])
            except (json.JSONDecodeError, KeyError):
                pass

    def _save(self) -> None:
        """Save credentials to file."""
        token_file = get_token_file()
        data = {}
        if self._token:
            data["token"] = self._token.to_dict()
        if self._user:
            data["user"] = self._user.to_dict()

        token_file.write_text(json.dumps(data, indent=2))

        # Set restrictive permissions on token file (Unix only)
        if os.name != "nt":
            os.chmod(token_file, 0o600)

    @property
    def token(self) -> Optional[AuthToken]:
        """Get the current auth token."""
        return self._token

    @property
    def user(self) -> Optional[UserInfo]:
        """Get the current user info."""
        return self._user

    @property
    def is_authenticated(self) -> bool:
        """Check if user is authenticated."""
        return self._token is not None and not self._token.is_expired()

    def save_token(self, token: AuthToken, user: Optional[UserInfo] = None) -> None:
        """Save authentication token and user info."""
        self._token = token
        if user:
            self._user = user
        self._save()

    def clear(self) -> None:
        """Clear all stored credentials."""
        self._token = None
        self._user = None
        token_file = get_token_file()
        if token_file.exists():
            token_file.unlink()

    def get_access_token(self) -> Optional[str]:
        """Get the access token if authenticated."""
        if self.is_authenticated and self._token:
            return self._token.access_token
        return None
