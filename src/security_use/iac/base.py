"""Base classes for IaC parsers."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class IaCResource:
    """Represents a parsed IaC resource."""

    resource_type: str
    name: str
    config: dict[str, Any]
    file_path: str
    line_number: int
    end_line: Optional[int] = None
    provider: str = "unknown"

    def get_config(self, *keys: str, default: Any = None) -> Any:
        """Get nested config value by key path.

        Args:
            *keys: Path of keys to traverse.
            default: Default value if not found.

        Returns:
            Config value or default.
        """
        current = self.config
        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return default
        return current


@dataclass
class ParseResult:
    """Result of parsing an IaC file."""

    resources: list[IaCResource] = field(default_factory=list)
    variables: dict[str, Any] = field(default_factory=dict)
    outputs: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


class IaCParser(ABC):
    """Abstract base class for IaC file parsers."""

    @abstractmethod
    def parse(self, content: str, file_path: str = "<string>") -> ParseResult:
        """Parse IaC file content.

        Args:
            content: File content to parse.
            file_path: Path to the file (for error reporting).

        Returns:
            ParseResult containing resources and any errors.
        """
        pass

    @classmethod
    @abstractmethod
    def supported_extensions(cls) -> list[str]:
        """Return list of supported file extensions."""
        pass
