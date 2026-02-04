"""Base classes for dependency parsers."""

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class Dependency:
    """Represents a parsed dependency."""

    name: str
    version: str | None
    version_spec: str | None = None
    line_number: int | None = None
    extras: list[str] | None = None
    source: str | None = None
    ecosystem: str = "PyPI"

    @property
    def normalized_name(self) -> str:
        """Return normalized package name (lowercase, hyphens to underscores)."""
        return self.name.lower().replace("-", "_").replace(".", "_")


class DependencyParser(ABC):
    """Abstract base class for dependency file parsers."""

    @abstractmethod
    def parse(self, content: str) -> list[Dependency]:
        """Parse dependency file content and return list of dependencies.

        Args:
            content: The file content to parse.

        Returns:
            List of Dependency objects.
        """
        pass

    @classmethod
    @abstractmethod
    def supported_filenames(cls) -> list[str]:
        """Return list of filenames this parser supports."""
        pass
