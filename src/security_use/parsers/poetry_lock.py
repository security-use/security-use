"""Parser for poetry.lock files."""

from security_use.parsers.base import Dependency, DependencyParser

try:
    import tomllib
except ImportError:
    import tomli as tomllib  # type: ignore[import-not-found]


class PoetryLockParser(DependencyParser):
    """Parser for poetry.lock files (TOML format)."""

    def parse(self, content: str) -> list[Dependency]:
        """Parse poetry.lock content."""
        try:
            data = tomllib.loads(content)
        except Exception:
            return []

        dependencies: list[Dependency] = []

        # Parse package entries
        for package in data.get("package", []):
            name = package.get("name")
            version = package.get("version")

            if name:
                dependencies.append(
                    Dependency(
                        name=name,
                        version=version,
                        version_spec=f"=={version}" if version else None,
                    )
                )

        return dependencies

    @classmethod
    def supported_filenames(cls) -> list[str]:
        """Return supported filenames."""
        return ["poetry.lock"]
