"""Parser for pyproject.toml files (PEP 621 and Poetry formats)."""

import re
from typing import Any, Optional

from security_use.parsers.base import Dependency, DependencyParser

try:
    import tomllib
except ImportError:
    import tomli as tomllib  # type: ignore[import-not-found]


class PyProjectParser(DependencyParser):
    """Parser for pyproject.toml files supporting PEP 621 and Poetry formats."""

    VERSION_RE = re.compile(
        r"^(?P<name>[a-zA-Z0-9][-a-zA-Z0-9._]*)"
        r"(?:\[(?P<extras>[^\]]+)\])?"
        r"(?P<spec>(?:[<>=!~^]+[^;#\s,]+,?)+)?"
        r"(?:;.*)?$"
    )

    def parse(self, content: str) -> list[Dependency]:
        """Parse pyproject.toml content."""
        try:
            data = tomllib.loads(content)
        except Exception:
            return []

        dependencies: list[Dependency] = []

        # Parse PEP 621 format ([project] section)
        dependencies.extend(self._parse_pep621(data))

        # Parse Poetry format ([tool.poetry] section)
        dependencies.extend(self._parse_poetry(data))

        return dependencies

    def _parse_pep621(self, data: dict[str, Any]) -> list[Dependency]:
        """Parse PEP 621 format dependencies."""
        dependencies = []
        project = data.get("project", {})

        # Main dependencies
        for dep_str in project.get("dependencies", []):
            dep = self._parse_requirement_string(dep_str)
            if dep:
                dependencies.append(dep)

        # Optional dependencies
        for group_deps in project.get("optional-dependencies", {}).values():
            for dep_str in group_deps:
                dep = self._parse_requirement_string(dep_str)
                if dep:
                    dependencies.append(dep)

        return dependencies

    def _parse_poetry(self, data: dict[str, Any]) -> list[Dependency]:
        """Parse Poetry format dependencies."""
        dependencies = []
        poetry = data.get("tool", {}).get("poetry", {})

        # Main dependencies
        dependencies.extend(
            self._parse_poetry_deps(poetry.get("dependencies", {}))
        )

        # Dev dependencies (old format)
        dependencies.extend(
            self._parse_poetry_deps(poetry.get("dev-dependencies", {}))
        )

        # Group dependencies (new format)
        for group in poetry.get("group", {}).values():
            dependencies.extend(
                self._parse_poetry_deps(group.get("dependencies", {}))
            )

        return dependencies

    def _parse_poetry_deps(
        self, deps: dict[str, Any]
    ) -> list[Dependency]:
        """Parse Poetry dependencies dict."""
        dependencies = []

        for name, spec in deps.items():
            # Skip python version requirement
            if name.lower() == "python":
                continue

            version = None
            version_spec = None
            extras = None

            if isinstance(spec, str):
                version, version_spec = self._parse_poetry_version(spec)
            elif isinstance(spec, dict):
                ver = spec.get("version")
                if ver:
                    version, version_spec = self._parse_poetry_version(ver)
                extras = spec.get("extras")

            dependencies.append(
                Dependency(
                    name=name,
                    version=version,
                    version_spec=version_spec,
                    extras=extras,
                )
            )

        return dependencies

    def _parse_poetry_version(self, spec: str) -> tuple[Optional[str], str]:
        """Parse Poetry version specifier."""
        spec = spec.strip()

        # Exact version
        if spec.startswith("=="):
            return spec[2:].strip(), spec

        # Caret (^) - compatible release
        if spec.startswith("^"):
            return spec[1:].strip(), spec

        # Tilde (~) - compatible release
        if spec.startswith("~"):
            return spec[1:].strip(), spec

        # Wildcard
        if spec == "*":
            return None, spec

        # Plain version (treated as exact)
        if re.match(r"^[\d.]+", spec):
            return spec, f"=={spec}"

        return None, spec

    def _parse_requirement_string(self, req: str) -> Optional[Dependency]:
        """Parse a PEP 508 requirement string."""
        req = req.strip()
        match = self.VERSION_RE.match(req)
        if not match:
            # Handle bare package names
            if re.match(r"^[a-zA-Z0-9][-a-zA-Z0-9._]*$", req):
                return Dependency(name=req, version=None)
            return None

        name = match.group("name")
        extras_str = match.group("extras")
        spec = match.group("spec")

        extras = [e.strip() for e in extras_str.split(",")] if extras_str else None

        version = None
        if spec:
            # Extract exact version if pinned
            if "==" in spec:
                ver_match = re.search(r"==([^,<>=!~;#\s]+)", spec)
                if ver_match:
                    version = ver_match.group(1)

        return Dependency(
            name=name,
            version=version,
            version_spec=spec,
            extras=extras,
        )

    @classmethod
    def supported_filenames(cls) -> list[str]:
        """Return supported filenames."""
        return ["pyproject.toml"]
