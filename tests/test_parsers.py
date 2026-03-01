"""Tests for dependency file parsers."""

import pytest

from security_use.parsers import (
    RequirementsParser,
    PyProjectParser,
    PipfileParser,
    PoetryLockParser,
)
from security_use.parsers.pipfile import PipfileLockParser


class TestRequirementsParser:
    """Tests for requirements.txt parser."""

    def test_parse_pinned_version(self):
        content = "requests==2.28.0"
        parser = RequirementsParser()
        deps = parser.parse(content)

        assert len(deps) == 1
        assert deps[0].name == "requests"
        assert deps[0].version == "2.28.0"

    def test_parse_version_range(self):
        content = "django>=3.0,<4.0"
        parser = RequirementsParser()
        deps = parser.parse(content)

        assert len(deps) == 1
        assert deps[0].name == "django"
        assert deps[0].version == "3.0"

    def test_parse_with_extras(self):
        content = "requests[security]==2.28.0"
        parser = RequirementsParser()
        deps = parser.parse(content)

        assert len(deps) == 1
        assert deps[0].name == "requests"
        assert deps[0].extras == ["security"]

    def test_parse_with_comments(self):
        content = """
# This is a comment
requests==2.28.0  # inline comment
django==3.2.0
"""
        parser = RequirementsParser()
        deps = parser.parse(content)

        assert len(deps) == 2
        assert deps[0].name == "requests"
        assert deps[1].name == "django"

    def test_parse_empty_lines(self):
        content = """
requests==2.28.0

django==3.2.0

"""
        parser = RequirementsParser()
        deps = parser.parse(content)

        assert len(deps) == 2

    def test_skip_editable_installs(self):
        content = """
-e git+https://github.com/user/repo.git#egg=package
requests==2.28.0
"""
        parser = RequirementsParser()
        deps = parser.parse(content)

        assert len(deps) == 1
        assert deps[0].name == "requests"


class TestPyProjectParser:
    """Tests for pyproject.toml parser."""

    def test_parse_pep621_dependencies(self):
        content = """
[project]
name = "myproject"
dependencies = [
    "requests>=2.28.0",
    "django==3.2.0",
]
"""
        parser = PyProjectParser()
        deps = parser.parse(content)

        assert len(deps) == 2
        assert deps[0].name == "requests"
        assert deps[1].name == "django"
        assert deps[1].version == "3.2.0"

    def test_parse_pep621_optional_dependencies(self):
        content = """
[project]
name = "myproject"
dependencies = ["requests>=2.28.0"]

[project.optional-dependencies]
dev = ["pytest>=7.0.0"]
"""
        parser = PyProjectParser()
        deps = parser.parse(content)

        assert len(deps) == 2
        names = {d.name for d in deps}
        assert "requests" in names
        assert "pytest" in names

    def test_parse_poetry_dependencies(self):
        content = """
[tool.poetry]
name = "myproject"

[tool.poetry.dependencies]
python = "^3.10"
requests = "^2.28.0"
django = "3.2.0"
"""
        parser = PyProjectParser()
        deps = parser.parse(content)

        assert len(deps) == 2  # python is skipped
        names = {d.name for d in deps}
        assert "requests" in names
        assert "django" in names

    def test_parse_poetry_dev_dependencies(self):
        content = """
[tool.poetry.dev-dependencies]
pytest = "^7.0.0"
"""
        parser = PyProjectParser()
        deps = parser.parse(content)

        assert len(deps) == 1
        assert deps[0].name == "pytest"


class TestPipfileParser:
    """Tests for Pipfile parser."""

    def test_parse_packages(self):
        content = """
[packages]
requests = "==2.28.0"
django = "*"

[dev-packages]
pytest = ">=7.0.0"
"""
        parser = PipfileParser()
        deps = parser.parse(content)

        assert len(deps) == 3
        names = {d.name for d in deps}
        assert "requests" in names
        assert "django" in names
        assert "pytest" in names


class TestPipfileLockParser:
    """Tests for Pipfile.lock parser."""

    def test_parse_lock_file(self):
        content = """
{
    "default": {
        "requests": {"version": "==2.28.0"},
        "django": {"version": "==3.2.0"}
    },
    "develop": {
        "pytest": {"version": "==7.0.0"}
    }
}
"""
        parser = PipfileLockParser()
        deps = parser.parse(content)

        assert len(deps) == 3
        versions = {d.name: d.version for d in deps}
        assert versions["requests"] == "2.28.0"
        assert versions["django"] == "3.2.0"
        assert versions["pytest"] == "7.0.0"


class TestPoetryLockParser:
    """Tests for poetry.lock parser."""

    def test_parse_lock_file(self):
        content = """
[[package]]
name = "requests"
version = "2.28.0"

[[package]]
name = "django"
version = "3.2.0"
"""
        parser = PoetryLockParser()
        deps = parser.parse(content)

        assert len(deps) == 2
        versions = {d.name: d.version for d in deps}
        assert versions["requests"] == "2.28.0"
        assert versions["django"] == "3.2.0"
