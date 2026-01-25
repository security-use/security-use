"""Dependency file parsers."""

from security_use.parsers.base import Dependency, DependencyParser
from security_use.parsers.requirements import RequirementsParser
from security_use.parsers.pyproject import PyProjectParser
from security_use.parsers.pipfile import PipfileParser
from security_use.parsers.poetry_lock import PoetryLockParser
from security_use.parsers.maven import MavenParser
from security_use.parsers.npm import NpmParser, NpmLockParser

__all__ = [
    "Dependency",
    "DependencyParser",
    "RequirementsParser",
    "PyProjectParser",
    "PipfileParser",
    "PoetryLockParser",
    "MavenParser",
    "NpmParser",
    "NpmLockParser",
]
