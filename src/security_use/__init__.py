"""Security-Use - Compatibility layer providing the security_use API.

This module provides the API expected by the MCP server, wrapping the
underlying securescan implementation.
"""

__version__ = "0.1.0"

from security_use.scanners.dependency_scanner import DependencyScanner
from security_use.scanners.iac_scanner import IaCScanner
from security_use.fixers.dependency_fixer import DependencyFixer
from security_use.fixers.iac_fixer import IaCFixer

__all__ = [
    "__version__",
    "DependencyScanner",
    "IaCScanner",
    "DependencyFixer",
    "IaCFixer",
]
