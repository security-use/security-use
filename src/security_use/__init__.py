"""security-use - Security scanning tool for dependencies and Infrastructure as Code."""

__version__ = "0.1.0"

from security_use.scanner import scan_dependencies, scan_iac
from security_use.models import Vulnerability, IaCFinding, ScanResult

__all__ = [
    "__version__",
    "scan_dependencies",
    "scan_iac",
    "Vulnerability",
    "IaCFinding",
    "ScanResult",
]
