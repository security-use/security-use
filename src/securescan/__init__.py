"""SecureScan - Security scanning tool for dependencies and Infrastructure as Code."""

__version__ = "0.1.0"

from securescan.scanner import scan_dependencies, scan_iac
from securescan.models import Vulnerability, IaCFinding, ScanResult

__all__ = [
    "__version__",
    "scan_dependencies",
    "scan_iac",
    "Vulnerability",
    "IaCFinding",
    "ScanResult",
]
