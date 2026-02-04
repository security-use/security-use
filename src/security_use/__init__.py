"""security-use - Security scanning tool for dependencies and Infrastructure as Code."""

__version__ = "0.2.9"

# Sensor imports (lazy-loaded for optional dependencies)
# Auth imports
from security_use import auth, sensor
from security_use.models import IaCFinding, ScanResult, Vulnerability
from security_use.scanner import scan_dependencies, scan_iac

__all__ = [
    "IaCFinding",
    "ScanResult",
    "Vulnerability",
    "__version__",
    "auth",
    "scan_dependencies",
    "scan_iac",
    "sensor",
]
