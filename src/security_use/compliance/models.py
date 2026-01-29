"""Data models for compliance mapping."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class ComplianceFramework(Enum):
    """Supported compliance frameworks."""

    SOC2 = "soc2"
    HIPAA = "hipaa"
    PCI_DSS = "pci-dss"
    NIST_800_53 = "nist-800-53"
    CIS_AWS = "cis-aws"
    CIS_AZURE = "cis-azure"
    CIS_GCP = "cis-gcp"
    CIS_K8S = "cis-kubernetes"
    ISO_27001 = "iso-27001"


@dataclass
class ComplianceControl:
    """Represents a compliance control/requirement."""

    framework: ComplianceFramework
    control_id: str
    title: str
    description: str
    category: Optional[str] = None


@dataclass
class ComplianceMapping:
    """Maps a security rule to compliance controls."""

    rule_id: str
    controls: list[ComplianceControl] = field(default_factory=list)


@dataclass
class ComplianceFinding:
    """A finding with compliance context."""

    rule_id: str
    title: str
    severity: str
    file_path: str
    line_number: int
    controls: list[ComplianceControl] = field(default_factory=list)
