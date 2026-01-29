"""Data models for SBOM generation."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class SBOMFormat(Enum):
    """Supported SBOM output formats."""

    CYCLONEDX_JSON = "cyclonedx-json"
    CYCLONEDX_XML = "cyclonedx-xml"
    SPDX_JSON = "spdx-json"
    SPDX_TV = "spdx-tv"  # Tag-value format


@dataclass
class SBOMComponent:
    """Represents a component in the SBOM."""

    name: str
    version: str
    ecosystem: str
    purl: Optional[str] = None
    licenses: list[str] = field(default_factory=list)
    hashes: dict[str, str] = field(default_factory=dict)
    supplier: Optional[str] = None
    description: Optional[str] = None
    vulnerabilities: list[str] = field(default_factory=list)


@dataclass
class SBOMOutput:
    """Result of SBOM generation."""

    format: SBOMFormat
    content: str
    component_count: int
    generated_at: datetime = field(default_factory=datetime.utcnow)
