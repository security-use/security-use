"""Base classes for IaC security rules."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Optional

from security_use.models import Severity
from security_use.iac.base import IaCResource


@dataclass
class RuleResult:
    """Result of applying a rule to a resource."""

    passed: bool
    rule_id: str
    title: str
    severity: Severity
    resource_type: str
    resource_name: str
    description: str
    remediation: str
    fix_code: Optional[str] = None


class Rule(ABC):
    """Abstract base class for security rules."""

    # Rule metadata - override in subclasses
    RULE_ID: str = "UNKNOWN"
    TITLE: str = "Unknown Rule"
    SEVERITY: Severity = Severity.MEDIUM
    DESCRIPTION: str = ""
    REMEDIATION: str = ""

    # Resource types this rule applies to
    RESOURCE_TYPES: list[str] = []

    @abstractmethod
    def evaluate(self, resource: IaCResource) -> RuleResult:
        """Evaluate the rule against a resource.

        Args:
            resource: The IaC resource to evaluate.

        Returns:
            RuleResult indicating pass/fail and details.
        """
        pass

    def applies_to(self, resource: IaCResource) -> bool:
        """Check if this rule applies to the given resource.

        Args:
            resource: The IaC resource to check.

        Returns:
            True if the rule should be evaluated for this resource.
        """
        if not self.RESOURCE_TYPES:
            return False

        # Handle both Terraform and CloudFormation resource types
        resource_type = resource.resource_type.lower()
        for rule_type in self.RESOURCE_TYPES:
            if rule_type.lower() in resource_type:
                return True
        return False

    def _create_result(
        self,
        passed: bool,
        resource: IaCResource,
        fix_code: Optional[str] = None,
    ) -> RuleResult:
        """Create a RuleResult for this rule.

        Args:
            passed: Whether the rule passed.
            resource: The evaluated resource.
            fix_code: Optional suggested fix code.

        Returns:
            RuleResult with rule metadata.
        """
        return RuleResult(
            passed=passed,
            rule_id=self.RULE_ID,
            title=self.TITLE,
            severity=self.SEVERITY,
            resource_type=resource.resource_type,
            resource_name=resource.name,
            description=self.DESCRIPTION,
            remediation=self.REMEDIATION,
            fix_code=fix_code,
        )
