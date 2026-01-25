"""Infrastructure as Code fixer.

Generates and optionally applies fixes for IaC security issues.
"""

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class FixResult:
    """Result of applying or suggesting a fix."""
    success: bool
    file_modified: str = ""
    old_version: str = ""
    new_version: str = ""
    diff: str = ""
    before: str = ""
    after: str = ""
    explanation: str = ""
    error: Optional[str] = None


# Fix mappings for known rules
IAC_FIXES = {
    "AWS001": {
        "pattern": r'acl\s*=\s*"public-read"',
        "replacement": 'acl = "private"',
        "explanation": "Changed S3 bucket ACL from public-read to private to prevent unauthorized public access.",
    },
    "AWS002": {
        "pattern": r'(versioning\s*\{[^}]*enabled\s*=\s*)false',
        "replacement": r'\g<1>true',
        "explanation": "Enabled S3 bucket versioning to allow recovery of accidentally deleted objects.",
    },
    "AWS003": {
        "pattern": r'cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]',
        "replacement": 'cidr_blocks = ["10.0.0.0/8"]',
        "explanation": "Restricted security group ingress to private IP range. Update this to your specific IP range.",
    },
    "AWS004": {
        "pattern": r'publicly_accessible\s*=\s*true',
        "replacement": 'publicly_accessible = false',
        "explanation": "Disabled public accessibility for RDS instance. Access via VPC or bastion host instead.",
    },
    "AWS005": {
        "pattern": r'encrypted\s*=\s*false',
        "replacement": 'encrypted = true',
        "explanation": "Enabled EBS volume encryption to protect data at rest.",
    },
    "AWS006": {
        "pattern": r'"Action"\s*:\s*"\*"',
        "replacement": '"Action": ["s3:GetObject", "s3:PutObject"]',
        "explanation": "Replaced wildcard action with specific actions. Update to your required actions.",
    },
    "AWS007": {
        "pattern": r'enable_logging\s*=\s*false',
        "replacement": 'enable_logging = true',
        "explanation": "Enabled CloudTrail logging to maintain audit trail.",
    },
    "AWS008": {
        "pattern": r'enable_key_rotation\s*=\s*false',
        "replacement": 'enable_key_rotation = true',
        "explanation": "Enabled KMS key rotation for improved security compliance.",
    },
}


class IaCFixer:
    """Fixer for Infrastructure as Code security issues."""

    def __init__(self):
        self.fixes = IAC_FIXES

    def fix(
        self,
        file_path: str,
        rule_id: str,
        line_number: Optional[int] = None,
        auto_apply: bool = False
    ) -> FixResult:
        """Fix an IaC security issue.

        Args:
            file_path: Path to the IaC file.
            rule_id: ID of the security rule that was violated.
            line_number: Optional line number where the issue is located.
            auto_apply: If True, apply the fix. If False, only suggest.

        Returns:
            FixResult with the fix details.
        """
        path_obj = Path(file_path)

        if not path_obj.exists():
            return FixResult(
                success=False,
                error=f"File does not exist: {file_path}"
            )

        if rule_id not in self.fixes:
            return FixResult(
                success=False,
                error=f"No fix available for rule: {rule_id}"
            )

        fix_info = self.fixes[rule_id]

        try:
            content = path_obj.read_text()
            lines = content.split("\n")

            # Find the problematic section
            pattern = re.compile(fix_info["pattern"], re.IGNORECASE | re.MULTILINE)
            match = pattern.search(content)

            if not match:
                return FixResult(
                    success=False,
                    error=f"Could not find the issue pattern for rule {rule_id}"
                )

            # Get the before snippet
            match_line = content[:match.start()].count("\n")
            start_line = max(0, match_line - 2)
            end_line = min(len(lines), match_line + 5)
            before_snippet = "\n".join(lines[start_line:end_line])

            # Apply the fix
            new_content = pattern.sub(fix_info["replacement"], content, count=1)
            new_lines = new_content.split("\n")

            # Get the after snippet
            after_snippet = "\n".join(new_lines[start_line:end_line])

            # Generate diff
            diff = self._generate_diff(content, new_content)

            if auto_apply:
                # Write the fixed content
                path_obj.write_text(new_content)
                return FixResult(
                    success=True,
                    file_modified=file_path,
                    diff=diff,
                    before=before_snippet,
                    after=after_snippet,
                    explanation=fix_info["explanation"],
                )
            else:
                # Return suggested fix without applying
                return FixResult(
                    success=True,
                    before=before_snippet,
                    after=after_snippet,
                    diff=diff,
                    explanation=fix_info["explanation"],
                )

        except Exception as e:
            return FixResult(
                success=False,
                error=str(e)
            )

    def _generate_diff(self, old_content: str, new_content: str) -> str:
        """Generate a unified diff of the changes."""
        old_lines = old_content.split("\n")
        new_lines = new_content.split("\n")

        diff_lines = []
        for i, (old_line, new_line) in enumerate(zip(old_lines, new_lines)):
            if old_line != new_line:
                diff_lines.append(f"-{old_line}")
                diff_lines.append(f"+{new_line}")

        # Handle length differences
        if len(old_lines) > len(new_lines):
            for line in old_lines[len(new_lines):]:
                diff_lines.append(f"-{line}")
        elif len(new_lines) > len(old_lines):
            for line in new_lines[len(old_lines):]:
                diff_lines.append(f"+{line}")

        return "\n".join(diff_lines) if diff_lines else "No changes"

    def get_available_fixes(self) -> list[str]:
        """Get list of rule IDs that have available fixes."""
        return list(self.fixes.keys())
