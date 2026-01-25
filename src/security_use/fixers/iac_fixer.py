"""Infrastructure as Code fixer.

Generates and optionally applies fixes for IaC security issues.
"""

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class IaCFixResult:
    """Result of applying or suggesting a fix."""
    success: bool
    file_path: str = ""
    rule_id: str = ""
    resource_name: str = ""
    before: str = ""
    after: str = ""
    explanation: str = ""
    error: Optional[str] = None


# Fix mappings for known rules - using CKV rule IDs from scanner
IAC_FIXES = {
    # S3 Bucket Rules
    "CKV_AWS_20": {  # S3 bucket with public access
        "pattern": r'acl\s*=\s*"public-read(?:-write)?"',
        "replacement": 'acl = "private"',
        "explanation": "Changed S3 bucket ACL from public to private to prevent unauthorized access.",
    },
    "CKV_AWS_19": {  # S3 bucket without encryption - handled via additions
        "skip": True,  # Use additions instead for cleaner handling
        "explanation": "Added server-side encryption configuration to S3 bucket.",
    },
    # Security Group Rules
    "CKV_AWS_23": {  # Security group allows unrestricted ingress
        "pattern": r'cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]',
        "replacement": 'cidr_blocks = ["10.0.0.0/8"]  # TODO: Restrict to your IP range',
        "explanation": "Restricted security group ingress to private IP range. Update to your specific IP range.",
    },
    # RDS Rules
    "CKV_AWS_16": {  # RDS instance without encryption
        "pattern": r'(resource\s+"aws_db_instance"\s+"[^"]+"\s*\{)',
        "replacement": r'\1\n  storage_encrypted = true',
        "explanation": "Enabled storage encryption for RDS instance.",
        "multiline": True,
    },
    # EBS Rules
    "CKV_AWS_3": {  # EBS volume without encryption
        "pattern": r'encrypted\s*=\s*false',
        "replacement": 'encrypted = true',
        "explanation": "Enabled EBS volume encryption to protect data at rest.",
    },
    # CloudTrail Rules
    "CKV_AWS_35": {  # CloudTrail not logging all events
        "pattern": r'is_multi_region_trail\s*=\s*false',
        "replacement": 'is_multi_region_trail = true',
        "explanation": "Enabled multi-region CloudTrail logging.",
    },
    # IAM Rules
    "CKV_AWS_40": {  # IAM policy with wildcard action
        "pattern": r'"Action"\s*:\s*"\*"',
        "replacement": '"Action": ["s3:GetObject", "s3:PutObject"]  # TODO: Specify required actions',
        "explanation": "Replaced wildcard action with specific actions. Update to your required actions.",
    },
    # KMS Rules
    "CKV_AWS_7": {  # KMS key rotation disabled
        "pattern": r'enable_key_rotation\s*=\s*false',
        "replacement": 'enable_key_rotation = true',
        "explanation": "Enabled KMS key rotation for improved security compliance.",
    },
}

# Additional patterns for adding missing configurations
IAC_ADDITIONS = {
    "CKV_AWS_19": {  # S3 bucket without encryption - add block if not present
        "resource_type": "aws_s3_bucket",
        "check_pattern": r'server_side_encryption_configuration',
        "add_block": '''
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }''',
        "explanation": "Added server-side encryption configuration to S3 bucket.",
    },
    "CKV_AWS_3": {  # EBS volume - add encrypted = true if not present
        "resource_type": "aws_ebs_volume",
        "check_pattern": r'encrypted\s*=',
        "add_block": '\n  encrypted = true',
        "explanation": "Added encryption setting to EBS volume.",
    },
    "CKV_AWS_16": {  # RDS - add storage_encrypted if not present
        "resource_type": "aws_db_instance",
        "check_pattern": r'storage_encrypted\s*=',
        "add_block": '\n  storage_encrypted = true',
        "explanation": "Added storage encryption to RDS instance.",
    },
}


class IaCFixer:
    """Fixer for Infrastructure as Code security issues."""

    def __init__(self):
        self.fixes = IAC_FIXES
        self.additions = IAC_ADDITIONS

    def fix_finding(
        self,
        file_path: str,
        rule_id: str,
        resource_name: str,
        line_number: Optional[int] = None,
        auto_apply: bool = True
    ) -> IaCFixResult:
        """Fix an IaC security issue.

        Args:
            file_path: Path to the IaC file.
            rule_id: ID of the security rule that was violated.
            resource_name: Name of the resource with the issue.
            line_number: Optional line number where the issue is located.
            auto_apply: If True, apply the fix. If False, only suggest.

        Returns:
            IaCFixResult with the fix details.
        """
        path_obj = Path(file_path)

        if not path_obj.exists():
            return IaCFixResult(
                success=False,
                file_path=file_path,
                rule_id=rule_id,
                error=f"File does not exist: {file_path}"
            )

        try:
            content = path_obj.read_text()
            original_content = content
            fix_applied = False
            explanation = ""

            # Try pattern replacement first
            if rule_id in self.fixes:
                fix_info = self.fixes[rule_id]

                # Skip if marked to use additions instead
                if fix_info.get("skip"):
                    pass  # Fall through to additions
                else:
                    flags = re.IGNORECASE | re.MULTILINE
                    if fix_info.get("multiline"):
                        flags |= re.DOTALL

                    pattern = re.compile(fix_info["pattern"], flags)

                    if pattern.search(content):
                        content = pattern.sub(fix_info["replacement"], content, count=1)
                        fix_applied = True
                        explanation = fix_info["explanation"]

            # Try adding missing configuration blocks
            if not fix_applied and rule_id in self.additions:
                add_info = self.additions[rule_id]
                resource_type = add_info["resource_type"]
                check_pattern = add_info["check_pattern"]

                # Check if already has this configuration in the file
                if re.search(check_pattern, content, re.IGNORECASE):
                    return IaCFixResult(
                        success=False,
                        file_path=file_path,
                        rule_id=rule_id,
                        resource_name=resource_name,
                        error="Configuration already exists in file"
                    )

                # Find the resource block - match balanced braces
                resource_start_pattern = rf'resource\s+"{resource_type}"\s+"{re.escape(resource_name)}"\s*\{{'
                match = re.search(resource_start_pattern, content)

                if match:
                    # Find the matching closing brace
                    start_pos = match.end() - 1  # Position of opening brace
                    brace_count = 1
                    pos = start_pos + 1

                    while pos < len(content) and brace_count > 0:
                        if content[pos] == '{':
                            brace_count += 1
                        elif content[pos] == '}':
                            brace_count -= 1
                        pos += 1

                    if brace_count == 0:
                        # Insert the new block before the closing brace
                        insert_pos = pos - 1
                        new_content = content[:insert_pos] + add_info["add_block"] + "\n" + content[insert_pos:]
                        content = new_content
                        fix_applied = True
                        explanation = add_info["explanation"]

            if not fix_applied:
                return IaCFixResult(
                    success=False,
                    file_path=file_path,
                    rule_id=rule_id,
                    resource_name=resource_name,
                    error=f"No automatic fix available for rule {rule_id} or pattern not found"
                )

            # Get before/after snippets
            before_lines = original_content.split("\n")
            after_lines = content.split("\n")

            # Find changed region
            start_line = 0
            end_line = len(before_lines)
            if line_number:
                start_line = max(0, line_number - 3)
                end_line = min(len(before_lines), line_number + 10)

            before_snippet = "\n".join(before_lines[start_line:end_line])
            after_snippet = "\n".join(after_lines[start_line:min(len(after_lines), end_line + 5)])

            if auto_apply:
                path_obj.write_text(content)
                return IaCFixResult(
                    success=True,
                    file_path=file_path,
                    rule_id=rule_id,
                    resource_name=resource_name,
                    before=before_snippet,
                    after=after_snippet,
                    explanation=explanation,
                )
            else:
                return IaCFixResult(
                    success=True,
                    file_path=file_path,
                    rule_id=rule_id,
                    resource_name=resource_name,
                    before=before_snippet,
                    after=after_snippet,
                    explanation=explanation,
                )

        except Exception as e:
            return IaCFixResult(
                success=False,
                file_path=file_path,
                rule_id=rule_id,
                error=str(e)
            )

    def get_available_fixes(self) -> list[str]:
        """Get list of rule IDs that have available fixes."""
        all_rules = set(self.fixes.keys()) | set(self.additions.keys())
        return sorted(list(all_rules))

    def has_fix(self, rule_id: str) -> bool:
        """Check if a fix is available for a rule."""
        return rule_id in self.fixes or rule_id in self.additions
