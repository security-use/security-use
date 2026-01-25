# security-use

A security scanning library for Python projects. Provides vulnerability scanning for dependencies and Infrastructure as Code (IaC) files.

## Features

- **Dependency Scanning**: Detect known vulnerabilities (CVEs) in Python packages
- **IaC Scanning**: Find security misconfigurations in Terraform, CloudFormation, and other IaC formats
- **Automated Fixes**: Generate and apply fixes for detected issues

## Installation

```bash
pip install security-use
```

## Usage

### Command Line

```bash
# Scan dependencies
security-use scan deps /path/to/project

# Scan IaC files
security-use scan iac /path/to/terraform

# Scan everything
security-use scan all /path/to/project

# Auto-fix vulnerable dependencies
security-use fix /path/to/project
```

### Python API

```python
from security_use import scan_dependencies, scan_iac

# Scan dependencies
result = scan_dependencies("/path/to/project")

for vuln in result.vulnerabilities:
    print(f"{vuln.package}: {vuln.severity.value}")

# Scan IaC
result = scan_iac("/path/to/terraform")

for finding in result.iac_findings:
    print(f"{finding.rule_id}: {finding.title}")
```

## License

MIT
