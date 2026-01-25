# SecureScan

A security scanning library for Python projects. Provides vulnerability scanning for dependencies and Infrastructure as Code (IaC) files.

## Features

- **Dependency Scanning**: Detect known vulnerabilities (CVEs) in Python packages
- **IaC Scanning**: Find security misconfigurations in Terraform, CloudFormation, and other IaC formats
- **Automated Fixes**: Generate and apply fixes for detected issues

## Installation

```bash
pip install securescan
```

## Usage

### Command Line

```bash
# Scan dependencies
securescan deps /path/to/project

# Scan IaC files
securescan iac /path/to/terraform
```

### Python API

```python
from security_use import DependencyScanner, IaCScanner

# Scan dependencies
scanner = DependencyScanner()
result = scanner.scan("/path/to/project")

for vuln in result.vulnerabilities:
    print(f"{vuln.package_name}: {vuln.severity}")

# Scan IaC
iac_scanner = IaCScanner()
result = iac_scanner.scan("/path/to/terraform")

for finding in result.findings:
    print(f"{finding.rule_id}: {finding.title}")
```

## License

MIT
