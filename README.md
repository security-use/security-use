<p align="center">
  <a href="https://security-use.dev">
    <img src="assets/logo.svg" alt="SecurityUse" width="400">
  </a>
</p>

<p align="center">
  <strong>Comprehensive security scanning for modern applications</strong>
</p>

<p align="center">
  <a href="https://pypi.org/project/security-use/"><img src="https://img.shields.io/pypi/v/security-use?color=5EEAD4&style=flat-square" alt="PyPI"></a>
  <a href="https://pypi.org/project/security-use/"><img src="https://img.shields.io/pypi/pyversions/security-use?color=5EEAD4&style=flat-square" alt="Python Versions"></a>
  <a href="https://github.com/security-use/security-use/blob/main/LICENSE"><img src="https://img.shields.io/github/license/security-use/security-use?color=5EEAD4&style=flat-square" alt="License"></a>
  <a href="https://github.com/security-use/security-use/actions"><img src="https://img.shields.io/github/actions/workflow/status/security-use/security-use/ci.yml?style=flat-square" alt="CI"></a>
</p>

<p align="center">
  <a href="#installation">Installation</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#features">Features</a> •
  <a href="#contributing">Contributing</a>
</p>

---

## Overview

**SecurityUse** is a unified security scanning platform for Python applications. It detects vulnerabilities in dependencies, misconfigurations in Infrastructure as Code, and provides runtime attack detection for web applications.

```bash
$ security-use scan all ./my-project

 SecurityUse v0.2.8

 Scanning dependencies...
 ✓ Found 3 vulnerabilities in 47 packages

 Scanning IaC files...
 ✓ Found 2 misconfigurations in 5 files

 ┌─────────────────────────────────────────────────────────────────┐
 │ CRITICAL  1   │   HIGH  2   │   MEDIUM  2   │   LOW  0         │
 └─────────────────────────────────────────────────────────────────┘

 Results synced to dashboard (5 finding(s))
```

## Features

### Dependency Vulnerability Scanning

Detect known CVEs in your Python dependencies using the [OSV database](https://osv.dev/).

- **Multi-format support**: `requirements.txt`, `Pipfile`, `pyproject.toml`, `poetry.lock`, `package.json`, `pom.xml`
- **Accurate matching**: Uses package ecosystem data for precise vulnerability matching
- **Severity scoring**: CVSS-based severity ratings (Critical, High, Medium, Low)
- **Fix suggestions**: Recommends safe versions to upgrade to

### Infrastructure as Code Scanning

Find security misconfigurations before they reach production.

| Platform | Formats | Rules |
|----------|---------|-------|
| **Terraform** | `.tf`, `.tf.json` | 25+ |
| **CloudFormation** | `.yaml`, `.yml`, `.json` | 20+ |
| **AWS** | S3, EC2, IAM, RDS, Lambda | Full coverage |

**Detects:**
- Unencrypted storage and databases
- Overly permissive IAM policies
- Public access to sensitive resources
- Missing logging and monitoring
- Insecure network configurations

### Runtime Security Sensor

Real-time attack detection middleware for FastAPI and Flask applications with dashboard integration.

```python
from fastapi import FastAPI
from security_use.sensor import SecurityMiddleware

app = FastAPI()

# Dashboard integration (recommended)
app.add_middleware(
    SecurityMiddleware,
    api_key="su_...",  # Or set SECURITY_USE_API_KEY env var
    block_on_detection=True,
)

# Auto-detect vulnerable endpoints from code analysis
app.add_middleware(
    SecurityMiddleware,
    auto_detect_vulnerable=True,
    project_path="./",
)

# Selective path monitoring
app.add_middleware(
    SecurityMiddleware,
    watch_paths=["/api/users", "/api/search", "/admin/*"],
    excluded_paths=["/health", "/metrics"],
)
```

**Detects:**
- SQL Injection (`' OR 1=1--`, `UNION SELECT`, etc.)
- Cross-Site Scripting (`<script>`, `javascript:`, event handlers)
- Path Traversal (`../`, `%2e%2e%2f`, etc.)
- Command Injection (`;cat /etc/passwd`, backticks, `$()`)
- Rate limit violations
- Suspicious user agents (sqlmap, nikto, etc.)

**Features:**
- Dashboard alerting with API key authentication
- Auto-detection of vulnerable endpoints via code analysis
- Selective path monitoring with wildcards
- Blocks attacks and reports to dashboard in real-time

### Auto-Fix

Automatically remediate security issues with a single command.

```bash
security-use fix ./my-project
```

**Dependency Fixes:**
- Updates vulnerable packages to patched versions
- Supports `requirements.txt`, `Pipfile`, `pyproject.toml`

**IaC Fixes:**

| Rule | Issue | Auto-Fix |
|------|-------|----------|
| CKV_AWS_19 | S3 bucket without encryption | Adds AES256 server-side encryption |
| CKV_AWS_20 | S3 bucket with public access | Changes ACL to private |
| CKV_AWS_3 | EBS volume unencrypted | Sets `encrypted = true` |
| CKV_AWS_16 | RDS instance unencrypted | Adds `storage_encrypted = true` |
| CKV_AWS_23 | Open security group ingress | Restricts CIDR blocks |

### Dashboard Integration

Sync your scan results to the [SecurityUse Dashboard](https://security-use.dev) for centralized monitoring, trend analysis, and team collaboration.

```bash
# Authenticate once
security-use auth login

# All scans now auto-sync to dashboard!
security-use scan all ./my-project
# → Results synced to dashboard (X finding(s))
```

**Features:**
- **Automatic sync**: Once logged in, all scan results are automatically uploaded
- **Multi-repo support**: Each repository is tracked separately with git metadata
- **No extra commands**: Just run your normal scans - syncing happens automatically

```bash
# Auth commands
security-use auth login     # Authenticate with dashboard
security-use auth status    # Check authentication status
security-use auth logout    # Clear credentials

# Manual sync (if needed)
security-use sync ./my-project --project "My App"
```

## Installation

```bash
pip install security-use
```

**With optional dependencies:**

```bash
# For runtime sensor with FastAPI/Flask
pip install security-use[sensor]

# For development
pip install security-use[dev]
```

**Requirements:** Python 3.10+

## Quick Start

### Command Line Interface

```bash
# Scan dependencies for vulnerabilities
security-use scan deps ./my-project

# Scan Infrastructure as Code
security-use scan iac ./terraform

# Scan everything
security-use scan all ./my-project

# Output as JSON
security-use scan all ./my-project --format json

# Output as SARIF (for GitHub Code Scanning)
security-use scan all ./my-project --format sarif > results.sarif

# Auto-fix vulnerabilities and IaC misconfigurations
security-use fix ./my-project

# Auto-fix with options
security-use fix ./my-project --dry-run      # Preview changes
security-use fix ./my-project --deps-only    # Only fix dependencies
security-use fix ./my-project --iac-only     # Only fix IaC issues

# Dashboard integration (results auto-sync when logged in)
security-use auth login                       # Authenticate with dashboard
security-use auth status                      # Check auth status
security-use auth logout                      # Clear credentials
```

### Python API

```python
from security_use import scan_dependencies, scan_iac

# Scan dependencies
result = scan_dependencies("./my-project")

print(f"Found {len(result.vulnerabilities)} vulnerabilities")
for vuln in result.vulnerabilities:
    print(f"  {vuln.severity.value}: {vuln.package} - {vuln.title}")

# Scan IaC
result = scan_iac("./terraform")

for finding in result.iac_findings:
    print(f"  [{finding.severity.value}] {finding.rule_id}")
    print(f"    {finding.title}")
    print(f"    {finding.file_path}:{finding.line_number}")
```

### Runtime Sensor

**FastAPI (ASGI) with Dashboard:**

```python
from fastapi import FastAPI
from security_use.sensor import SecurityMiddleware

app = FastAPI()

# Recommended: Dashboard integration
app.add_middleware(
    SecurityMiddleware,
    api_key="su_...",                # Or set SECURITY_USE_API_KEY env var
    block_on_detection=True,         # Return 403 on attacks (default)
    excluded_paths=["/health", "/metrics"],
    rate_limit_threshold=100,        # Requests per minute per IP
)

# Or with auto-detection of vulnerable endpoints
app.add_middleware(
    SecurityMiddleware,
    api_key="su_...",
    auto_detect_vulnerable=True,     # Scan code for risky endpoints
    project_path="./",
)

# Or monitor specific paths only
app.add_middleware(
    SecurityMiddleware,
    api_key="su_...",
    watch_paths=["/api/users", "/admin/*"],  # Only monitor these
)

@app.get("/api/users")
def get_users():
    return {"users": []}
```

**Flask (WSGI):**

```python
from flask import Flask
from security_use.sensor import FlaskSecurityMiddleware

app = Flask(__name__)

app.wsgi_app = FlaskSecurityMiddleware(
    app.wsgi_app,
    api_key="su_...",          # Dashboard integration
    block_on_detection=True,
)

@app.route("/api/users")
def get_users():
    return {"users": []}
```

**Programmatic Endpoint Analysis:**

```python
from security_use.sensor import VulnerableEndpointDetector

# Analyze your codebase for vulnerable endpoints
detector = VulnerableEndpointDetector()
result = detector.analyze("./my-project")

for endpoint in result.vulnerable_endpoints:
    print(f"{endpoint.method} {endpoint.path} - risk: {endpoint.risk_score}")
```

**Dashboard Alert Format:**

```json
{
  "scan_type": "runtime",
  "status": "completed",
  "findings": [{
    "finding_type": "attack",
    "category": "runtime",
    "severity": "HIGH",
    "title": "Sql Injection attack detected",
    "description": "UNION SELECT injection attempt",
    "pattern": "(?i)union\\s+(all\\s+)?select",
    "payload_preview": "1 UNION SELECT * FROM users--",
    "recommendation": "Review and parameterize database queries.",
    "file_path": "/api/users",
    "metadata": {
      "source_ip": "192.168.1.100",
      "method": "GET",
      "user_agent": "Mozilla/5.0...",
      "action_taken": "blocked",
      "confidence": 0.9,
      "timestamp": "2024-01-25T12:00:00.000000"
    }
  }],
  "metadata": {
    "sensor_version": "0.2.8",
    "alert_type": "runtime_attack"
  }
}
```

## Supported Formats

### Dependency Files

| Ecosystem | File | Status |
|-----------|------|--------|
| Python | `requirements.txt` | ✅ Full support |
| Python | `Pipfile` / `Pipfile.lock` | ✅ Full support |
| Python | `pyproject.toml` | ✅ Full support |
| Python | `poetry.lock` | ✅ Full support |
| JavaScript | `package.json` / `package-lock.json` | ✅ Full support |
| Java | `pom.xml` | ✅ Full support |

### IaC Formats

| Platform | Format | Status |
|----------|--------|--------|
| Terraform | `.tf` (HCL2) | ✅ Full support |
| Terraform | `.tf.json` | ✅ Full support |
| CloudFormation | `.yaml` / `.yml` | ✅ Full support |
| CloudFormation | `.json` | ✅ Full support |

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install SecurityUse
        run: pip install security-use

      - name: Run security scan
        run: security-use scan all . --format sarif > results.sarif

      - name: Upload SARIF results
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### GitLab CI

```yaml
security-scan:
  image: python:3.11
  script:
    - pip install security-use
    - security-use scan all . --format json > security-report.json
  artifacts:
    reports:
      security: security-report.json
```

### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: security-use
        name: Security Scan
        entry: security-use scan deps . --fail-on high
        language: python
        additional_dependencies: [security-use]
        pass_filenames: false
```

## Configuration

Create a `security-use.yaml` in your project root:

```yaml
# Dependency scanning
dependencies:
  enabled: true
  fail_on: high  # critical, high, medium, low
  ignore:
    - CVE-2021-12345  # Known false positive

# IaC scanning
iac:
  enabled: true
  fail_on: high
  exclude_paths:
    - "examples/"
    - "test/"

# Output
output:
  format: table  # table, json, sarif
  verbose: false
```

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

```bash
# Clone the repository
git clone https://github.com/security-use/security-use.git
cd security-use

# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run linting
ruff check .
```

## Security

Found a security vulnerability? Please report it privately via [security@security-use.dev](mailto:security@security-use.dev) or through [GitHub Security Advisories](https://github.com/security-use/security-use/security/advisories/new).

## License

[MIT License](LICENSE) - see the [LICENSE](LICENSE) file for details.

---

<p align="center">
  <a href="https://security-use.dev">Website</a> •
  <a href="https://github.com/security-use/security-use">GitHub</a> •
  <a href="https://pypi.org/project/security-use/">PyPI</a>
</p>
