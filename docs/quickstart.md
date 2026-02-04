# Quick Start Guide

Get up and running with SecurityUse in 5 minutes.

## Installation

```bash
pip install security-use
```

## Initialize Your Project

The fastest way to get started is with the `init` command:

```bash
cd your-project
security-use init
```

This automatically:
- Detects your framework (FastAPI, Flask, or Django)
- Injects the security middleware for runtime protection
- Sets up pre-commit hooks for dependency scanning
- Creates a `.security-use.yaml` configuration file

## Scan for Vulnerabilities

### Scan Dependencies

```bash
security-use scan deps
```

Example output:
```
 SecurityUse v0.2.9
 
 Scanning dependencies...
 ✓ Found 2 vulnerabilities in 15 packages

 ┌────────────────────────────────────────────────────────────────┐
 │  CRITICAL: CVE-2023-12345                                     │
 │  Package: requests 2.25.0                                     │
 │  Fix: Upgrade to 2.31.0                                       │
 └────────────────────────────────────────────────────────────────┘
```

### Scan Infrastructure as Code

```bash
security-use scan iac
```

This scans Terraform, CloudFormation, and Kubernetes manifests for misconfigurations.

### Scan Everything

```bash
security-use scan all
```

## Runtime Protection

If you used `security-use init`, runtime protection is already set up. The middleware:

- Detects SQL injection, XSS, and other attacks in real-time
- Logs security events for analysis
- Can optionally block malicious requests

### Manual Setup (if not using init)

**FastAPI:**
```python
from fastapi import FastAPI
from security_use.sensor import SecurityMiddleware

app = FastAPI()
app.add_middleware(SecurityMiddleware)
```

**Flask:**
```python
from flask import Flask
from security_use.sensor import FlaskSecurityMiddleware

app = Flask(__name__)
FlaskSecurityMiddleware(app)
```

**Django:**
Add to your `settings.py`:
```python
MIDDLEWARE = [
    'security_use.sensor.DjangoSecurityMiddleware',
    # ... other middleware
]
```

## CI/CD Integration

### GitHub Actions

Create `.github/workflows/security.yml`:

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install security-use
      - run: security-use scan all --ci
```

## Next Steps

- [Configuration Guide](./configuration.md) - Customize SecurityUse behavior
- [IaC Rules Reference](./iac-rules.md) - List of all IaC security rules
- [Runtime Sensor Guide](./runtime-sensor.md) - Deep dive into attack detection
