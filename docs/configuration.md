# Configuration Guide

SecurityUse can be configured via a `.security-use.yaml` file in your project root.

## Default Configuration

Running `security-use init` creates this default configuration:

```yaml
# SecurityUse Configuration
version: "1"

# Project settings
project:
  name: my-project
  framework: auto  # auto, fastapi, flask, django

# Dependency scanning
dependencies:
  enabled: true
  files:
    - requirements.txt
    - requirements/*.txt
    - pyproject.toml
    - Pipfile
    - Pipfile.lock
  ignore:
    - "**/test-requirements.txt"
  severity_threshold: low  # low, medium, high, critical

# IaC scanning
iac:
  enabled: true
  paths:
    - "**/*.tf"
    - "**/*.yaml"
    - "**/*.yml"
    - "**/*.json"
  ignore:
    - "**/node_modules/**"
    - "**/.venv/**"
  rules:
    exclude: []  # List rule IDs to exclude

# Runtime sensor
sensor:
  enabled: true
  mode: detect  # detect, block
  log_level: warning
  webhook_url: null
  dashboard_sync: true

# Reporting
reporting:
  format: rich  # rich, json, sarif
  output: stdout
  save_to_file: false

# CI settings
ci:
  fail_on: high  # Fail CI if severity >= this level
  upload_sarif: true
```

## Configuration Options

### Project Settings

| Option | Description | Default |
|--------|-------------|---------|
| `project.name` | Project name for reporting | Directory name |
| `project.framework` | Framework type | `auto` |

### Dependency Scanning

| Option | Description | Default |
|--------|-------------|---------|
| `dependencies.enabled` | Enable dependency scanning | `true` |
| `dependencies.files` | Dependency file patterns | Multiple |
| `dependencies.ignore` | Patterns to ignore | None |
| `dependencies.severity_threshold` | Minimum severity to report | `low` |

### IaC Scanning

| Option | Description | Default |
|--------|-------------|---------|
| `iac.enabled` | Enable IaC scanning | `true` |
| `iac.paths` | File patterns to scan | `**/*.tf`, `**/*.yaml` |
| `iac.ignore` | Patterns to ignore | `node_modules`, `.venv` |
| `iac.rules.exclude` | Rule IDs to skip | None |

### Runtime Sensor

| Option | Description | Default |
|--------|-------------|---------|
| `sensor.enabled` | Enable runtime sensor | `true` |
| `sensor.mode` | `detect` or `block` | `detect` |
| `sensor.log_level` | Logging verbosity | `warning` |
| `sensor.webhook_url` | URL for alert webhooks | None |
| `sensor.dashboard_sync` | Sync to dashboard | `true` |

## Environment Variables

You can also use environment variables (prefixed with `SECURITY_USE_`):

```bash
export SECURITY_USE_SENSOR_MODE=block
export SECURITY_USE_WEBHOOK_URL=https://example.com/webhook
export SECURITY_USE_API_KEY=your-api-key
```

## Per-File Ignores

Add inline comments to ignore specific rules:

**Terraform:**
```hcl
# security-use: ignore=CKV_AWS_19
resource "aws_s3_bucket" "public_data" {
  bucket = "my-public-bucket"
}
```

**Python:**
```python
# security-use: ignore-next-line
password = input("Enter password: ")  # noqa: security
```

## Multiple Configurations

Use different configs for different environments:

```bash
# Development
security-use scan all --config .security-use.dev.yaml

# Production (stricter)
security-use scan all --config .security-use.prod.yaml
```
