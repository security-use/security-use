# Changelog

All notable changes to SecurityUse will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Zero-config `init` command**: Run `security-use init` to automatically detect your framework (FastAPI, Flask, Django) and set up:
  - SecurityMiddleware injection for runtime protection
  - Pre-commit hooks for dependency scanning
  - Configuration file (`.security-use.yaml`)
- **SSRF detection patterns**: Server-Side Request Forgery detection including:
  - Localhost/127.0.0.1 access attempts
  - Cloud metadata endpoints (AWS 169.254.169.254, GCP, Alibaba)
  - Private IP ranges (10.x, 172.16-31.x, 192.168.x)
  - Dangerous protocols (file://, gopher://, dict://, ftp://)
- **SSTI detection patterns**: Server-Side Template Injection detection including:
  - Jinja2 expression injection (`{{7*7}}`)
  - Python class introspection (`__class__`, `__mro__`, `__globals__`)
  - Expression language injection (`${...}`, `#{...}`)
  - ERB/JSP template tags (`<%...%>`)
- **NoSQL Injection detection**: MongoDB operator injection patterns
  - `$where`, `$ne`, `$gt`, `$lt`, `$regex` operators
  - Query injection via JSON payloads
- **XXE detection**: XML External Entity attack patterns
  - `<!ENTITY>` declarations, SYSTEM/PUBLIC keywords
  - File and HTTP protocol access attempts
- **Deserialization attack detection**: Serialized object attack patterns
  - Java serialized objects (base64/hex markers)
  - PHP serialized arrays/objects
  - Python pickle and YAML unsafe load patterns
- **CI workflow**: Comprehensive GitHub Actions workflow with:
  - Tests on Python 3.10, 3.11, 3.12
  - Linting with ruff
  - Type checking with mypy
  - Security self-scan with SARIF upload
  - Package build verification
- **New AWS IaC rules**:
  - CKV_AWS_91: ALB/ELB access logging
  - CKV_AWS_117: Lambda function VPC configuration
  - CKV_AWS_26: SNS topic encryption
  - CKV_AWS_27: SQS queue encryption
- **New Azure IaC rules**:
  - CKV_AZURE_14: App Service HTTPS enforcement
  - CKV_AZURE_3: Storage account HTTPS requirement
  - CKV_AZURE_70: Function App HTTPS enforcement
- **New GCP IaC rules**:
  - CKV_GCP_18: GKE private cluster configuration
  - CKV_GCP_6: Cloud SQL SSL enforcement
  - CKV_GCP_32: Compute instance SSH key isolation
- **New Kubernetes IaC rules**:
  - CKV_K8S_20: Allow privilege escalation check
  - CKV_K8S_26: HostPath volume check

### Changed
- Runtime sensor now has 11 attack detection categories (was 6)
- Test suite expanded to 320 tests (was 206)
- Codebase formatted with ruff for consistency
- Total AWS IaC rules: 12 (was 8)
- Total Azure IaC rules: 9 (was 6)
- Total GCP IaC rules: 10 (was 7)
- Total K8s IaC rules: 9 (was 7)
- **Total IaC rules: 40** (was 28)

### Tests
- Added 23 compliance module tests
- Added 11 CI command tests
- Added 6 init command tests
- Added 8 SSRF/SSTI detection tests
- Added 9 new AWS IaC rule tests
- Added 4 Django middleware tests
- Added 7 new attack detection tests (NoSQL, XXE, Deserialization)

### New AWS IaC Rules
- **CKV_AWS_91**: ALB/ELB access logging
- **CKV_AWS_117**: Lambda function VPC configuration
- **CKV_AWS_26**: SNS topic encryption
- **CKV_AWS_27**: SQS queue encryption

### Django Support
- New `DjangoSecurityMiddleware` class for Django applications
- Configurable via Django settings (`SECURITY_USE_*` variables)
- Supports block_on_detection, excluded_paths, watch_paths

## [0.2.9] - Previous Release

### Features
- Dependency vulnerability scanning via OSV database
- Infrastructure as Code scanning (Terraform, CloudFormation)
- Runtime security middleware for FastAPI and Flask
- Dashboard integration with real-time alerting
- Auto-fix capabilities for vulnerable dependencies
- SARIF output for CI integration
- Pre-commit hook support
