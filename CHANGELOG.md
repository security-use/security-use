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
- **CI workflow**: Comprehensive GitHub Actions workflow with:
  - Tests on Python 3.10, 3.11, 3.12
  - Linting with ruff
  - Type checking with mypy
  - Security self-scan with SARIF upload
  - Package build verification

### Changed
- Runtime sensor now has 8 attack detection categories (was 6)
- Test suite expanded to 244 tests (was 206)

## [0.2.9] - Previous Release

### Features
- Dependency vulnerability scanning via OSV database
- Infrastructure as Code scanning (Terraform, CloudFormation)
- Runtime security middleware for FastAPI and Flask
- Dashboard integration with real-time alerting
- Auto-fix capabilities for vulnerable dependencies
- SARIF output for CI integration
- Pre-commit hook support
