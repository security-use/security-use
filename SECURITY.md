# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.2.x   | :white_check_mark: |
| 0.1.x   | :x:                |

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability in SecurityUse, please report it responsibly.

### How to Report

1. **Do NOT** open a public GitHub issue
2. Email security concerns to: security@security-use.dev
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Any suggested fixes

### What to Expect

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 1 week
- **Resolution Timeline**: Depends on severity
  - Critical: 24-48 hours
  - High: 1 week
  - Medium: 2 weeks
  - Low: Next release

### Disclosure Policy

- We follow responsible disclosure practices
- We will credit reporters in our changelog (unless anonymity is requested)
- We aim to fix vulnerabilities before public disclosure
- We will coordinate with reporters on disclosure timing

## Security Best Practices

When using SecurityUse:

1. **Keep Updated**: Always use the latest version
2. **Review Configurations**: Audit your `.security-use.yaml` settings
3. **Protect Credentials**: Never commit API keys or tokens
4. **CI/CD Security**: Use secrets management for dashboard credentials

## Security Features

SecurityUse includes several security features:

- **No data exfiltration**: Scans run locally by default
- **Opt-in dashboard sync**: Only sync results if explicitly configured
- **Minimal permissions**: CLI requires only read access to scan
- **Runtime sensor**: Detects attacks without sending data externally

## Dependency Security

We actively monitor our dependencies for vulnerabilities:

- Automated dependency scanning via Dependabot
- Weekly security audits
- Rapid response to CVEs in dependencies

Thank you for helping keep SecurityUse secure!
