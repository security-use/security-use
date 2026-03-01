# Contributing to SecurityUse

Thank you for your interest in contributing to SecurityUse! This document provides guidelines and instructions for contributing.

## Code of Conduct

Please be respectful and constructive in all interactions. We welcome contributors of all experience levels.

## Getting Started

### Prerequisites

- Python 3.10 or higher
- Git

### Setting Up the Development Environment

1. **Fork and clone the repository**

   ```bash
   git clone https://github.com/YOUR_USERNAME/security-use.git
   cd security-use
   ```

2. **Create a virtual environment**

   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install development dependencies**

   ```bash
   pip install -e ".[dev]"
   ```

4. **Verify the setup**

   ```bash
   pytest
   ```

## Development Workflow

### Branching Strategy

- Create a new branch for each feature or bug fix
- Use descriptive branch names: `feature/add-gradle-support`, `fix/sqli-false-positive`

```bash
git checkout -b feature/your-feature-name
```

### Making Changes

1. Write your code following the project's style guidelines
2. Add tests for new functionality
3. Ensure all tests pass: `pytest`
4. Run the linter: `ruff check .`
5. Format your code: `ruff format .`

### Commit Messages

Write clear, concise commit messages:

- Use the imperative mood ("Add feature" not "Added feature")
- Keep the first line under 72 characters
- Reference issues when applicable: "Fix SQL injection false positive (#123)"

Examples:
```
Add Gradle build file parser
Fix XSS detection for SVG files
Update documentation for sensor middleware
```

### Submitting a Pull Request

1. Push your branch to your fork
2. Open a pull request against the `main` branch
3. Fill out the PR template with:
   - Description of changes
   - Related issues
   - Testing performed
4. Wait for review and address any feedback

## Project Structure

```
security-use/
├── src/security_use/
│   ├── __init__.py          # Package exports
│   ├── cli.py               # Command-line interface
│   ├── scanner.py           # Main scanning orchestration
│   ├── dependency_scanner.py # Dependency vulnerability scanning
│   ├── osv_client.py        # OSV API client
│   ├── models.py            # Data models
│   ├── reporter.py          # Output formatters
│   ├── parsers/             # Dependency file parsers
│   │   ├── requirements.py
│   │   ├── pipfile.py
│   │   ├── pyproject.py
│   │   ├── poetry_lock.py
│   │   ├── npm.py
│   │   └── maven.py
│   ├── iac/                 # Infrastructure as Code scanning
│   │   ├── terraform.py
│   │   ├── cloudformation.py
│   │   └── rules/
│   ├── fixers/              # Auto-fix functionality
│   └── sensor/              # Runtime security sensor
│       ├── detector.py
│       ├── middleware.py
│       ├── webhook.py
│       └── models.py
├── tests/                   # Test suite
├── assets/                  # Logo and images
└── pyproject.toml          # Project configuration
```

## Types of Contributions

### Adding a New Dependency Parser

1. Create a new file in `src/security_use/parsers/`
2. Implement the parser following the existing patterns
3. Register the parser in `parsers/__init__.py`
4. Add tests in `tests/test_parsers.py`

### Adding IaC Rules

1. Add rules to the appropriate file in `src/security_use/iac/rules/`
2. Follow the existing rule format with clear descriptions
3. Include remediation guidance
4. Add test cases

### Adding Sensor Detection Patterns

1. Add patterns to `src/security_use/sensor/detector.py`
2. Include both the regex and a description
3. Add test cases for true positives and false negatives
4. Consider edge cases and encoding variations

## Testing

### Running Tests

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run specific test file
pytest tests/test_sensor.py

# Run with coverage
pytest --cov=security_use
```

### Writing Tests

- Place tests in the `tests/` directory
- Name test files `test_*.py`
- Use descriptive test function names
- Include both positive and negative test cases

## Questions?

- Open an issue for bugs or feature requests
- Start a discussion for questions or ideas

Thank you for contributing!
