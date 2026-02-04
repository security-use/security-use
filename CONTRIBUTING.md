# Contributing to SecurityUse

Thank you for your interest in contributing to SecurityUse! This document provides guidelines and instructions for contributing.

## Getting Started

### Prerequisites

- Python 3.10 or higher
- Git

### Setting Up Development Environment

1. Fork and clone the repository:
   ```bash
   git clone https://github.com/YOUR_USERNAME/security-use.git
   cd security-use
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. Install in development mode with dev dependencies:
   ```bash
   pip install -e ".[dev]"
   ```

4. Run tests to verify your setup:
   ```bash
   pytest tests/ -v
   ```

## Development Workflow

### Making Changes

1. Create a new branch for your feature or fix:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes and write tests

3. Run the test suite:
   ```bash
   pytest tests/ -v --cov=security_use
   ```

4. Run linting and type checking:
   ```bash
   ruff check src/ tests/
   ruff format src/ tests/
   mypy src/security_use
   ```

5. Commit your changes with a clear message:
   ```bash
   git commit -m "feat: add new feature description"
   ```

### Commit Message Format

We follow [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` - New features
- `fix:` - Bug fixes
- `docs:` - Documentation changes
- `test:` - Adding or updating tests
- `refactor:` - Code changes that neither fix bugs nor add features
- `style:` - Formatting, missing semicolons, etc.
- `ci:` - CI/CD changes
- `build:` - Build system or dependency changes
- `chore:` - Other changes

### Pull Request Process

1. Update documentation if needed
2. Add tests for new functionality
3. Ensure all tests pass
4. Update CHANGELOG.md with your changes
5. Submit a pull request with a clear description

## Project Structure

```
security-use/
├── src/security_use/
│   ├── cli.py              # CLI commands
│   ├── init.py             # Project initialization
│   ├── scanner.py          # Main scanner interface
│   ├── dependency_scanner.py
│   ├── iac_scanner.py
│   ├── fixers/             # Auto-fix modules
│   ├── iac/                # IaC scanning rules
│   │   └── rules/          # AWS, Azure, GCP, K8s rules
│   ├── parsers/            # Dependency file parsers
│   ├── sensor/             # Runtime security sensor
│   └── compliance/         # Compliance framework mappings
├── tests/                  # Test suite
├── docs/                   # Documentation
└── ci-templates/           # CI/CD templates
```

## Adding New Features

### Adding a New IaC Rule

1. Add the rule class to the appropriate file in `src/security_use/iac/rules/`
2. Register the rule in `src/security_use/iac/rules/registry.py`
3. Add compliance mappings in `src/security_use/compliance/mapper.py`
4. Add tests in `tests/test_iac_rules.py`

### Adding a New Attack Detection Pattern

1. Add the pattern to `src/security_use/sensor/detector.py`
2. Update the `AttackType` enum in `src/security_use/sensor/models.py` if needed
3. Add tests in `tests/test_sensor.py`

### Adding a New Parser

1. Create a new parser class in `src/security_use/parsers/`
2. Inherit from `DependencyParser` base class
3. Add the parser to `src/security_use/parsers/__init__.py`
4. Add tests in `tests/test_parsers.py`

## Testing

### Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=security_use --cov-report=html

# Run specific test file
pytest tests/test_sensor.py -v

# Run tests matching a pattern
pytest tests/ -k "test_ssrf" -v
```

### Test Coverage

We aim for >70% test coverage. Run coverage reports to identify gaps:

```bash
pytest tests/ --cov=security_use --cov-report=term-missing
```

## Code Style

We use [Ruff](https://github.com/astral-sh/ruff) for linting and formatting:

```bash
# Check for issues
ruff check src/ tests/

# Auto-fix issues
ruff check --fix src/ tests/

# Format code
ruff format src/ tests/
```

## Questions?

- Open an issue for bugs or feature requests
- Join our Discord community for discussions
- Check existing issues before creating new ones

Thank you for contributing! 🚀
