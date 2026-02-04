"""Zero-config initialization for security-use.

This module provides automatic project detection and setup for security-use,
making it dead simple for developers (especially vibe coders) to secure their
applications with a single command.
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

import yaml


class Framework(Enum):
    """Detected Python web framework."""

    FASTAPI = "fastapi"
    FLASK = "flask"
    DJANGO = "django"
    UNKNOWN = "unknown"


@dataclass
class AppFile:
    """Detected application file with framework info."""

    path: Path
    framework: Framework
    app_variable: str  # e.g., "app" in "app = FastAPI()"
    has_middleware: bool = False  # Already has SecurityMiddleware?


@dataclass
class ProjectInfo:
    """Detected project information."""

    root: Path
    framework: Framework
    app_files: list[AppFile] = field(default_factory=list)
    has_requirements: bool = False
    has_pyproject: bool = False
    has_pipfile: bool = False
    has_poetry_lock: bool = False
    has_terraform: bool = False
    has_cloudformation: bool = False
    has_dockerfile: bool = False
    has_pre_commit: bool = False
    has_security_use_config: bool = False
    python_version: str | None = None

    @property
    def primary_app(self) -> AppFile | None:
        """Get the primary app file (first FastAPI/Flask file found)."""
        for app in self.app_files:
            if app.framework in (Framework.FASTAPI, Framework.FLASK):
                return app
        return self.app_files[0] if self.app_files else None

    @property
    def has_iac(self) -> bool:
        """Check if project has Infrastructure as Code files."""
        return self.has_terraform or self.has_cloudformation


class ProjectDetector:
    """Detects project type and configuration."""

    # Patterns to detect framework usage
    FASTAPI_PATTERNS = [
        r"from\s+fastapi\s+import",
        r"import\s+fastapi",
        r"FastAPI\s*\(",
    ]

    FLASK_PATTERNS = [
        r"from\s+flask\s+import",
        r"import\s+flask",
        r"Flask\s*\(",
    ]

    DJANGO_PATTERNS = [
        r"from\s+django",
        r"import\s+django",
        r"DJANGO_SETTINGS_MODULE",
    ]

    # Pattern to find app variable assignment
    APP_ASSIGNMENT_PATTERNS = {
        Framework.FASTAPI: r"(\w+)\s*=\s*FastAPI\s*\(",
        Framework.FLASK: r"(\w+)\s*=\s*Flask\s*\(",
    }

    # Pattern to detect existing SecurityMiddleware
    SECURITY_MIDDLEWARE_PATTERN = r"SecurityMiddleware|security_use\.sensor"

    def __init__(self, root: Path):
        self.root = root.resolve()

    def detect(self) -> ProjectInfo:
        """Detect project information."""
        info = ProjectInfo(root=self.root, framework=Framework.UNKNOWN)

        # Check for dependency files
        info.has_requirements = (self.root / "requirements.txt").exists()
        info.has_pyproject = (self.root / "pyproject.toml").exists()
        info.has_pipfile = (self.root / "Pipfile").exists()
        info.has_poetry_lock = (self.root / "poetry.lock").exists()

        # Check for IaC files
        info.has_terraform = any(self.root.rglob("*.tf"))
        info.has_cloudformation = self._has_cloudformation()

        # Check for Docker
        info.has_dockerfile = (self.root / "Dockerfile").exists() or (
            self.root / "docker-compose.yml"
        ).exists()

        # Check for pre-commit
        info.has_pre_commit = (self.root / ".pre-commit-config.yaml").exists()

        # Check for existing security-use config
        info.has_security_use_config = (self.root / ".security-use.yaml").exists() or (
            self.root / "security-use.yaml"
        ).exists()

        # Scan Python files for frameworks
        info.app_files = self._scan_python_files()

        # Determine primary framework
        if info.app_files:
            # Prioritize FastAPI > Flask > Django
            for framework in [Framework.FASTAPI, Framework.FLASK, Framework.DJANGO]:
                for app in info.app_files:
                    if app.framework == framework:
                        info.framework = framework
                        break
                if info.framework != Framework.UNKNOWN:
                    break

        return info

    def _has_cloudformation(self) -> bool:
        """Check for CloudFormation templates."""
        cf_patterns = ["cloudformation", "cfn", "template"]
        for yaml_file in self.root.rglob("*.yaml"):
            if any(p in yaml_file.name.lower() for p in cf_patterns):
                return True
            # Check content for AWSTemplateFormatVersion
            try:
                content = yaml_file.read_text()
                if "AWSTemplateFormatVersion" in content:
                    return True
            except Exception:
                pass
        return False

    def _scan_python_files(self) -> list[AppFile]:
        """Scan Python files for web framework usage."""
        app_files = []

        # Common entry point names
        entry_points = [
            "main.py",
            "app.py",
            "application.py",
            "server.py",
            "api.py",
            "wsgi.py",
            "asgi.py",
        ]

        # First check common entry points
        for name in entry_points:
            path = self.root / name
            if path.exists():
                app_file = self._analyze_python_file(path)
                if app_file:
                    app_files.append(app_file)

        # Then check src/ directory
        src_dir = self.root / "src"
        if src_dir.exists():
            for path in src_dir.rglob("*.py"):
                if path.name in entry_points or path.name == "__init__.py":
                    app_file = self._analyze_python_file(path)
                    if app_file:
                        app_files.append(app_file)

        return app_files

    def _analyze_python_file(self, path: Path) -> AppFile | None:
        """Analyze a Python file for framework usage."""
        try:
            content = path.read_text()
        except Exception:
            return None

        # Detect framework
        framework = Framework.UNKNOWN

        for pattern in self.FASTAPI_PATTERNS:
            if re.search(pattern, content):
                framework = Framework.FASTAPI
                break

        if framework == Framework.UNKNOWN:
            for pattern in self.FLASK_PATTERNS:
                if re.search(pattern, content):
                    framework = Framework.FLASK
                    break

        if framework == Framework.UNKNOWN:
            for pattern in self.DJANGO_PATTERNS:
                if re.search(pattern, content):
                    framework = Framework.DJANGO
                    break

        if framework == Framework.UNKNOWN:
            return None

        # Find app variable name
        app_variable = "app"  # default
        if framework in self.APP_ASSIGNMENT_PATTERNS:
            match = re.search(self.APP_ASSIGNMENT_PATTERNS[framework], content)
            if match:
                app_variable = match.group(1)

        # Check for existing SecurityMiddleware
        has_middleware = bool(re.search(self.SECURITY_MIDDLEWARE_PATTERN, content))

        return AppFile(
            path=path,
            framework=framework,
            app_variable=app_variable,
            has_middleware=has_middleware,
        )


class ConfigGenerator:
    """Generates security-use configuration files."""

    DEFAULT_CONFIG = {
        "version": "1",
        "scan": {
            "dependencies": {
                "enabled": True,
                "fail_on": "high",
            },
            "iac": {
                "enabled": True,
                "fail_on": "high",
            },
        },
        "sensor": {
            "enabled": True,
            "block_on_detection": True,
            "excluded_paths": ["/health", "/metrics", "/ready", "/live"],
        },
        "dashboard": {
            "auto_sync": True,
        },
    }

    def generate_config(self, info: ProjectInfo) -> dict:
        """Generate configuration based on project info."""
        import copy

        config = copy.deepcopy(self.DEFAULT_CONFIG)

        # Disable IaC scanning if no IaC files
        if not info.has_iac:
            config["scan"]["iac"]["enabled"] = False

        return config

    def write_config(self, info: ProjectInfo, path: Path | None = None) -> Path:
        """Write configuration file."""
        config = self.generate_config(info)
        config_path = path or info.root / ".security-use.yaml"

        with open(config_path, "w") as f:
            yaml.dump(config, f, default_flow_style=False, sort_keys=False)

        return config_path


class MiddlewareInjector:
    """Injects SecurityMiddleware into application files."""

    FASTAPI_IMPORT = "from security_use.sensor import SecurityMiddleware"
    FLASK_IMPORT = "from security_use.sensor import FlaskSecurityMiddleware"
    DJANGO_MIDDLEWARE_CLASS = "security_use.sensor.DjangoSecurityMiddleware"

    FASTAPI_MIDDLEWARE = """
# Security-Use: Runtime attack detection and protection
app.add_middleware(
    SecurityMiddleware,
    block_on_detection=True,
    excluded_paths=["/health", "/metrics"],
)
"""

    FLASK_MIDDLEWARE = """
# Security-Use: Runtime attack detection and protection
app.wsgi_app = FlaskSecurityMiddleware(
    app.wsgi_app,
    block_on_detection=True,
    excluded_paths=["/health", "/metrics"],
)
"""

    # Django instructions (settings.py modification)
    DJANGO_INSTRUCTIONS = f"""
# Add to MIDDLEWARE in settings.py (at the top for best protection):
#
# MIDDLEWARE = [
#     '{DJANGO_MIDDLEWARE_CLASS}',  # Security-Use middleware
#     'django.middleware.security.SecurityMiddleware',
#     ...
# ]
#
# Optional: Configure in settings.py:
# SECURITY_USE_BLOCK_ON_DETECTION = True
# SECURITY_USE_EXCLUDED_PATHS = ['/health/', '/metrics/']
"""

    def generate_injection(self, app_file: AppFile) -> tuple[str, str]:
        """Generate import and middleware code for injection.

        Returns:
            Tuple of (import_statement, middleware_code)
        """
        if app_file.framework == Framework.FASTAPI:
            middleware = self.FASTAPI_MIDDLEWARE.replace("app.", f"{app_file.app_variable}.")
            return (self.FASTAPI_IMPORT, middleware)
        elif app_file.framework == Framework.FLASK:
            middleware = self.FLASK_MIDDLEWARE.replace("app.", f"{app_file.app_variable}.")
            return (self.FLASK_IMPORT, middleware)
        elif app_file.framework == Framework.DJANGO:
            # Django uses settings.py, not direct injection
            return ("", self.DJANGO_INSTRUCTIONS)
        else:
            raise ValueError(f"Unsupported framework: {app_file.framework}")

    def inject(self, app_file: AppFile, dry_run: bool = False) -> tuple[bool, str]:
        """Inject middleware into app file.

        Returns:
            Tuple of (success, modified_content_or_error)
        """
        if app_file.has_middleware:
            return (False, "SecurityMiddleware already present")

        if app_file.framework not in (Framework.FASTAPI, Framework.FLASK, Framework.DJANGO):
            return (False, f"Unsupported framework: {app_file.framework}")

        # Django requires manual settings.py modification
        if app_file.framework == Framework.DJANGO:
            return (True, self.DJANGO_INSTRUCTIONS)

        try:
            content = app_file.path.read_text()
        except Exception as e:
            return (False, f"Failed to read file: {e}")

        import_stmt, middleware_code = self.generate_injection(app_file)

        # Find position to insert import (after other imports)
        lines = content.split("\n")
        import_insert_idx = 0

        for i, line in enumerate(lines):
            if line.startswith(("import ", "from ")):
                import_insert_idx = i + 1
            elif line.strip() and not line.startswith("#") and import_insert_idx > 0:
                break

        # Insert import
        lines.insert(import_insert_idx, import_stmt)

        # Find position to insert middleware (after app creation)
        app_creation_pattern = rf"{app_file.app_variable}\s*=\s*(FastAPI|Flask)\s*\("

        middleware_insert_idx = len(lines)
        for i, line in enumerate(lines):
            if re.search(app_creation_pattern, line):
                # Find end of app creation (might be multi-line)
                paren_count = line.count("(") - line.count(")")
                j = i
                while paren_count > 0 and j < len(lines) - 1:
                    j += 1
                    paren_count += lines[j].count("(") - lines[j].count(")")
                middleware_insert_idx = j + 1
                break

        # Insert middleware
        for line in reversed(middleware_code.strip().split("\n")):
            lines.insert(middleware_insert_idx, line)

        modified_content = "\n".join(lines)

        if not dry_run:
            try:
                app_file.path.write_text(modified_content)
            except Exception as e:
                return (False, f"Failed to write file: {e}")

        return (True, modified_content)


class PreCommitGenerator:
    """Generates pre-commit hook configuration."""

    HOOK_CONFIG = {
        "repo": "local",
        "hooks": [
            {
                "id": "security-use",
                "name": "Security Scan",
                "entry": "security-use scan all . --fail-on high",
                "language": "system",
                "pass_filenames": False,
                "stages": ["commit"],
            }
        ],
    }

    def generate(self, info: ProjectInfo) -> str:
        """Generate pre-commit configuration."""
        if info.has_pre_commit:
            # Return just the hook to add
            return yaml.dump({"repos": [self.HOOK_CONFIG]}, default_flow_style=False)
        else:
            # Return full config
            config = {"repos": [self.HOOK_CONFIG]}
            return yaml.dump(config, default_flow_style=False)

    def inject(self, info: ProjectInfo, dry_run: bool = False) -> tuple[bool, str]:
        """Inject or create pre-commit configuration.

        Returns:
            Tuple of (success, message)
        """
        config_path = info.root / ".pre-commit-config.yaml"

        if info.has_pre_commit:
            # Read existing config and add our hook
            try:
                with open(config_path) as f:
                    existing = yaml.safe_load(f)

                # Check if our hook already exists
                for repo in existing.get("repos", []):
                    for hook in repo.get("hooks", []):
                        if hook.get("id") == "security-use":
                            return (False, "security-use hook already present")

                # Add our hook
                existing["repos"].append(self.HOOK_CONFIG)

                if not dry_run:
                    with open(config_path, "w") as f:
                        yaml.dump(existing, f, default_flow_style=False)

                return (True, "Added security-use hook to existing .pre-commit-config.yaml")
            except Exception as e:
                return (False, f"Failed to update pre-commit config: {e}")
        else:
            # Create new config
            config = {"repos": [self.HOOK_CONFIG]}

            if not dry_run:
                try:
                    with open(config_path, "w") as f:
                        yaml.dump(config, f, default_flow_style=False)
                except Exception as e:
                    return (False, f"Failed to create pre-commit config: {e}")

            return (True, "Created .pre-commit-config.yaml")


class ProjectInitializer:
    """Main initializer that orchestrates the setup process."""

    def __init__(self, root: Path):
        self.root = root.resolve()
        self.detector = ProjectDetector(root)
        self.config_gen = ConfigGenerator()
        self.middleware_injector = MiddlewareInjector()
        self.precommit_gen = PreCommitGenerator()

    def detect(self) -> ProjectInfo:
        """Detect project information."""
        return self.detector.detect()

    def initialize(
        self,
        info: ProjectInfo,
        inject_middleware: bool = True,
        setup_precommit: bool = True,
        dry_run: bool = False,
    ) -> dict:
        """Initialize security-use for the project.

        Returns:
            Dictionary with results of each step.
        """
        results = {
            "config": {"success": False, "message": "", "path": None},
            "middleware": {"success": False, "message": "", "file": None},
            "precommit": {"success": False, "message": ""},
        }

        # 1. Create config file
        if not info.has_security_use_config:
            try:
                if not dry_run:
                    config_path = self.config_gen.write_config(info)
                    results["config"]["path"] = str(config_path)
                results["config"]["success"] = True
                results["config"]["message"] = "Created .security-use.yaml"
            except Exception as e:
                results["config"]["message"] = f"Failed to create config: {e}"
        else:
            results["config"]["message"] = "Config already exists"

        # 2. Inject middleware
        if inject_middleware and info.primary_app:
            app = info.primary_app
            if app.has_middleware:
                results["middleware"]["message"] = "SecurityMiddleware already present"
            elif app.framework in (Framework.FASTAPI, Framework.FLASK):
                success, msg = self.middleware_injector.inject(app, dry_run=dry_run)
                results["middleware"]["success"] = success
                results["middleware"]["message"] = (
                    msg if not success else f"Injected middleware into {app.path.name}"
                )
                results["middleware"]["file"] = str(app.path)
            else:
                results["middleware"]["message"] = f"Unsupported framework: {app.framework.value}"
        elif not info.primary_app:
            results["middleware"]["message"] = "No app file detected"

        # 3. Setup pre-commit
        if setup_precommit:
            success, msg = self.precommit_gen.inject(info, dry_run=dry_run)
            results["precommit"]["success"] = success
            results["precommit"]["message"] = msg

        return results
