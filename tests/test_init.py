"""Tests for the init module."""

from pathlib import Path
from textwrap import dedent

import pytest

from security_use.init import (
    AppFile,
    ConfigGenerator,
    Framework,
    MiddlewareInjector,
    PreCommitGenerator,
    ProjectDetector,
    ProjectInfo,
    ProjectInitializer,
)


class TestProjectDetector:
    """Tests for ProjectDetector."""

    def test_detect_fastapi_project(self, tmp_path: Path):
        """Should detect FastAPI framework."""
        # Create a FastAPI app file
        app_file = tmp_path / "main.py"
        app_file.write_text(
            dedent("""
            from fastapi import FastAPI
            
            app = FastAPI()
            
            @app.get("/")
            def read_root():
                return {"Hello": "World"}
        """)
        )

        # Create requirements.txt
        (tmp_path / "requirements.txt").write_text("fastapi>=0.100.0\nuvicorn")

        detector = ProjectDetector(tmp_path)
        info = detector.detect()

        assert info.framework == Framework.FASTAPI
        assert info.has_requirements is True
        assert len(info.app_files) == 1
        assert info.app_files[0].app_variable == "app"
        assert info.app_files[0].has_middleware is False

    def test_detect_flask_project(self, tmp_path: Path):
        """Should detect Flask framework."""
        app_file = tmp_path / "app.py"
        app_file.write_text(
            dedent("""
            from flask import Flask
            
            application = Flask(__name__)
            
            @application.route("/")
            def hello():
                return "Hello World!"
        """)
        )

        detector = ProjectDetector(tmp_path)
        info = detector.detect()

        assert info.framework == Framework.FLASK
        assert len(info.app_files) == 1
        assert info.app_files[0].app_variable == "application"

    def test_detect_existing_middleware(self, tmp_path: Path):
        """Should detect when SecurityMiddleware is already present."""
        app_file = tmp_path / "main.py"
        app_file.write_text(
            dedent("""
            from fastapi import FastAPI
            from security_use.sensor import SecurityMiddleware
            
            app = FastAPI()
            app.add_middleware(SecurityMiddleware)
            
            @app.get("/")
            def read_root():
                return {"Hello": "World"}
        """)
        )

        detector = ProjectDetector(tmp_path)
        info = detector.detect()

        assert info.app_files[0].has_middleware is True

    def test_detect_terraform_files(self, tmp_path: Path):
        """Should detect Terraform files."""
        tf_dir = tmp_path / "infrastructure"
        tf_dir.mkdir()
        (tf_dir / "main.tf").write_text('resource "aws_s3_bucket" "example" {}')

        detector = ProjectDetector(tmp_path)
        info = detector.detect()

        assert info.has_terraform is True

    def test_detect_cloudformation(self, tmp_path: Path):
        """Should detect CloudFormation templates."""
        cfn_file = tmp_path / "cloudformation.yaml"
        cfn_file.write_text(
            dedent("""
            AWSTemplateFormatVersion: '2010-09-09'
            Resources:
              MyBucket:
                Type: AWS::S3::Bucket
        """)
        )

        detector = ProjectDetector(tmp_path)
        info = detector.detect()

        assert info.has_cloudformation is True

    def test_detect_pyproject_toml(self, tmp_path: Path):
        """Should detect pyproject.toml."""
        (tmp_path / "pyproject.toml").write_text(
            dedent("""
            [project]
            name = "my-app"
            version = "0.1.0"
        """)
        )

        detector = ProjectDetector(tmp_path)
        info = detector.detect()

        assert info.has_pyproject is True

    def test_detect_precommit(self, tmp_path: Path):
        """Should detect existing pre-commit config."""
        (tmp_path / ".pre-commit-config.yaml").write_text("repos: []")

        detector = ProjectDetector(tmp_path)
        info = detector.detect()

        assert info.has_pre_commit is True

    def test_detect_security_use_config(self, tmp_path: Path):
        """Should detect existing security-use config."""
        (tmp_path / ".security-use.yaml").write_text("version: 1")

        detector = ProjectDetector(tmp_path)
        info = detector.detect()

        assert info.has_security_use_config is True

    def test_empty_project(self, tmp_path: Path):
        """Should handle empty projects gracefully."""
        detector = ProjectDetector(tmp_path)
        info = detector.detect()

        assert info.framework == Framework.UNKNOWN
        assert len(info.app_files) == 0
        assert info.has_requirements is False


class TestConfigGenerator:
    """Tests for ConfigGenerator."""

    def test_generate_default_config(self, tmp_path: Path):
        """Should generate default configuration."""
        info = ProjectInfo(root=tmp_path, framework=Framework.FASTAPI)
        generator = ConfigGenerator()
        config = generator.generate_config(info)

        assert config["version"] == "1"
        assert config["scan"]["dependencies"]["enabled"] is True
        assert config["sensor"]["enabled"] is True
        assert config["sensor"]["block_on_detection"] is True

    def test_disable_iac_when_not_present(self, tmp_path: Path):
        """Should disable IaC scanning when no IaC files present."""
        info = ProjectInfo(
            root=tmp_path,
            framework=Framework.FASTAPI,
            has_terraform=False,
            has_cloudformation=False,
        )
        generator = ConfigGenerator()
        config = generator.generate_config(info)

        assert config["scan"]["iac"]["enabled"] is False

    def test_enable_iac_when_present(self, tmp_path: Path):
        """Should enable IaC scanning when IaC files present."""
        info = ProjectInfo(
            root=tmp_path,
            framework=Framework.FASTAPI,
            has_terraform=True,
        )
        generator = ConfigGenerator()
        config = generator.generate_config(info)

        assert config["scan"]["iac"]["enabled"] is True

    def test_write_config(self, tmp_path: Path):
        """Should write config file to disk."""
        info = ProjectInfo(root=tmp_path, framework=Framework.FASTAPI)
        generator = ConfigGenerator()
        config_path = generator.write_config(info)

        assert config_path.exists()
        assert config_path.name == ".security-use.yaml"

        content = config_path.read_text()
        assert "version:" in content
        assert "sensor:" in content


class TestMiddlewareInjector:
    """Tests for MiddlewareInjector."""

    def test_generate_fastapi_injection(self):
        """Should generate correct FastAPI middleware code."""
        app_file = AppFile(
            path=Path("main.py"),
            framework=Framework.FASTAPI,
            app_variable="app",
        )
        injector = MiddlewareInjector()
        import_stmt, middleware = injector.generate_injection(app_file)

        assert "from security_use.sensor import SecurityMiddleware" in import_stmt
        assert "app.add_middleware" in middleware
        assert "SecurityMiddleware" in middleware

    def test_generate_flask_injection(self):
        """Should generate correct Flask middleware code."""
        app_file = AppFile(
            path=Path("app.py"),
            framework=Framework.FLASK,
            app_variable="application",
        )
        injector = MiddlewareInjector()
        import_stmt, middleware = injector.generate_injection(app_file)

        assert "FlaskSecurityMiddleware" in import_stmt
        assert "application.wsgi_app = FlaskSecurityMiddleware" in middleware

    def test_inject_fastapi_middleware(self, tmp_path: Path):
        """Should inject middleware into FastAPI app."""
        app_path = tmp_path / "main.py"
        app_path.write_text(
            dedent("""
            from fastapi import FastAPI
            
            app = FastAPI()
            
            @app.get("/")
            def read_root():
                return {"Hello": "World"}
        """)
        )

        app_file = AppFile(
            path=app_path,
            framework=Framework.FASTAPI,
            app_variable="app",
        )

        injector = MiddlewareInjector()
        success, _ = injector.inject(app_file)

        assert success is True

        content = app_path.read_text()
        assert "from security_use.sensor import SecurityMiddleware" in content
        assert "app.add_middleware" in content

    def test_inject_flask_middleware(self, tmp_path: Path):
        """Should inject middleware into Flask app."""
        app_path = tmp_path / "app.py"
        app_path.write_text(
            dedent("""
            from flask import Flask
            
            app = Flask(__name__)
            
            @app.route("/")
            def hello():
                return "Hello!"
        """)
        )

        app_file = AppFile(
            path=app_path,
            framework=Framework.FLASK,
            app_variable="app",
        )

        injector = MiddlewareInjector()
        success, _ = injector.inject(app_file)

        assert success is True

        content = app_path.read_text()
        assert "FlaskSecurityMiddleware" in content
        assert "app.wsgi_app = FlaskSecurityMiddleware" in content

    def test_skip_if_already_present(self, tmp_path: Path):
        """Should skip injection if middleware already present."""
        app_path = tmp_path / "main.py"
        app_path.write_text(
            dedent("""
            from fastapi import FastAPI
            from security_use.sensor import SecurityMiddleware
            
            app = FastAPI()
            app.add_middleware(SecurityMiddleware)
        """)
        )

        app_file = AppFile(
            path=app_path,
            framework=Framework.FASTAPI,
            app_variable="app",
            has_middleware=True,
        )

        injector = MiddlewareInjector()
        success, message = injector.inject(app_file)

        assert success is False
        assert "already present" in message

    def test_dry_run(self, tmp_path: Path):
        """Should not modify file in dry run mode."""
        app_path = tmp_path / "main.py"
        original_content = dedent("""
            from fastapi import FastAPI
            
            app = FastAPI()
        """)
        app_path.write_text(original_content)

        app_file = AppFile(
            path=app_path,
            framework=Framework.FASTAPI,
            app_variable="app",
        )

        injector = MiddlewareInjector()
        success, modified_content = injector.inject(app_file, dry_run=True)

        assert success is True
        assert "SecurityMiddleware" in modified_content

        # Original file should be unchanged
        assert app_path.read_text() == original_content


class TestPreCommitGenerator:
    """Tests for PreCommitGenerator."""

    def test_generate_new_config(self, tmp_path: Path):
        """Should generate new pre-commit config."""
        info = ProjectInfo(root=tmp_path, framework=Framework.FASTAPI)
        generator = PreCommitGenerator()
        config = generator.generate(info)

        assert "security-use" in config
        assert "security-use scan all" in config

    def test_create_precommit_file(self, tmp_path: Path):
        """Should create .pre-commit-config.yaml."""
        info = ProjectInfo(
            root=tmp_path,
            framework=Framework.FASTAPI,
            has_pre_commit=False,
        )
        generator = PreCommitGenerator()
        success, message = generator.inject(info)

        assert success is True
        assert "Created" in message

        config_path = tmp_path / ".pre-commit-config.yaml"
        assert config_path.exists()

        content = config_path.read_text()
        assert "security-use" in content

    def test_update_existing_precommit(self, tmp_path: Path):
        """Should add hook to existing pre-commit config."""
        config_path = tmp_path / ".pre-commit-config.yaml"
        config_path.write_text(
            dedent("""
            repos:
              - repo: https://github.com/pre-commit/pre-commit-hooks
                rev: v4.0.0
                hooks:
                  - id: trailing-whitespace
        """)
        )

        info = ProjectInfo(
            root=tmp_path,
            framework=Framework.FASTAPI,
            has_pre_commit=True,
        )
        generator = PreCommitGenerator()
        success, message = generator.inject(info)

        assert success is True
        assert "Added" in message

        content = config_path.read_text()
        assert "security-use" in content
        assert "trailing-whitespace" in content  # Original hook preserved

    def test_skip_if_hook_exists(self, tmp_path: Path):
        """Should skip if security-use hook already exists."""
        config_path = tmp_path / ".pre-commit-config.yaml"
        config_path.write_text(
            dedent("""
            repos:
              - repo: local
                hooks:
                  - id: security-use
                    name: Security Scan
                    entry: security-use scan all .
        """)
        )

        info = ProjectInfo(
            root=tmp_path,
            framework=Framework.FASTAPI,
            has_pre_commit=True,
        )
        generator = PreCommitGenerator()
        success, message = generator.inject(info)

        assert success is False
        assert "already present" in message


class TestProjectInitializer:
    """Tests for ProjectInitializer."""

    def test_full_initialization(self, tmp_path: Path):
        """Should perform full initialization."""
        # Create a FastAPI project
        app_path = tmp_path / "main.py"
        app_path.write_text(
            dedent("""
            from fastapi import FastAPI
            
            app = FastAPI()
            
            @app.get("/")
            def root():
                return {"message": "Hello"}
        """)
        )
        (tmp_path / "requirements.txt").write_text("fastapi\nuvicorn")

        initializer = ProjectInitializer(tmp_path)
        info = initializer.detect()
        results = initializer.initialize(info)

        # Check config was created
        assert results["config"]["success"] is True
        assert (tmp_path / ".security-use.yaml").exists()

        # Check middleware was injected
        assert results["middleware"]["success"] is True
        app_content = app_path.read_text()
        assert "SecurityMiddleware" in app_content

        # Check pre-commit was created
        assert results["precommit"]["success"] is True
        assert (tmp_path / ".pre-commit-config.yaml").exists()

    def test_skip_middleware_injection(self, tmp_path: Path):
        """Should skip middleware injection when disabled."""
        app_path = tmp_path / "main.py"
        app_path.write_text(
            dedent("""
            from fastapi import FastAPI
            app = FastAPI()
        """)
        )

        initializer = ProjectInitializer(tmp_path)
        info = initializer.detect()
        results = initializer.initialize(info, inject_middleware=False)

        # Middleware should not be injected
        app_content = app_path.read_text()
        assert "SecurityMiddleware" not in app_content

    def test_dry_run(self, tmp_path: Path):
        """Should not modify anything in dry run mode."""
        app_path = tmp_path / "main.py"
        original_content = dedent("""
            from fastapi import FastAPI
            app = FastAPI()
        """)
        app_path.write_text(original_content)

        initializer = ProjectInitializer(tmp_path)
        info = initializer.detect()
        results = initializer.initialize(info, dry_run=True)

        # Config should not be created
        assert not (tmp_path / ".security-use.yaml").exists()

        # App should not be modified
        assert app_path.read_text() == original_content

        # Pre-commit should not be created
        assert not (tmp_path / ".pre-commit-config.yaml").exists()

    def test_idempotent(self, tmp_path: Path):
        """Running init twice should be safe."""
        app_path = tmp_path / "main.py"
        app_path.write_text(
            dedent("""
            from fastapi import FastAPI
            app = FastAPI()
        """)
        )

        initializer = ProjectInitializer(tmp_path)

        # First run
        info1 = initializer.detect()
        results1 = initializer.initialize(info1)

        # Second run
        info2 = initializer.detect()
        results2 = initializer.initialize(info2)

        # Should detect existing config and skip
        assert (
            results2["config"]["success"] is False
            or "already exists" in results2["config"]["message"]
        )
        assert results2["middleware"]["message"] is not None

        # Should not double-inject middleware
        app_content = app_path.read_text()
        assert app_content.count("SecurityMiddleware") == 2  # Import + usage


class TestCLIInit:
    """Tests for the CLI init command."""

    def test_init_command_exists(self):
        """Should have init command registered."""
        from security_use.cli import main

        assert "init" in [cmd.name for cmd in main.commands.values()]

    def test_init_help(self, cli_runner):
        """Should show help text."""
        from security_use.cli import main

        result = cli_runner.invoke(main, ["init", "--help"])
        assert result.exit_code == 0
        assert "Initialize security-use" in result.output

    def test_init_dry_run(self, tmp_path: Path, cli_runner):
        """Should run in dry-run mode."""
        from security_use.cli import main

        app_path = tmp_path / "main.py"
        app_path.write_text("from fastapi import FastAPI\napp = FastAPI()")

        result = cli_runner.invoke(main, ["init", str(tmp_path), "--dry-run", "-y"])

        assert result.exit_code == 0
        assert "Dry run" in result.output or "dry-run" in result.output.lower()


@pytest.fixture
def cli_runner():
    """Create a CLI runner."""
    from click.testing import CliRunner

    return CliRunner()
