"""Tests for dependency file parsers."""

from security_use.parsers import (
    PipfileParser,
    PoetryLockParser,
    PyProjectParser,
    RequirementsParser,
)
from security_use.parsers.pipfile import PipfileLockParser
from security_use.parsers.npm import NpmParser, NpmLockParser
from security_use.parsers.yarn import YarnLockParser
from security_use.parsers.maven import MavenParser
from security_use.parsers.gradle import GradleParser


class TestRequirementsParser:
    """Tests for requirements.txt parser."""

    def test_parse_pinned_version(self):
        content = "requests==2.28.0"
        parser = RequirementsParser()
        deps = parser.parse(content)

        assert len(deps) == 1
        assert deps[0].name == "requests"
        assert deps[0].version == "2.28.0"

    def test_parse_version_range(self):
        content = "django>=3.0,<4.0"
        parser = RequirementsParser()
        deps = parser.parse(content)

        assert len(deps) == 1
        assert deps[0].name == "django"
        assert deps[0].version == "3.0"

    def test_parse_with_extras(self):
        content = "requests[security]==2.28.0"
        parser = RequirementsParser()
        deps = parser.parse(content)

        assert len(deps) == 1
        assert deps[0].name == "requests"
        assert deps[0].extras == ["security"]

    def test_parse_with_comments(self):
        content = """
# This is a comment
requests==2.28.0  # inline comment
django==3.2.0
"""
        parser = RequirementsParser()
        deps = parser.parse(content)

        assert len(deps) == 2
        assert deps[0].name == "requests"
        assert deps[1].name == "django"

    def test_parse_empty_lines(self):
        content = """
requests==2.28.0

django==3.2.0

"""
        parser = RequirementsParser()
        deps = parser.parse(content)

        assert len(deps) == 2

    def test_skip_editable_installs(self):
        content = """
-e git+https://github.com/user/repo.git#egg=package
requests==2.28.0
"""
        parser = RequirementsParser()
        deps = parser.parse(content)

        assert len(deps) == 1
        assert deps[0].name == "requests"


class TestPyProjectParser:
    """Tests for pyproject.toml parser."""

    def test_parse_pep621_dependencies(self):
        content = """
[project]
name = "myproject"
dependencies = [
    "requests>=2.28.0",
    "django==3.2.0",
]
"""
        parser = PyProjectParser()
        deps = parser.parse(content)

        assert len(deps) == 2
        assert deps[0].name == "requests"
        assert deps[1].name == "django"
        assert deps[1].version == "3.2.0"

    def test_parse_pep621_optional_dependencies(self):
        content = """
[project]
name = "myproject"
dependencies = ["requests>=2.28.0"]

[project.optional-dependencies]
dev = ["pytest>=7.0.0"]
"""
        parser = PyProjectParser()
        deps = parser.parse(content)

        assert len(deps) == 2
        names = {d.name for d in deps}
        assert "requests" in names
        assert "pytest" in names

    def test_parse_poetry_dependencies(self):
        content = """
[tool.poetry]
name = "myproject"

[tool.poetry.dependencies]
python = "^3.10"
requests = "^2.28.0"
django = "3.2.0"
"""
        parser = PyProjectParser()
        deps = parser.parse(content)

        assert len(deps) == 2  # python is skipped
        names = {d.name for d in deps}
        assert "requests" in names
        assert "django" in names

    def test_parse_poetry_dev_dependencies(self):
        content = """
[tool.poetry.dev-dependencies]
pytest = "^7.0.0"
"""
        parser = PyProjectParser()
        deps = parser.parse(content)

        assert len(deps) == 1
        assert deps[0].name == "pytest"


class TestPipfileParser:
    """Tests for Pipfile parser."""

    def test_parse_packages(self):
        content = """
[packages]
requests = "==2.28.0"
django = "*"

[dev-packages]
pytest = ">=7.0.0"
"""
        parser = PipfileParser()
        deps = parser.parse(content)

        assert len(deps) == 3
        names = {d.name for d in deps}
        assert "requests" in names
        assert "django" in names
        assert "pytest" in names


class TestPipfileLockParser:
    """Tests for Pipfile.lock parser."""

    def test_parse_lock_file(self):
        content = """
{
    "default": {
        "requests": {"version": "==2.28.0"},
        "django": {"version": "==3.2.0"}
    },
    "develop": {
        "pytest": {"version": "==7.0.0"}
    }
}
"""
        parser = PipfileLockParser()
        deps = parser.parse(content)

        assert len(deps) == 3
        versions = {d.name: d.version for d in deps}
        assert versions["requests"] == "2.28.0"
        assert versions["django"] == "3.2.0"
        assert versions["pytest"] == "7.0.0"


class TestPoetryLockParser:
    """Tests for poetry.lock parser."""

    def test_parse_lock_file(self):
        content = """
[[package]]
name = "requests"
version = "2.28.0"

[[package]]
name = "django"
version = "3.2.0"
"""
        parser = PoetryLockParser()
        deps = parser.parse(content)

        assert len(deps) == 2
        versions = {d.name: d.version for d in deps}
        assert versions["requests"] == "2.28.0"
        assert versions["django"] == "3.2.0"


class TestNpmParser:
    """Tests for package.json parser."""

    def test_parse_dependencies(self):
        content = """
{
    "name": "my-project",
    "dependencies": {
        "express": "4.18.0",
        "lodash": "^4.17.21"
    }
}
"""
        parser = NpmParser()
        deps = parser.parse(content)

        assert len(deps) == 2
        names = {d.name for d in deps}
        assert "express" in names
        assert "lodash" in names

    def test_parse_dev_dependencies(self):
        content = """
{
    "name": "my-project",
    "dependencies": {
        "express": "4.18.0"
    },
    "devDependencies": {
        "jest": "^29.0.0"
    }
}
"""
        parser = NpmParser()
        deps = parser.parse(content)

        assert len(deps) == 2
        names = {d.name for d in deps}
        assert "express" in names
        assert "jest" in names

    def test_parse_empty_dependencies(self):
        content = """
{
    "name": "my-project"
}
"""
        parser = NpmParser()
        deps = parser.parse(content)

        assert len(deps) == 0

    def test_parse_version_formats(self):
        content = """
{
    "dependencies": {
        "pinned": "1.0.0",
        "caret": "^1.0.0",
        "tilde": "~1.0.0",
        "range": ">=1.0.0 <2.0.0"
    }
}
"""
        parser = NpmParser()
        deps = parser.parse(content)

        # Star (*) versions may be skipped
        assert len(deps) >= 4


class TestNpmLockParser:
    """Tests for package-lock.json parser."""

    def test_parse_v2_format(self):
        content = """
{
    "name": "my-project",
    "lockfileVersion": 2,
    "packages": {
        "": {
            "dependencies": {
                "express": "^4.18.0"
            }
        },
        "node_modules/express": {
            "version": "4.18.2",
            "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz"
        },
        "node_modules/lodash": {
            "version": "4.17.21"
        }
    }
}
"""
        parser = NpmLockParser()
        deps = parser.parse(content)

        # Should extract versions from node_modules
        assert len(deps) >= 2
        versions = {d.name: d.version for d in deps}
        assert versions.get("express") == "4.18.2"
        assert versions.get("lodash") == "4.17.21"

    def test_parse_v1_format(self):
        content = """
{
    "name": "my-project",
    "lockfileVersion": 1,
    "dependencies": {
        "express": {
            "version": "4.18.2"
        },
        "lodash": {
            "version": "4.17.21"
        }
    }
}
"""
        parser = NpmLockParser()
        deps = parser.parse(content)

        assert len(deps) == 2
        versions = {d.name: d.version for d in deps}
        assert versions.get("express") == "4.18.2"


class TestYarnLockParser:
    """Tests for yarn.lock parser."""

    def test_parse_yarn_lock(self):
        content = '''
express@^4.18.0:
  version "4.18.2"
  resolved "https://registry.yarnpkg.com/express/-/express-4.18.2.tgz"

lodash@^4.17.21:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"
'''
        parser = YarnLockParser()
        deps = parser.parse(content)

        # Should extract versioned packages
        versions = {d.name: d.version for d in deps if d.version}
        assert versions.get("express") == "4.18.2"
        assert versions.get("lodash") == "4.17.21"


class TestMavenParser:
    """Tests for pom.xml parser."""

    def test_parse_dependencies(self):
        content = """
<project>
    <dependencies>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-core</artifactId>
            <version>5.3.0</version>
        </dependency>
        <dependency>
            <groupId>junit</groupId>
            <artifactId>junit</artifactId>
            <version>4.13.2</version>
            <scope>test</scope>
        </dependency>
    </dependencies>
</project>
"""
        parser = MavenParser()
        deps = parser.parse(content)

        assert len(deps) == 2
        names = {d.name for d in deps}
        # Maven uses groupId:artifactId format
        assert any("spring-core" in n for n in names)
        assert any("junit" in n for n in names)


class TestGradleParser:
    """Tests for build.gradle parser."""

    def test_parse_dependencies(self):
        content = """
dependencies {
    implementation 'org.springframework:spring-core:5.3.0'
    testImplementation 'junit:junit:4.13.2'
    compile 'com.google.guava:guava:30.1-jre'
}
"""
        parser = GradleParser()
        deps = parser.parse(content)

        assert len(deps) >= 2
        names = {d.name for d in deps}
        # Gradle uses groupId:artifactId format
        assert any("spring-core" in n for n in names) or any("guava" in n for n in names)

    def test_parse_kotlin_dsl(self):
        content = """
dependencies {
    implementation("org.springframework:spring-core:5.3.0")
    testImplementation("junit:junit:4.13.2")
}
"""
        parser = GradleParser()
        deps = parser.parse(content)

        # Kotlin DSL uses different syntax
        assert len(deps) >= 1
