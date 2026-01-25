"""Command-line interface for securescan."""

import click

from securescan import __version__


@click.group()
@click.version_option(version=__version__, prog_name="securescan")
def main() -> None:
    """SecureScan - Security scanning tool for dependencies and IaC."""
    pass


@main.command()
def version() -> None:
    """Show version information."""
    click.echo(f"securescan version {__version__}")


if __name__ == "__main__":
    main()
