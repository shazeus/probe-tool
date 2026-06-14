from typer.testing import CliRunner

from probe.cli import app


runner = CliRunner()


def test_version_flag_prints_installed_version():
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert "probe, version 0.1.1" in result.stdout


def test_help_lists_core_modules():
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "network" in result.stdout
    assert "report" in result.stdout
