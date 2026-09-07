"""Tests for the CLI entry points."""

from typer.testing import CliRunner

from secscan.cli import app

runner = CliRunner()


def test_version_command():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "secscan" in result.stdout


def test_patterns_command_lists_patterns():
    result = runner.invoke(app, ["patterns"])
    assert result.exit_code == 0
    assert "AWS Access Key" in result.stdout


def test_scan_clean_directory_exits_zero(tmp_path):
    (tmp_path / "app.py").write_text("print('hello world')\n")
    result = runner.invoke(app, ["scan", str(tmp_path), "--no-deps", "--no-lints"])
    assert result.exit_code == 0
    assert "CLEAN" in result.stdout


def test_scan_detects_secret_exits_nonzero(tmp_path):
    (tmp_path / "config.env").write_text("AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF\n")
    result = runner.invoke(app, ["scan", str(tmp_path), "--no-deps", "--no-lints"])
    assert result.exit_code == 1
