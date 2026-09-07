"""Tests for scan orchestration."""

from secscan.config import ScanConfig
from secscan.scanner import run_scan


def test_run_scan_clean_directory(tmp_path):
    (tmp_path / "app.py").write_text("print('hello world')\n")
    config = ScanConfig()
    report = run_scan(str(tmp_path), config, include_deps=False, include_lints=False)

    assert report.target == str(tmp_path.resolve())
    assert report.secret_findings == []
    assert report.vuln_findings == []
    assert report.lint_results == []
    assert report.elapsed_seconds >= 0


def test_run_scan_detects_secret(tmp_path):
    (tmp_path / "config.env").write_text("AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF\n")
    config = ScanConfig()
    report = run_scan(str(tmp_path), config, include_deps=False, include_lints=False)

    assert any(f.pattern_name == "AWS Access Key" for f in report.secret_findings)


def test_run_scan_populates_default_patterns_when_missing(tmp_path):
    config = ScanConfig(secrets_patterns=[])
    run_scan(str(tmp_path), config, include_deps=False, include_lints=False)

    assert len(config.secrets_patterns) > 0


def test_run_scan_skips_deps_and_lints_when_disabled(tmp_path):
    config = ScanConfig()
    report = run_scan(str(tmp_path), config, include_deps=False, include_lints=False)

    assert report.vuln_findings == []
    assert report.lint_results == []
