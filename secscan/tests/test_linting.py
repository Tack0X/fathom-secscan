"""Tests for security linting wrappers (gosec, clippy, bandit)."""

import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from secscan.linting import (
    LintResult,
    LintFinding,
    run_gosec,
    run_clippy,
    run_bandit,
    run_security_lints,
    _lint_severity_color,
)


class TestLintSeverityColor:
    """Test severity color mapping."""

    def test_critical_is_red_bold(self):
        assert _lint_severity_color("critical") == "red bold"

    def test_high_is_red(self):
        assert _lint_severity_color("high") == "red"

    def test_medium_is_yellow(self):
        assert _lint_severity_color("medium") == "yellow"

    def test_low_is_blue(self):
        assert _lint_severity_color("low") == "blue"

    def test_unknown_is_white(self):
        assert _lint_severity_color("unknown") == "white"


class TestRunGosec:
    """Test Go security linter wrapper."""

    def test_returns_empty_for_non_go_project(self, tmp_path):
        """No go.mod present should return empty results."""
        result = run_gosec(tmp_path)
        assert isinstance(result, LintResult)
        assert result.tool == "gosec"
        assert not result.findings
        assert not result.success  # tool not available

    def test_parses_success_output(self, tmp_path):
        """go.mod present should attempt scan even with no findings."""
        go_mod = tmp_path / "go.mod"
        go_mod.write_text('module test\n\ngo 1.23\n')

        with patch('secscan.linting.run_cmd') as mock_run:
            mock_run.return_value = (0, '', '')  # success, no output
            result = run_gosec(tmp_path)
            assert isinstance(result, LintResult)
            assert result.tool == "gosec"
            assert result.success  # command ran successfully
            assert not result.findings  # no findings in output

    def test_parses_failure_output(self, tmp_path):
        """go.mod present but scan fails should return empty, not success."""
        go_mod = tmp_path / "go.mod"
        go_mod.write_text('module test\n\ngo 1.23\n')

        with patch('secscan.linting.run_cmd') as mock_run:
            mock_run.return_value = (1, '', 'gosec: some error')
            result = run_gosec(tmp_path)
            assert isinstance(result, LintResult)
            assert not result.success

    def test_parses_findings_from_json(self, tmp_path):
        """gosec JSON output should produce findings."""
        go_mod = tmp_path / "go.mod"
        go_mod.write_text('module test\n\ngo 1.23\n')

        import json
        sample_finding = {
            "file": "main.go",
            "line": 10,
            "rule_id": "G101",
            "severity": "HIGH",
            "details": "Potential hardcoded credentials"
        }

        with patch('secscan.linting.run_cmd') as mock_run:
            mock_run.return_value = (0, json.dumps(sample_finding), '')
            result = run_gosec(tmp_path)
            assert isinstance(result, LintResult)
            assert len(result.findings) == 1
            finding = result.findings[0]
            assert isinstance(finding, LintFinding)
            assert finding.tool == "gosec"
            assert finding.file == "main.go"
            assert finding.line == 10


class TestRunClippy:
    """Test Rust security linter wrapper."""

    def test_returns_empty_for_non_rust_project(self, tmp_path):
        """No Cargo.toml present should return empty results."""
        result = run_clippy(tmp_path)
        assert isinstance(result, LintResult)
        assert result.tool == "clippy"
        assert not result.findings

    def test_parses_clippy_warnings(self, tmp_path):
        """Clippy JSON output should produce findings."""
        cargo_toml = tmp_path / "Cargo.toml"
        cargo_toml.write_text('[package]\nname = "test"\nversion = "0.1.0"\n')

        import json
        sample_message = {
            "reason": "compiler-message",
            "message": {
                "message": "unused variable",
                "level": "warning",
                "code": {"code": "unused_variables", "explanation": None},
                "spans": [{"file_name": "src/main.rs", "line_start": 5}]
            }
        }

        with patch('secscan.linting.run_cmd') as mock_run:
            mock_run.return_value = (0, json.dumps(sample_message), '')
            result = run_clippy(tmp_path)
            assert isinstance(result, LintResult)
            assert len(result.findings) == 1
            finding = result.findings[0]
            assert finding.tool == "clippy"
            assert finding.severity == "high"  # warning -> high
            assert finding.file == "src/main.rs"

    def test_parses_error_level(self, tmp_path):
        """Clippy errors should map to critical severity."""
        cargo_toml = tmp_path / "Cargo.toml"
        cargo_toml.write_text('[package]\nname = "test"\nversion = "0.1.0"\n')

        import json
        sample_message = {
            "reason": "compiler-message",
            "message": {
                "message": "unsafe block required",
                "level": "error",
                "code": {"code": "clippy::needless_pass_by_value", "explanation": None},
                "spans": [{"file_name": "src/main.rs", "line_start": 3}]
            }
        }

        with patch('secscan.linting.run_cmd') as mock_run:
            mock_run.return_value = (0, json.dumps(sample_message), '')
            result = run_clippy(tmp_path)
            assert len(result.findings) == 1
            assert result.findings[0].severity == "critical"


class TestRunBandit:
    """Test Python security linter wrapper."""

    def test_returns_empty_for_non_python_project(self, tmp_path):
        """No pyproject.toml or setup.py present should return empty results."""
        result = run_bandit(tmp_path)
        assert isinstance(result, LintResult)
        assert result.tool == "bandit"
        assert not result.findings

    def test_parses_bandit_findings(self, tmp_path):
        """Bandit JSON output should produce findings."""
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text('[project]\nname = "test"\n')

        import json
        sample_result = {
            "results": [
                {
                    "filename": "app.py",
                    "line_number": 10,
                    "issue_severity": "HIGH",
                    "issue_text": "Use of insecure hash function",
                    "issue_confidence": "HIGH"
                }
            ]
        }

        with patch('secscan.linting.run_cmd') as mock_run:
            mock_run.return_value = (0, json.dumps(sample_result), '')
            result = run_bandit(tmp_path)
            assert isinstance(result, LintResult)
            assert len(result.findings) == 1
            finding = result.findings[0]
            assert finding.tool == "bandit"
            assert finding.file == "app.py"
            assert finding.line == 10

    def test_bandit_high_severity(self, tmp_path):
        """Bandit HIGH severity should map to critical."""
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text('[project]\nname = "test"\n')

        import json
        sample_result = {
            "results": [
                {
                    "filename": "app.py",
                    "line_number": 5,
                    "issue_severity": "HIGH",
                    "issue_text": "SQL injection",
                    "issue_confidence": "HIGH"
                }
            ]
        }

        with patch('secscan.linting.run_cmd') as mock_run:
            mock_run.return_value = (0, json.dumps(sample_result), '')
            result = run_bandit(tmp_path)
            assert result.findings[0].severity == "critical"

    def test_bandit_medium_severity(self, tmp_path):
        """Bandit MEDIUM severity should map to high."""
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text('[project]\nname = "test"\n')

        import json
        sample_result = {
            "results": [
                {
                    "filename": "app.py",
                    "line_number": 15,
                    "issue_severity": "MEDIUM",
                    "issue_text": "Possible XSS",
                    "issue_confidence": "MEDIUM"
                }
            ]
        }

        with patch('secscan.linting.run_cmd') as mock_run:
            mock_run.return_value = (0, json.dumps(sample_result), '')
            result = run_bandit(tmp_path)
            assert result.findings[0].severity == "high"


class TestRunSecurityLints:
    """Test full linting pipeline."""

    def test_returns_three_linters_for_empty_dir(self, tmp_path):
        """No projects found should still check all three linters."""
        results = run_security_lints(tmp_path)
        assert len(results) == 3
        tools = [r.tool for r in results]
        assert "gosec" in tools
        assert "clippy" in tools
        assert "bandit" in tools

    def test_returns_mixed_results_for_multi_language(self, tmp_path):
        """Multi-language project should check all applicable linters."""
        (tmp_path / "go.mod").write_text('module test\n\ngo 1.23\n')
        (tmp_path / "Cargo.toml").write_text('[package]\nname = "test"\nversion = "0.1.0"\n')
        (tmp_path / "pyproject.toml").write_text('[project]\nname = "test"\n')

        results = run_security_lints(tmp_path)
        tools = [r.tool for r in results]
        assert "gosec" in tools
        assert "clippy" in tools
        assert "bandit" in tools

    def test_all_findings_are_lint_finding_instances(self, tmp_path):
        """Every finding across all linters should be a LintFinding."""
        (tmp_path / "go.mod").write_text('module test\n\ngo 1.23\n')

        import json
        sample_finding = {
            "file": "main.go",
            "line": 10,
            "rule_id": "G101",
            "severity": "HIGH",
            "details": "Potential hardcoded credentials"
        }

        with patch('secscan.linting.run_cmd') as mock_run:
            mock_run.return_value = (0, json.dumps(sample_finding), '')
            results = run_security_lints(tmp_path)
            for r in results:
                for f in r.findings:
                    assert isinstance(f, LintFinding)
