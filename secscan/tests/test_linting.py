"""Tests for security linter wrappers.

Real linters (gosec/clippy/bandit) are mocked via `run_cmd` so these tests
don't depend on the tools being installed or their exact output format.
"""

import json

from secscan import linting
from secscan.linting import (
    _bandit_severity,
    _severity_from_gosec_rule,
    run_bandit,
    run_clippy,
    run_gosec,
    run_security_lints,
)


class TestGuards:
    """No manifest file present => no subprocess call, unsuccessful result."""

    def test_gosec_no_go_mod(self, tmp_path, monkeypatch):
        called = []
        monkeypatch.setattr(linting, "run_cmd", lambda *a, **k: called.append(1) or (0, "", ""))

        result = run_gosec(tmp_path)

        assert result.success is False
        assert result.findings == []
        assert called == []

    def test_clippy_no_cargo_toml(self, tmp_path, monkeypatch):
        called = []
        monkeypatch.setattr(linting, "run_cmd", lambda *a, **k: called.append(1) or (0, "", ""))

        result = run_clippy(tmp_path)

        assert result.success is False
        assert called == []

    def test_bandit_no_pyproject_or_setup(self, tmp_path, monkeypatch):
        called = []
        monkeypatch.setattr(linting, "run_cmd", lambda *a, **k: called.append(1) or (0, "", ""))

        result = run_bandit(tmp_path)

        assert result.success is False
        assert called == []

    def test_run_security_lints_empty_dir(self, tmp_path):
        results = run_security_lints(tmp_path)

        assert len(results) == 3
        assert all(r.success is False for r in results)
        assert all(r.findings == [] for r in results)


class TestGosecParsing:
    def test_parses_json_lines(self, tmp_path, monkeypatch):
        (tmp_path / "go.mod").write_text("module x\n")
        line = json.dumps({
            "file": "main.go", "line": 10, "rule_id": "G101", "details": "hardcoded credentials",
        })
        monkeypatch.setattr(linting, "run_cmd", lambda *a, **k: (0, line, ""))

        result = run_gosec(tmp_path)

        assert result.success is True
        assert len(result.findings) == 1
        assert result.findings[0].severity == "critical"
        assert result.findings[0].code == "G101"


class TestClippyParsing:
    def test_parses_compiler_message(self, tmp_path, monkeypatch):
        (tmp_path / "Cargo.toml").write_text("[package]\nname = \"x\"\n")
        msg = json.dumps({
            "reason": "compiler-message",
            "message": {
                "code": {"code": "clippy::foo", "label": ""},
                "level": "warning",
                "spans": [{"file_name": "src/main.rs", "line_start": 5}],
                "message": "useless conversion",
            },
        })
        monkeypatch.setattr(linting, "run_cmd", lambda *a, **k: (0, msg, ""))

        result = run_clippy(tmp_path)

        assert result.success is True
        assert len(result.findings) == 1
        assert result.findings[0].severity == "high"
        assert result.findings[0].file == "src/main.rs"


class TestBanditParsing:
    def test_parses_results(self, tmp_path, monkeypatch):
        (tmp_path / "pyproject.toml").write_text("[project]\nname = \"x\"\n")
        payload = json.dumps({
            "results": [{
                "filename": "app.py", "line_number": 3, "issue_severity": "HIGH",
                "issue_text": "use of eval", "issue_confidence": "HIGH",
            }]
        })
        monkeypatch.setattr(linting, "run_cmd", lambda *a, **k: (0, payload, ""))

        result = run_bandit(tmp_path)

        assert result.success is True
        assert len(result.findings) == 1
        assert result.findings[0].severity == "critical"


class TestSeverityMapping:
    def test_gosec_rule_severity(self):
        assert _severity_from_gosec_rule("G101") == "critical"
        assert _severity_from_gosec_rule("G301") == "high"
        assert _severity_from_gosec_rule("G401") == "medium"
        assert _severity_from_gosec_rule("UNKNOWN") == "low"

    def test_bandit_severity(self):
        assert _bandit_severity("HIGH") == "critical"
        assert _bandit_severity("MEDIUM") == "high"
        assert _bandit_severity("LOW") == "medium"
        assert _bandit_severity("") == "low"
