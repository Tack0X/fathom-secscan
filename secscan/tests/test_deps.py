"""Tests for dependency vulnerability scanning.

These tests avoid invoking real external tools (safety/npm/cargo-audit/
govulncheck) by monkeypatching `run_cmd`, since availability and output
format of those tools can't be relied on in CI.
"""

import json

from secscan import deps
from secscan.deps import scan_all, scan_go, scan_python, scan_rust, scan_typescript


class TestRunCmd:
    def test_command_not_found(self):
        rc, out, err = deps.run_cmd(["this-binary-does-not-exist-xyz"])
        assert rc == -1
        assert "not found" in err.lower()

    def test_timeout(self, monkeypatch):
        import subprocess

        def fake_run(*args, **kwargs):
            raise subprocess.TimeoutExpired(cmd=args[0], timeout=1)

        monkeypatch.setattr(deps.subprocess, "run", fake_run)
        rc, out, err = deps.run_cmd(["sleep", "5"], timeout=1)
        assert rc == -1
        assert "timed out" in err.lower()

    def test_success(self, monkeypatch):
        class FakeResult:
            returncode = 0
            stdout = "ok"
            stderr = ""

        monkeypatch.setattr(deps.subprocess, "run", lambda *a, **k: FakeResult())
        assert deps.run_cmd(["echo", "ok"]) == (0, "ok", "")


class TestScanGuards:
    """Scanners should no-op when the relevant manifest file is absent."""

    def test_scan_go_no_go_mod(self, tmp_path):
        assert scan_go(tmp_path) == []

    def test_scan_rust_no_cargo_lock(self, tmp_path):
        assert scan_rust(tmp_path) == []

    def test_scan_typescript_no_manifest(self, tmp_path):
        assert scan_typescript(tmp_path) == []

    def test_scan_all_empty_dir_calls_nothing(self, tmp_path, monkeypatch):
        monkeypatch.setattr(deps, "run_cmd", lambda *a, **k: (0, "should not run", ""))
        assert scan_all(tmp_path) == []


class TestScanPython:
    def test_no_manifest_no_findings(self, tmp_path, monkeypatch):
        monkeypatch.setattr(deps, "run_cmd", lambda *a, **k: (1, "", "not installed"))
        assert scan_python(tmp_path) == []

    def test_no_manifest_parses_safety_text_output(self, tmp_path, monkeypatch):
        output = "flask (1.0) - CVE-2019-1010083: some vuln description\n"

        def fake_run_cmd(cmd, **kwargs):
            if cmd[0] == "python3":
                return 0, output, ""
            return 1, "", ""

        monkeypatch.setattr(deps, "run_cmd", fake_run_cmd)
        findings = scan_python(tmp_path)

        assert len(findings) == 1
        assert findings[0].package == "flask"
        assert findings[0].version == "1.0"
        assert "CVE-2019-1010083" in findings[0].description

    def test_pip_list_fallback(self, tmp_path, monkeypatch):
        pkgs = json.dumps([{"name": "flask", "version": "1.0"}])

        def fake_run_cmd(cmd, **kwargs):
            if cmd[0] == "python3":
                return 1, "", ""
            if cmd == ["pip", "list", "--format=json"]:
                return 0, pkgs, ""
            if cmd[0] == "safety":
                return 0, "vulnerable: some info", ""
            return 1, "", ""

        monkeypatch.setattr(deps, "run_cmd", fake_run_cmd)
        findings = scan_python(tmp_path)

        assert len(findings) == 1
        assert findings[0].package == "flask"


class TestScanGo:
    def test_parses_govulncheck_output(self, tmp_path, monkeypatch):
        (tmp_path / "go.mod").write_text("module example.com/foo\n")
        output = "Vulnerability in github.com/foo/bar detected\n"
        monkeypatch.setattr(deps, "run_cmd", lambda *a, **k: (0, output, ""))

        findings = scan_go(tmp_path)

        assert len(findings) == 1
        assert findings[0].package == "github.com/foo/bar"
        assert findings[0].tool == "govulncheck"


class TestScanRust:
    def test_parses_json_advisories(self, tmp_path, monkeypatch):
        (tmp_path / "Cargo.lock").write_text("")
        payload = json.dumps({
            "advisories": {
                "somecrate": [{"severity": "high", "id": "RUSTSEC-2024-0001", "version": "1.2.3"}]
            },
            "vulnerabilities": {},
        })
        monkeypatch.setattr(deps, "run_cmd", lambda *a, **k: (0, payload, ""))

        findings = scan_rust(tmp_path)

        assert len(findings) == 1
        assert findings[0].package == "somecrate"
        assert findings[0].severity == "high"
        assert findings[0].tool == "cargo-audit"


class TestScanTypescript:
    def test_parses_npm_audit_json(self, tmp_path, monkeypatch):
        (tmp_path / "package-lock.json").write_text("{}")
        payload = json.dumps({
            "dependencies": {
                "lodash": {
                    "vulnerabilities": {
                        "high": {
                            "lodash-vuln": {"version": "4.17.15", "title": "Prototype Pollution"}
                        }
                    }
                }
            }
        })
        monkeypatch.setattr(deps, "run_cmd", lambda *a, **k: (0, payload, ""))

        findings = scan_typescript(tmp_path)

        assert len(findings) == 1
        assert findings[0].severity == "high"
        assert "Prototype Pollution" in findings[0].description
        assert findings[0].tool == "npm-audit"
