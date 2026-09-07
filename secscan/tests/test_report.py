"""Tests for report generation."""

import json

from secscan.deps import VulnFinding
from secscan.linting import LintFinding, LintResult
from secscan.report import ScanReport
from secscan.secrets import SecretFinding


def make_report(secret_findings=None, vuln_findings=None, lint_results=None):
    return ScanReport(
        target="/some/path",
        secret_findings=secret_findings or [],
        vuln_findings=vuln_findings or [],
        lint_results=lint_results or [],
        elapsed_seconds=0.1,
    )


class TestScanReport:
    def test_clean_report(self):
        report = make_report()
        assert report.total_findings == 0
        assert report.has_critical is False
        assert report.exit_code == 0
        assert report.to_dict()["status"] == "clean"

    def test_critical_secret_finding(self):
        finding = SecretFinding(
            file="a.py", line=1, column=0, pattern_name="AWS Access Key",
            severity="critical", matched_text="AKIA****", description="AWS key",
        )
        report = make_report(secret_findings=[finding])
        assert report.has_critical is True
        assert report.exit_code == 1
        assert report.to_dict()["status"] == "critical"

    def test_critical_vuln_finding(self):
        finding = VulnFinding(package="foo", version="1.0", severity="critical", description="bad", tool="safety")
        report = make_report(vuln_findings=[finding])
        assert report.has_critical is True
        assert report.exit_code == 1

    def test_critical_lint_finding(self):
        lf = LintFinding(file="a.go", line=1, severity="critical", message="bad", code="G101", tool="gosec")
        report = make_report(lint_results=[LintResult(tool="gosec", findings=[lf], success=True)])
        assert report.has_critical is True

    def test_non_critical_findings_set_exit_code_2(self):
        finding = VulnFinding(package="foo", version="1.0", severity="medium", description="meh", tool="safety")
        report = make_report(vuln_findings=[finding])
        assert report.exit_code == 2
        assert report.to_dict()["status"] == "warning"

    def test_to_json_round_trips(self):
        report = make_report()
        data = json.loads(report.to_json())
        assert data["target"] == "/some/path"
        assert data["summary"]["total_findings"] == 0

    def test_print_report_human_readable(self, capsys):
        report = make_report()
        report.print_report()
        out = capsys.readouterr().out
        assert "CLEAN" in out

    def test_print_report_json_writes_file(self, tmp_path):
        report = make_report()
        out_file = tmp_path / "report.json"
        report.print_report(json_output=True, json_path=str(out_file))
        assert out_file.exists()
        assert json.loads(out_file.read_text())["status"] == "clean"
