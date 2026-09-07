"""Report generation — JSON and human-readable output."""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .secrets import SecretFinding, SecretPattern, print_secrets_report, severity_counts
from .deps import VulnFinding, print_deps_report
from .linting import LintResult, print_lint_report


class ScanReport:
    """Complete scan report containing all findings."""

    def __init__(
        self,
        target: str,
        secret_findings: list[SecretFinding],
        vuln_findings: list[VulnFinding],
        lint_results: list[LintResult],
        elapsed_seconds: float,
    ):
        self.target = target
        self.secret_findings = secret_findings
        self.vuln_findings = vuln_findings
        self.lint_results = lint_results
        self.elapsed_seconds = elapsed_seconds
        self.timestamp = datetime.now(timezone.utc).isoformat()

    @property
    def total_findings(self) -> int:
        return len(self.secret_findings) + len(self.vuln_findings) + sum(
            len(r.findings) for r in self.lint_results
        )

    @property
    def has_critical(self) -> bool:
        for f in self.secret_findings:
            if f.severity == "critical":
                return True
        for f in self.vuln_findings:
            if f.severity == "critical":
                return True
        for r in self.lint_results:
            for f in r.findings:
                if f.severity == "critical":
                    return True
        return False

    @property
    def exit_code(self) -> int:
        """Return non-zero exit code if any critical/severe findings exist."""
        if self.has_critical:
            return 1
        if self.total_findings > 0:
            return 2
        return 0

    def to_dict(self) -> dict:
        """Convert report to a JSON-serializable dict."""
        return {
            "timestamp": self.timestamp,
            "target": self.target,
            "elapsed_seconds": self.elapsed_seconds,
            "summary": {
                "total_findings": self.total_findings,
                "secrets": len(self.secret_findings),
                "dependency_vulns": len(self.vuln_findings),
                "lint_issues": sum(len(r.findings) for r in self.lint_results),
            },
            "severity_counts": severity_counts(self.secret_findings),
            "findings": {
                "secrets": [
                    {
                        "file": f.file,
                        "line": f.line,
                        "pattern": f.pattern_name,
                        "severity": f.severity,
                        "description": f.description,
                        "matched_text": f.matched_text,
                    }
                    for f in self.secret_findings
                ],
                "dependencies": [
                    {
                        "package": f.package,
                        "version": f.version,
                        "severity": f.severity,
                        "description": f.description,
                        "scanner": f.tool,
                    }
                    for f in self.vuln_findings
                ],
                "lints": [
                    {
                        "tool": r.tool,
                        "findings": [
                            {
                                "file": f.file,
                                "line": f.line,
                                "severity": f.severity,
                                "message": f.message,
                                "code": f.code,
                            }
                            for f in r.findings
                        ],
                    }
                    for r in self.lint_results
                ],
            },
            "status": "critical" if self.has_critical else ("warning" if self.total_findings > 0 else "clean"),
        }

    def to_json(self) -> str:
        """Serialize report as JSON."""
        return json.dumps(self.to_dict(), indent=2)

    def print_report(self, json_output: bool = False, json_path: Optional[str] = None) -> None:
        """Print report to stdout, optionally also write JSON."""
        if json_output:
            print(self.to_json())
            if json_path:
                Path(json_path).write_text(self.to_json())
            return

        print(f"\n{'='*60}")
        print(f"  Security Scan Report")
        print(f"  Target: {self.target}")
        print(f"  Time: {self.timestamp}")
        print(f"  Duration: {self.elapsed_seconds:.1f}s")
        print(f"{'='*60}")

        print(f"\n  Summary: {self.total_findings} finding(s)")
        print(f"    Secrets: {len(self.secret_findings)}")
        print(f"    Dependencies: {len(self.vuln_findings)}")
        print(f"    Lint issues: {sum(len(r.findings) for r in self.lint_results)}")

        if self.secret_findings:
            print_secrets_report(self.secret_findings, self.target)

        if self.vuln_findings:
            print_deps_report(self.vuln_findings, self.target)

        if self.lint_results:
            print_lint_report(self.lint_results)

        if json_path:
            Path(json_path).write_text(self.to_json())
            print(f"\nJSON report written to: {json_path}")

        print(f"\n{'='*60}")
        if self.has_critical:
            print(f"  [CRITICAL] Critical issues found — see report above")
        elif self.total_findings > 0:
            print(f"  [WARNING] Issues found — review recommended")
        else:
            print(f"  [CLEAN] No security issues detected")
        print(f"{'='*60}\n")
