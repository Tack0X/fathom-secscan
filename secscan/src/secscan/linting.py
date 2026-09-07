"""Security linting — wrapper calls for language-specific security scanners."""

import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from rich.console import Console

console = Console()


@dataclass
class LintFinding:
    """A single security lint finding."""
    file: str
    line: int
    severity: str
    message: str
    code: str  # lint rule code
    tool: str


@dataclass
class LintResult:
    """Result from a security linter scan."""
    tool: str
    findings: list[LintFinding]
    success: bool


def run_cmd(cmd: list[str], cwd: Path, timeout: int = 120) -> tuple[int, str, str]:
    """Run a subprocess command."""
    try:
        result = subprocess.run(
            cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"Command timed out after {timeout}s"
    except FileNotFoundError:
        return -1, "", f"Command not found: {cmd[0]}"


def run_gosec(path: Path) -> LintResult:
    """Run gosec on a Go project."""
    go_mod = path / "go.mod"
    if not go_mod.exists():
        return LintResult(tool="gosec", findings=[], success=False)

    rc, out, err = run_cmd(["gosec", "-fmt=json", "./..."], cwd=path, timeout=120)

    if rc != 0 and not out.strip():
        return LintResult(tool="gosec", findings=[], success=False)

    findings: list[LintFinding] = []
    for line in (out + err).split("\n"):
        if not line.strip():
            continue
        try:
            import json
            data = json.loads(line)
            if isinstance(data, dict):
                findings.append(LintFinding(
                    file=data.get("file", "unknown"),
                    line=data.get("line", 0),
                    severity=_severity_from_gosec_rule(data.get("rule_id", "")),
                    message=data.get("details", data.get("severity", "")),
                    code=data.get("rule_id", "GOSEC"),
                    tool="gosec",
                ))
        except (json.JSONDecodeError, TypeError):
            pass

    return LintResult(tool="gosec", findings=findings, success=True)


def _severity_from_gosec_rule(rule_id: str) -> str:
    """Map gosec rule IDs to severity."""
    if rule_id in ("G101", "G102", "G103", "G104", "G201", "G202", "G203", "G204"):
        return "critical"
    if rule_id in ("G301", "G302", "G303", "G304", "G305", "G306", "G307", "G308"):
        return "high"
    if rule_id in ("G401", "G402", "G403", "G404", "G405", "G406"):
        return "medium"
    return "low"


def run_clippy(path: Path) -> LintResult:
    """Run cargo clippy with security-related lint rules."""
    manifest = path / "Cargo.toml"
    if not manifest.exists():
        return LintResult(tool="clippy", findings=[], success=False)

    rc, out, err = run_cmd(
        ["cargo", "clippy", "--message-format=json"],
        cwd=path,
        timeout=180,
    )

    findings: list[LintFinding] = []
    for line in (out + err).split("\n"):
        if not line.strip():
            continue
        try:
            import json
            data = json.loads(line)
            if data.get("reason") == "compiler-message":
                msg = data.get("message", {})
                code = msg.get("code", {}).get("code", "CLIPPY")
                level = msg.get("level", "")
                # Map clippy levels to our severity
                severity = {
                    "error": "critical",
                    "warning": "high",
                    "help": "medium",
                }.get(level, "low")

                spans = msg.get("spans", [])
                file_loc = spans[0]["file_name"] if spans else "unknown"
                line_num = spans[0]["line_start"] if spans else 0
                msg_text = msg.get("message", "")

                findings.append(LintFinding(
                    file=file_loc,
                    line=line_num,
                    severity=severity,
                    message=msg_text,
                    code=f"{code}: {msg.get("code", {}).get("label", "")}",
                    tool="clippy",
                ))
        except (json.JSONDecodeError, KeyError, TypeError):
            continue

    return LintResult(tool="clippy", findings=findings, success=True)


def run_bandit(path: Path) -> LintResult:
    """Run bandit (Python security linter)."""
    pyproject = path / "pyproject.toml"
    setup_py = path / "setup.py"
    if not pyproject.exists() and not setup_py.exists():
        return LintResult(tool="bandit", findings=[], success=False)

    rc, out, err = run_cmd(
        ["bandit", "-r", str(path), "-f", "json"],
        cwd=path,
        timeout=120,
    )

    if rc != 0 and not out.strip():
        return LintResult(tool="bandit", findings=[], success=False)

    findings: list[LintFinding] = []
    try:
        import json
        data = json.loads(out)
        if isinstance(data, dict) and "results" in data:
            for r in data["results"]:
                findings.append(LintFinding(
                    file=r.get("filename", "unknown"),
                    line=r.get("line_number", 0),
                    severity=_bandit_severity(r.get("issue_severity", "")),
                    message=r.get("issue_text", ""),
                    code=r.get("issue_confidence", ""),
                    tool="bandit",
                ))
    except (json.JSONDecodeError, TypeError):
        pass

    return LintResult(tool="bandit", findings=findings, success=True)


def _bandit_severity(severity: str) -> str:
    """Map bandit severity levels."""
    return {
        "LOW": "medium",
        "MEDIUM": "high",
        "HIGH": "critical",
    }.get(severity.upper(), "low")


def run_security_lints(path: Path) -> list[LintResult]:
    """Run all security linters on a target path."""
    results: list[LintResult] = []

    results.append(run_gosec(path))
    results.append(run_clippy(path))
    results.append(run_bandit(path))

    return results


def print_lint_report(results: list[LintResult]) -> None:
    """Print human-readable security lint reports."""
    total_findings = 0

    for r in results:
        if not r.findings:
            console.print(f"[green]✓[/green] {r.tool}: no issues found")
            continue

        total_findings += len(r.findings)
        console.print(f"\n[red]⚠ {len(r.findings)} security issue(s) from {r.tool}[/red]")
        console.print("")

        for f in r.findings:
            color = _lint_severity_color(f.severity)
            console.print(f"  [{f.severity.upper()}] {f.file}:{f.line} — {f.message[:80]}")

        console.print("")

    if total_findings == 0:
        console.print(f"\n[green]✓[/green] Security linters passed with no issues")


def _lint_severity_color(severity: str) -> str:
    """Map severity to rich color."""
    colors = {
        "critical": "red bold",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
    }
    return colors.get(severity.lower(), "white")
