"""Secret detection engine — scans files for secret patterns."""

import re
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from .config import ScanConfig, SecretPattern
from pydantic import BaseModel

console = Console()


class SecretFinding(BaseModel):  # type: ignore
    """A single secret finding."""
    file: str
    line: int
    column: int
    pattern_name: str
    severity: str
    matched_text: str  # redacted
    description: str


def _redact(match: str) -> str:
    """Redact sensitive parts of a matched secret."""
    if len(match) <= 8:
        return match[:2] + "****"
    return match[:4] + "****" + match[-2:]


def _should_skip(path: Path, ignore_patterns: list[str]) -> bool:
    """Check if a path should be skipped based on ignore patterns."""
    for pattern in ignore_patterns:
        if pattern in str(path):
            return True
    return False


def _load_ignore_file(path: Path) -> list[str]:
    """Load additional ignore patterns from .secscanignore."""
    ignore_file = path / ".secscanignore"
    if ignore_file.exists():
        with open(ignore_file) as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]
    return []


def _check_ignore_file(filepath: Path, ignore_files: list[str]) -> bool:
    """Check if a file should be skipped based on ignore file list."""
    for pattern in ignore_files:
        if str(filepath).endswith(pattern) or filepath.name == pattern:
            return True
    return False


def _should_include(path: Path, extensions: list[str]) -> bool:
    """Check if a file extension is in the include list."""
    return path.suffix.lower() in [e.lower() for e in extensions]


def scan_file(filepath: Path, patterns: list[SecretPattern], max_size_kb: int = 1024) -> list[SecretFinding]:
    """Scan a single file for secret patterns.

    Returns list of findings. Skips files larger than max_size_kb.
    """
    findings: list[SecretFinding] = []

    try:
        size = filepath.stat().st_size
        if size > max_size_kb * 1024:
            return findings  # skip oversized files silently

        content = filepath.read_text(errors="replace")
        lines = content.split("\n")

        for pattern in patterns:
            compiled = re.compile(pattern.regex)
            for i, line in enumerate(lines, start=1):
                for match in compiled.finditer(line):
                    text = match.group()
                    # Skip trivially short matches
                    if len(text.strip()) < 8:
                        continue
                    findings.append(SecretFinding(
                        file=str(filepath),
                        line=i,
                        column=match.start(),
                        pattern_name=pattern.name,
                        severity=pattern.severity,
                        matched_text=_redact(text),
                        description=pattern.description,
                    ))
    except (OSError, PermissionError):
        pass  # skip files we can't read

    return findings


def scan_path(path: Path, config: ScanConfig) -> list[SecretFinding]:
    """Scan a directory recursively for secrets."""
    all_findings: list[SecretFinding] = []
    patterns = config.secrets_patterns or []

    if not path.exists():
        console.print(f"[red]Path not found:[/red] {path}")
        return all_findings

    if path.is_file():
        all_findings = scan_file(path, patterns, config.max_file_size_kb)
    else:
        for filepath in sorted(path.rglob("*")):
            if _should_skip(filepath, config.ignore_patterns):
                continue
            if _check_ignore_file(filepath, config.ignore_file_patterns):
                continue
            if not _should_include(filepath, config.extensions):
                continue
            if filepath.is_file():
                all_findings.extend(scan_file(filepath, patterns, config.max_file_size_kb))

    # Deduplicate: same file + line + pattern_name = unique
    seen = set()
    unique: list[SecretFinding] = []
    for f in all_findings:
        key = (f.file, f.line, f.pattern_name)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return unique


def severity_color(severity: str) -> str:
    """Map severity to rich color."""
    colors = {
        "critical": "red bold",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
    }
    return colors.get(severity.lower(), "white")


def severity_rank(severity: str) -> int:
    """Rank severity for sorting (lower = worse)."""
    ranks = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
    }
    return ranks.get(severity.lower(), 4)


def print_secrets_report(findings: list[SecretFinding], target: str) -> None:
    """Print a human-readable report of secret findings."""
    if not findings:
        console.print(f"[green]✓[/green] No secrets detected in [bold]{target}[/bold]")
        return

    console.print(f"\n[red]⚠ {len(findings)} secret(s) detected in {target}[/red]")
    console.print("")

    for f in sorted(findings, key=lambda x: severity_rank(x.severity)):
        color = severity_color(f.severity)
        text = Text()
        text.append(f"[{f.severity.upper()}] ", style=color)
        text.append(f"{f.file}:{f.line}")
        text.append(f" — {f.pattern_name}")
        console.print(text)
        console.print(f"      {f.description}")

        # Show context (line before and after)
        try:
            lines = Path(f.file).read_text(errors="replace").split("\n")
            start = max(0, f.line - 2)
            end = min(len(lines), f.line + 1)
            for li in range(start, end):
                marker = ">>>" if li == f.line - 1 else "   "
                console.print(f"  {marker} {lines[li]}")
        except OSError:
            pass

        console.print("")


def severity_counts(findings: list[SecretFinding]) -> dict[str, int]:
    """Count findings by severity."""
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts
