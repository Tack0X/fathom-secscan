"""CLI entry point for secscan."""

import sys
from pathlib import Path

import typer

app = typer.Typer(
    name="secscan",
    help="Multi-language security scanner CLI",
    add_completion=False,
)


@app.command()
def scan(
    target: str = typer.Argument(".", help="File or directory to scan"),
    config: str = typer.Option(
        None, "--config", "-c", help="Path to YAML config file"
    ),
    as_json: bool = typer.Option(
        False, "--json", "-j", help="Output report as JSON to stdout"
    ),
    json_file: str = typer.Option(
        None, "--json-file", "-o", help="Write JSON report to file"
    ),
    no_deps: bool = typer.Option(
        False, "--no-deps", help="Skip dependency vulnerability scanning"
    ),
    no_lints: bool = typer.Option(
        False, "--no-lints", help="Skip security linting"
    ),
    severity: str = typer.Option(
        "high", "--severity", "-s",
        help="Minimum severity threshold (low|medium|high|critical)"
    ),
    extensions: str = typer.Option(
        None, "--extensions", "-e",
        help="Comma-separated file extensions to scan"
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Verbose output"
    ),
):
    """Scan a target for security issues: secrets, dependency vulns, and lint findings."""
    from .config import ScanConfig, default_secrets_patterns
    from .scanner import run_scan

    config_path = Path(config) if config else Path("secscan.yml")
    if config_path.exists():
        from .config import load_config
        scan_config = load_config(str(config_path))
    else:
        scan_config = ScanConfig()

    if severity:
        scan_config.severity_threshold = severity
    if extensions:
        scan_config.extensions = [e.strip() for e in extensions.split(",")]

    report = run_scan(
        target=target,
        config=scan_config,
        include_deps=not no_deps,
        include_lints=not no_lints,
    )

    report.print_report(json_output=as_json, json_path=json_file)
    sys.exit(report.exit_code)


@app.command()
def patterns():
    """List all built-in secret detection patterns."""
    from .config import default_secrets_patterns

    patterns = default_secrets_patterns()
    print(f"\n  {len(patterns)} built-in secret detection patterns:\n")

    for p in sorted(patterns, key=lambda x: {
        "critical": 0, "high": 1, "medium": 2, "low": 3
    }.get(x.severity.lower(), 4)):
        print(f"  [{p.severity.upper()}] {p.name}")
        print(f"          {p.description}")
        print()


@app.command()
def version():
    """Print version."""
    print("secscan 0.1.0")

