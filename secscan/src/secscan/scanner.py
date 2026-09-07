"""Main scanner orchestration — ties together secrets, deps, and linting."""

import time
from pathlib import Path

from .config import ScanConfig, default_secrets_patterns, load_config
from .secrets import scan_path, SecretFinding
from .deps import scan_all, VulnFinding
from .linting import run_security_lints, LintResult
from .report import ScanReport


def run_scan(
    target: str,
    config: ScanConfig,
    include_deps: bool = True,
    include_lints: bool = True,
) -> ScanReport:
    """Run the full security scan on a target path.

    Args:
        target: File or directory path to scan
        config: Scan configuration
        include_deps: Run dependency vulnerability scanning
        include_lints: Run security linting (gosec, clippy, bandit)
    """
    start_time = time.time()
    target_path = Path(target).resolve()

    config.paths = [str(target_path)]

    # Load secrets patterns from config or use defaults
    if not config.secrets_patterns:
        config.secrets_patterns = default_secrets_patterns()

    # Step 1: Secret scanning
    secret_findings: list[SecretFinding] = scan_path(target_path, config)

    # Step 2: Dependency scanning
    vuln_findings: list[VulnFinding] = []
    if include_deps:
        vuln_findings = scan_all(target_path)

    # Step 3: Security linting
    lint_results: list[LintResult] = []
    if include_lints:
        lint_results = run_security_lints(target_path)

    elapsed = time.time() - start_time

    return ScanReport(
        target=str(target_path),
        secret_findings=secret_findings,
        vuln_findings=vuln_findings,
        lint_results=lint_results,
        elapsed_seconds=elapsed,
    )
