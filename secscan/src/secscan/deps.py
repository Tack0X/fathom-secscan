"""Dependency vulnerability scanning per language."""

import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from rich.console import Console

console = Console()


@dataclass
class VulnFinding:
    """A single vulnerability finding from dependency scanning."""
    package: str
    version: str
    severity: str
    description: str
    tool: str  # which scanner found it


def run_cmd(cmd: list[str], cwd: Optional[Path] = None, timeout: int = 60) -> tuple[int, str, str]:
    """Run a subprocess command, return (returncode, stdout, stderr)."""
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"Command timed out after {timeout}s"
    except FileNotFoundError:
        return -1, "", f"Command not found: {cmd[0]}"


def scan_python(path: Path) -> list[VulnFinding]:
    """Scan Python dependencies using `safety`."""
    findings: list[VulnFinding] = []
    lockfile = path / "requirements.txt"
    if not lockfile.exists():
        lockfile = path / "pyproject.toml"

    if not lockfile.exists():
        # Check for Pipfile
        lockfile = path / "Pipfile"
        if lockfile.exists():
            rc, out, _ = run_cmd(["pipenv", "install", "--dev"], cwd=path)
            if rc == 0:
                rc, out, _ = run_cmd(
                    ["safety", "check", "--json"],
                    cwd=path,
                    timeout=120,
                )
                if rc == 0 and out.strip():
                    for line in out.strip().split("\n"):
                        try:
                            import json
                            entry = json.loads(line)
                            findings.append(VulnFinding(
                                package=entry.get("dependency_name", "unknown"),
                                version=entry.get("installed_version", "unknown"),
                                severity=entry.get("vulnerability_severity", "unknown"),
                                description=entry.get("vulnerability_id", "unknown"),
                                tool="safety",
                            ))
                        except json.JSONDecodeError:
                            continue

        if not findings:
            rc, out, _ = run_cmd(
                ["python3", "-m", "safety", "check", "--file", str(lockfile)],
                cwd=path,
            )
            if rc == 0 and out.strip():
                for line in out.strip().split("\n"):
                    if line.startswith("=") or not line.strip():
                        continue
                    # Format: Package (version) - Vulnerability
                    parts = line.split(" - ", 1)
                    pkg_part = parts[0].strip() if parts else "unknown"
                    if "(" in pkg_part:
                        pkg, ver = pkg_part.rsplit("(", 1)
                        pkg = pkg.strip()
                        ver = ver.strip(")")
                    else:
                        pkg = pkg_part
                        ver = "unknown"
                    desc = parts[1].strip() if len(parts) > 1 else "vulnerability"
                    findings.append(VulnFinding(
                        package=pkg, version=ver, severity="unknown",
                        description=desc, tool="safety",
                    ))

    if not findings:
        rc, out, _ = run_cmd(
            ["pip", "list", "--format=json"],
            cwd=path,
        )
        if rc == 0:
            try:
                import json
                pkgs = json.loads(out)
                for pkg in pkgs:
                    rc2, out2, _ = run_cmd(
                        ["safety", "check", "--bare", "-r", "-"],
                        cwd=path,
                        timeout=30,
                    )
                    if rc2 == 0 and out2.strip():
                        findings.append(VulnFinding(
                            package=pkg.get("name", "unknown"),
                            version=pkg.get("version", "unknown"),
                            severity="unknown",
                            description=out2.strip(),
                            tool="safety",
                        ))
            except json.JSONDecodeError:
                pass

    return findings


def scan_go(path: Path) -> list[VulnFinding]:
    """Scan Go dependencies using `govulncheck`."""
    findings: list[VulnFinding] = []
    go_mod = path / "go.mod"
    if not go_mod.exists():
        return findings

    rc, out, err = run_cmd(
        ["govulncheck", "-m", "./..."],
        cwd=path,
    )

    if out.strip():
        # Parse govulncheck output: each finding starts with "go: security: ..."
        for line in out.strip().split("\n"):
            if "security:" in line or "Vulnerability" in line or "go:" in line:
                # Extract package name from GOPATH format
                pkg = "unknown"
                ver = "unknown"
                desc = line.strip()

                # Try to extract package from module path
                if "github.com/" in line or "golang.org/" in line:
                    parts = line.split()
                    for part in parts:
                        if "github.com/" in part or "golang.org/" in part:
                            pkg = part.rstrip(")")
                            break

                findings.append(VulnFinding(
                    package=pkg, version=ver, severity="unknown",
                    description=desc, tool="govulncheck",
                ))

    return findings


def scan_rust(path: Path) -> list[VulnFinding]:
    """Scan Rust dependencies using `cargo-audit`."""
    findings: list[VulnFinding] = []
    lockfile = path / "Cargo.lock"
    if not lockfile.exists():
        return findings

    rc, out, _ = run_cmd(
        ["cargo-audit", "-f", "json"],
        cwd=path,
        timeout=120,
    )

    if rc == 0 and out.strip():
        try:
            import json
            data = json.loads(out)
            advisories = data.get("advisories", {})
            vulns = data.get("vulnerabilities", {})

            for crate_name, vulns_list in advisories.items():
                for v in (vulns_list if isinstance(vulns_list, list) else [vulns_list]):
                    if isinstance(v, dict):
                        sev = v.get("severity", v.get("level", "unknown"))
                        desc = v.get("id", v.get("description", ""))
                        ver = v.get("version", "unknown")
                    else:
                        sev = "unknown"
                        desc = str(v)
                        ver = "unknown"
                    findings.append(VulnFinding(
                        package=crate_name, version=ver, severity=sev,
                        description=desc, tool="cargo-audit",
                    ))
        except json.JSONDecodeError:
            # Parse plain text output as fallback
            for line in out.strip().split("\n"):
                if line.strip() and not line.startswith("{"):
                    findings.append(VulnFinding(
                        package="unknown", version="unknown",
                        severity="unknown", description=line.strip(),
                        tool="cargo-audit",
                    ))

    return findings


def scan_typescript(path: Path) -> list[VulnFinding]:
    """Scan TypeScript dependencies using `npm audit`."""
    findings: list[VulnFinding] = []
    lockfile = path / "package-lock.json"
    if not lockfile.exists():
        lockfile = path / "pnpm-lock.yaml"
        if lockfile.exists():
            rc, out, _ = run_cmd(
                ["pnpm", "audit", "--json"],
                cwd=path,
            )
            if rc == 0 and out.strip():
                try:
                    import json
                    data = json.loads(out)
                    for pkg, info in data.get("advisories", {}).items():
                        if isinstance(info, dict):
                            findings.append(VulnFinding(
                                package=pkg, version=info.get("version", "unknown"),
                                severity=info.get("severity", "unknown"),
                                description=info.get("title", info.get("overview", "")),
                                tool="pnpm-audit",
                            ))
                except json.JSONDecodeError:
                    pass
            return findings

    if not lockfile.exists() and not (path / "package.json").exists():
        return findings

    rc, out, _ = run_cmd(
        ["npm", "audit", "--json"],
        cwd=path,
    )

    if rc == 0 and out.strip():
        try:
            import json
            data = json.loads(out)
            for pkg, info in data.get("dependencies", {}).items():
                if isinstance(info, dict) and info.get("vulnerabilities"):
                    for sev, vulns in info["vulnerabilities"].items():
                        for vname, vinfo in (vulns if isinstance(vulns, dict) else {}).items():
                            if isinstance(vinfo, dict):
                                findings.append(VulnFinding(
                                    package=f"{pkg}@{vinfo.get('version', 'unknown')}",
                                    version=vinfo.get("version", "unknown"),
                                    severity=sev,
                                    description=vinfo.get("title", vinfo.get("overview", vname)),
                                    tool="npm-audit",
                                ))
        except json.JSONDecodeError:
            for line in out.strip().split("\n"):
                if line.strip() and line.startswith('{'):
                    continue
                if line.strip() and ("vulnerability" in line.lower() or "high" in line.lower()):
                    findings.append(VulnFinding(
                        package="unknown", version="unknown",
                        severity="unknown", description=line.strip(),
                        tool="npm-audit",
                    ))

    return findings


def scan_all(path: Path) -> list[VulnFinding]:
    """Run dependency scans for all languages found in the target path."""
    all_findings: list[VulnFinding] = []

    # Check which language files are present
    has_py = any(p.name == "requirements.txt" or p.name == "pyproject.toml" or p.name == "Pipfile" for p in path.rglob("*") if p.name in ("requirements.txt", "pyproject.toml", "Pipfile"))
    has_go = any(p.name == "go.mod" for p in path.rglob("*") if p.is_file())
    has_rust = any(p.name == "Cargo.lock" for p in path.rglob("*") if p.is_file())
    has_ts = any(p.name in ("package-lock.json", "pnpm-lock.yaml", "package.json") for p in path.rglob("*") if p.is_file())

    if has_py:
        all_findings.extend(scan_python(path))
    if has_go:
        all_findings.extend(scan_go(path))
    if has_rust:
        all_findings.extend(scan_rust(path))
    if has_ts:
        all_findings.extend(scan_typescript(path))

    return all_findings


def print_deps_report(findings: list[VulnFinding], target: str) -> None:
    """Print a human-readable dependency vulnerability report."""
    if not findings:
        console.print(f"[green]✓[/green] No vulnerabilities found in {target} dependencies")
        return

    console.print(f"\n[red]⚠ {len(findings)} vulnerability(ies) in {target} dependencies[/red]")
    console.print("")

    for f in sorted(findings, key=lambda x: severity_rank(x.severity)):
        color = severity_color(f.severity)
        console.print(f"[{f.severity.upper()}] {f.package} — {f.description}")
        console.print(f"      Scanner: {f.tool} | Version: {f.version}")
        console.print("")


def severity_color(severity: str) -> str:
    """Map severity to rich color."""
    colors = {
        "critical": "red bold",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
        "unknown": "white",
    }
    return colors.get(severity.lower(), "white")


def severity_rank(severity: str) -> int:
    """Rank severity for sorting."""
    ranks = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return ranks.get(severity.lower(), 4)
