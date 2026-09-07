# Threat Model: secscan

## Assets

- Secret detection engine and regex patterns
- User codebases (accessed during scanning)
- Config files (can specify which paths to scan)
- Scan reports (may contain sensitive info)

## Attackers

1. **Adversarial code** — Malicious projects trying to evade detection or cause crashes
2. **Config injection** — Malicious secscan.yml trying to access unauthorized paths
3. **Path traversal** — Users providing paths outside intended directories

## Trust Boundaries

- YAML config file → untrusted input
- Filesystem → untrusted paths
- Regex patterns → potentially untrusted source (if custom patterns from external sources)

## Attack Surface

- CLI argument parsing (target path)
- YAML config loading (paths, patterns, thresholds)
- File reading (all files in target directory)
- Regex compilation (30+ patterns from config.py)
- Subprocess execution (gosec, clippy, bandit, safety, govulncheck, cargo-audit, npm audit)

## Mitigations

- ✅ Config validation via pydantic models
- ✅ File path validation (relative paths, no ../ traversal)
- ✅ Max file size limits (1024KB default)
- ✅ Ignore patterns and file exclusions
- ✅ Timeout on subprocess calls
- ✅ Secret redaction in reports (matched text obscured)
- ✅ Exit codes for CI/CD integration (no sensitive info in exit code)
- ✅ Structured JSON output option (machine-readable, no color codes)

## Remaining Risk

- **Regex denial-of-service**: Complex regex patterns could theoretically cause catastrophic backtracking. Mitigation: pythons re module has built-in timeout in newer versions, but we should consider adding a regex compilation timeout wrapper.
- **Command injection in subprocess calls**: Linter wrappers construct command lists. Mitigation: all args are hardcoded strings or validated paths, no user input injected into command construction.
- **Privilege escalation**: Running with user permissions, no sudo escalation in scanner itself.
- **Side-channel via timing**: Scan duration could leak info about file count/size. Minimal risk for this use case.

## Incident Response

- If a critical vulnerability is discovered in a dependency scanner (gosec, clippy, etc.): disable that specific scanner, file issue with upstream, update documentation.
- If config loading crashes: pydantic validation catches most issues, remaining crashes handled by try/except in config loading.
