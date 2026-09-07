# secscan

Multi-language security scanner CLI. Detects secrets, dependency vulnerabilities, and security lint issues across Python, Go, Rust, and TypeScript/Node.js projects.

## Features

- **Secret detection** — 30+ patterns for API keys, tokens, private keys, database URLs, and more
- **Dependency scanning** — integrates `safety` (Python), `govulncheck` (Go), `cargo-audit` (Rust), `npm audit` (TS)
- **Security linting** — wraps `gosec` (Go), `clippy` (Rust), `bandit` (Python)
- **Configurable** — YAML config for paths, extensions, ignore patterns, severity thresholds
- **Structured output** — JSON report for CI/CD integration

## Quick Start

```bash
# Install (development mode)
pip install -e src/

# Scan current directory
secscan scan .

# Scan with JSON output
secscan scan . --json

# Write report to file
secscan scan . --json-file report.json

# Scan with custom config
secscan scan . --config my-security.yml

# Skip dependency or lint scanning
secscan scan . --no-deps --no-lints

# Custom severity threshold
secscan scan . --severity medium

# Custom file extensions
secscan scan . --extensions ".py,.go,.rs,.ts"
```

## Built-in Patterns

30+ secret detection patterns including:

| Category | Patterns |
|----------|----------|
| Cloud | AWS keys, GCP API keys, Azure tokens |
| Platforms | GitHub PATs, Slack tokens, Heroku keys, npm tokens |
| Services | Stripe keys, Twilio SIDs, Telegram bot tokens |
| Auth | JWT tokens, bearer tokens, basic auth |
| Keys | RSA, EC, DSA, OpenSSH private keys |
| Database | PostgreSQL, MySQL, MongoDB, Redis URLs |

View all patterns: `secscan patterns`

## Configuration

```yaml
# secscan.yml

paths:
  - "."

extensions:
  - ".py"
  - ".go"
  - ".rs"
  - ".ts"

ignore_patterns:
  - ".git/"
  - "node_modules/"
  - "venv/"

severity_threshold: "high"
max_file_size_kb: 1024

# Add custom patterns (optional)
# secrets_patterns:
#   - name: "My Secret"
#     regex: "MY_SECRET_[A-Z0-9]+"
#     severity: "critical"
#     description: "Custom secret pattern"
```

## CI/CD Integration

```yaml
# GitHub Actions example
jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Install secscan
        run: pip install -e secscan/
      - name: Run security scan
        run: secscan scan . --json-file report.json || true
      - name: Check for critical issues
        run: |
          report=$(secscan scan . --json)
          status=$(echo "$report" | jq -r '.status')
          if [ "$status" = "critical" ]; then
            echo "::error::Critical security issues found"
            exit 1
          fi
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Clean — no issues |
| 1 | Critical issues found |
| 2 | Non-critical issues found |

## Project Structure

```
secscan/
├── src/secscan/
│   ├── cli.py          # CLI entry point (typer)
│   ├── config.py       # YAML config loading + built-in patterns
│   ├── scanner.py      # Main scan orchestration
│   ├── secrets.py      # Secret detection engine
│   ├── deps.py         # Dependency vulnerability scanning
│   ├── linting.py      # Security linter wrappers (gosec/clippy/bandit)
│   ├── report.py       # Report generation (JSON + human-readable)
│   └── patterns/       # (future) external pattern files
├── tests/
├── secscan.yml         # Example config
├── pyproject.toml
└── README.md
```
