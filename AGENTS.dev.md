# AGENTS.dev.md - Secure Development Conventions

## Philosophy

Security is the default. Not a post-audit checklist. Every line of code is a potential attack vector. Write code as if an adversary is actively trying to exploit it — because they will.

---

## 1. Secure Coding Standards

### Input/Output (applies to ALL languages)

- **Never trust input.** Validate at every boundary. Type, length, format, range, structure.
- **Sanitize output.** Context-aware escaping (HTML, SQL, shell, LDAP, path).
- **Fail closed.** Errors default to deny, never allow.
- **Explicit error handling.** No swallowing exceptions. No bare `except/pass/return nil`.

### Memory Safety (Go, Rust)

- Go: never pass pointers unnecessarily. Validate slices before use. Avoid nil pointer dereferences.
- Rust: never use `unwrap()` or `expect()` on user input. Use `?` propagation and `Result`/`Option`.
- Both: bound buffer sizes, no off-by-one trust, always validate indices.

### Cryptography

- Use established libraries. Never roll your own crypto.
- Prefer `bcrypt`/`argon2` for passwords. Never MD5/SHA1 for security.
- Use AES-GCM (authenticated encryption). Never ECB or unauthenticated CBC.
- Generate randomness from CSPRNG only. Never `rand()`, `random()`, or timestamps.
- Verify all signatures. Never accept data without signature verification.

### Authentication & Authorization

- Use established frameworks. Never implement auth from scratch.
- Validate tokens on every request. Check expiry, issuer, audience, signature.
- Least privilege by default. Deny all, grant specific.
- Session: secure flags (`HttpOnly`, `Secure`, `SameSite`), rotation on privilege change.
- Rate limit authentication endpoints.

### Secrets Management

- Never hardcode secrets. Never log secrets. Never transmit in URLs.
- Use environment variables, secret managers, or vaults.
- Rotate regularly. Never reuse credentials.
- Audit access. Log who accessed what, when, and why.

### Dependencies

- Only use well-maintained, audited libraries.
- Pin versions in lockfiles. No `latest`, no `^`, no rolling.
- Scan for vulnerabilities regularly. Update promptly.
- Verify package integrity (checksums, signatures).

---

## 2. Language-Specific Rules

### Python (FastAPI / Flask / Django)

- Use `pydantic` for input validation — models, not raw dicts.
- FastAPI: use dependency injection for auth, use `Path`/`Query` with validators.
- Flask: use blueprints, validate on entry, use `marshmallow`/`pydantic` for serialization.
- Django: use ORM (never raw SQL unless necessary), use `models.CharField(max_length=...)`, enable CSRF.
- `mypy` for static type checking. `ruff` for linting. `safety` for dependency scanning.
- No `eval()`, no `exec()`, no `pickle.loads()` on untrusted data.
- `logging` with structured JSON format, never log request bodies with PII.

### Go

- Use `context` for cancellation/timeout on every I/O and external call.
- `go vet`, `staticcheck`, `gosec` — all must pass.
- No raw SQL. Use `database/sql` parametersized queries.
- HTTP: set timeouts, use `httputil.ReverseProxy` for upstream, validate headers.
- No `defer` in tight loops. No unused variables (`deadcode` will catch them).
- `go mod tidy` on every change. Pin every version.
- JSON: use `json.Decoder` streaming for untrusted input, never `json.Unmarshal` into `interface{}`.

### Rust

- `cargo clippy` and `cargo audit` on every change.
- No `unsafe` blocks unless absolutely necessary — and if used, document why and add invariants.
- Use `tracing` over `println!` for production logging.
- Handle all `Result` and `Option` explicitly. No `.unwrap()` in production code.
- Timeouts on every network call. Backpressure on channels.
- `serde` for serialization with `deny_unknown_fields`.
- Test error paths, not just happy path.

### TypeScript / Node.js

- `strict: true` in `tsconfig`. No `any`. No `// @ts-ignore`.
- `express`: use `helmet`, `express-rate-limit`, validate with `zod` or `joi`.
- Never use `eval()`, `new Function()`, or `child_process.exec()` with user input.
- Use `child_process.spawn()` with explicit args array, not string templates.
- `npm audit` / `pnpm audit` on every install. `--frozen-lockfile` in CI.
- `prettier` + `eslint` with `@typescript-eslint/strict` and security plugins.
- Environment validation at startup (`zod` schema) — crash if env is invalid.

---

## 3. CI/CD Security Gates

Every PR must pass ALL of the following before merge:

### Scan Layer
- [ ] **SAST** (static analysis) — `semgrep`, `sonarqube`, or equivalent
- [ ] **Secret scan** — `gitleaks`, `trufflehog`
- [ ] **Dependency scan** — `safety` (Python), `go list -json -m all` + `govulncheck` (Go), `cargo audit` (Rust), `npm audit`/`pnpm audit` (TS)
- [ ] **Lint + format** — per-language tooling
- [ ] **Type checking** — `mypy`, `go vet`/`staticcheck`, `clippy`, `tsc`
- [ ] **Tests** — all green, minimum coverage threshold per-language

### Verification
- [ ] **Signed commits** required (GPG or SSH)
- [ ] **Signed tags** for releases
- [ ] **Branch protection** — no direct push, require PR review (minimum 1, preferably 2 for security-sensitive files)
- [ ] **Dependency lockfiles** committed and not modified outside PR

### Deployment
- [ ] **No secrets in images** — use runtime injection only
- [ ] **Non-root containers** — explicitly set `USER` in Dockerfile
- [ ] **Image signing** — `cosign` or equivalent for releases
- [ ] **Canary or blue-green** — never blast-to-production

---

## 4. Threat Modeling Convention

Every new feature or component gets a lightweight threat model:

```markdown
## Threat Model: {Feature Name}

### Assets
- What am I protecting?

### Attackers
- Who might attack? What's their capability?

### Trust Boundaries
- Where does data cross from untrusted to trusted?

### Attack Surface
- Inputs, outputs, dependencies, side channels

### Mitigations
- What's already mitigated by frameworks/tools?
- What needs explicit code?

### Remaining Risk
- What can't we fully mitigate? Document it.
```

Run through this during design, before implementation.

---

## 5. Incident Response Protocol

### Detection
- Structured logging with correlation IDs.
- Health checks and alerting on error rate spikes, auth failures, resource exhaustion.
- Regular log review (automated where possible).

### Containment
- Kill switch pattern in all services.
- Credential rotation playbook (pre-prepared commands/scripts).
- Network segmentation where applicable.

### Recovery
- Backup verification (tested, not just configured).
- Roll-forward or roll-back with clear criteria.
- Post-incident review within 48 hours.

### Post-Incident
- Document timeline, root cause, impact.
- Create actionable follow-up items (not vague "improve monitoring").
- Update threat models based on findings.

---

## 6. Documentation Standards

- **README**: architecture overview, setup, security considerations.
- **SECURITY.md**: how to report vulnerabilities, what's in scope, response SLA.
- **CHANGELOG.md**: all changes tracked, security fixes highlighted.
- **Code comments**: explain *why*, not *what*. Security-critical logic must be documented.

---

## 7. Git Workflow

- **Commit early, commit often.** Atomic commits with clear messages.
- **Signed commits.** `git commit -S` always.
- **Rebase, not merge.** Linear history. No merge commits.
- **PR descriptions:** what changed, why, security implications.
- **Squash on merge** to keep history clean.

---

## 8. Review Checklist

Before submitting or approving any PR:

- [ ] Input validated at every boundary?
- [ ] Secrets not exposed in code, logs, or error messages?
- [ ] Error handling explicit? No swallowed errors?
- [ ] Dependencies pinned and scanned?
- [ ] No new `eval()`, `exec()`, raw SQL, or unsafe blocks?
- [ ] Timeouts on all external calls?
- [ ] Tests cover happy path AND failure modes?
- [ ] Threat model updated if attack surface changed?
- [ ] Documentation updated?
- [ ] No new console.logs/printlns with sensitive data?
