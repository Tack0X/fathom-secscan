"""Configuration loading and validation."""

import os
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, Field


class SecretPattern(BaseModel):
    """A single secret detection pattern."""
    name: str
    regex: str
    severity: str = "high"
    description: str = ""


class ScanConfig(BaseModel):
    """Top-level scan configuration."""
    paths: list[str] = Field(default=["."], description="Directories to scan")
    extensions: list[str] = Field(
        default=[".py", ".go", ".rs", ".ts", ".js", ".yml", ".yaml", ".toml", ".json", ".env", ".sh", ".conf"],
        description="File extensions to include"
    )
    secrets_patterns: list[SecretPattern] = Field(default_factory=list)
    ignore_patterns: list[str] = Field(
        default=[
            ".git/", "venv/", ".venv/", "node_modules/",
            "__pycache__/", ".cache/", ".pyc",
            ".pytest_cache/", ".vscode/", ".idea/",
            ".secscanignore", "pyproject.toml",
        ],
        description="File/directory patterns to ignore"
    )
    # Files that contain pattern definitions (not actual secrets) — skip these
    ignore_file_patterns: list[str] = Field(
        default=[
            "/config.py",  # patterns are defined here, not secrets
        ],
        description="File name patterns that contain only pattern definitions"
    )
    severity_threshold: str = "high"
    max_file_size_kb: int = 1024


def load_config(path: Optional[str] = None) -> ScanConfig:
    """Load scan config from YAML file or return defaults."""
    if path and Path(path).exists():
        with open(path) as f:
            raw = yaml.safe_load(f) or {}
        return ScanConfig(**raw)
    return ScanConfig()


def default_secrets_patterns() -> list[SecretPattern]:
    """Return the built-in secret detection patterns."""
    return [
        # AWS
        SecretPattern(
            name="AWS Access Key",
            regex=r"(?:AKIA|ABIA|ACCA)[A-Z0-9]{16}",
            severity="critical",
            description="AWS Access Key ID (AKIA/ABIA/ACCA prefix)",
        ),
        # AWS Secret
        SecretPattern(
            name="AWS Secret Key",
            regex=r"(?i)aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{40}",
            severity="critical",
            description="AWS Secret Access Key",
        ),
        # GitHub Token
        SecretPattern(
            name="GitHub Token",
            regex=r"ghp_[A-Za-z0-9_]{36}",
            severity="critical",
            description="GitHub personal access token",
        ),
        SecretPattern(
            name="GitHub Fine-Grained Token",
            regex=r"github_pat_[A-Za-z0-9_]{22}_[A-Za-z0-9_]{59}",
            severity="critical",
            description="GitHub fine-grained personal access token",
        ),
        # GitHub OAuth
        SecretPattern(
            name="GitHub OAuth",
            regex=r"gho_[A-Za-z0-9_]{36}",
            severity="critical",
            description="GitHub OAuth access token",
        ),
        # Stripe
        SecretPattern(
            name="Stripe Secret Key",
            regex=r"sk_live_[A-Za-z0-9]{24,}",
            severity="critical",
            description="Stripe live secret key",
        ),
        SecretPattern(
            name="Stripe Test Key",
            regex=r"sk_test_[A-Za-z0-9]{24,}",
            severity="high",
            description="Stripe test secret key",
        ),
        # Generic API Key
        SecretPattern(
            name="Generic API Key",
            regex=r"(?i)(?:api[_-]?key|apikey)\s*[:=]\s*[A-Za-z0-9_\-]{20,}",
            severity="high",
            description="Generic API key value",
        ),
        # Generic Secret
        SecretPattern(
            name="Generic Secret",
            regex=r"(?i)(?:secret|password|passwd|pwd)\s*[:=]\s*[A-Za-z0-9_\-@#$%^&*]{8,}",
            severity="high",
            description="Generic secret or password value",
        ),
        # JWT
        SecretPattern(
            name="JWT Token",
            regex=r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
            severity="high",
            description="JSON Web Token (JWT)",
        ),
        # Private Key
        SecretPattern(
            name="RSA Private Key",
            regex=r"-----BEGIN RSA PRIVATE KEY-----",
            severity="critical",
            description="RSA private key block",
        ),
        SecretPattern(
            name="EC Private Key",
            regex=r"-----BEGIN EC PRIVATE KEY-----",
            severity="critical",
            description="EC private key block",
        ),
        SecretPattern(
            name="Generic Private Key",
            regex=r"-----BEGIN (?:DSA|OPENSSH|PGP|PRIVATE KEY)-----",
            severity="critical",
            description="Private key block",
        ),
        # Database URLs
        SecretPattern(
            name="MySQL URL",
            regex=r"mysql://[^\s:]+:[^\s@]+@[^\s]+",
            severity="high",
            description="MySQL connection URL with credentials",
        ),
        SecretPattern(
            name="PostgreSQL URL",
            regex=r"(?:postgres|postgresql)://[^\s:]+:[^\s@]+@[^\s]+",
            severity="high",
            description="PostgreSQL connection URL with credentials",
        ),
        SecretPattern(
            name="MongoDB URL",
            regex=r"mongodb(\+srv)?://[^\s:]+:[^\s@]+@[^\s]+",
            severity="high",
            description="MongoDB connection URL with credentials",
        ),
        SecretPattern(
            name="Redis URL",
            regex=r"redis://(?::?[^\s@]+@[^\s]+)",
            severity="medium",
            description="Redis connection URL",
        ),
        # Slack
        SecretPattern(
            name="Slack Token",
            regex=r"xox[baprs]-[A-Za-z0-9\-]{10,}",
            severity="critical",
            description="Slack bot or user token",
        ),
        # Twilio
        SecretPattern(
            name="Twilio Account SID",
            regex=r"AC[a-f0-9]{32}",
            severity="high",
            description="Twilio account SID",
        ),
        SecretPattern(
            name="Twilio Auth Token",
            regex=r"[0-9a-f]{32}",
            severity="medium",
            description="Possible Twilio auth token (hex, 32 chars)",
        ),
        # Google Cloud
        SecretPattern(
            name="Google API Key",
            regex=r"AIza[A-Za-z0-9_\-]{35}",
            severity="high",
            description="Google Cloud API key",
        ),
        # Heroku
        SecretPattern(
            name="Heroku API Key",
            regex=r"[Hh][Ee][Rr][Oo][Kk][Uu]\s+[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
            severity="high",
            description="Heroku API key",
        ),
        # npm
        SecretPattern(
            name="npm Token",
            regex=r"npm_[A-Za-z0-9]{36}",
            severity="critical",
            description="npm access token",
        ),
        # Telegram
        SecretPattern(
            name="Telegram Bot Token",
            regex=r"[0-9]{8,}:[A-Za-z0-9_\-]{35}",
            severity="high",
            description="Telegram bot token (pattern: ID:SECRET)",
        ),
        # Generic bearer token
        SecretPattern(
            name="Bearer Token",
            regex=r"(?i)bearer\s+[A-Za-z0-9_\-\.]{20,}",
            severity="high",
            description="Bearer token value",
        ),
        # Basic auth
        SecretPattern(
            name="Basic Auth",
            regex=r"(?i)basic\s+[A-Za-z0-9+/=]{20,}",
            severity="high",
            description="Basic auth credentials",
        ),
        # AWS Region config with key
        SecretPattern(
            name="AWS Session Token",
            regex=r"AWS_SESSION_TOKEN\s*=\s*[A-Za-z0-9/+=]{40,}",
            severity="critical",
            description="AWS session token",
        ),
        # Generic token
        SecretPattern(
            name="Generic Token",
            regex=r"(?i)(?:token|access_token|auth_token)\s*[:=]\s*[A-Za-z0-9_\-\.\/+=]{20,}",
            severity="medium",
            description="Generic token value",
        ),
        # Generic password
        SecretPattern(
            name="Generic Password Assignment",
            regex=r"(?i)(?:password|passwd|pwd)\s*[:=]\s*[^\s\{\}]{4,}",
            severity="medium",
            description="Password assignment in code or config",
        ),
        # Google OAuth
        SecretPattern(
            name="Google OAuth Client Secret",
            regex=r"[A-Za-z0-9_\-_]{43}",
            severity="medium",
            description="Possible Google OAuth client secret (43 chars, high entropy)",
        ),
    ]
