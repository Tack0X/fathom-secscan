"""Tests for configuration loading and built-in secret patterns."""

import yaml

from secscan.config import ScanConfig, default_secrets_patterns, load_config


class TestLoadConfig:
    def test_defaults_when_no_path(self):
        config = load_config(None)
        assert isinstance(config, ScanConfig)
        assert config.severity_threshold == "high"
        assert config.paths == ["."]

    def test_defaults_when_path_missing(self):
        config = load_config("/nonexistent/path/secscan.yml")
        assert isinstance(config, ScanConfig)

    def test_reads_yaml_overrides(self, tmp_path):
        cfg_file = tmp_path / "secscan.yml"
        cfg_file.write_text(yaml.dump({"severity_threshold": "low", "extensions": [".py"]}))
        config = load_config(str(cfg_file))
        assert config.severity_threshold == "low"
        assert config.extensions == [".py"]


class TestDefaultSecretsPatterns:
    def test_nonempty_and_well_formed(self):
        patterns = default_secrets_patterns()
        assert len(patterns) > 20
        names = {p.name for p in patterns}
        assert "AWS Access Key" in names
        for p in patterns:
            assert p.regex
            assert p.severity in {"critical", "high", "medium", "low"}

    def test_patterns_are_valid_regex(self):
        import re
        for p in default_secrets_patterns():
            re.compile(p.regex)  # should not raise
