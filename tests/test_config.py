"""Comprehensive tests for the AegisFW configuration engine."""

from __future__ import annotations

from pathlib import Path

import pytest

from aegisfw.config import (
    AegisFWConfig,
    ConfigurationFileNotFoundError,
    ConfigurationParseError,
    ConfigurationValidationError,
    FirewallConfig,
    LoggingConfig,
    RuleConfig,
    load_config,
)

# ---------------------------------------------------------------------------
# Helper to write YAML to a temp file
# ---------------------------------------------------------------------------


def _write_yaml(tmp_path: Path, content: str, name: str = "test.yaml") -> Path:
    """Write content to a YAML file inside tmp_path and return its path."""
    filepath = tmp_path / name
    filepath.write_text(content, encoding="utf-8")
    return filepath


# ---------------------------------------------------------------------------
# Valid configuration tests
# ---------------------------------------------------------------------------


class TestValidConfiguration:
    """Tests for valid configuration loading."""

    def test_complete_configuration(self, tmp_path: Path) -> None:
        """A fully specified configuration loads without errors."""
        path = _write_yaml(
            tmp_path,
            """\
firewall:
  default_input: drop
  default_output: accept
  default_forward: drop

logging:
  enabled: true
  level: info

rules:
  - name: allow-ssh
    action: allow
    protocol: tcp
    port: 22
    source: any
""",
        )
        config = load_config(path)

        assert config.firewall.default_input == "drop"
        assert config.firewall.default_output == "accept"
        assert config.firewall.default_forward == "drop"
        assert config.logging.enabled is True
        assert config.logging.level == "info"
        assert len(config.rules) == 1
        assert config.rules[0].name == "allow-ssh"
        assert config.rules[0].action == "allow"
        assert config.rules[0].protocol == "tcp"
        assert config.rules[0].port == 22
        assert config.rules[0].source == "any"

    def test_minimal_configuration_uses_defaults(self, tmp_path: Path) -> None:
        """An empty mapping produces safe defaults."""
        path = _write_yaml(tmp_path, "---\n{}\n")
        config = load_config(path)

        assert config.firewall.default_input == "drop"
        assert config.firewall.default_output == "accept"
        assert config.firewall.default_forward == "drop"
        assert config.logging.enabled is True
        assert config.logging.level == "info"
        assert config.rules == []

    def test_example_file_loads_successfully(self) -> None:
        """The shipped example configuration file loads without errors."""
        example_path = Path("config/aegisfw.example.yaml")
        if not example_path.exists():
            pytest.skip("Example configuration file not found")

        config = load_config(example_path)
        assert isinstance(config, AegisFWConfig)
        assert len(config.rules) > 0

    def test_rules_default_to_empty_list(self, tmp_path: Path) -> None:
        """Missing rules section defaults to an empty list."""
        path = _write_yaml(
            tmp_path,
            """\
firewall:
  default_input: accept
""",
        )
        config = load_config(path)
        assert config.rules == []

    def test_string_path_accepted(self, tmp_path: Path) -> None:
        """load_config accepts a string path, not just pathlib.Path."""
        path = _write_yaml(tmp_path, "---\n{}\n")
        config = load_config(str(path))
        assert isinstance(config, AegisFWConfig)


# ---------------------------------------------------------------------------
# File error tests
# ---------------------------------------------------------------------------


class TestFileErrors:
    """Tests for file-level errors."""

    def test_missing_file(self, tmp_path: Path) -> None:
        """A nonexistent file raises ConfigurationFileNotFoundError."""
        with pytest.raises(ConfigurationFileNotFoundError, match="not found"):
            load_config(tmp_path / "nonexistent.yaml")

    def test_path_is_directory(self, tmp_path: Path) -> None:
        """A directory path raises ConfigurationFileNotFoundError."""
        with pytest.raises(ConfigurationFileNotFoundError, match="not a regular file"):
            load_config(tmp_path)


# ---------------------------------------------------------------------------
# Parse error tests
# ---------------------------------------------------------------------------


class TestParseErrors:
    """Tests for YAML parsing errors."""

    def test_empty_yaml_file(self, tmp_path: Path) -> None:
        """An empty YAML file raises ConfigurationParseError."""
        path = _write_yaml(tmp_path, "")
        with pytest.raises(ConfigurationParseError, match="empty"):
            load_config(path)

    def test_invalid_yaml_syntax(self, tmp_path: Path) -> None:
        """Invalid YAML syntax raises ConfigurationParseError."""
        path = _write_yaml(tmp_path, "firewall:\n  bad: [unclosed\n")
        with pytest.raises(ConfigurationParseError, match="Failed to parse"):
            load_config(path)

    def test_yaml_root_is_list(self, tmp_path: Path) -> None:
        """A YAML root that is a list raises ConfigurationParseError."""
        path = _write_yaml(tmp_path, "- item1\n- item2\n")
        with pytest.raises(ConfigurationParseError, match="must be a YAML mapping"):
            load_config(path)


# ---------------------------------------------------------------------------
# Firewall validation tests
# ---------------------------------------------------------------------------


class TestFirewallValidation:
    """Tests for firewall policy validation."""

    def test_invalid_default_input(self, tmp_path: Path) -> None:
        """An invalid default_input policy raises ConfigurationValidationError."""
        path = _write_yaml(
            tmp_path,
            """\
firewall:
  default_input: block
""",
        )
        with pytest.raises(
            ConfigurationValidationError,
            match=r"Invalid value for firewall\.default_input: 'block'",
        ):
            load_config(path)

    def test_invalid_default_output(self, tmp_path: Path) -> None:
        """An invalid default_output policy raises ConfigurationValidationError."""
        path = _write_yaml(
            tmp_path,
            """\
firewall:
  default_output: allow
""",
        )
        with pytest.raises(
            ConfigurationValidationError,
            match=r"Invalid value for firewall\.default_output: 'allow'",
        ):
            load_config(path)

    def test_invalid_default_forward(self, tmp_path: Path) -> None:
        """An invalid default_forward policy raises ConfigurationValidationError."""
        path = _write_yaml(
            tmp_path,
            """\
firewall:
  default_forward: deny
""",
        )
        with pytest.raises(
            ConfigurationValidationError,
            match=r"Invalid value for firewall\.default_forward: 'deny'",
        ):
            load_config(path)

    def test_all_valid_policies_accepted(self) -> None:
        """All valid policy values are accepted without error."""
        for policy in ("accept", "drop", "reject"):
            config = FirewallConfig(
                default_input=policy,
                default_output=policy,
                default_forward=policy,
            )
            assert config.default_input == policy


# ---------------------------------------------------------------------------
# Logging validation tests
# ---------------------------------------------------------------------------


class TestLoggingValidation:
    """Tests for logging configuration validation."""

    def test_invalid_log_level(self, tmp_path: Path) -> None:
        """An invalid logging level raises ConfigurationValidationError."""
        path = _write_yaml(
            tmp_path,
            """\
logging:
  level: verbose
""",
        )
        with pytest.raises(
            ConfigurationValidationError,
            match=r"Invalid value for logging\.level: 'verbose'",
        ):
            load_config(path)

    def test_all_valid_log_levels_accepted(self) -> None:
        """All valid log levels are accepted without error."""
        for level in ("debug", "info", "warning", "error", "critical"):
            config = LoggingConfig(level=level)
            assert config.level == level


# ---------------------------------------------------------------------------
# Rule validation tests
# ---------------------------------------------------------------------------


class TestRuleValidation:
    """Tests for individual rule validation."""

    def test_invalid_action(self, tmp_path: Path) -> None:
        """An invalid rule action raises ConfigurationValidationError."""
        path = _write_yaml(
            tmp_path,
            """\
rules:
  - name: bad-rule
    action: permit
    protocol: tcp
    port: 80
""",
        )
        with pytest.raises(
            ConfigurationValidationError,
            match="Invalid action for rule 'bad-rule': 'permit'",
        ):
            load_config(path)

    def test_invalid_protocol(self, tmp_path: Path) -> None:
        """An invalid protocol raises ConfigurationValidationError."""
        path = _write_yaml(
            tmp_path,
            """\
rules:
  - name: bad-rule
    action: allow
    protocol: sctp
    port: 80
""",
        )
        with pytest.raises(
            ConfigurationValidationError,
            match="Invalid protocol for rule 'bad-rule': 'sctp'",
        ):
            load_config(path)

    def test_port_below_minimum(self, tmp_path: Path) -> None:
        """A port below 1 raises ConfigurationValidationError."""
        path = _write_yaml(
            tmp_path,
            """\
rules:
  - name: bad-port
    action: allow
    protocol: tcp
    port: 0
""",
        )
        with pytest.raises(
            ConfigurationValidationError,
            match="Invalid port for rule 'bad-port': 0",
        ):
            load_config(path)

    def test_port_above_maximum(self, tmp_path: Path) -> None:
        """A port above 65535 raises ConfigurationValidationError."""
        path = _write_yaml(
            tmp_path,
            """\
rules:
  - name: bad-port
    action: allow
    protocol: tcp
    port: 70000
""",
        )
        with pytest.raises(
            ConfigurationValidationError,
            match="Invalid port for rule 'bad-port': 70000",
        ):
            load_config(path)

    def test_empty_rule_name(self, tmp_path: Path) -> None:
        """An empty rule name raises ConfigurationValidationError."""
        path = _write_yaml(
            tmp_path,
            """\
rules:
  - name: ""
    action: allow
    protocol: tcp
    port: 80
""",
        )
        with pytest.raises(
            ConfigurationValidationError,
            match="Rule name must be a non-empty string",
        ):
            load_config(path)

    def test_missing_required_action(self, tmp_path: Path) -> None:
        """A rule missing the action field raises ConfigurationValidationError."""
        path = _write_yaml(
            tmp_path,
            """\
rules:
  - name: no-action
    protocol: tcp
    port: 80
""",
        )
        with pytest.raises(
            ConfigurationValidationError,
            match="missing the required 'action' field",
        ):
            load_config(path)

    def test_missing_required_protocol(self, tmp_path: Path) -> None:
        """A rule missing the protocol field raises ConfigurationValidationError."""
        path = _write_yaml(
            tmp_path,
            """\
rules:
  - name: no-protocol
    action: allow
    port: 80
""",
        )
        with pytest.raises(
            ConfigurationValidationError,
            match="missing the required 'protocol' field",
        ):
            load_config(path)


# ---------------------------------------------------------------------------
# Port-protocol compatibility tests
# ---------------------------------------------------------------------------


class TestPortProtocolCompatibility:
    """Tests for port-protocol validation rules."""

    def test_tcp_with_port_accepted(self) -> None:
        """TCP with a valid port is accepted."""
        rule = RuleConfig(name="tcp-rule", action="allow", protocol="tcp", port=80)
        assert rule.port == 80

    def test_udp_with_port_accepted(self) -> None:
        """UDP with a valid port is accepted."""
        rule = RuleConfig(name="udp-rule", action="allow", protocol="udp", port=53)
        assert rule.port == 53

    def test_icmp_without_port_accepted(self) -> None:
        """ICMP without a port is accepted."""
        rule = RuleConfig(name="icmp-rule", action="allow", protocol="icmp")
        assert rule.port is None

    def test_any_without_port_accepted(self) -> None:
        """ANY without a port is accepted."""
        rule = RuleConfig(name="any-rule", action="allow", protocol="any")
        assert rule.port is None

    def test_icmp_with_port_rejected(self) -> None:
        """ICMP with a port raises ConfigurationValidationError."""
        with pytest.raises(
            ConfigurationValidationError,
            match="Port is not allowed for rule 'icmp-rule' with protocol 'icmp'",
        ):
            RuleConfig(name="icmp-rule", action="allow", protocol="icmp", port=80)

    def test_any_with_port_rejected(self) -> None:
        """ANY with a port raises ConfigurationValidationError."""
        with pytest.raises(
            ConfigurationValidationError,
            match="Port is not allowed for rule 'any-rule' with protocol 'any'",
        ):
            RuleConfig(name="any-rule", action="allow", protocol="any", port=80)


# ---------------------------------------------------------------------------
# Source validation tests
# ---------------------------------------------------------------------------


class TestSourceValidation:
    """Tests for rule source address validation."""

    def test_source_any_accepted(self) -> None:
        """The source value 'any' is accepted."""
        rule = RuleConfig(name="test", action="allow", protocol="tcp", source="any")
        assert rule.source == "any"

    def test_valid_ipv4_address(self) -> None:
        """A valid IPv4 address is accepted."""
        rule = RuleConfig(
            name="test", action="allow", protocol="tcp", source="192.168.1.1"
        )
        assert rule.source == "192.168.1.1"

    def test_valid_ipv6_address(self) -> None:
        """A valid IPv6 address is accepted."""
        rule = RuleConfig(name="test", action="allow", protocol="tcp", source="::1")
        assert rule.source == "::1"

    def test_valid_cidr_network(self) -> None:
        """A valid CIDR network is accepted."""
        rule = RuleConfig(
            name="test", action="allow", protocol="tcp", source="10.0.0.0/8"
        )
        assert rule.source == "10.0.0.0/8"

    def test_invalid_source_address(self) -> None:
        """An invalid source string raises ConfigurationValidationError."""
        with pytest.raises(
            ConfigurationValidationError,
            match="Invalid source for rule 'bad-src'",
        ):
            RuleConfig(
                name="bad-src",
                action="allow",
                protocol="tcp",
                source="not-an-address",
            )


# ---------------------------------------------------------------------------
# Model construction tests
# ---------------------------------------------------------------------------


class TestModelDefaults:
    """Tests for model default values."""

    def test_firewall_defaults(self) -> None:
        """FirewallConfig uses safe defaults."""
        config = FirewallConfig()
        assert config.default_input == "drop"
        assert config.default_output == "accept"
        assert config.default_forward == "drop"

    def test_logging_defaults(self) -> None:
        """LoggingConfig uses safe defaults."""
        config = LoggingConfig()
        assert config.enabled is True
        assert config.level == "info"

    def test_aegisfw_config_defaults(self) -> None:
        """AegisFWConfig uses safe defaults for all sections."""
        config = AegisFWConfig()
        assert config.firewall.default_input == "drop"
        assert config.logging.enabled is True
        assert config.rules == []

    def test_rule_source_defaults_to_any(self) -> None:
        """RuleConfig source defaults to 'any'."""
        rule = RuleConfig(name="test", action="allow", protocol="tcp")
        assert rule.source == "any"

    def test_rule_port_defaults_to_none(self) -> None:
        """RuleConfig port defaults to None."""
        rule = RuleConfig(name="test", action="allow", protocol="icmp")
        assert rule.port is None
