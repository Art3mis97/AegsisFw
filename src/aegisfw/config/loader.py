"""YAML configuration loader for AegisFW."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from aegisfw.config.exceptions import (
    ConfigurationFileNotFoundError,
    ConfigurationParseError,
    ConfigurationValidationError,
)
from aegisfw.config.models import (
    AegisFWConfig,
    FirewallConfig,
    LoggingConfig,
    RuleConfig,
)


def load_config(path: str | Path) -> AegisFWConfig:
    """Load and validate an AegisFW configuration file.

    Args:
        path: Path to a YAML configuration file.

    Returns:
        A fully validated AegisFWConfig object.

    Raises:
        ConfigurationFileNotFoundError: If the file does not exist or is not
            a regular file.
        ConfigurationParseError: If the file is empty, contains invalid YAML,
            or the root element is not a mapping.
        ConfigurationValidationError: If any configuration values are invalid.
    """
    filepath = Path(path)

    if not filepath.exists():
        raise ConfigurationFileNotFoundError(
            f"Configuration file not found: {filepath}"
        )

    if not filepath.is_file():
        raise ConfigurationFileNotFoundError(
            f"Configuration path is not a regular file: {filepath}"
        )

    text = filepath.read_text(encoding="utf-8")

    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigurationParseError(
            f"Failed to parse YAML configuration: {exc}"
        ) from exc

    if data is None:
        raise ConfigurationParseError(
            "Configuration file is empty. "
            "Expected a YAML mapping with configuration values."
        )

    if not isinstance(data, dict):
        raise ConfigurationParseError(
            f"Configuration root must be a YAML mapping, got {type(data).__name__}. "
            "The configuration file should start with key-value pairs, not a list."
        )

    return _build_config(data)


def _build_config(data: dict[str, Any]) -> AegisFWConfig:
    """Construct an AegisFWConfig from a parsed YAML dictionary."""
    firewall = _build_firewall_config(data.get("firewall"))
    logging_config = _build_logging_config(data.get("logging"))
    rules = _build_rules(data.get("rules"))

    return AegisFWConfig(
        firewall=firewall,
        logging=logging_config,
        rules=rules,
    )


def _build_firewall_config(data: Any) -> FirewallConfig:
    """Construct a FirewallConfig from parsed data."""
    if data is None:
        return FirewallConfig()

    if not isinstance(data, dict):
        raise ConfigurationValidationError(
            "The 'firewall' section must be a YAML mapping."
        )

    return FirewallConfig(
        default_input=data.get("default_input", "drop"),
        default_output=data.get("default_output", "accept"),
        default_forward=data.get("default_forward", "drop"),
    )


def _build_logging_config(data: Any) -> LoggingConfig:
    """Construct a LoggingConfig from parsed data."""
    if data is None:
        return LoggingConfig()

    if not isinstance(data, dict):
        raise ConfigurationValidationError(
            "The 'logging' section must be a YAML mapping."
        )

    return LoggingConfig(
        enabled=data.get("enabled", True),
        level=data.get("level", "info"),
    )


def _build_rules(data: Any) -> list[RuleConfig]:
    """Construct a list of RuleConfig from parsed data."""
    if data is None:
        return []

    if not isinstance(data, list):
        raise ConfigurationValidationError("The 'rules' section must be a YAML list.")

    rules: list[RuleConfig] = []
    for index, entry in enumerate(data):
        if not isinstance(entry, dict):
            raise ConfigurationValidationError(
                f"Rule at index {index} must be a YAML mapping."
            )

        name = entry.get("name")
        if name is None:
            raise ConfigurationValidationError(
                f"Rule at index {index} is missing the required 'name' field."
            )

        action = entry.get("action")
        if action is None:
            raise ConfigurationValidationError(
                f"Rule '{name}' is missing the required 'action' field."
            )

        protocol = entry.get("protocol")
        if protocol is None:
            raise ConfigurationValidationError(
                f"Rule '{name}' is missing the required 'protocol' field."
            )

        rules.append(
            RuleConfig(
                name=name,
                action=action,
                protocol=protocol,
                port=entry.get("port"),
                source=entry.get("source", "any"),
            )
        )

    return rules
