"""AegisFW configuration engine.

Provides YAML-based configuration loading, validation, and typed models.

Usage::

    from aegisfw.config import load_config

    config = load_config("config/aegisfw.example.yaml")
    print(config.firewall.default_input)
    print(config.rules)
"""

from aegisfw.config.exceptions import (
    ConfigurationError,
    ConfigurationFileNotFoundError,
    ConfigurationParseError,
    ConfigurationValidationError,
)
from aegisfw.config.loader import load_config
from aegisfw.config.models import (
    AegisFWConfig,
    FirewallConfig,
    LoggingConfig,
    RuleConfig,
)

__all__ = [
    "AegisFWConfig",
    "ConfigurationError",
    "ConfigurationFileNotFoundError",
    "ConfigurationParseError",
    "ConfigurationValidationError",
    "FirewallConfig",
    "LoggingConfig",
    "RuleConfig",
    "load_config",
]
