"""Typed configuration models for AegisFW."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from aegisfw.config.exceptions import ConfigurationValidationError

# ---------------------------------------------------------------------------
# Allowed values
# ---------------------------------------------------------------------------

VALID_POLICIES = frozenset({"accept", "drop", "reject"})
VALID_RULE_ACTIONS = frozenset({"allow", "deny", "reject"})
VALID_PROTOCOLS = frozenset({"tcp", "udp", "icmp", "any"})
VALID_LOG_LEVELS = frozenset({"debug", "info", "warning", "error", "critical"})

PORT_MIN = 1
PORT_MAX = 65535


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _validate_policy(value: str, field_name: str) -> str:
    """Validate a firewall policy value."""
    value = str(value).lower().strip()
    if value not in VALID_POLICIES:
        sorted_policies = ", ".join(sorted(VALID_POLICIES))
        raise ConfigurationValidationError(
            f"Invalid value for {field_name}: '{value}'. "
            f"Expected one of: {sorted_policies}."
        )
    return value


def _validate_source(value: str, rule_name: str) -> str:
    """Validate a rule source value.

    Accepts 'any', a valid IPv4/IPv6 address, or a valid CIDR network.
    """
    value = str(value).strip()
    if value.lower() == "any":
        return "any"

    # Try parsing as a single IP address first, then as a network.
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass

    try:
        # strict=False allows host bits to be set (e.g. 192.168.1.5/24).
        ipaddress.ip_network(value, strict=False)
        return value
    except ValueError:
        raise ConfigurationValidationError(
            f"Invalid source for rule '{rule_name}': '{value}'. "
            "Expected 'any', a valid IP address, or a CIDR network."
        ) from None


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FirewallConfig:
    """Firewall default chain policies."""

    default_input: str = "drop"
    default_output: str = "accept"
    default_forward: str = "drop"

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "default_input",
            _validate_policy(self.default_input, "firewall.default_input"),
        )
        object.__setattr__(
            self,
            "default_output",
            _validate_policy(self.default_output, "firewall.default_output"),
        )
        object.__setattr__(
            self,
            "default_forward",
            _validate_policy(self.default_forward, "firewall.default_forward"),
        )


@dataclass(frozen=True)
class LoggingConfig:
    """Logging configuration."""

    enabled: bool = True
    level: str = "info"

    def __post_init__(self) -> None:
        if not isinstance(self.enabled, bool):
            raise ConfigurationValidationError(
                f"Invalid value for logging.enabled: '{self.enabled}'. "
                "Expected a boolean (true or false)."
            )

        level = str(self.level).lower().strip()
        if level not in VALID_LOG_LEVELS:
            sorted_levels = ", ".join(sorted(VALID_LOG_LEVELS))
            raise ConfigurationValidationError(
                f"Invalid value for logging.level: '{self.level}'. "
                f"Expected one of: {sorted_levels}."
            )
        object.__setattr__(self, "level", level)


@dataclass(frozen=True)
class RuleConfig:
    """A single firewall rule."""

    name: str
    action: str
    protocol: str
    source: str = "any"
    port: int | None = None

    def __post_init__(self) -> None:
        # Name validation.
        if not isinstance(self.name, str) or not self.name.strip():
            raise ConfigurationValidationError("Rule name must be a non-empty string.")
        object.__setattr__(self, "name", self.name.strip())

        # Action validation.
        action = str(self.action).lower().strip()
        if action not in VALID_RULE_ACTIONS:
            sorted_actions = ", ".join(sorted(VALID_RULE_ACTIONS))
            raise ConfigurationValidationError(
                f"Invalid action for rule '{self.name}': '{self.action}'. "
                f"Expected one of: {sorted_actions}."
            )
        object.__setattr__(self, "action", action)

        # Protocol validation.
        protocol = str(self.protocol).lower().strip()
        if protocol not in VALID_PROTOCOLS:
            sorted_protocols = ", ".join(sorted(VALID_PROTOCOLS))
            raise ConfigurationValidationError(
                f"Invalid protocol for rule '{self.name}': '{self.protocol}'. "
                f"Expected one of: {sorted_protocols}."
            )
        object.__setattr__(self, "protocol", protocol)

        # Port validation.
        if self.port is not None:
            if not isinstance(self.port, int) or isinstance(self.port, bool):
                raise ConfigurationValidationError(
                    f"Invalid port for rule '{self.name}': '{self.port}'. "
                    f"Port must be an integer between {PORT_MIN} and {PORT_MAX}."
                )
            if not (PORT_MIN <= self.port <= PORT_MAX):
                raise ConfigurationValidationError(
                    f"Invalid port for rule '{self.name}': {self.port}. "
                    f"Port must be between {PORT_MIN} and {PORT_MAX}."
                )

        # Source validation.
        object.__setattr__(
            self,
            "source",
            _validate_source(self.source, self.name),
        )


@dataclass(frozen=True)
class AegisFWConfig:
    """Complete AegisFW configuration."""

    firewall: FirewallConfig = field(default_factory=FirewallConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    rules: list[RuleConfig] = field(default_factory=list)
