"""Custom exceptions for AegisFW configuration handling."""


class ConfigurationError(Exception):
    """Base exception for all configuration-related errors."""


class ConfigurationFileNotFoundError(ConfigurationError):
    """Raised when the configuration file does not exist or is not a regular file."""


class ConfigurationParseError(ConfigurationError):
    """Raised when the configuration file contains invalid YAML or structure."""


class ConfigurationValidationError(ConfigurationError):
    """Raised when configuration values fail validation."""
