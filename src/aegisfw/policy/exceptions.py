"""Custom exceptions for AegisFW policy compilation."""


class PolicyError(Exception):
    """Base exception for all policy-related errors."""


class PolicyCompilationError(PolicyError):
    """Raised when policy compilation fails due to logical errors."""


class DuplicateRuleNameError(PolicyCompilationError):
    """Raised when two or more rules share the same name."""
