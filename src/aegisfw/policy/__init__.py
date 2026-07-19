"""AegisFW policy engine.

Compiles validated configuration into an immutable, backend-independent
firewall policy model.

Usage::

    from aegisfw.config import load_config
    from aegisfw.policy import compile_policy

    config = load_config("config/aegisfw.example.yaml")
    policy = compile_policy(config)

    print(policy.defaults.input)   # DefaultPolicy.DROP
    print(policy.rules[0].action)  # RuleAction.ALLOW
"""

from aegisfw.policy.compiler import compile_policy
from aegisfw.policy.enums import DefaultPolicy, NetworkProtocol, RuleAction
from aegisfw.policy.exceptions import (
    DuplicateRuleNameError,
    PolicyCompilationError,
    PolicyError,
)
from aegisfw.policy.models import DefaultPolicies, FirewallPolicy, FirewallRule

__all__ = [
    "DefaultPolicies",
    "DefaultPolicy",
    "DuplicateRuleNameError",
    "FirewallPolicy",
    "FirewallRule",
    "NetworkProtocol",
    "PolicyCompilationError",
    "PolicyError",
    "RuleAction",
    "compile_policy",
]
