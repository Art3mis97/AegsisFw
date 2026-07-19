"""Policy compiler — converts validated configuration into firewall policy."""

from __future__ import annotations

from aegisfw.config.models import AegisFWConfig, RuleConfig
from aegisfw.policy.enums import DefaultPolicy, NetworkProtocol, RuleAction
from aegisfw.policy.exceptions import DuplicateRuleNameError
from aegisfw.policy.models import DefaultPolicies, FirewallPolicy, FirewallRule


def compile_policy(config: AegisFWConfig) -> FirewallPolicy:
    """Compile a validated configuration into an immutable firewall policy.

    Args:
        config: A fully validated AegisFWConfig (produced by ``load_config``).

    Returns:
        A complete, immutable FirewallPolicy ready for backend consumption.

    Raises:
        DuplicateRuleNameError: If two or more rules share the same name.
    """
    defaults = _compile_defaults(config)
    rules = _compile_rules(config.rules)

    return FirewallPolicy(defaults=defaults, rules=rules)


def _compile_defaults(config: AegisFWConfig) -> DefaultPolicies:
    """Convert configuration default policies into domain enums."""
    return DefaultPolicies(
        input=DefaultPolicy(config.firewall.default_input),
        output=DefaultPolicy(config.firewall.default_output),
        forward=DefaultPolicy(config.firewall.default_forward),
    )


def _compile_rules(rules: list[RuleConfig]) -> tuple[FirewallRule, ...]:
    """Convert configuration rules into an immutable tuple of domain rules.

    Raises:
        DuplicateRuleNameError: If any rule names collide.
    """
    _check_duplicate_names(rules)

    return tuple(_compile_rule(rule) for rule in rules)


def _compile_rule(rule: RuleConfig) -> FirewallRule:
    """Convert a single configuration rule into a domain rule."""
    return FirewallRule(
        name=rule.name,
        action=RuleAction(rule.action),
        protocol=NetworkProtocol(rule.protocol),
        source=rule.source,
        port=rule.port,
    )


def _check_duplicate_names(rules: list[RuleConfig]) -> None:
    """Detect duplicate rule names and raise if found."""
    seen: set[str] = set()
    for rule in rules:
        if rule.name in seen:
            raise DuplicateRuleNameError(
                f"Duplicate rule name: '{rule.name}'. "
                "Each rule must have a unique name."
            )
        seen.add(rule.name)
