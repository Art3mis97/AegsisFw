"""Comprehensive tests for the AegisFW policy compiler."""

from __future__ import annotations

import pytest

from aegisfw.config.models import AegisFWConfig, FirewallConfig, RuleConfig
from aegisfw.policy import (
    DefaultPolicies,
    DefaultPolicy,
    DuplicateRuleNameError,
    FirewallPolicy,
    FirewallRule,
    NetworkProtocol,
    RuleAction,
    compile_policy,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_config(
    rules: list[RuleConfig] | None = None,
    firewall: FirewallConfig | None = None,
) -> AegisFWConfig:
    """Build a minimal AegisFWConfig for testing."""
    return AegisFWConfig(
        firewall=firewall or FirewallConfig(),
        rules=rules or [],
    )


def _make_rule(
    name: str = "test-rule",
    action: str = "allow",
    protocol: str = "tcp",
    port: int | None = 80,
    source: str = "any",
) -> RuleConfig:
    """Build a RuleConfig with convenient defaults."""
    return RuleConfig(
        name=name,
        action=action,
        protocol=protocol,
        port=port,
        source=source,
    )


# ---------------------------------------------------------------------------
# Single rule compilation
# ---------------------------------------------------------------------------


class TestSingleRuleCompilation:
    """Tests for compiling a single rule."""

    def test_returns_firewall_policy(self) -> None:
        """compile_policy returns a FirewallPolicy instance."""
        config = _make_config(rules=[_make_rule()])
        policy = compile_policy(config)
        assert isinstance(policy, FirewallPolicy)

    def test_rule_values_are_correct(self) -> None:
        """Compiled rule has correctly mapped fields."""
        config = _make_config(
            rules=[
                _make_rule(
                    name="allow-ssh",
                    action="allow",
                    protocol="tcp",
                    port=22,
                    source="192.168.1.0/24",
                )
            ]
        )
        policy = compile_policy(config)

        assert len(policy.rules) == 1
        rule = policy.rules[0]
        assert isinstance(rule, FirewallRule)
        assert rule.name == "allow-ssh"
        assert rule.action is RuleAction.ALLOW
        assert rule.protocol is NetworkProtocol.TCP
        assert rule.port == 22
        assert rule.source == "192.168.1.0/24"

    def test_rules_are_tuple(self) -> None:
        """Compiled rules are stored as a tuple, not a list."""
        config = _make_config(rules=[_make_rule()])
        policy = compile_policy(config)
        assert isinstance(policy.rules, tuple)


# ---------------------------------------------------------------------------
# Multiple rules and ordering
# ---------------------------------------------------------------------------


class TestMultipleRules:
    """Tests for compiling multiple rules."""

    def test_multiple_rules_compile(self) -> None:
        """All rules are compiled when multiple are provided."""
        rules = [
            _make_rule(name="rule-1", port=80),
            _make_rule(name="rule-2", port=443),
            _make_rule(name="rule-3", port=22),
        ]
        policy = compile_policy(_make_config(rules=rules))
        assert len(policy.rules) == 3

    def test_rule_order_preserved(self) -> None:
        """Rules maintain their original order after compilation."""
        rules = [
            _make_rule(name="first"),
            _make_rule(name="second"),
            _make_rule(name="third"),
        ]
        policy = compile_policy(_make_config(rules=rules))
        names = [r.name for r in policy.rules]
        assert names == ["first", "second", "third"]


# ---------------------------------------------------------------------------
# Default policies
# ---------------------------------------------------------------------------


class TestDefaultPolicies:
    """Tests for default firewall policy compilation."""

    def test_default_policies_transferred(self) -> None:
        """Default policies are correctly converted to enums."""
        config = _make_config(
            firewall=FirewallConfig(
                default_input="drop",
                default_output="accept",
                default_forward="reject",
            )
        )
        policy = compile_policy(config)

        assert isinstance(policy.defaults, DefaultPolicies)
        assert policy.defaults.input is DefaultPolicy.DROP
        assert policy.defaults.output is DefaultPolicy.ACCEPT
        assert policy.defaults.forward is DefaultPolicy.REJECT

    def test_all_policies_accept(self) -> None:
        """All policies set to accept are correctly compiled."""
        config = _make_config(
            firewall=FirewallConfig(
                default_input="accept",
                default_output="accept",
                default_forward="accept",
            )
        )
        policy = compile_policy(config)
        assert policy.defaults.input is DefaultPolicy.ACCEPT
        assert policy.defaults.output is DefaultPolicy.ACCEPT
        assert policy.defaults.forward is DefaultPolicy.ACCEPT

    def test_safe_defaults_from_config(self) -> None:
        """Default FirewallConfig produces safe policy defaults."""
        config = _make_config()
        policy = compile_policy(config)
        assert policy.defaults.input is DefaultPolicy.DROP
        assert policy.defaults.output is DefaultPolicy.ACCEPT
        assert policy.defaults.forward is DefaultPolicy.DROP


# ---------------------------------------------------------------------------
# Empty rules
# ---------------------------------------------------------------------------


class TestEmptyRules:
    """Tests for empty rule sets."""

    def test_empty_rules_compiles(self) -> None:
        """Compilation succeeds with no rules."""
        config = _make_config(rules=[])
        policy = compile_policy(config)
        assert policy.rules == ()

    def test_empty_rules_is_empty_tuple(self) -> None:
        """Empty rules produce an empty tuple, not an empty list."""
        config = _make_config()
        policy = compile_policy(config)
        assert isinstance(policy.rules, tuple)
        assert len(policy.rules) == 0


# ---------------------------------------------------------------------------
# Duplicate rule names
# ---------------------------------------------------------------------------


class TestDuplicateRuleNames:
    """Tests for duplicate rule name detection."""

    def test_duplicate_names_raise(self) -> None:
        """Two rules with the same name raise DuplicateRuleNameError."""
        rules = [
            _make_rule(name="allow-ssh", port=22),
            _make_rule(name="allow-ssh", port=2222),
        ]
        with pytest.raises(DuplicateRuleNameError, match="allow-ssh"):
            compile_policy(_make_config(rules=rules))

    def test_duplicate_error_message(self) -> None:
        """Error message identifies the duplicate name."""
        rules = [
            _make_rule(name="web-rule", port=80),
            _make_rule(name="other-rule", port=443),
            _make_rule(name="web-rule", port=8080),
        ]
        with pytest.raises(DuplicateRuleNameError, match="web-rule"):
            compile_policy(_make_config(rules=rules))

    def test_unique_names_accepted(self) -> None:
        """Rules with unique names compile without error."""
        rules = [
            _make_rule(name="rule-a", port=80),
            _make_rule(name="rule-b", port=443),
        ]
        policy = compile_policy(_make_config(rules=rules))
        assert len(policy.rules) == 2


# ---------------------------------------------------------------------------
# Protocol enum mapping (parametrized)
# ---------------------------------------------------------------------------


class TestProtocolMapping:
    """Tests for protocol string-to-enum conversion."""

    @pytest.mark.parametrize(
        ("config_value", "expected_enum"),
        [
            ("tcp", NetworkProtocol.TCP),
            ("udp", NetworkProtocol.UDP),
            ("icmp", NetworkProtocol.ICMP),
            ("any", NetworkProtocol.ANY),
        ],
    )
    def test_protocol_enum_mapping(
        self,
        config_value: str,
        expected_enum: NetworkProtocol,
    ) -> None:
        """Each config protocol string maps to the correct enum."""
        rule = _make_rule(protocol=config_value, port=None)
        policy = compile_policy(_make_config(rules=[rule]))
        assert policy.rules[0].protocol is expected_enum


# ---------------------------------------------------------------------------
# Action enum mapping (parametrized)
# ---------------------------------------------------------------------------


class TestActionMapping:
    """Tests for action string-to-enum conversion."""

    @pytest.mark.parametrize(
        ("config_value", "expected_enum"),
        [
            ("allow", RuleAction.ALLOW),
            ("deny", RuleAction.DENY),
            ("reject", RuleAction.REJECT),
        ],
    )
    def test_action_enum_mapping(
        self,
        config_value: str,
        expected_enum: RuleAction,
    ) -> None:
        """Each config action string maps to the correct enum."""
        rule = _make_rule(action=config_value)
        policy = compile_policy(_make_config(rules=[rule]))
        assert policy.rules[0].action is expected_enum


# ---------------------------------------------------------------------------
# Optional fields
# ---------------------------------------------------------------------------


class TestOptionalFields:
    """Tests for optional field handling."""

    def test_source_any_preserved(self) -> None:
        """Source 'any' is passed through to the compiled rule."""
        rule = _make_rule(source="any")
        policy = compile_policy(_make_config(rules=[rule]))
        assert policy.rules[0].source == "any"

    def test_source_ip_preserved(self) -> None:
        """A specific source IP is passed through to the compiled rule."""
        rule = _make_rule(source="10.0.0.1")
        policy = compile_policy(_make_config(rules=[rule]))
        assert policy.rules[0].source == "10.0.0.1"

    def test_port_none_preserved(self) -> None:
        """Port None (e.g. for ICMP) is preserved in the compiled rule."""
        rule = _make_rule(protocol="icmp", port=None)
        policy = compile_policy(_make_config(rules=[rule]))
        assert policy.rules[0].port is None

    def test_port_value_preserved(self) -> None:
        """An integer port value is preserved in the compiled rule."""
        rule = _make_rule(port=443)
        policy = compile_policy(_make_config(rules=[rule]))
        assert policy.rules[0].port == 443


# ---------------------------------------------------------------------------
# Immutability
# ---------------------------------------------------------------------------


class TestImmutability:
    """Tests verifying that compiled policy objects are immutable."""

    def test_cannot_reassign_policy_defaults(self) -> None:
        """FirewallPolicy.defaults cannot be reassigned."""
        policy = compile_policy(_make_config())
        with pytest.raises(AttributeError):
            policy.defaults = DefaultPolicies(  # type: ignore[misc]
                input=DefaultPolicy.ACCEPT,
                output=DefaultPolicy.ACCEPT,
                forward=DefaultPolicy.ACCEPT,
            )

    def test_cannot_reassign_policy_rules(self) -> None:
        """FirewallPolicy.rules cannot be reassigned."""
        policy = compile_policy(_make_config(rules=[_make_rule()]))
        with pytest.raises(AttributeError):
            policy.rules = ()  # type: ignore[misc]

    def test_cannot_append_to_rules_tuple(self) -> None:
        """The rules tuple does not support append."""
        policy = compile_policy(_make_config(rules=[_make_rule()]))
        assert not hasattr(policy.rules, "append")

    def test_cannot_reassign_rule_fields(self) -> None:
        """FirewallRule fields cannot be reassigned."""
        rule = _make_rule()
        policy = compile_policy(_make_config(rules=[rule]))
        compiled_rule = policy.rules[0]
        with pytest.raises(AttributeError):
            compiled_rule.name = "hacked"  # type: ignore[misc]

    def test_cannot_reassign_defaults_fields(self) -> None:
        """DefaultPolicies fields cannot be reassigned."""
        policy = compile_policy(_make_config())
        with pytest.raises(AttributeError):
            policy.defaults.input = DefaultPolicy.ACCEPT  # type: ignore[misc]
