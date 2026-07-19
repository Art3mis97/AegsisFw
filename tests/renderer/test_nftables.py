"""Comprehensive tests for the AegisFW nftables renderer."""

from __future__ import annotations

import pytest

from aegisfw.policy.enums import DefaultPolicy, NetworkProtocol, RuleAction
from aegisfw.policy.models import DefaultPolicies, FirewallPolicy, FirewallRule
from aegisfw.renderer import NftablesRenderer

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def renderer() -> NftablesRenderer:
    """Provide a fresh NftablesRenderer instance."""
    return NftablesRenderer()


def _make_policy(
    rules: tuple[FirewallRule, ...] = (),
    input_policy: DefaultPolicy = DefaultPolicy.DROP,
    output_policy: DefaultPolicy = DefaultPolicy.ACCEPT,
    forward_policy: DefaultPolicy = DefaultPolicy.DROP,
) -> FirewallPolicy:
    """Build a FirewallPolicy with convenient defaults."""
    return FirewallPolicy(
        defaults=DefaultPolicies(
            input=input_policy,
            output=output_policy,
            forward=forward_policy,
        ),
        rules=rules,
    )


def _make_rule(
    name: str = "test-rule",
    action: RuleAction = RuleAction.ALLOW,
    protocol: NetworkProtocol = NetworkProtocol.TCP,
    source: str = "any",
    port: int | None = 80,
) -> FirewallRule:
    """Build a FirewallRule with convenient defaults."""
    return FirewallRule(
        name=name,
        action=action,
        protocol=protocol,
        source=source,
        port=port,
    )


# ---------------------------------------------------------------------------
# Empty rules
# ---------------------------------------------------------------------------


class TestEmptyRules:
    """Tests for rendering a policy with no rules."""

    def test_empty_rules_renders(self, renderer: NftablesRenderer) -> None:
        """A policy with no rules renders valid nftables syntax."""
        policy = _make_policy()
        result = renderer.render(policy)
        assert "table inet aegisfw" in result
        assert "chain input" in result
        assert "chain output" in result
        assert "chain forward" in result

    def test_empty_rules_has_no_rule_comments(self, renderer: NftablesRenderer) -> None:
        """A policy with no rules produces no rule comment lines."""
        policy = _make_policy()
        result = renderer.render(policy)
        # Rule comments start with "        # " (8 spaces + hash).
        rule_comments = [
            line for line in result.splitlines() if line.startswith("        # ")
        ]
        assert rule_comments == []


# ---------------------------------------------------------------------------
# Default policy rendering
# ---------------------------------------------------------------------------


class TestDefaultPolicyRendering:
    """Tests for default chain policy rendering."""

    def test_default_drop_accept_drop(self, renderer: NftablesRenderer) -> None:
        """Default policies render as nftables policy statements."""
        policy = _make_policy(
            input_policy=DefaultPolicy.DROP,
            output_policy=DefaultPolicy.ACCEPT,
            forward_policy=DefaultPolicy.DROP,
        )
        result = renderer.render(policy)
        lines = result.splitlines()

        # Find policy lines within each chain.
        policy_lines = [line.strip() for line in lines if "policy " in line]
        assert "policy drop;" in policy_lines[0]
        assert "policy accept;" in policy_lines[1]
        assert "policy drop;" in policy_lines[2]

    def test_all_accept(self, renderer: NftablesRenderer) -> None:
        """All-accept policies render correctly."""
        policy = _make_policy(
            input_policy=DefaultPolicy.ACCEPT,
            output_policy=DefaultPolicy.ACCEPT,
            forward_policy=DefaultPolicy.ACCEPT,
        )
        result = renderer.render(policy)
        policy_lines = [
            line.strip() for line in result.splitlines() if "policy " in line
        ]
        assert all(line == "policy accept;" for line in policy_lines)

    def test_reject_input_renders_as_drop_plus_reject_rule(
        self, renderer: NftablesRenderer
    ) -> None:
        """REJECT input default uses 'policy drop;' with a final 'reject' rule."""
        policy = _make_policy(input_policy=DefaultPolicy.REJECT)
        result = renderer.render(policy)
        lines = result.splitlines()

        # Find the input chain section.
        input_start = next(i for i, line in enumerate(lines) if "chain input" in line)
        input_end = next(
            i for i in range(input_start + 1, len(lines)) if lines[i].strip() == "}"
        )
        input_lines = lines[input_start : input_end + 1]

        # Base-chain policy must be "drop", not "reject".
        assert any("policy drop;" in line for line in input_lines)
        assert not any("policy reject;" in line for line in input_lines)
        # Final rule in the chain must be unconditional "reject".
        reject_lines = [
            line.strip() for line in input_lines if line.strip() == "reject"
        ]
        assert len(reject_lines) == 1

    def test_reject_output_renders_as_drop_plus_reject_rule(
        self, renderer: NftablesRenderer
    ) -> None:
        """REJECT output default uses 'policy drop;' with a final 'reject' rule."""
        policy = _make_policy(output_policy=DefaultPolicy.REJECT)
        result = renderer.render(policy)
        lines = result.splitlines()

        output_start = next(i for i, line in enumerate(lines) if "chain output" in line)
        output_end = next(
            i for i in range(output_start + 1, len(lines)) if lines[i].strip() == "}"
        )
        output_lines = lines[output_start : output_end + 1]

        assert any("policy drop;" in line for line in output_lines)
        assert not any("policy reject;" in line for line in output_lines)
        reject_lines = [
            line.strip() for line in output_lines if line.strip() == "reject"
        ]
        assert len(reject_lines) == 1

    def test_reject_forward_renders_as_drop_plus_reject_rule(
        self, renderer: NftablesRenderer
    ) -> None:
        """REJECT forward default uses 'policy drop;' with a final 'reject' rule."""
        policy = _make_policy(forward_policy=DefaultPolicy.REJECT)
        result = renderer.render(policy)
        lines = result.splitlines()

        forward_start = next(
            i for i, line in enumerate(lines) if "chain forward" in line
        )
        forward_end = next(
            i for i in range(forward_start + 1, len(lines)) if lines[i].strip() == "}"
        )
        forward_lines = lines[forward_start : forward_end + 1]

        assert any("policy drop;" in line for line in forward_lines)
        assert not any("policy reject;" in line for line in forward_lines)
        reject_lines = [
            line.strip() for line in forward_lines if line.strip() == "reject"
        ]
        assert len(reject_lines) == 1


# ---------------------------------------------------------------------------
# Protocol rendering
# ---------------------------------------------------------------------------


class TestProtocolRendering:
    """Tests for protocol-specific rule rendering."""

    def test_tcp_with_port(self, renderer: NftablesRenderer) -> None:
        """TCP rule renders with 'tcp dport <port>'."""
        rule = _make_rule(protocol=NetworkProtocol.TCP, port=22)
        result = renderer.render(_make_policy(rules=(rule,)))
        assert "tcp dport 22 accept" in result

    def test_udp_with_port(self, renderer: NftablesRenderer) -> None:
        """UDP rule renders with 'udp dport <port>'."""
        rule = _make_rule(protocol=NetworkProtocol.UDP, port=53)
        result = renderer.render(_make_policy(rules=(rule,)))
        assert "udp dport 53 accept" in result

    def test_icmp_no_port(self, renderer: NftablesRenderer) -> None:
        """ICMP rule renders with 'meta l4proto icmp'."""
        rule = _make_rule(protocol=NetworkProtocol.ICMP, port=None)
        result = renderer.render(_make_policy(rules=(rule,)))
        assert "meta l4proto icmp accept" in result

    def test_any_protocol_no_port(self, renderer: NftablesRenderer) -> None:
        """ANY protocol rule renders without a protocol keyword."""
        rule = _make_rule(protocol=NetworkProtocol.ANY, port=None)
        result = renderer.render(_make_policy(rules=(rule,)))
        # Should contain just the action with no protocol specifier.
        lines = result.splitlines()
        rule_line = next(
            line.strip()
            for line in lines
            if line.strip() == "accept" or line.strip().endswith(" accept")
        )
        # No "tcp", "udp", "icmp", or "meta" in this rule line.
        assert "tcp" not in rule_line
        assert "udp" not in rule_line
        assert "icmp" not in rule_line
        assert "meta" not in rule_line


# ---------------------------------------------------------------------------
# Action rendering
# ---------------------------------------------------------------------------


class TestActionRendering:
    """Tests for rule action rendering."""

    def test_allow_renders_accept(self, renderer: NftablesRenderer) -> None:
        """RuleAction.ALLOW renders as 'accept' in nftables."""
        rule = _make_rule(action=RuleAction.ALLOW)
        result = renderer.render(_make_policy(rules=(rule,)))
        assert "accept" in result

    def test_deny_renders_drop(self, renderer: NftablesRenderer) -> None:
        """RuleAction.DENY renders as 'drop' in nftables."""
        rule = _make_rule(action=RuleAction.DENY)
        result = renderer.render(_make_policy(rules=(rule,)))
        # Find the rule line (not the policy line).
        lines = result.splitlines()
        rule_lines = [line for line in lines if "# test-rule" in line]
        assert len(rule_lines) == 1
        # The line after the comment should contain "drop".
        idx = lines.index(rule_lines[0])
        assert "drop" in lines[idx + 1]

    def test_reject_renders_reject(self, renderer: NftablesRenderer) -> None:
        """RuleAction.REJECT renders as 'reject' in nftables."""
        rule = _make_rule(action=RuleAction.REJECT)
        result = renderer.render(_make_policy(rules=(rule,)))
        lines = result.splitlines()
        rule_lines = [line for line in lines if "# test-rule" in line]
        idx = lines.index(rule_lines[0])
        assert "reject" in lines[idx + 1]


# ---------------------------------------------------------------------------
# Source rendering
# ---------------------------------------------------------------------------


class TestSourceRendering:
    """Tests for source address rendering."""

    def test_source_any_omitted(self, renderer: NftablesRenderer) -> None:
        """Source 'any' produces no source clause in the rule."""
        rule = _make_rule(source="any")
        result = renderer.render(_make_policy(rules=(rule,)))
        # No "saddr" should appear in the output.
        rule_lines = [
            line
            for line in result.splitlines()
            if line.strip().startswith(("tcp", "udp", "meta", "accept", "drop", "ip"))
            and "type filter" not in line
        ]
        for line in rule_lines:
            assert "saddr" not in line

    def test_source_ipv4(self, renderer: NftablesRenderer) -> None:
        """An IPv4 source renders as 'ip saddr <address>'."""
        rule = _make_rule(source="192.168.1.1")
        result = renderer.render(_make_policy(rules=(rule,)))
        assert "ip saddr 192.168.1.1" in result

    def test_source_cidr(self, renderer: NftablesRenderer) -> None:
        """A CIDR source renders as 'ip saddr <network>'."""
        rule = _make_rule(source="10.0.0.0/8")
        result = renderer.render(_make_policy(rules=(rule,)))
        assert "ip saddr 10.0.0.0/8" in result


# ---------------------------------------------------------------------------
# Multiple rules
# ---------------------------------------------------------------------------


class TestMultipleRules:
    """Tests for rendering multiple rules."""

    def test_all_rules_rendered(self, renderer: NftablesRenderer) -> None:
        """All rules appear in the rendered output."""
        rules = (
            _make_rule(name="allow-ssh", port=22),
            _make_rule(name="allow-http", port=80),
            _make_rule(name="allow-https", port=443),
        )
        result = renderer.render(_make_policy(rules=rules))
        assert "# allow-ssh" in result
        assert "# allow-http" in result
        assert "# allow-https" in result

    def test_rule_order_preserved(self, renderer: NftablesRenderer) -> None:
        """Rules appear in the same order as the policy tuple."""
        rules = (
            _make_rule(name="first", port=22),
            _make_rule(name="second", port=80),
            _make_rule(name="third", port=443),
        )
        result = renderer.render(_make_policy(rules=rules))
        first_idx = result.index("# first")
        second_idx = result.index("# second")
        third_idx = result.index("# third")
        assert first_idx < second_idx < third_idx


# ---------------------------------------------------------------------------
# Formatting stability
# ---------------------------------------------------------------------------


class TestFormattingStability:
    """Tests verifying deterministic and consistent output."""

    def test_same_input_same_output(self, renderer: NftablesRenderer) -> None:
        """Rendering the same policy twice produces identical output."""
        rules = (
            _make_rule(name="allow-ssh", port=22),
            _make_rule(name="allow-dns", protocol=NetworkProtocol.UDP, port=53),
        )
        policy = _make_policy(rules=rules)
        first = renderer.render(policy)
        second = renderer.render(policy)
        assert first == second

    def test_output_ends_with_newline(self, renderer: NftablesRenderer) -> None:
        """Rendered output ends with a trailing newline."""
        result = renderer.render(_make_policy())
        assert result.endswith("\n")

    def test_table_structure(self, renderer: NftablesRenderer) -> None:
        """Rendered output has the expected table/chain structure."""
        result = renderer.render(_make_policy())
        assert result.startswith("table inet aegisfw {")
        assert result.strip().endswith("}")

    def test_chain_hooks(self, renderer: NftablesRenderer) -> None:
        """All three chains declare correct hooks and priority."""
        result = renderer.render(_make_policy())
        assert "type filter hook input priority 0;" in result
        assert "type filter hook output priority 0;" in result
        assert "type filter hook forward priority 0;" in result

    def test_complete_ruleset_snapshot(self, renderer: NftablesRenderer) -> None:
        """A known policy produces the exact expected nftables output."""
        rules = (
            FirewallRule(
                name="allow-ssh",
                action=RuleAction.ALLOW,
                protocol=NetworkProtocol.TCP,
                source="any",
                port=22,
            ),
            FirewallRule(
                name="allow-icmp",
                action=RuleAction.ALLOW,
                protocol=NetworkProtocol.ICMP,
                source="any",
                port=None,
            ),
        )
        policy = _make_policy(rules=rules)

        expected = (
            "table inet aegisfw {\n"
            "\n"
            "    chain input {\n"
            "        type filter hook input priority 0;\n"
            "        policy drop;\n"
            "\n"
            "        # allow-ssh\n"
            "        tcp dport 22 accept\n"
            "\n"
            "        # allow-icmp\n"
            "        meta l4proto icmp accept\n"
            "    }\n"
            "\n"
            "    chain output {\n"
            "        type filter hook output priority 0;\n"
            "        policy accept;\n"
            "    }\n"
            "\n"
            "    chain forward {\n"
            "        type filter hook forward priority 0;\n"
            "        policy drop;\n"
            "    }\n"
            "}\n"
        )
        assert renderer.render(policy) == expected
