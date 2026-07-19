"""nftables ruleset renderer for AegisFW.

Translates an immutable FirewallPolicy into a complete nftables ruleset
string. Does not execute any commands or modify the system.
"""

from __future__ import annotations

from aegisfw.policy.enums import DefaultPolicy, NetworkProtocol, RuleAction
from aegisfw.policy.models import FirewallPolicy, FirewallRule

# ---------------------------------------------------------------------------
# nftables action mapping
# ---------------------------------------------------------------------------
# Domain RuleAction values ("allow", "deny") differ from nftables keywords
# ("accept", "drop"). DefaultPolicy values already match nftables syntax.

_NFT_ACTIONS: dict[RuleAction, str] = {
    RuleAction.ALLOW: "accept",
    RuleAction.DENY: "drop",
    RuleAction.REJECT: "reject",
}


class NftablesRenderer:
    """Renders a FirewallPolicy into nftables ruleset syntax.

    This class is a pure function wrapper — it holds no state and performs
    no I/O. It only converts domain objects into nftables configuration text.

    Usage::

        from aegisfw.renderer import NftablesRenderer

        renderer = NftablesRenderer()
        ruleset = renderer.render(policy)
        print(ruleset)
    """

    TABLE_NAME = "aegisfw"
    TABLE_FAMILY = "inet"

    def render(self, policy: FirewallPolicy) -> str:
        """Render a complete nftables ruleset from a compiled policy.

        Args:
            policy: An immutable FirewallPolicy produced by ``compile_policy``.

        Returns:
            A string containing a complete, valid nftables ruleset.
        """
        lines: list[str] = []

        lines.append(f"table {self.TABLE_FAMILY} {self.TABLE_NAME} {{")
        lines.append("")
        lines.extend(
            self._render_chain(
                name="input",
                hook="input",
                default=policy.defaults.input,
                rules=policy.rules,
            )
        )
        lines.append("")
        lines.extend(
            self._render_chain(
                name="output",
                hook="output",
                default=policy.defaults.output,
                rules=(),
            )
        )
        lines.append("")
        lines.extend(
            self._render_chain(
                name="forward",
                hook="forward",
                default=policy.defaults.forward,
                rules=(),
            )
        )
        lines.append("}")
        lines.append("")

        return "\n".join(lines)

    def _render_chain(
        self,
        name: str,
        hook: str,
        default: DefaultPolicy,
        rules: tuple[FirewallRule, ...],
    ) -> list[str]:
        """Render a single nftables chain.

        nftables base-chain policies only support ``accept`` and ``drop``.
        When the domain default is REJECT, the chain uses ``policy drop;``
        and an unconditional ``reject`` statement is appended after all
        user-defined rules.
        """
        # nftables base-chain policy: only accept or drop.
        nft_policy = "drop" if default is DefaultPolicy.REJECT else default.value

        lines: list[str] = []
        lines.append(f"    chain {name} {{")
        lines.append(f"        type filter hook {hook} priority 0;")
        lines.append(f"        policy {nft_policy};")

        for rule in rules:
            lines.append("")
            lines.append(f"        # {rule.name}")
            lines.append(f"        {self._render_rule(rule)}")

        # Unconditional reject for REJECT default policy.
        if default is DefaultPolicy.REJECT:
            lines.append("")
            lines.append("        reject")

        lines.append("    }")
        return lines

    def _render_rule(self, rule: FirewallRule) -> str:
        """Render a single nftables rule statement."""
        parts: list[str] = []

        # Source match (omitted for "any").
        if rule.source != "any":
            family = "ip6" if ":" in rule.source else "ip"
            parts.append(f"{family} saddr {rule.source}")

        # Protocol and port match.
        if rule.protocol is not NetworkProtocol.ANY:
            if rule.port is not None:
                parts.append(f"{rule.protocol.value} dport {rule.port}")
            else:
                parts.append(f"meta l4proto {rule.protocol.value}")

        # Action.
        parts.append(_NFT_ACTIONS[rule.action])

        return " ".join(parts)
