"""Immutable domain models for AegisFW firewall policy."""

from __future__ import annotations

from dataclasses import dataclass

from aegisfw.policy.enums import DefaultPolicy, NetworkProtocol, RuleAction


@dataclass(frozen=True)
class FirewallRule:
    """A single normalized firewall rule."""

    name: str
    action: RuleAction
    protocol: NetworkProtocol
    source: str
    port: int | None = None


@dataclass(frozen=True)
class DefaultPolicies:
    """Default chain policies for unmatched traffic."""

    input: DefaultPolicy
    output: DefaultPolicy
    forward: DefaultPolicy


@dataclass(frozen=True)
class FirewallPolicy:
    """Complete compiled firewall policy.

    This is the backend-independent representation of firewall intent.
    It is produced by ``compile_policy()`` and consumed by backend
    generators (e.g. the Phase 3 nftables backend).
    """

    defaults: DefaultPolicies
    rules: tuple[FirewallRule, ...]
