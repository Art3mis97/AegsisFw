"""Domain enums for AegisFW firewall policy."""

from enum import StrEnum


class RuleAction(StrEnum):
    """Action to apply when a firewall rule matches."""

    ALLOW = "allow"
    DENY = "deny"
    REJECT = "reject"


class NetworkProtocol(StrEnum):
    """Network protocol a firewall rule applies to."""

    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    ANY = "any"


class DefaultPolicy(StrEnum):
    """Default chain policy for unmatched traffic."""

    ACCEPT = "accept"
    DROP = "drop"
    REJECT = "reject"
