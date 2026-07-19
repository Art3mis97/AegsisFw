"""AegisFW renderer package.

Provides backend-specific renderers that convert a compiled FirewallPolicy
into firewall configuration syntax. Currently supports nftables.

Usage::

    from aegisfw.renderer import NftablesRenderer
    from aegisfw.policy import compile_policy
    from aegisfw.config import load_config

    config = load_config("config/aegisfw.example.yaml")
    policy = compile_policy(config)

    renderer = NftablesRenderer()
    ruleset = renderer.render(policy)
"""

from aegisfw.renderer.nftables import NftablesRenderer

__all__ = ["NftablesRenderer"]
