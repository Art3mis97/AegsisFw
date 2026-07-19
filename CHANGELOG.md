# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Project foundation: repository structure, Python packaging, development tooling.
- `pyproject.toml` with src-layout and development dependencies.
- `.gitignore`, `.editorconfig` for git hygiene and editor consistency.
- `CONTRIBUTING.md`, `SECURITY.md`, and `CHANGELOG.md`.
- Minimal `aegisfw` Python package with version metadata.
- Basic test suite validating package structure.
- GitHub Actions CI workflow for testing and linting.
- Configuration engine: YAML loading, validation, and typed models.
- Custom exception hierarchy for configuration errors.
- Dataclass models for firewall policies, logging, and rules.
- Source validation supporting IPv4, IPv6, and CIDR networks.
- Annotated example configuration file (`config/aegisfw.example.yaml`).
- Comprehensive configuration test suite.
- PyYAML runtime dependency.
- Internal firewall policy engine with immutable domain models.
- `compile_policy()` function converting configuration into `FirewallPolicy`.
- Domain enums: `RuleAction`, `NetworkProtocol`, `DefaultPolicy`.
- Frozen dataclasses: `FirewallRule`, `DefaultPolicies`, `FirewallPolicy`.
- Duplicate rule name detection during policy compilation.
- Policy-specific exception hierarchy.
- Comprehensive policy compiler test suite.
- `NftablesRenderer` class generating complete nftables rulesets from `FirewallPolicy`.
- Support for TCP, UDP, ICMP, and ANY protocol rendering.
- Support for IPv4 address and CIDR source rendering.
- Action mapping: ALLOW→accept, DENY→drop, REJECT→reject.
- Comprehensive nftables renderer test suite with snapshot verification.
