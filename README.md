# AegisFW

**Modern Linux Host Firewall**

A lightweight, modular Linux host firewall management system built with Python and nftables.

> ⚠️ **This project is under active development and is not yet ready for production use.**
> No firewall features are currently implemented. Do not rely on this software to protect any system.

## About

AegisFW is an open-source tool designed to give Linux system administrators a clean, maintainable way to manage host firewall rules through nftables.

Python provides the management layer — configuration loading, validation, rule generation, and safe deployment. nftables remains responsible for actual packet filtering.

## Current Status

Currently implemented:

- Project structure
- Packaging and installation
- Development tooling
- Continuous Integration (GitHub Actions)
- Code quality checks (Ruff)
- Unit testing framework
- Configuration engine (YAML loading and validation)
- Policy engine (internal firewall policy model and compiler)

Not yet implemented:

- nftables integration
- Command-Line Interface
- Logging
- Monitoring

## Goals

- Provide a professional, easy-to-use firewall management interface for Linux hosts.
- Generate and apply nftables rulesets from structured configuration.
- Support safe deployment with automatic rollback on failure.
- Maintain a clear separation between management logic and packet filtering.
- Stay lightweight, auditable, and dependency-conscious.

## Roadmap

| Phase | Description | Status |
|-------|-------------|--------|
| 0 | Project Foundation | ✅ Complete |
| 1 | Configuration Engine | ✅ Complete |
| 2 | Rule and Policy Engine | ✅ Complete |
| 3 | nftables Backend | 🔲 Planned |
| 4 | Command-Line Interface | 🔲 Planned |
| 5 | Logging and Monitoring | 🔲 Planned |
| 6 | Advanced Security Features | 🔲 Planned |
| 7 | Web Dashboard | 🔲 Planned |
| 8 | Production and Deployment | 🔲 Planned |
| 9 | Quality and Release | 🔲 Planned |

## Platform

- **Primary:** Ubuntu Linux
- **Future:** Other Debian-based distributions

## Technologies

- **Language:** Python 3.11+
- **Firewall Backend:** nftables
- **Packaging:** setuptools with src-layout

## Architecture

AegisFW is composed of independent modules:

- **Configuration Engine** — loads and validates firewall configuration.
- **Rule Engine** — models firewall rules and policies.
- **nftables Backend** — generates and applies nftables rulesets.
- **Command-Line Interface** — provides administrative control.
- **Logging** — records firewall events and management actions.
- **Dashboard** — future web-based monitoring interface.

This modular architecture improves maintainability and testing by keeping each component focused on a single responsibility.

## Usage

Load and validate a configuration file:

```python
from aegisfw.config import load_config

config = load_config("config/aegisfw.example.yaml")

print(config.firewall.default_input)   # "drop"
print(config.logging.level)            # "info"

for rule in config.rules:
    print(f"{rule.name}: {rule.action} {rule.protocol}/{rule.port}")
```

See `config/aegisfw.example.yaml` for the full configuration format.

Compile configuration into an internal firewall policy:

```python
from aegisfw.config import load_config
from aegisfw.policy import compile_policy

config = load_config("config/aegisfw.example.yaml")
policy = compile_policy(config)

print(policy.defaults.input)       # DefaultPolicy.DROP
print(policy.rules[0].action)      # RuleAction.ALLOW
print(policy.rules[0].protocol)    # NetworkProtocol.TCP
```

The compiled policy is immutable and backend-independent. nftables rule generation will be added in Phase 3.

## Development Setup

### Prerequisites

- Python 3.11 or later
- Git

### Setup

```bash
git clone https://github.com/Art3mis97/AegisFW.git
cd AegisFW
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

### Running Checks

```bash
pytest                              # Run tests
ruff check src/ tests/              # Lint
ruff format --check src/ tests/     # Check formatting
```

## License

[MIT](LICENSE)
