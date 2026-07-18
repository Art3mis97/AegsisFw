# AegisFW

**Modern Linux Host Firewall**

A lightweight, modular Linux host firewall management system built with Python and nftables.

> ⚠️ **This project is under active development and is not yet ready for production use.**
> No firewall features are currently implemented. Do not rely on this software to protect any system.

## About

AegisFW is an open-source tool designed to give Linux system administrators a clean, maintainable way to manage host firewall rules through nftables.

Python provides the management layer — configuration loading, validation, rule generation, and safe deployment. nftables remains responsible for actual packet filtering.

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
| 1 | Configuration Engine | 🔲 Planned |
| 2 | Rule and Policy Engine | 🔲 Planned |
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
pip install -e ".[dev]"
```

### Running Checks

```bash
pytest                              # Run tests
ruff check src/ tests/              # Lint
ruff format --check src/ tests/     # Check formatting
```

## License

[MIT](LICENSE)
