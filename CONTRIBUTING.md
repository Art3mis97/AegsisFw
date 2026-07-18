# Contributing to AegisFW

Thank you for your interest in contributing to AegisFW.

AegisFW is in early development. Contributions are welcome, but please coordinate before starting significant work.

## Getting Started

### Prerequisites

- Python 3.11 or later
- Git

### Development Setup

```bash
# Clone the repository
git clone https://github.com/Art3mis97/AegisFW.git
cd AegisFW

# Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install in editable mode with development dependencies
pip install -e ".[dev]"
```

### Running Checks

```bash
# Run tests
pytest

# Run linter
ruff check src/ tests/

# Check formatting
ruff format --check src/ tests/

# Apply formatting fixes
ruff format src/ tests/
```

## Contribution Guidelines

### Before You Start

- Open an issue to discuss your proposed change before writing code.
- Check existing issues to avoid duplicate work.

### Code Standards

- Follow PEP 8 and existing project conventions.
- Use type hints.
- Write tests for meaningful behaviour.
- Keep changes focused — one concern per pull request.

### Commit Messages

This project uses [Conventional Commits](https://www.conventionalcommits.org/).

Format: `type(scope): description`

Examples:

```
feat(config): add YAML configuration loader
fix(rules): correct protocol validation for ICMP
test(config): add edge-case tests for port ranges
docs: update installation instructions
```

### Pull Requests

- Branch from `main`.
- Ensure all checks pass before requesting review.
- Keep pull requests small and reviewable.
- Describe what your change does and why.

## Code of Conduct

Be respectful and constructive. This is a security-focused project — careful, thoughtful work is valued over speed.

## Questions

Open an issue for questions about the project or how to contribute.
