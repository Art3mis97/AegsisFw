"""Tests for aegisfw package structure and metadata."""

import re


def test_package_importable() -> None:
    """The aegisfw package can be imported without error."""
    import aegisfw

    assert aegisfw is not None


def test_version_defined() -> None:
    """The package exposes a __version__ string."""
    from aegisfw import __version__

    assert isinstance(__version__, str)
    assert len(__version__) > 0


def test_version_format() -> None:
    """The version string follows PEP 440 (simplified check)."""
    from aegisfw import __version__

    # Matches patterns like: 0.1.0, 0.1.0.dev0, 1.0.0a1, 1.0.0rc1
    pep440_pattern = re.compile(
        r"^\d+\.\d+\.\d+"
        r"(\.dev\d+|a\d+|b\d+|rc\d+)?$"
    )
    assert pep440_pattern.match(__version__), (
        f"Version '{__version__}' does not match expected PEP 440 format"
    )


def test_all_is_list() -> None:
    """The package __all__ is a list."""
    from aegisfw import __all__

    assert isinstance(__all__, list)
