"""Shared pytest fixtures for all tests."""
import textwrap
import pytest


@pytest.fixture
def cfg(tmp_path):
    """Return a helper that writes a config snippet to a temp file and returns the path."""
    def _write(content: str) -> str:
        p = tmp_path / "test.conf"
        p.write_text(textwrap.dedent(content).strip() + "\n")
        return str(p)
    return _write


EXAMPLE_CONFIG = "tests/test_data/cisco_ios_example.conf"
