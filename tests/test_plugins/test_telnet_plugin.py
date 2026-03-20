"""Tests for telnet_plugin.py — CIS 2.2.1"""
import pytest
from src.analyze.cisco.ios.plugins.telnet_plugin import PluginTelnet


@pytest.fixture
def plugin():
    return PluginTelnet()


def test_telnet_allowed(cfg, plugin):
    """VTY explicitly allowing Telnet → issue."""
    f = cfg("""
    line vty 0 4
     transport input all
    """)
    assert plugin.get_telnet_enabled(f) is not None


def test_telnet_ssh_only(cfg, plugin):
    f = cfg("""
    line vty 0 4
     transport input ssh
    """)
    assert plugin.get_telnet_enabled(f) is None


def test_telnet_transport_none(cfg, plugin):
    f = cfg("""
    line vty 0 4
     transport input none
    """)
    assert plugin.get_telnet_enabled(f) is None


def test_telnet_no_vty_configured(cfg, plugin):
    """No VTY lines configured at all → issue (telnet could be default)."""
    f = cfg("hostname R1")
    assert plugin.get_telnet_enabled(f) is not None


def test_analyze_issues(cfg, plugin):
    f = cfg("""
    line vty 0 4
     transport input telnet
    """)
    plugin.analyze(f)
    assert len(plugin.get_issues()) == 1


def test_analyze_compliant(cfg, plugin):
    f = cfg("""
    line vty 0 4
     transport input ssh
    """)
    plugin.analyze(f)
    assert len(plugin.get_issues()) == 0


def test_plugin_name(plugin):
    assert "Telnet" in plugin.name() or "telnet" in plugin.name().lower()
