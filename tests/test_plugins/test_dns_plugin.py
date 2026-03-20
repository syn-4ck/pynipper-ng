"""Tests for dns_plugin.py — CIS 2.4.1"""
import pytest
from src.analyze.cisco.ios.plugins.dns_plugin import PluginDNS


@pytest.fixture
def plugin():
    return PluginDNS()


def test_dns_lookup_enabled_with_server(cfg, plugin):
    """ip name-server present without 'no ip domain-lookup' → no issue."""
    f = cfg("ip name-server 8.8.8.8")
    assert plugin.get_dns_lookup_control(f) is None


def test_dns_lookup_disabled(cfg, plugin):
    """'no ip domain-lookup' present → no issue."""
    f = cfg("no ip domain-lookup")
    assert plugin.get_dns_lookup_control(f) is None


def test_dns_lookup_unconfigured(cfg, plugin):
    """Neither server nor explicit disable → issue."""
    f = cfg("hostname R1")
    assert plugin.get_dns_lookup_control(f) is not None


def test_analyze_issues(cfg, plugin):
    f = cfg("hostname R1")
    plugin.analyze(f)
    assert len(plugin.get_issues()) == 1


def test_analyze_compliant(cfg, plugin):
    f = cfg("no ip domain-lookup")
    plugin.analyze(f)
    assert len(plugin.get_issues()) == 0


def test_plugin_name(plugin):
    assert "DNS" in plugin.name() or "dns" in plugin.name().lower()
