"""Tests for cdp_lldp_plugin.py — CIS 2.3.x"""
import pytest
from src.analyze.cisco.ios.plugins.cdp_lldp_plugin import PluginCDPLLDP


@pytest.fixture
def plugin():
    return PluginCDPLLDP()


# ---------------------------------------------------------------------------
# CIS 2.3.1 - CDP global
# ---------------------------------------------------------------------------

def test_cdp_global_enabled(cfg, plugin):
    """CDP is on by default — no 'no cdp run' → issue."""
    f = cfg("hostname R1")
    assert plugin.get_cdp_global(f) is not None


def test_cdp_global_disabled(cfg, plugin):
    f = cfg("no cdp run")
    assert plugin.get_cdp_global(f) is None


# ---------------------------------------------------------------------------
# CIS 2.3.1 - CDP on interfaces
# ---------------------------------------------------------------------------

def test_cdp_on_interfaces_issue(cfg, plugin):
    """CDP globally enabled, interface lacks 'no cdp enable'."""
    f = cfg("""
    interface GigabitEthernet0/0
     ip address 1.2.3.4 255.255.255.0
    """)
    assert plugin.get_cdp_on_interfaces(f) is not None


def test_cdp_on_interfaces_no_issue_global_disabled(cfg, plugin):
    """CDP globally disabled — per-interface check skipped."""
    f = cfg("""
    no cdp run
    interface GigabitEthernet0/0
     ip address 1.2.3.4 255.255.255.0
    """)
    assert plugin.get_cdp_on_interfaces(f) is None


def test_cdp_on_interfaces_no_issue_per_interface(cfg, plugin):
    """CDP still on globally but every interface has 'no cdp enable'."""
    f = cfg("""
    interface GigabitEthernet0/0
     no cdp enable
    """)
    assert plugin.get_cdp_on_interfaces(f) is None


# ---------------------------------------------------------------------------
# CIS 2.3.2 - LLDP global
# ---------------------------------------------------------------------------

def test_lldp_global_not_explicitly_enabled(cfg, plugin):
    """LLDP not explicitly enabled — no issue."""
    f = cfg("hostname R1")
    assert plugin.get_lldp_global(f) is None


def test_lldp_global_explicitly_enabled(cfg, plugin):
    f = cfg("lldp run")
    assert plugin.get_lldp_global(f) is not None


def test_lldp_global_disabled(cfg, plugin):
    f = cfg("no lldp run")
    assert plugin.get_lldp_global(f) is None


# ---------------------------------------------------------------------------
# analyze()
# ---------------------------------------------------------------------------

def test_analyze_issues(cfg, plugin):
    f = cfg("""
    lldp run
    interface GigabitEthernet0/0
     ip address 1.2.3.4 255.255.255.0
    """)
    plugin.analyze(f)
    assert len(plugin.get_issues()) >= 2


def test_analyze_compliant(cfg, plugin):
    f = cfg("""
    no cdp run
    no lldp run
    """)
    plugin.analyze(f)
    assert len(plugin.get_issues()) == 0


def test_plugin_name(plugin):
    assert "CDP" in plugin.name()
