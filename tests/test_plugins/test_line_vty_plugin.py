import pytest
import textwrap
from src.analyze.cisco.ios.plugins.line_vty_plugin import PluginLineVTY


@pytest.fixture
def plugin():
    return PluginLineVTY()


def test_name(plugin):
    assert plugin.name() == "Line VTY Security"


# --- access-class ---

def test_vty_no_acl(cfg, plugin):
    f = cfg("""
line vty 0 4
 login local
 transport input ssh
""")
    assert plugin.get_vty_access_class(f) is not None


def test_vty_with_acl(cfg, plugin):
    f = cfg("""
line vty 0 4
 access-class 10 in
 login local
 transport input ssh
""")
    assert plugin.get_vty_access_class(f) is None


def test_vty_no_lines(cfg, plugin):
    f = cfg("hostname R1")
    assert plugin.get_vty_access_class(f) is not None


# --- exec-timeout ---

def test_vty_timeout_missing(cfg, plugin):
    f = cfg("""
line vty 0 4
 login local
""")
    assert plugin.get_vty_exec_timeout(f) is not None


def test_vty_timeout_zero(cfg, plugin):
    f = cfg("""
line vty 0 4
 exec-timeout 0 0
 login local
""")
    assert plugin.get_vty_exec_timeout(f) is not None


def test_vty_timeout_ok(cfg, plugin):
    f = cfg("""
line vty 0 4
 exec-timeout 10 0
 login local
""")
    assert plugin.get_vty_exec_timeout(f) is None


# --- transport input ssh ---

def test_vty_transport_not_ssh(cfg, plugin):
    f = cfg("""
line vty 0 4
 login local
""")
    assert plugin.get_vty_transport_input_ssh(f) is not None


def test_vty_transport_telnet(cfg, plugin):
    f = cfg("""
line vty 0 4
 transport input telnet
 login local
""")
    assert plugin.get_vty_transport_input_ssh(f) is not None


def test_vty_transport_ssh(cfg, plugin):
    f = cfg("""
line vty 0 4
 transport input ssh
 login local
""")
    assert plugin.get_vty_transport_input_ssh(f) is None


# --- logging synchronous ---

def test_vty_logging_sync_missing(cfg, plugin):
    f = cfg("""
line vty 0 4
 login local
""")
    assert plugin.get_vty_logging_sync(f) is not None


def test_vty_logging_sync_present(cfg, plugin):
    f = cfg("""
line vty 0 4
 logging synchronous
 login local
""")
    assert plugin.get_vty_logging_sync(f) is None


# --- login ---

def test_vty_login_missing(cfg, plugin):
    f = cfg("""
line vty 0 4
""")
    assert plugin.get_vty_login(f) is not None


def test_vty_login_present(cfg, plugin):
    f = cfg("""
line vty 0 4
 login local
""")
    assert plugin.get_vty_login(f) is None


# --- analyze ---

def test_analyze_all_issues(cfg, plugin):
    f = cfg("""
line vty 0 4
""")
    plugin.analyze(f)
    # access_class, exec_timeout, transport_ssh, logging_sync, login = 5
    assert len(plugin.get_issues()) == 5


def test_analyze_compliant(cfg, plugin):
    f = cfg("""
line vty 0 4
 access-class 10 in
 exec-timeout 10 0
 transport input ssh
 logging synchronous
 login local
""")
    plugin.analyze(f)
    assert len(plugin.get_issues()) == 0
