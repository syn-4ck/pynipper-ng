import pytest
import textwrap
from src.analyze.cisco.ios.plugins.line_console_plugin import PluginLineConsole


@pytest.fixture
def plugin():
    return PluginLineConsole()


def test_name(plugin):
    assert plugin.name() == "Line Console Security"


# --- exec-timeout ---

def test_console_timeout_not_configured(cfg, plugin):
    f = cfg("""
line con 0
 login
""")
    assert plugin.get_console_exec_timeout(f) is not None


def test_console_timeout_zero(cfg, plugin):
    f = cfg("""
line con 0
 exec-timeout 0 0
 login
""")
    assert plugin.get_console_exec_timeout(f) is not None


def test_console_timeout_ok(cfg, plugin):
    f = cfg("""
line con 0
 exec-timeout 5 0
 login
""")
    assert plugin.get_console_exec_timeout(f) is None


def test_console_timeout_1_minute(cfg, plugin):
    f = cfg("""
line con 0
 exec-timeout 1 0
 login
""")
    assert plugin.get_console_exec_timeout(f) is None


# --- transport input none ---

def test_console_transport_missing(cfg, plugin):
    f = cfg("""
line con 0
 login
""")
    assert plugin.get_console_transport_input(f) is not None


def test_console_transport_none(cfg, plugin):
    f = cfg("""
line con 0
 transport input none
 login
""")
    assert plugin.get_console_transport_input(f) is None


def test_console_transport_ssh(cfg, plugin):
    # Not 'none' → issue
    f = cfg("""
line con 0
 transport input ssh
 login
""")
    assert plugin.get_console_transport_input(f) is not None


# --- login ---

def test_console_login_missing(cfg, plugin):
    f = cfg("""
line con 0
""")
    assert plugin.get_console_login(f) is not None


def test_console_login_present(cfg, plugin):
    f = cfg("""
line con 0
 login
""")
    assert plugin.get_console_login(f) is None


def test_console_login_local(cfg, plugin):
    f = cfg("""
line con 0
 login local
""")
    assert plugin.get_console_login(f) is None


# --- logging synchronous ---

def test_console_logging_sync_missing(cfg, plugin):
    f = cfg("""
line con 0
 login
""")
    assert plugin.get_console_logging_sync(f) is not None


def test_console_logging_sync_present(cfg, plugin):
    f = cfg("""
line con 0
 logging synchronous
 login
""")
    assert plugin.get_console_logging_sync(f) is None


# --- analyze ---

def test_analyze_all_issues(cfg, plugin):
    f = cfg("""
line con 0
""")
    plugin.analyze(f)
    # timeout_not_configured + transport_not_restricted + login_missing + logging_sync_missing = 4
    assert len(plugin.get_issues()) == 4


def test_analyze_compliant(cfg, plugin):
    f = cfg("""
line con 0
 exec-timeout 5 0
 transport input none
 login local
 logging synchronous
""")
    plugin.analyze(f)
    assert len(plugin.get_issues()) == 0
