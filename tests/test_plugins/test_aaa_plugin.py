"""Tests for aaa_plugin.py — CIS 1.4.x"""
import pytest
from src.analyze.cisco.ios.plugins.aaa_plugin import AAAPlugin


@pytest.fixture
def plugin():
    return AAAPlugin()


# ---------------------------------------------------------------------------
# CIS 1.4.1 - aaa new-model
# ---------------------------------------------------------------------------

def test_aaa_new_model_missing(cfg, plugin):
    f = cfg("hostname R1")
    assert plugin.get_aaa_new_model(f) is not None


def test_aaa_new_model_present(cfg, plugin):
    f = cfg("aaa new-model")
    assert plugin.get_aaa_new_model(f) is None


# ---------------------------------------------------------------------------
# CIS 1.4.2 - aaa authentication login
# ---------------------------------------------------------------------------

def test_aaa_authentication_login_missing(cfg, plugin):
    f = cfg("aaa new-model")
    assert plugin.get_aaa_authentication_login(f) is not None


def test_aaa_authentication_login_present(cfg, plugin):
    f = cfg("aaa authentication login default local")
    assert plugin.get_aaa_authentication_login(f) is None


# ---------------------------------------------------------------------------
# CIS 1.4.3 - aaa authentication enable
# ---------------------------------------------------------------------------

def test_aaa_authentication_enable_missing(cfg, plugin):
    f = cfg("aaa new-model")
    assert plugin.get_aaa_authentication_enable(f) is not None


def test_aaa_authentication_enable_present(cfg, plugin):
    f = cfg("aaa authentication enable default group tacacs+ enable")
    assert plugin.get_aaa_authentication_enable(f) is None


# ---------------------------------------------------------------------------
# CIS 1.4.4 - login authentication on lines
# ---------------------------------------------------------------------------

def test_login_auth_on_lines_missing(cfg, plugin):
    f = cfg("""
    line vty 0 4
     transport input ssh
    """)
    assert plugin.get_login_authentication_on_lines(f) is not None


def test_login_auth_on_lines_present(cfg, plugin):
    f = cfg("""
    line vty 0 4
     login authentication default
    """)
    assert plugin.get_login_authentication_on_lines(f) is None


# ---------------------------------------------------------------------------
# CIS 1.4.5 - aaa authorization exec
# ---------------------------------------------------------------------------

def test_aaa_authorization_exec_missing(cfg, plugin):
    f = cfg("aaa new-model")
    assert plugin.get_aaa_authorization_exec(f) is not None


def test_aaa_authorization_exec_present(cfg, plugin):
    f = cfg("aaa authorization exec default group tacacs+ local")
    assert plugin.get_aaa_authorization_exec(f) is None


# ---------------------------------------------------------------------------
# CIS 1.4.6 - aaa authorization network
# ---------------------------------------------------------------------------

def test_aaa_authorization_network_missing(cfg, plugin):
    f = cfg("aaa new-model")
    assert plugin.get_aaa_authorization_network(f) is not None


def test_aaa_authorization_network_present(cfg, plugin):
    f = cfg("aaa authorization network default group tacacs+ local")
    assert plugin.get_aaa_authorization_network(f) is None


# ---------------------------------------------------------------------------
# CIS 1.4.7 - aaa accounting exec
# ---------------------------------------------------------------------------

def test_aaa_accounting_exec_missing(cfg, plugin):
    f = cfg("aaa new-model")
    assert plugin.get_aaa_accounting_exec(f) is not None


def test_aaa_accounting_exec_present(cfg, plugin):
    f = cfg("aaa accounting exec default start-stop group tacacs+")
    assert plugin.get_aaa_accounting_exec(f) is None


# ---------------------------------------------------------------------------
# CIS 1.4.8 - aaa accounting commands 15
# ---------------------------------------------------------------------------

def test_aaa_accounting_commands_15_missing(cfg, plugin):
    f = cfg("aaa new-model")
    assert plugin.get_aaa_accounting_commands_15(f) is not None


def test_aaa_accounting_commands_15_present(cfg, plugin):
    f = cfg("aaa accounting commands 15 default start-stop group tacacs+")
    assert plugin.get_aaa_accounting_commands_15(f) is None


# ---------------------------------------------------------------------------
# CIS 1.4.9 - aaa accounting connection
# ---------------------------------------------------------------------------

def test_aaa_accounting_connection_missing(cfg, plugin):
    f = cfg("aaa new-model")
    assert plugin.get_aaa_accounting_connection(f) is not None


def test_aaa_accounting_connection_present(cfg, plugin):
    f = cfg("aaa accounting connection default start-stop group tacacs+")
    assert plugin.get_aaa_accounting_connection(f) is None


# ---------------------------------------------------------------------------
# analyze() dispatch
# ---------------------------------------------------------------------------

def test_analyze_all_issues(cfg, plugin):
    """Bare config triggers all 9 issues."""
    f = cfg("hostname R1")
    plugin.analyze(f)
    assert len(plugin.get_issues()) == 9


def test_analyze_compliant(cfg, plugin):
    """Fully compliant config produces no issues."""
    f = cfg("""
    aaa new-model
    aaa authentication login default local
    aaa authentication enable default group tacacs+ enable
    aaa authorization exec default group tacacs+ local
    aaa authorization network default group tacacs+ local
    aaa accounting exec default start-stop group tacacs+
    aaa accounting commands 15 default start-stop group tacacs+
    aaa accounting connection default start-stop group tacacs+
    line vty 0 4
     login authentication default
    """)
    plugin.analyze(f)
    assert len(plugin.get_issues()) == 0


def test_plugin_name(plugin):
    assert "AAA" in plugin.name() or "Authentication" in plugin.name()
