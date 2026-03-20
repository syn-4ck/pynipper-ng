import pytest
import textwrap
from src.analyze.cisco.ios.plugins.line_aux_plugin import PluginLineAux


@pytest.fixture
def plugin():
    return PluginLineAux()


def test_name(plugin):
    assert plugin.name() == "Line AUX Security"


# --- no AUX line present (all guards return None) ---

def test_no_aux_line_no_exec(cfg, plugin):
    f = cfg("hostname R1")
    assert plugin.get_aux_no_exec(f) is None


def test_no_aux_line_timeout(cfg, plugin):
    f = cfg("hostname R1")
    assert plugin.get_aux_exec_timeout(f) is None


def test_no_aux_line_transport(cfg, plugin):
    f = cfg("hostname R1")
    assert plugin.get_aux_transport_input(f) is None


def test_no_aux_line_login(cfg, plugin):
    f = cfg("hostname R1")
    assert plugin.get_aux_login(f) is None


# --- no exec ---

def test_aux_no_exec_missing(cfg, plugin):
    f = cfg("""
line aux 0
 login
""")
    assert plugin.get_aux_no_exec(f) is not None


def test_aux_no_exec_set(cfg, plugin):
    f = cfg("""
line aux 0
 no exec
 login
""")
    assert plugin.get_aux_no_exec(f) is None


# --- exec-timeout ---

def test_aux_timeout_not_configured(cfg, plugin):
    f = cfg("""
line aux 0
 login
""")
    assert plugin.get_aux_exec_timeout(f) is not None


def test_aux_timeout_zero(cfg, plugin):
    f = cfg("""
line aux 0
 exec-timeout 0 0
 login
""")
    assert plugin.get_aux_exec_timeout(f) is not None


def test_aux_timeout_too_long(cfg, plugin):
    f = cfg("""
line aux 0
 exec-timeout 10 0
 login
""")
    assert plugin.get_aux_exec_timeout(f) is not None


def test_aux_timeout_ok(cfg, plugin):
    f = cfg("""
line aux 0
 exec-timeout 5 0
 login
""")
    assert plugin.get_aux_exec_timeout(f) is None


# --- transport input none ---

def test_aux_transport_not_set(cfg, plugin):
    f = cfg("""
line aux 0
 login
""")
    assert plugin.get_aux_transport_input(f) is not None


def test_aux_transport_ssh(cfg, plugin):
    # Not 'none' → issue
    f = cfg("""
line aux 0
 transport input ssh
 login
""")
    assert plugin.get_aux_transport_input(f) is not None


def test_aux_transport_none(cfg, plugin):
    f = cfg("""
line aux 0
 transport input none
 login
""")
    assert plugin.get_aux_transport_input(f) is None


# --- login ---

def test_aux_login_missing(cfg, plugin):
    f = cfg("""
line aux 0
""")
    assert plugin.get_aux_login(f) is not None


def test_aux_login_present(cfg, plugin):
    f = cfg("""
line aux 0
 login local
""")
    assert plugin.get_aux_login(f) is None


# --- analyze ---

def test_analyze_no_aux(cfg, plugin):
    f = cfg("hostname R1")
    plugin.analyze(f)
    assert len(plugin.get_issues()) == 0


def test_analyze_all_issues(cfg, plugin):
    f = cfg("""
line aux 0
""")
    plugin.analyze(f)
    # no_exec + timeout_not_configured + transport_not_set + login_missing = 4
    assert len(plugin.get_issues()) == 4


def test_analyze_compliant(cfg, plugin):
    f = cfg("""
line aux 0
 no exec
 exec-timeout 5 0
 transport input none
 login local
""")
    plugin.analyze(f)
    assert len(plugin.get_issues()) == 0
