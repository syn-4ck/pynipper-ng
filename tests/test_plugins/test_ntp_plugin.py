import pytest
import textwrap
from src.analyze.cisco.ios.plugins.ntp_plugin import PluginNTP


@pytest.fixture
def plugin():
    return PluginNTP()


def test_name(plugin):
    assert plugin.name() == "Network Time Protocol (NTP)"


# --- ntp server ---

def test_ntp_server_missing(cfg, plugin):
    f = cfg("hostname R1")
    assert plugin.get_ntp_server(f) is not None


def test_ntp_server_present(cfg, plugin):
    f = cfg("ntp server 1.1.1.1")
    assert plugin.get_ntp_server(f) is None


# --- ntp authentication ---

def test_ntp_auth_no_ntp_server(cfg, plugin):
    # Guard: no NTP configured → None
    f = cfg("hostname R1")
    assert plugin.get_ntp_authentication(f) is None


def test_ntp_auth_server_no_auth(cfg, plugin):
    f = cfg("ntp server 1.1.1.1")
    assert plugin.get_ntp_authentication(f) is not None


def test_ntp_auth_partial_auth(cfg, plugin):
    # Has ntp server + authenticate but no trusted-key
    f = cfg("""
ntp server 1.1.1.1
ntp authenticate
ntp authentication-key 1 md5 mysecret
""")
    assert plugin.get_ntp_authentication(f) is not None


def test_ntp_auth_full(cfg, plugin):
    f = cfg("""
ntp server 1.1.1.1
ntp authenticate
ntp authentication-key 1 md5 mysecret
ntp trusted-key 1
""")
    assert plugin.get_ntp_authentication(f) is None


# --- ntp access-group ---

def test_ntp_acg_no_ntp_server(cfg, plugin):
    f = cfg("hostname R1")
    assert plugin.get_ntp_access_group(f) is None


def test_ntp_acg_server_no_acg(cfg, plugin):
    f = cfg("ntp server 1.1.1.1")
    assert plugin.get_ntp_access_group(f) is not None


def test_ntp_acg_present(cfg, plugin):
    f = cfg("""
ntp server 1.1.1.1
ntp access-group peer 10
""")
    assert plugin.get_ntp_access_group(f) is None


# --- analyze ---

def test_analyze_no_ntp(cfg, plugin):
    f = cfg("hostname R1")
    plugin.analyze(f)
    # Only ntp_server check fires (auth and acg are guarded)
    assert len(plugin.get_issues()) == 1


def test_analyze_ntp_server_only(cfg, plugin):
    f = cfg("ntp server 1.1.1.1")
    plugin.analyze(f)
    # server OK, but auth and acg missing → 2 issues
    assert len(plugin.get_issues()) == 2


def test_analyze_compliant(cfg, plugin):
    f = cfg("""
ntp server 1.1.1.1
ntp authenticate
ntp authentication-key 1 md5 mysecret
ntp trusted-key 1
ntp access-group peer 10
""")
    plugin.analyze(f)
    assert len(plugin.get_issues()) == 0
