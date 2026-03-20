import pytest
import textwrap
from src.analyze.cisco.ios.plugins.password_policy_plugin import PluginPasswordPolicy


@pytest.fixture
def plugin():
    return PluginPasswordPolicy()


def test_name(plugin):
    assert plugin.name() == "Password Policy and Enable Secret"


# --- enable secret ---

def test_enable_secret_missing(cfg, plugin):
    f = cfg("hostname R1")
    assert plugin.get_enable_secret(f) is not None


def test_enable_secret_present(cfg, plugin):
    f = cfg("enable secret 5 $1$abc$hash")
    assert plugin.get_enable_secret(f) is None


# --- enable password plain ---

def test_enable_pw_with_secret(cfg, plugin):
    # Both present → issue
    f = cfg("""
enable secret 5 $1$abc$hash
enable password 7 0822455D0A16
""")
    assert plugin.get_enable_password_plain(f) is not None


def test_enable_pw_without_secret(cfg, plugin):
    # Only enable password, no secret → issue
    f = cfg("enable password cisco")
    assert plugin.get_enable_password_plain(f) is not None


def test_enable_secret_only(cfg, plugin):
    # Only enable secret → no issue
    f = cfg("enable secret 5 $1$abc$hash")
    assert plugin.get_enable_password_plain(f) is None


def test_neither_enable_pw_nor_secret(cfg, plugin):
    # Neither → no issue from this check
    f = cfg("hostname R1")
    assert plugin.get_enable_password_plain(f) is None


# --- security passwords min-length ---

def test_min_length_not_set(cfg, plugin):
    f = cfg("hostname R1")
    assert plugin.get_security_password_min_length(f) is not None


def test_min_length_too_short(cfg, plugin):
    f = cfg("security passwords min-length 6")
    assert plugin.get_security_password_min_length(f) is not None


def test_min_length_ok(cfg, plugin):
    f = cfg("security passwords min-length 10")
    assert plugin.get_security_password_min_length(f) is None


def test_min_length_exactly_8(cfg, plugin):
    f = cfg("security passwords min-length 8")
    assert plugin.get_security_password_min_length(f) is None


# --- login delay ---

def test_login_delay_missing(cfg, plugin):
    f = cfg("hostname R1")
    assert plugin.get_login_delay(f) is not None


def test_login_delay_present(cfg, plugin):
    f = cfg("login delay 4")
    assert plugin.get_login_delay(f) is None


# --- login block-for ---

def test_login_block_for_missing(cfg, plugin):
    f = cfg("hostname R1")
    assert plugin.get_login_block_for(f) is not None


def test_login_block_for_present(cfg, plugin):
    f = cfg("login block-for 120 attempts 3 within 60")
    assert plugin.get_login_block_for(f) is None


# --- login on-failure log ---

def test_login_on_failure_missing(cfg, plugin):
    f = cfg("hostname R1")
    assert plugin.get_login_on_failure_log(f) is not None


def test_login_on_failure_present(cfg, plugin):
    f = cfg("login on-failure log")
    assert plugin.get_login_on_failure_log(f) is None


# --- login on-success log ---

def test_login_on_success_missing(cfg, plugin):
    f = cfg("hostname R1")
    assert plugin.get_login_on_success_log(f) is not None


def test_login_on_success_present(cfg, plugin):
    f = cfg("login on-success log")
    assert plugin.get_login_on_success_log(f) is None


# --- analyze ---

def test_analyze_all_issues(cfg, plugin):
    f = cfg("hostname R1")
    plugin.analyze(f)
    # enable_secret + enable_pw_plain(None on no pw) + min_length + delay + block + fail_log + success_log
    # enable_pw_plain returns None when neither password nor secret is configured
    assert len(plugin.get_issues()) == 6


def test_analyze_compliant(cfg, plugin):
    f = cfg("""
enable secret 5 $1$abc$hash
security passwords min-length 10
login delay 4
login block-for 120 attempts 3 within 60
login on-failure log
login on-success log
""")
    plugin.analyze(f)
    assert len(plugin.get_issues()) == 0
