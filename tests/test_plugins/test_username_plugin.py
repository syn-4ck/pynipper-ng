import pytest
import textwrap
from src.analyze.cisco.ios.plugins.username_plugin import PluginUsername


@pytest.fixture
def plugin():
    return PluginUsername()


def test_name(plugin):
    assert plugin.name() == "Username credentials"


# --- service password-encryption ---

def test_service_pw_enc_missing(cfg, plugin):
    f = cfg("hostname R1")
    assert plugin.get_service_password_encryption(f) is not None


def test_service_pw_enc_disabled(cfg, plugin):
    f = cfg("no service password-encryption")
    assert plugin.get_service_password_encryption(f) is not None


def test_service_pw_enc_present(cfg, plugin):
    f = cfg("service password-encryption")
    assert plugin.get_service_password_encryption(f) is None


def test_service_pw_enc_aes(cfg, plugin):
    f = cfg("password encryption aes")
    assert plugin.get_service_password_encryption(f) is None


# --- type-0 passwords ---

def test_type0_password_present(cfg, plugin):
    f = cfg("username admin password 0 cleartext")
    assert plugin.get_type0_passwords(f) is not None


def test_type0_password_absent(cfg, plugin):
    f = cfg("username admin secret 5 $1$abc$hash")
    assert plugin.get_type0_passwords(f) is None


# --- type-7 passwords ---

def test_type7_password_present(cfg, plugin):
    f = cfg("username admin password 7 0822455D0A16")
    assert plugin.get_type7_passwords(f) is not None


def test_type7_password_absent(cfg, plugin):
    f = cfg("username admin secret 8 $8$abc$hash")
    assert plugin.get_type7_passwords(f) is None


# --- type-5 passwords ---

def test_type5_password_present(cfg, plugin):
    f = cfg("username admin password 5 $1$abc$hash")
    assert plugin.get_type5_passwords(f) is not None


def test_type5_secret_present(cfg, plugin):
    f = cfg("username admin secret 5 $1$abc$hash")
    assert plugin.get_type5_passwords(f) is not None


def test_type5_password_absent(cfg, plugin):
    f = cfg("username admin secret 9 $9$abc$hash")
    assert plugin.get_type5_passwords(f) is None


# --- analyze ---

def test_analyze_all_issues(cfg, plugin):
    f = cfg("""
hostname R1
username admin password 0 cleartext
username guest password 7 0822455D0A16
username op password 5 $1$abc$hash
""")
    plugin.analyze(f)
    # no encryption + type0 + type7 + type5 = 4 issues
    assert len(plugin.get_issues()) == 4


def test_analyze_compliant(cfg, plugin):
    f = cfg("""
service password-encryption
username admin secret 9 $9$abc$scrypthash
""")
    plugin.analyze(f)
    assert len(plugin.get_issues()) == 0
