"""Tests for ssh_plugin.py — CIS 2.2.x"""
import pytest
from src.analyze.cisco.ios.plugins.ssh_plugin import PluginSSH


@pytest.fixture
def plugin():
    return PluginSSH()


# CIS 2.2.2
def test_ssh_version_not_set(cfg, plugin):
    f = cfg("hostname R1")
    assert plugin.get_ssh_version(f) is not None


def test_ssh_version_1(cfg, plugin):
    f = cfg("ip ssh version 1")
    assert plugin.get_ssh_version(f) is not None


def test_ssh_version_2(cfg, plugin):
    f = cfg("ip ssh version 2")
    assert plugin.get_ssh_version(f) is None


# CIS 2.2.3
def test_ssh_retries_not_configured(cfg, plugin):
    f = cfg("hostname R1")
    assert plugin.get_ssh_retries(f) is not None


def test_ssh_retries_too_high(cfg, plugin):
    f = cfg("ip ssh authentication-retries 5")
    assert plugin.get_ssh_retries(f) is not None


def test_ssh_retries_ok(cfg, plugin):
    f = cfg("ip ssh authentication-retries 3")
    assert plugin.get_ssh_retries(f) is None


# CIS 2.2.4
def test_ssh_timeout_not_configured(cfg, plugin):
    f = cfg("hostname R1")
    assert plugin.get_ssh_timeout(f) is not None


def test_ssh_timeout_too_high(cfg, plugin):
    f = cfg("ip ssh time-out 120")
    assert plugin.get_ssh_timeout(f) is not None


def test_ssh_timeout_ok(cfg, plugin):
    f = cfg("ip ssh time-out 60")
    assert plugin.get_ssh_timeout(f) is None


# CIS 2.2.5
def test_ssh_source_interface_missing(cfg, plugin):
    f = cfg("hostname R1")
    assert plugin.get_ssh_source_interface(f) is not None


def test_ssh_source_interface_present(cfg, plugin):
    f = cfg("ip ssh source-interface Loopback0")
    assert plugin.get_ssh_source_interface(f) is None


# CIS 2.2.6 - RSA key size
def test_rsa_key_size_not_in_config(cfg, plugin):
    """Key not in config — returns None (cannot determine)."""
    f = cfg("hostname R1")
    assert plugin.get_rsa_key_size(f) is None


def test_rsa_key_size_too_small(cfg, plugin):
    f = cfg("crypto key generate rsa modulus 1024")
    assert plugin.get_rsa_key_size(f) is not None


def test_rsa_key_size_ok(cfg, plugin):
    f = cfg("crypto key generate rsa modulus 2048")
    assert plugin.get_rsa_key_size(f) is None


def test_rsa_key_size_4096(cfg, plugin):
    f = cfg("crypto key generate rsa modulus 4096")
    assert plugin.get_rsa_key_size(f) is None


# analyze()
def test_analyze_all_issues(cfg, plugin):
    f = cfg("hostname R1")
    plugin.analyze(f)
    # version, retries, timeout, source-interface = 4 issues (rsa returns None)
    assert len(plugin.get_issues()) == 4


def test_analyze_compliant(cfg, plugin):
    f = cfg("""
    ip ssh version 2
    ip ssh authentication-retries 3
    ip ssh time-out 60
    ip ssh source-interface Loopback0
    crypto key generate rsa modulus 4096
    """)
    plugin.analyze(f)
    assert len(plugin.get_issues()) == 0


def test_plugin_name(plugin):
    assert "SSH" in plugin.name()
