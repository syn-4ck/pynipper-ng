"""Tests for banner_plugin.py — CIS 1.5.x"""
import pytest
from src.analyze.cisco.ios.plugins.banner_plugin import PluginBanner


@pytest.fixture
def plugin():
    return PluginBanner()


def test_banner_login_missing(cfg, plugin):
    f = cfg("hostname R1")
    assert plugin.get_banner_login(f) is not None


def test_banner_login_present(cfg, plugin):
    f = cfg("banner login ^Authorized access only^")
    assert plugin.get_banner_login(f) is None


def test_banner_motd_missing(cfg, plugin):
    f = cfg("hostname R1")
    assert plugin.get_banner_motd(f) is not None


def test_banner_motd_present(cfg, plugin):
    f = cfg("banner motd ^Authorized access only^")
    assert plugin.get_banner_motd(f) is None


def test_banner_webauth_missing(cfg, plugin):
    f = cfg("hostname R1")
    assert plugin.get_banner_webauth(f) is not None


def test_banner_webauth_present(cfg, plugin):
    f = cfg("ip admission auth-proxy-banner http C Authorized only C")
    assert plugin.get_banner_webauth(f) is None


def test_analyze_all_issues(cfg, plugin):
    f = cfg("hostname R1")
    plugin.analyze(f)
    assert len(plugin.get_issues()) == 3


def test_analyze_compliant(cfg, plugin):
    f = cfg("""
    banner login ^Authorized^
    banner motd ^Authorized^
    ip admission auth-proxy-banner http C Authorized C
    """)
    plugin.analyze(f)
    assert len(plugin.get_issues()) == 0


def test_plugin_name(plugin):
    assert plugin.name() == "Banners"
