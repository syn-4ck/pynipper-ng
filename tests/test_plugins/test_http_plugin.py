"""Tests for http_plugin.py — CIS 2.5.x"""
import pytest
from src.analyze.cisco.ios.plugins.http_plugin import PluginHTTP


@pytest.fixture
def plugin():
    return PluginHTTP()


def test_http_service_explicitly_enabled(cfg, plugin):
    f = cfg("ip http server")
    assert plugin.get_http_service(f) is not None


def test_http_service_explicitly_disabled(cfg, plugin):
    f = cfg("no ip http server")
    assert plugin.get_http_service(f) is None


def test_http_service_not_configured(cfg, plugin):
    """Neither 'ip http server' nor 'no ip http server' — no issue."""
    f = cfg("hostname R1")
    assert plugin.get_http_service(f) is None


def test_http_service_enabled_then_disabled(cfg, plugin):
    """'ip http server' AND 'no ip http server' → disabled wins."""
    f = cfg("""
    ip http server
    no ip http server
    """)
    assert plugin.get_http_service(f) is None


def test_http_access_class_missing_when_http_on(cfg, plugin):
    f = cfg("ip http server")
    assert plugin.get_http_access_class(f) is not None


def test_http_access_class_present(cfg, plugin):
    f = cfg("""
    ip http server
    ip http access-class 10
    """)
    assert plugin.get_http_access_class(f) is None


def test_http_access_class_not_flagged_when_http_off(cfg, plugin):
    f = cfg("no ip http server")
    assert plugin.get_http_access_class(f) is None


def test_http_authentication_missing_when_http_on(cfg, plugin):
    f = cfg("ip http server")
    assert plugin.get_http_authentication(f) is not None


def test_http_authentication_present(cfg, plugin):
    f = cfg("""
    ip http server
    ip http authentication local
    """)
    assert plugin.get_http_authentication(f) is None


def test_http_authentication_not_flagged_when_http_off(cfg, plugin):
    f = cfg("no ip http server")
    assert plugin.get_http_authentication(f) is None


def test_analyze_no_http(cfg, plugin):
    """HTTP server not configured — no issues."""
    f = cfg("hostname R1")
    plugin.analyze(f)
    assert len(plugin.get_issues()) == 0


def test_analyze_http_on_all_issues(cfg, plugin):
    f = cfg("ip http server")
    plugin.analyze(f)
    # http_server + access_class + authentication = 3 issues
    assert len(plugin.get_issues()) == 3


def test_analyze_compliant(cfg, plugin):
    f = cfg("""
    no ip http server
    ip http secure-server
    ip http authentication local
    ip http access-class 10
    """)
    plugin.analyze(f)
    assert len(plugin.get_issues()) == 0


def test_plugin_name(plugin):
    assert "HTTP" in plugin.name()
