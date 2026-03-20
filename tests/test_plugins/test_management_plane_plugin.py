import pytest
import textwrap
from src.analyze.cisco.ios.plugins.management_plane_plugin import PluginManagementPlane


@pytest.fixture
def plugin():
    return PluginManagementPlane()


def test_name(plugin):
    assert plugin.name() == "Management Plane Access Control"


# --- management plane protection ---

def test_mpp_missing(cfg, plugin):
    f = cfg("hostname R1")
    assert plugin.get_management_plane_protection(f) is not None


def test_mpp_present(cfg, plugin):
    f = cfg("""
control-plane host
 management-interface GigabitEthernet0/0 allow ssh
""")
    assert plugin.get_management_plane_protection(f) is None


# --- management ACL ---

def test_management_acl_missing(cfg, plugin):
    f = cfg("""
line vty 0 4
 login local
""")
    assert plugin.get_management_acl(f) is not None


def test_management_acl_present(cfg, plugin):
    f = cfg("""
line vty 0 4
 access-class 10 in
 login local
""")
    assert plugin.get_management_acl(f) is None


# --- HTTPS TLS version ---

def test_https_tls_no_https(cfg, plugin):
    # HTTPS not configured → no issue
    f = cfg("hostname R1")
    assert plugin.get_https_tls_version(f) is None


def test_https_tls10(cfg, plugin):
    f = cfg("""
ip http secure-server
ip http tls-version TLSv1
""")
    assert plugin.get_https_tls_version(f) is not None


def test_https_tls11(cfg, plugin):
    f = cfg("""
ip http secure-server
ip http tls-version TLSv1.1
""")
    assert plugin.get_https_tls_version(f) is not None


def test_https_tls12(cfg, plugin):
    # TLS 1.2 explicitly → no issue
    f = cfg("""
ip http secure-server
ip http tls-version TLSv1.2
""")
    assert plugin.get_https_tls_version(f) is None


def test_https_no_tls_directive(cfg, plugin):
    # HTTPS enabled without explicit TLS directive → no issue (defaults to modern)
    f = cfg("ip http secure-server")
    assert plugin.get_https_tls_version(f) is None


# --- direct privilege 15 ---

def test_priv15_user_present(cfg, plugin):
    f = cfg("username admin privilege 15 secret 5 $1$abc$hash")
    assert plugin.get_no_direct_privilege_15(f) is not None


def test_priv15_no_priv15(cfg, plugin):
    f = cfg("username admin privilege 1 secret 5 $1$abc$hash")
    assert plugin.get_no_direct_privilege_15(f) is None


def test_priv15_no_users(cfg, plugin):
    f = cfg("hostname R1")
    assert plugin.get_no_direct_privilege_15(f) is None


# --- control plane policing ---

def test_copp_missing(cfg, plugin):
    f = cfg("hostname R1")
    assert plugin.get_control_plane_policing(f) is not None


def test_copp_no_service_policy(cfg, plugin):
    f = cfg("""
control-plane
""")
    assert plugin.get_control_plane_policing(f) is not None


def test_copp_present(cfg, plugin):
    f = cfg("""
control-plane
 service-policy input COPP_POLICY
""")
    assert plugin.get_control_plane_policing(f) is None


# --- analyze ---

def test_analyze_all_issues(cfg, plugin):
    f = cfg("""
line vty 0 4
 login local
""")
    plugin.analyze(f)
    # mpp_missing + management_acl_missing + https_not_checked(None) + no_priv15(None) + copp_missing = 3
    assert len(plugin.get_issues()) == 3


def test_analyze_compliant(cfg, plugin):
    f = cfg("""
control-plane host
 management-interface GigabitEthernet0/0 allow ssh
control-plane
 service-policy input COPP_POLICY
line vty 0 4
 access-class 10 in
 login local
""")
    plugin.analyze(f)
    assert len(plugin.get_issues()) == 0
