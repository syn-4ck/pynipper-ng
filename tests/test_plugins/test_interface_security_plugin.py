import pytest
import textwrap
from src.analyze.cisco.ios.plugins.interface_security_plugin import PluginInterfaceSecurity


@pytest.fixture
def plugin():
    return PluginInterfaceSecurity()


def test_name(plugin):
    assert plugin.name() == "Interface-Level Security"


# --- ip directed-broadcast ---

def test_directed_broadcast_explicit(cfg, plugin):
    f = cfg("""
interface GigabitEthernet0/0
 ip address 192.168.1.1 255.255.255.0
 ip directed-broadcast
""")
    assert plugin.get_ip_directed_broadcast(f) is not None


def test_directed_broadcast_not_present(cfg, plugin):
    f = cfg("""
interface GigabitEthernet0/0
 ip address 192.168.1.1 255.255.255.0
""")
    assert plugin.get_ip_directed_broadcast(f) is None


# --- ip unreachables ---

def test_ip_unreachables_missing(cfg, plugin):
    f = cfg("""
interface GigabitEthernet0/0
 ip address 192.168.1.1 255.255.255.0
""")
    assert plugin.get_ip_unreachables(f) is not None


def test_ip_unreachables_disabled(cfg, plugin):
    f = cfg("""
interface GigabitEthernet0/0
 ip address 192.168.1.1 255.255.255.0
 no ip unreachables
""")
    assert plugin.get_ip_unreachables(f) is None


# --- ip redirects ---

def test_ip_redirects_missing(cfg, plugin):
    f = cfg("""
interface GigabitEthernet0/0
 ip address 192.168.1.1 255.255.255.0
""")
    assert plugin.get_ip_redirects(f) is not None


def test_ip_redirects_disabled(cfg, plugin):
    f = cfg("""
interface GigabitEthernet0/0
 ip address 192.168.1.1 255.255.255.0
 no ip redirects
""")
    assert plugin.get_ip_redirects(f) is None


# --- ip mask-reply ---

def test_ip_mask_reply_missing(cfg, plugin):
    f = cfg("""
interface GigabitEthernet0/0
 ip address 192.168.1.1 255.255.255.0
""")
    assert plugin.get_ip_mask_reply(f) is not None


def test_ip_mask_reply_disabled(cfg, plugin):
    f = cfg("""
interface GigabitEthernet0/0
 ip address 192.168.1.1 255.255.255.0
 no ip mask-reply
""")
    assert plugin.get_ip_mask_reply(f) is None


# --- anti-spoofing ACL ---

def test_antispoofing_no_external_interfaces(cfg, plugin):
    # No external-marked interfaces → returns True → no issue
    f = cfg("""
interface GigabitEthernet0/0
 ip address 192.168.1.1 255.255.255.0
""")
    assert plugin.get_antispoofing_acl(f) is None


def test_antispoofing_external_no_acl(cfg, plugin):
    f = cfg("""
interface GigabitEthernet0/1
 description external_uplink
 ip address 1.2.3.4 255.255.255.0
""")
    assert plugin.get_antispoofing_acl(f) is not None


def test_antispoofing_external_with_acl(cfg, plugin):
    f = cfg("""
interface GigabitEthernet0/1
 description external_uplink
 ip address 1.2.3.4 255.255.255.0
 ip access-group ANTI_SPOOF in
""")
    assert plugin.get_antispoofing_acl(f) is None


def test_antispoofing_wan_without_acl(cfg, plugin):
    f = cfg("""
interface GigabitEthernet0/2
 description WAN_link
 ip address 5.6.7.8 255.255.255.0
""")
    assert plugin.get_antispoofing_acl(f) is not None


# --- analyze ---

def test_analyze_all_issues(cfg, plugin):
    f = cfg("""
interface GigabitEthernet0/0
 ip address 192.168.1.1 255.255.255.0
 ip directed-broadcast
interface GigabitEthernet0/1
 description external_uplink
 ip address 1.2.3.4 255.255.255.0
""")
    plugin.analyze(f)
    # directed_broadcast + unreachables + redirects + mask_reply + antispoofing = 5
    assert len(plugin.get_issues()) == 5


def test_analyze_compliant(cfg, plugin):
    f = cfg("""
interface GigabitEthernet0/0
 ip address 192.168.1.1 255.255.255.0
 no ip unreachables
 no ip redirects
 no ip mask-reply
interface GigabitEthernet0/1
 description external_uplink
 ip address 1.2.3.4 255.255.255.0
 no ip unreachables
 no ip redirects
 no ip mask-reply
 ip access-group ANTI_SPOOF in
""")
    plugin.analyze(f)
    assert len(plugin.get_issues()) == 0
