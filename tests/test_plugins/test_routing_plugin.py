import pytest
import textwrap
from src.analyze.cisco.ios.plugins.routing_plugin import PluginRouting


@pytest.fixture
def plugin():
    return PluginRouting()


def test_name(plugin):
    assert plugin.name() == "Routing Security"


# --- ip source-route ---

def test_ip_source_route_missing(cfg, plugin):
    f = cfg("hostname R1")
    assert plugin.get_ip_source_route(f) is not None


def test_ip_source_route_disabled(cfg, plugin):
    f = cfg("no ip source-route")
    assert plugin.get_ip_source_route(f) is None


# --- proxy ARP ---

def test_proxy_arp_not_disabled(cfg, plugin):
    f = cfg("""
interface GigabitEthernet0/0
 ip address 192.168.1.1 255.255.255.0
""")
    assert plugin.get_ip_proxy_arp(f) is not None


def test_proxy_arp_disabled(cfg, plugin):
    f = cfg("""
interface GigabitEthernet0/0
 ip address 192.168.1.1 255.255.255.0
 no ip proxy-arp
""")
    assert plugin.get_ip_proxy_arp(f) is None


# --- tunnel interface ---

def test_tunnel_interface_present(cfg, plugin):
    f = cfg("""
interface Tunnel0
 ip address 10.0.0.1 255.255.255.252
""")
    assert plugin.get_tunnel_interface(f) is not None


def test_tunnel_interface_absent(cfg, plugin):
    f = cfg("""
interface GigabitEthernet0/0
 ip address 192.168.1.1 255.255.255.0
""")
    assert plugin.get_tunnel_interface(f) is None


# --- uRPF ---

def test_urpf_not_configured(cfg, plugin):
    f = cfg("""
interface GigabitEthernet0/0
 ip address 192.168.1.1 255.255.255.0
""")
    assert plugin.get_urpf(f) is not None


def test_urpf_configured(cfg, plugin):
    f = cfg("""
interface GigabitEthernet0/0
 ip address 192.168.1.1 255.255.255.0
 ip verify unicast source reachable-via rx
""")
    assert plugin.get_urpf(f) is None


# --- analyze ---

def test_analyze_all_issues(cfg, plugin):
    f = cfg("""
hostname R1
interface GigabitEthernet0/0
 ip address 192.168.1.1 255.255.255.0
""")
    plugin.analyze(f)
    # source-route + proxy-arp + no tunnel (no issue) + no urpf = 3 issues
    assert len(plugin.get_issues()) == 3


def test_analyze_compliant(cfg, plugin):
    f = cfg("""
no ip source-route
interface GigabitEthernet0/0
 ip address 192.168.1.1 255.255.255.0
 no ip proxy-arp
 ip verify unicast source reachable-via rx
""")
    plugin.analyze(f)
    assert len(plugin.get_issues()) == 0
