import pytest
import textwrap
from src.analyze.cisco.ios.plugins.routing_protocols_plugin import PluginRoutingProtocols


@pytest.fixture
def plugin():
    return PluginRoutingProtocols()


def test_name(plugin):
    assert plugin.name() == "Routing Protocol Authentication"


# --- OSPF ---

def test_ospf_not_configured(cfg, plugin):
    # No OSPF → no issue
    f = cfg("hostname R1")
    assert plugin.get_ospf_authentication(f) is None


def test_ospf_no_auth(cfg, plugin):
    f = cfg("""
router ospf 1
 network 10.0.0.0 0.255.255.255 area 0
""")
    assert plugin.get_ospf_authentication(f) is not None


def test_ospf_area_auth(cfg, plugin):
    f = cfg("""
router ospf 1
 network 10.0.0.0 0.255.255.255 area 0
 area 0 authentication message-digest
""")
    assert plugin.get_ospf_authentication(f) is None


def test_ospf_interface_auth(cfg, plugin):
    f = cfg("""
router ospf 1
 network 10.0.0.0 0.255.255.255 area 0
interface GigabitEthernet0/0
 ip ospf message-digest-key 1 md5 mykey
""")
    assert plugin.get_ospf_authentication(f) is None


# --- EIGRP ---

def test_eigrp_not_configured(cfg, plugin):
    f = cfg("hostname R1")
    assert plugin.get_eigrp_authentication(f) is None


def test_eigrp_no_auth(cfg, plugin):
    f = cfg("""
router eigrp 100
 network 10.0.0.0
""")
    assert plugin.get_eigrp_authentication(f) is not None


def test_eigrp_with_auth(cfg, plugin):
    f = cfg("""
router eigrp 100
 network 10.0.0.0
interface GigabitEthernet0/0
 ip authentication mode eigrp 100 md5
 ip authentication key-chain eigrp 100 MYCHAIN
""")
    assert plugin.get_eigrp_authentication(f) is None


# --- BGP ---

def test_bgp_not_configured(cfg, plugin):
    f = cfg("hostname R1")
    assert plugin.get_bgp_authentication(f) is None


def test_bgp_no_auth(cfg, plugin):
    f = cfg("""
router bgp 65001
 neighbor 1.2.3.4 remote-as 65002
""")
    assert plugin.get_bgp_authentication(f) is not None


def test_bgp_with_password(cfg, plugin):
    f = cfg("""
router bgp 65001
 neighbor 1.2.3.4 remote-as 65002
 neighbor 1.2.3.4 password mypassword
""")
    assert plugin.get_bgp_authentication(f) is None


# --- RIP ---

def test_rip_not_configured(cfg, plugin):
    f = cfg("hostname R1")
    assert plugin.get_rip_version_and_auth(f) is None


def test_rip_version1(cfg, plugin):
    f = cfg("""
router rip
 network 10.0.0.0
""")
    assert plugin.get_rip_version_and_auth(f) is not None


def test_ripv2_no_auth(cfg, plugin):
    f = cfg("""
router rip
 version 2
 network 10.0.0.0
""")
    assert plugin.get_rip_version_and_auth(f) is not None


def test_ripv2_with_auth(cfg, plugin):
    f = cfg("""
router rip
 version 2
 network 10.0.0.0
interface GigabitEthernet0/0
 ip rip authentication mode md5
 ip rip authentication key-chain MYCHAIN
""")
    assert plugin.get_rip_version_and_auth(f) is None


# --- analyze ---

def test_analyze_no_protocols(cfg, plugin):
    f = cfg("hostname R1")
    plugin.analyze(f)
    assert len(plugin.get_issues()) == 0


def test_analyze_all_issues(cfg, plugin):
    f = cfg("""
router ospf 1
 network 10.0.0.0 0.255.255.255 area 0
router eigrp 100
 network 10.0.0.0
router bgp 65001
 neighbor 1.2.3.4 remote-as 65002
router rip
 network 10.0.0.0
""")
    plugin.analyze(f)
    # ospf + eigrp + bgp + rip(v1) = 4 issues
    assert len(plugin.get_issues()) == 4


def test_analyze_compliant(cfg, plugin):
    f = cfg("""
router ospf 1
 network 10.0.0.0 0.255.255.255 area 0
 area 0 authentication message-digest
router eigrp 100
 network 10.0.0.0
router bgp 65001
 neighbor 1.2.3.4 remote-as 65002
 neighbor 1.2.3.4 password s3cr3t
router rip
 version 2
 network 10.0.0.0
interface GigabitEthernet0/0
 ip authentication mode eigrp 100 md5
 ip authentication key-chain eigrp 100 MYCHAIN
 ip rip authentication mode md5
 ip rip authentication key-chain MYCHAIN
""")
    plugin.analyze(f)
    assert len(plugin.get_issues()) == 0
