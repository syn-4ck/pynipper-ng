import pytest
import textwrap
from src.analyze.cisco.ios.plugins.service_plugin import PluginService


@pytest.fixture
def plugin():
    return PluginService()


def test_name(plugin):
    assert plugin.name() == "Global Services Security"


# --- service pad ---

def test_service_pad_missing(cfg, plugin):
    f = cfg("hostname R1")
    assert plugin.get_service_pad(f) is not None


def test_service_pad_disabled(cfg, plugin):
    f = cfg("no service pad")
    assert plugin.get_service_pad(f) is None


# --- udp small servers ---

def test_udp_small_servers_missing(cfg, plugin):
    f = cfg("hostname R1")
    assert plugin.get_udp_small_servers(f) is not None


def test_udp_small_servers_disabled(cfg, plugin):
    f = cfg("no service udp-small-servers")
    assert plugin.get_udp_small_servers(f) is None


# --- tcp small servers ---

def test_tcp_small_servers_missing(cfg, plugin):
    f = cfg("hostname R1")
    assert plugin.get_tcp_small_servers(f) is not None


def test_tcp_small_servers_disabled(cfg, plugin):
    f = cfg("no service tcp-small-servers")
    assert plugin.get_tcp_small_servers(f) is None


# --- bootp server ---

def test_bootp_server_missing(cfg, plugin):
    f = cfg("hostname R1")
    assert plugin.get_bootp_server(f) is not None


def test_bootp_server_disabled(cfg, plugin):
    f = cfg("no ip bootp server")
    assert plugin.get_bootp_server(f) is None


# --- ip finger ---

def test_ip_finger_missing(cfg, plugin):
    f = cfg("hostname R1")
    assert plugin.get_ip_finger(f) is not None


def test_ip_finger_disabled(cfg, plugin):
    f = cfg("no ip finger")
    assert plugin.get_ip_finger(f) is None


def test_service_finger_disabled(cfg, plugin):
    f = cfg("no service finger")
    assert plugin.get_ip_finger(f) is None


# --- identd ---

def test_ip_identd_missing(cfg, plugin):
    f = cfg("hostname R1")
    assert plugin.get_ip_identd(f) is not None


def test_ip_identd_disabled(cfg, plugin):
    f = cfg("no ip identd")
    assert plugin.get_ip_identd(f) is None


# --- service config ---

def test_service_config_missing(cfg, plugin):
    f = cfg("hostname R1")
    assert plugin.get_service_config(f) is not None


def test_service_config_disabled(cfg, plugin):
    f = cfg("no service config")
    assert plugin.get_service_config(f) is None


# --- tcp keepalives ---

def test_tcp_keepalives_missing(cfg, plugin):
    f = cfg("hostname R1")
    assert plugin.get_tcp_keepalives(f) is not None


def test_tcp_keepalives_only_in(cfg, plugin):
    f = cfg("service tcp-keepalives-in")
    assert plugin.get_tcp_keepalives(f) is not None


def test_tcp_keepalives_present(cfg, plugin):
    f = cfg("""
service tcp-keepalives-in
service tcp-keepalives-out
""")
    assert plugin.get_tcp_keepalives(f) is None


# --- tcp synwait-time ---

def test_synwait_not_configured(cfg, plugin):
    f = cfg("hostname R1")
    assert plugin.get_tcp_synwait_time(f) is not None


def test_synwait_too_long(cfg, plugin):
    f = cfg("ip tcp synwait-time 30")
    assert plugin.get_tcp_synwait_time(f) is not None


def test_synwait_ok(cfg, plugin):
    f = cfg("ip tcp synwait-time 10")
    assert plugin.get_tcp_synwait_time(f) is None


def test_synwait_below_max(cfg, plugin):
    f = cfg("ip tcp synwait-time 5")
    assert plugin.get_tcp_synwait_time(f) is None


# --- mop disabled ---

def test_mop_ethernet_no_mop(cfg, plugin):
    f = cfg("""
interface GigabitEthernet0/0
 ip address 192.168.1.1 255.255.255.0
""")
    assert plugin.get_mop_disabled(f) is not None


def test_mop_ethernet_disabled(cfg, plugin):
    f = cfg("""
interface GigabitEthernet0/0
 ip address 192.168.1.1 255.255.255.0
 no mop enabled
""")
    assert plugin.get_mop_disabled(f) is None


def test_mop_no_ethernet_interfaces(cfg, plugin):
    f = cfg("""
interface Loopback0
 ip address 1.1.1.1 255.255.255.255
""")
    assert plugin.get_mop_disabled(f) is None


# --- gratuitous ARPs ---

def test_gratuitous_arps_missing(cfg, plugin):
    f = cfg("hostname R1")
    assert plugin.get_gratuitous_arps(f) is not None


def test_gratuitous_arps_disabled(cfg, plugin):
    f = cfg("no ip gratuitous-arps")
    assert plugin.get_gratuitous_arps(f) is None


# --- analyze ---

def test_analyze_all_issues(cfg, plugin):
    f = cfg("hostname R1")
    plugin.analyze(f)
    # All checks on a bare config: pad, udp, tcp, bootp, finger, identd, config,
    # keepalives, synwait, gratuitous_arps = 10 issues
    # (mop returns None because there are no Ethernet interfaces to check)
    assert len(plugin.get_issues()) == 10


def test_analyze_compliant(cfg, plugin):
    f = cfg("""
no service pad
no service udp-small-servers
no service tcp-small-servers
no ip bootp server
no ip finger
no ip identd
no service config
service tcp-keepalives-in
service tcp-keepalives-out
ip tcp synwait-time 10
no ip gratuitous-arps
interface GigabitEthernet0/0
 ip address 192.168.1.1 255.255.255.0
 no mop enabled
""")
    plugin.analyze(f)
    assert len(plugin.get_issues()) == 0
