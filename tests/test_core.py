import pytest
import textwrap
from src.analyze.cisco.ios.cisco_parser.parse_config import (
    get_cisco_ios_hostname,
    get_cisco_ios_version,
    get_cisco_ios_passwd_enc,
    get_cisco_ios_passwd_length,
    get_cisco_ios_ip_source_routing,
    get_cisco_ios_bootp,
    get_cisco_ios_tcp_keep_alives_in,
    get_cisco_ios_tcp_keep_alives_out,
)
from src.analyze.cisco.ios.core.process_cisco_ios_conf import process_cisco_ios_conf


# --- get_cisco_ios_hostname ---

def test_hostname_present(cfg):
    f = cfg("hostname MyRouter")
    assert get_cisco_ios_hostname(f) == "MyRouter"


def test_hostname_absent(cfg):
    f = cfg("no service pad")
    assert get_cisco_ios_hostname(f) == "?"


# --- get_cisco_ios_version ---

def test_version_full(cfg):
    # Full version like 15.1(1)T
    f = cfg("version 15.1(1)T")
    assert get_cisco_ios_version(f) == "15.1(1)T"


def test_version_short(cfg):
    # Short version gets (1) appended
    f = cfg("version 15.1")
    assert get_cisco_ios_version(f) == "15.1(1)"


def test_version_absent(cfg):
    f = cfg("hostname R1")
    assert get_cisco_ios_version(f) == "?"


# --- get_cisco_ios_passwd_enc ---

def test_passwd_enc_disabled(cfg):
    f = cfg("no service password-encryption")
    assert get_cisco_ios_passwd_enc(f) is True


def test_passwd_enc_not_disabled(cfg):
    f = cfg("service password-encryption")
    assert get_cisco_ios_passwd_enc(f) is False


# --- get_cisco_ios_passwd_length ---

def test_passwd_length_set(cfg):
    f = cfg("security passwords min-length 10")
    assert get_cisco_ios_passwd_length(f) == "10"


def test_passwd_length_not_set(cfg):
    f = cfg("hostname R1")
    assert get_cisco_ios_passwd_length(f) == "No specified"


# --- get_cisco_ios_ip_source_routing ---

def test_ip_source_routing_disabled(cfg):
    f = cfg("no ip source routing")
    assert get_cisco_ios_ip_source_routing(f) is False


def test_ip_source_routing_enabled(cfg):
    f = cfg("hostname R1")
    assert get_cisco_ios_ip_source_routing(f) is True


# --- get_cisco_ios_bootp ---

def test_bootp_disabled(cfg):
    f = cfg("no ip bootp server")
    assert get_cisco_ios_bootp(f) is False


def test_bootp_enabled(cfg):
    f = cfg("hostname R1")
    assert get_cisco_ios_bootp(f) is True


# --- get_cisco_ios_tcp_keep_alives_in ---

def test_keepalives_in_present(cfg):
    f = cfg("service tcp-keepalives-in")
    assert get_cisco_ios_tcp_keep_alives_in(f) is True


def test_keepalives_in_absent(cfg):
    f = cfg("hostname R1")
    assert get_cisco_ios_tcp_keep_alives_in(f) is False


# --- get_cisco_ios_tcp_keep_alives_out ---

def test_keepalives_out_present(cfg):
    f = cfg("service tcp-keepalives-out")
    assert get_cisco_ios_tcp_keep_alives_out(f) is True


def test_keepalives_out_absent(cfg):
    f = cfg("hostname R1")
    assert get_cisco_ios_tcp_keep_alives_out(f) is False


# --- process_cisco_ios_conf ---

def test_process_cisco_ios_conf(cfg):
    # Uses the real example config
    f = cfg("""
hostname TestRouter
version 15.1
service password-encryption
no service pad
no service udp-small-servers
no service tcp-small-servers
""")
    result = process_cisco_ios_conf(f)
    assert isinstance(result, dict)
    # Should have one key per plugin class in the plugins directory
    assert len(result) > 0
