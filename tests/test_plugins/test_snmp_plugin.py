import pytest
import textwrap
from src.analyze.cisco.ios.plugins.snmp_plugin import PluginSNMP


@pytest.fixture
def plugin():
    return PluginSNMP()


def test_name(plugin):
    assert plugin.name() == "Simple Network Management Protocol (SNMP)"


# --- snmp community strings ---

def test_snmp_community_present(cfg, plugin):
    f = cfg("snmp-server community mystring ro")
    assert plugin.get_snmp_community_strings(f) is not None


def test_snmp_no_community(cfg, plugin):
    f = cfg("hostname R1")
    assert plugin.get_snmp_community_strings(f) is None


# --- default community strings ---

def test_snmp_default_public(cfg, plugin):
    f = cfg("snmp-server community public ro")
    assert plugin.get_snmp_default_community(f) is not None


def test_snmp_default_private(cfg, plugin):
    f = cfg("snmp-server community private rw")
    assert plugin.get_snmp_default_community(f) is not None


def test_snmp_custom_community(cfg, plugin):
    f = cfg("snmp-server community s3cr3t ro")
    assert plugin.get_snmp_default_community(f) is None


# --- snmpv3 ---

def test_snmp_v3_not_configured(cfg, plugin):
    f = cfg("snmp-server community s3cr3t ro")
    assert plugin.get_snmp_v3(f) is not None


def test_snmp_v3_configured(cfg, plugin):
    f = cfg("""
snmp-server group MYGROUP v3 priv
snmp-server user admin MYGROUP v3 auth sha authpass priv aes 128 privpass
""")
    assert plugin.get_snmp_v3(f) is None


def test_snmp_v3_no_snmp(cfg, plugin):
    # No SNMP at all → guard returns None
    f = cfg("hostname R1")
    assert plugin.get_snmp_v3(f) is None


# --- snmp ACL ---

def test_snmp_acl_missing(cfg, plugin):
    f = cfg("snmp-server community s3cr3t ro")
    assert plugin.get_snmp_acl(f) is not None


def test_snmp_acl_community_with_acl(cfg, plugin):
    f = cfg("snmp-server community s3cr3t ro 10")
    assert plugin.get_snmp_acl(f) is None


def test_snmp_acl_group_with_access(cfg, plugin):
    f = cfg("snmp-server group MYGROUP v3 priv access 10")
    assert plugin.get_snmp_acl(f) is None


def test_snmp_acl_no_snmp(cfg, plugin):
    f = cfg("hostname R1")
    assert plugin.get_snmp_acl(f) is None


# --- snmp traps ---

def test_snmp_traps_missing(cfg, plugin):
    f = cfg("hostname R1")
    assert plugin.get_snmp_traps(f) is not None


def test_snmp_traps_no_host(cfg, plugin):
    f = cfg("snmp-server enable traps")
    assert plugin.get_snmp_traps(f) is not None


def test_snmp_traps_complete(cfg, plugin):
    f = cfg("""
snmp-server host 10.0.0.1 version 3 priv admin
snmp-server enable traps
""")
    assert plugin.get_snmp_traps(f) is None


# --- analyze ---

def test_analyze_all_issues(cfg, plugin):
    f = cfg("snmp-server community public ro")
    plugin.analyze(f)
    # community_strings + default_community + v3 missing + acl missing + traps missing = 5
    assert len(plugin.get_issues()) == 5


def test_analyze_compliant(cfg, plugin):
    f = cfg("""
snmp-server group MYGROUP v3 priv access 10
snmp-server user admin MYGROUP v3 auth sha authpass priv aes 128 privpass
snmp-server host 10.0.0.1 version 3 priv admin
snmp-server enable traps
""")
    plugin.analyze(f)
    assert len(plugin.get_issues()) == 0
