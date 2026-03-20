import pytest
import textwrap
from src.analyze.cisco.ios.plugins.logging_plugin import PluginLogging


@pytest.fixture
def plugin():
    return PluginLogging()


def test_name(plugin):
    assert plugin.name() == "Logging and Auditing"


# --- logging on ---

def test_logging_on_disabled(cfg, plugin):
    f = cfg("no logging on")
    assert plugin.get_logging_on(f) is not None


def test_logging_on_default(cfg, plugin):
    f = cfg("hostname R1")
    assert plugin.get_logging_on(f) is None


# --- logging buffered ---

def test_logging_buffered_missing(cfg, plugin):
    f = cfg("hostname R1")
    assert plugin.get_logging_buffered(f) is not None


def test_logging_buffered_too_restrictive(cfg, plugin):
    # 'errors' is severity 3, below informational(6) — too restrictive
    f = cfg("logging buffered errors")
    assert plugin.get_logging_buffered(f) is not None


def test_logging_buffered_informational(cfg, plugin):
    f = cfg("logging buffered informational")
    assert plugin.get_logging_buffered(f) is None


def test_logging_buffered_with_size(cfg, plugin):
    f = cfg("logging buffered 16384 informational")
    assert plugin.get_logging_buffered(f) is None


def test_logging_buffered_debugging(cfg, plugin):
    # 'debugging' is severity 7 >= informational(6) — OK
    f = cfg("logging buffered debugging")
    assert plugin.get_logging_buffered(f) is None


# --- logging host ---

def test_logging_host_missing(cfg, plugin):
    f = cfg("hostname R1")
    assert plugin.get_logging_host(f) is not None


def test_logging_host_present(cfg, plugin):
    f = cfg("logging host 10.0.0.1")
    assert plugin.get_logging_host(f) is None


def test_logging_ip_present(cfg, plugin):
    f = cfg("logging 10.0.0.1")
    assert plugin.get_logging_host(f) is None


# --- logging source-interface ---

def test_logging_source_interface_missing(cfg, plugin):
    f = cfg("hostname R1")
    assert plugin.get_logging_source_interface(f) is not None


def test_logging_source_interface_present(cfg, plugin):
    f = cfg("logging source-interface Loopback0")
    assert plugin.get_logging_source_interface(f) is None


# --- service timestamps log ---

def test_logging_timestamps_missing(cfg, plugin):
    f = cfg("hostname R1")
    assert plugin.get_logging_timestamps(f) is not None


def test_logging_timestamps_present(cfg, plugin):
    f = cfg("service timestamps log datetime msec")
    assert plugin.get_logging_timestamps(f) is None


# --- logging userinfo ---

def test_logging_userinfo_missing(cfg, plugin):
    f = cfg("hostname R1")
    assert plugin.get_logging_userinfo(f) is not None


def test_logging_userinfo_present(cfg, plugin):
    f = cfg("logging userinfo")
    assert plugin.get_logging_userinfo(f) is None


# --- logging console ---

def test_logging_console_missing(cfg, plugin):
    f = cfg("hostname R1")
    assert plugin.get_logging_console(f) is not None


def test_logging_console_too_verbose(cfg, plugin):
    # 'debugging' is severity 7 > critical(2) — too verbose
    f = cfg("logging console debugging")
    assert plugin.get_logging_console(f) is not None


def test_logging_console_informational_too_verbose(cfg, plugin):
    # 'informational' is severity 6 > critical(2) — too verbose
    f = cfg("logging console informational")
    assert plugin.get_logging_console(f) is not None


def test_logging_console_critical(cfg, plugin):
    f = cfg("logging console critical")
    assert plugin.get_logging_console(f) is None


def test_logging_console_alerts(cfg, plugin):
    # 'alerts' is severity 1 <= critical(2) — OK
    f = cfg("logging console alerts")
    assert plugin.get_logging_console(f) is None


# --- logging trap ---

def test_logging_trap_missing(cfg, plugin):
    f = cfg("hostname R1")
    assert plugin.get_logging_trap(f) is not None


def test_logging_trap_too_restrictive(cfg, plugin):
    # 'errors' is severity 3 < informational(6) — too restrictive
    f = cfg("logging trap errors")
    assert plugin.get_logging_trap(f) is not None


def test_logging_trap_informational(cfg, plugin):
    f = cfg("logging trap informational")
    assert plugin.get_logging_trap(f) is None


def test_logging_trap_debugging(cfg, plugin):
    # 'debugging' is severity 7 >= informational(6) — OK
    f = cfg("logging trap debugging")
    assert plugin.get_logging_trap(f) is None


# --- archive log config ---

def test_archive_log_config_missing(cfg, plugin):
    f = cfg("hostname R1")
    assert plugin.get_archive_log_config(f) is not None


def test_archive_no_log_config(cfg, plugin):
    f = cfg("""
archive
 path tftp://10.0.0.1/
""")
    assert plugin.get_archive_log_config(f) is not None


def test_archive_log_config_present(cfg, plugin):
    f = cfg("""
archive
 log config
  logging enable
""")
    assert plugin.get_archive_log_config(f) is None


# --- analyze ---

def test_analyze_all_issues(cfg, plugin):
    f = cfg("hostname R1")
    plugin.analyze(f)
    # logging_on=None (default on), buffered, host, source_iface, timestamps,
    # userinfo, console, trap, archive = 8 issues
    assert len(plugin.get_issues()) == 8


def test_analyze_compliant(cfg, plugin):
    f = cfg("""
logging on
logging buffered 16384 informational
logging host 10.0.0.1
logging source-interface Loopback0
service timestamps log datetime msec
logging userinfo
logging console critical
logging trap informational
archive
 log config
  logging enable
""")
    plugin.analyze(f)
    assert len(plugin.get_issues()) == 0
