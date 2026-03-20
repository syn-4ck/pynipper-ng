import pytest
from src.analyze.common.issue.issue import Issue
from src.analyze.common.base_plugin.base_plugin import GenericPlugin
from src.analyze.cisco.ios.core.base_plugin import BasePlugin
from src.error.files_errors import DeviceConfigurationFileNotFound, PynipperConfigurationFileNotFound
from src.error.cisco_errors import GenericCiscoError


# --- Issue ---

def test_issue_attributes():
    issue = Issue("Title", "Observation", "Impact", "Ease", "Recommendation")
    assert issue.title == "Title"
    assert issue.observation == "Observation"
    assert issue.impact == "Impact"
    assert issue.ease == "Ease"
    assert issue.recommendation == "Recommendation"


def test_issue_str_returns_none():
    # __str__ calls print() and returns None
    issue = Issue("T", "O", "I", "E", "R")
    result = issue.__str__()
    assert result is None


def test_issue_dict_method():
    issue = Issue("T", "O", "I", "E", "R")
    d = issue.__dict__()
    assert d["title"] == "T"
    assert d["observation"] == "O"
    assert d["impact"] == "I"
    assert d["ease"] == "E"
    assert d["recommendation"] == "R"


# --- GenericPlugin ---

class ConcretePlugin(GenericPlugin):
    def analyze(self, config_file):
        pass

    def name(self):
        return "Concrete"


def test_generic_plugin_initial_issues():
    p = ConcretePlugin()
    assert p.get_issues() == []


def test_generic_plugin_add_issue():
    p = ConcretePlugin()
    issue = Issue("T", "O", "I", "E", "R")
    p.add_issue(issue)
    assert len(p.get_issues()) == 1
    assert p.get_issues()[0] is issue


def test_generic_plugin_multiple_issues():
    p = ConcretePlugin()
    for i in range(3):
        p.add_issue(Issue(f"T{i}", "O", "I", "E", "R"))
    assert len(p.get_issues()) == 3


def test_generic_plugin_name():
    p = ConcretePlugin()
    assert p.name() == "Concrete"


# --- BasePlugin (Cisco IOS) ---

def test_base_plugin_parse(cfg):
    f = cfg("hostname TestRouter")
    plugin = BasePlugin()
    parser = plugin.parse_cisco_ios_config_file(f)
    # Should return a CiscoConfParse object
    assert parser is not None
    hosts = parser.find_objects(r"^hostname")
    assert len(hosts) == 1


# --- Error classes ---

def test_device_config_not_found():
    err = DeviceConfigurationFileNotFound("File not found: /tmp/x")
    assert str(err) == "File not found: /tmp/x"
    assert isinstance(err, Exception)


def test_pynipper_config_not_found():
    err = PynipperConfigurationFileNotFound("Config missing")
    assert str(err) == "Config missing"
    assert isinstance(err, Exception)


def test_generic_cisco_error():
    err = GenericCiscoError("Cisco error occurred")
    assert str(err) == "Cisco error occurred"
    assert isinstance(err, Exception)
