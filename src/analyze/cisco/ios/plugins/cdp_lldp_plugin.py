# flake8: noqa
# CIS Cisco IOS Benchmark references:
#   2.3.1  - Ensure CDP is disabled globally or on all untrusted interfaces
#   2.3.2  - Ensure LLDP is disabled globally or on all untrusted interfaces

from ..core.base_plugin import BasePlugin
from ....common.issue.issue import Issue


class PluginCDPLLDP(BasePlugin):

    def __init__(self):
        super().__init__()

    def name(self):
        return "CDP and LLDP Discovery Protocols"

    # CIS 2.3.1 - CDP disabled globally

    def _has_cdp_disabled_globally(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        no_cdp = parser.find_objects(r"^no cdp run")
        return len(no_cdp) > 0

    def _has_cdp_globally(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        no_cdp = parser.find_objects(r"^no cdp run")
        cdp_run = parser.find_objects(r"^cdp run")
        # CDP is enabled by default on Cisco IOS; absence of 'no cdp run' means it is active
        if len(no_cdp) > 0:
            return False
        return True

    def get_cdp_global(self, filename: str):
        if self._has_cdp_globally(filename):
            return Issue(
                "CDP (Cisco Discovery Protocol) globally enabled",
                "CDP is enabled globally on the device. CDP broadcasts device type, IOS version, hostname, IP addresses, and interface information to directly connected neighbors without any authentication.",  # noqa: E501
                "CDP advertises sensitive information including the exact IOS version and device model. This information can be used by an attacker to craft targeted exploits. CDP is also vulnerable to denial-of-service attacks where CDP table exhaustion can crash or degrade device performance.",  # noqa: E501
                "Any host on a directly connected Layer 2 segment can listen for CDP packets using standard packet-capture tools. No authentication or credentials are required.",  # noqa: E501
                "If CDP is not required, disable it globally. Otherwise disable it on all untrusted interfaces:\n\n```\nno cdp run\n```\n\nOr per untrusted interface:\n\n```\ninterface <type> <number>\n no cdp enable\n```",  # noqa: E501
                "CIS 2.3.1"
            )
        return None

    def _has_cdp_on_external_interfaces(self, filename: str) -> bool:
        """Check if CDP is enabled on interfaces that face external or untrusted networks."""
        parser = self.parse_cisco_ios_config_file(filename)
        # Look for interfaces without 'no cdp enable'
        interfaces = parser.find_objects(r"^interface")
        for iface in interfaces:
            no_cdp = iface.re_search_children(r"no cdp enable")
            if not no_cdp:
                return True
        return False

    # CIS 2.3.1 - CDP disabled on all interfaces when globally enabled
    def get_cdp_on_interfaces(self, filename: str):
        if not self._has_cdp_disabled_globally(filename) and self._has_cdp_on_external_interfaces(filename):
            return Issue(
                "CDP not disabled on all interfaces",
                "CDP is not explicitly disabled on one or more interfaces. Even if CDP is globally enabled for operational reasons, it should be disabled on all interfaces that face untrusted networks.",  # noqa: E501
                "CDP enabled on external or untrusted interfaces broadcasts device information to those segments, enabling reconnaissance by hosts on those networks.",  # noqa: E501
                "Sniffing CDP packets requires only standard packet-capture tools and network access to the same broadcast domain.",  # noqa: E501
                "Disable CDP on all interfaces that do not explicitly require it:\n\n```\ninterface <type> <number>\n no cdp enable\n```",  # noqa: E501
                "CIS 2.3.1"
            )
        return None

    def _has_lldp_disabled(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        no_lldp = parser.find_objects(r"^no lldp run")
        return len(no_lldp) > 0

    # CIS 2.3.2 - LLDP disabled globally
    def get_lldp_global(self, filename: str):
        parser = self.parse_cisco_ios_config_file(filename)
        lldp_run = parser.find_objects(r"^lldp run")
        if len(lldp_run) > 0 or not self._has_lldp_disabled(filename):
            # Only flag if LLDP is explicitly enabled
            if len(lldp_run) > 0:
                return Issue(
                    "LLDP (Link Layer Discovery Protocol) globally enabled",
                    "LLDP is enabled globally on the device. Like CDP, LLDP advertises device information (capabilities, system name, management addresses) to directly connected neighbors without authentication.",  # noqa: E501
                    "LLDP-enabled devices broadcast system information to all directly connected neighbors. This information can be captured to fingerprint the network and identify vulnerable devices.", # noqa: E501  
                    "Any host on a directly connected Layer 2 segment can passively receive LLDP frames. No credentials or active probing are required.",  # noqa: E501
                    "If LLDP is not required, disable it globally. Otherwise disable it on untrusted interfaces:\n\n```\nno lldp run\n```\n\nOr per untrusted interface:\n\n```\ninterface <type> <number>\n no lldp transmit\n no lldp receive\n```",  # noqa: E501
                    "CIS 2.3.2"
                )
        return None

    def analyze(self, config_file) -> None:
        issues = []

        issues.append(self.get_cdp_global(config_file))
        issues.append(self.get_cdp_on_interfaces(config_file))
        issues.append(self.get_lldp_global(config_file))

        for issue in issues:
            if issue is not None:
                self.add_issue(issue)
