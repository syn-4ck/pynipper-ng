# flake8: noqa
# CIS Cisco IOS Benchmark references:
#   4.1  - Ensure SNMP community strings are not default ('public'/'private')
#   4.2  - Ensure SNMPv1 and SNMPv2c are not used (migrate to SNMPv3)
#   4.3  - Ensure SNMPv3 uses 'authPriv' security level
#   4.4  - Ensure SNMP access is restricted by ACL
#   4.5  - Ensure SNMP traps are configured to an authorised server

from ..core.base_plugin import BasePlugin
from ....common.issue.issue import Issue


class PluginSNMP(BasePlugin):

    def __init__(self):
        super().__init__()

    def name(self):
        return "Simple Network Management Protocol (SNMP)"

    def _is_snmp_configured(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        return len(parser.find_objects(r"^snmp-server")) > 0

    # CIS 4.2 - Ensure SNMPv1/v2c community strings are not used
    def _has_snmp_community(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        return len(parser.find_objects(r"^snmp-server community")) > 0

    def get_snmp_community_strings(self, filename: str):
        if self._has_snmp_community(filename):
            return Issue(
                "SNMPv1/v2c community strings configured",
                "SNMP community strings for version 1 or version 2c are configured. These protocols use cleartext community strings as the only authentication mechanism.",  # noqa: E501
                "Community strings transmitted in cleartext can be captured by any host on the network path. A read-write community string provides full configuration access to the device.",  # noqa: E501
                "Standard packet-capture tools (Wireshark, tcpdump) are sufficient to extract SNMPv1/v2c community strings from network traffic.",  # noqa: E501
                "Remove all SNMPv1/v2c community strings and migrate to **SNMPv3** with authPriv:\n\n```\nno snmp-server community <string>\nsnmp-server group <group> v3 priv\nsnmp-server user <user> <group> v3 auth sha <auth-key> priv aes 128 <priv-key>\n```",  # noqa: E501
                "CIS 4.2"
            )
        return None

    # CIS 4.1 - Ensure default community strings are not in use
    def _has_default_community(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        return (
            len(parser.find_objects(r"^snmp-server community public")) > 0
            or len(parser.find_objects(r"^snmp-server community private")) > 0
        )

    def get_snmp_default_community(self, filename: str):
        if self._has_default_community(filename):
            return Issue(
                "Default SNMP community strings in use ('public'/'private')",
                "The well-known default SNMP community strings 'public' and/or 'private' are configured. These are universally known and routinely targeted.",  # noqa: E501
                "An attacker using any SNMP scanner will try default community strings first. The 'private' string typically grants read-write access, allowing full configuration control.",  # noqa: E501
                "Default community string attacks require only an SNMP tool (snmpwalk, snmpset) — no prior knowledge of the organisation's environment is needed.",  # noqa: E501
                "Remove the default SNMP community strings immediately:\n\n```\nno snmp-server community public\nno snmp-server community private\n```\n\nThen configure **SNMPv3** with unique credentials.",  # noqa: E501
                "CIS 4.1"
            )
        return None

    # CIS 4.3 - Ensure SNMPv3 with authPriv is configured if SNMP is in use
    def _has_snmp_v3_group(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        return len(parser.find_objects(r"^snmp-server group\s+\S+\s+v3")) > 0

    def get_snmp_v3(self, filename: str):
        if self._is_snmp_configured(filename) and not self._has_snmp_v3_group(filename):
            return Issue(
                "SNMPv3 not configured",
                "SNMP is in use but no SNMPv3 group is configured. SNMPv3 is the only SNMP version that provides mutual authentication and traffic encryption.",  # noqa: E501
                "Without SNMPv3, SNMP traffic is unauthenticated or uses weak cleartext community strings, exposing device configuration data and allowing unauthorised management operations.",  # noqa: E501
                "Capturing SNMP traffic with Wireshark and inspecting community strings requires no special skill.",  # noqa: E501
                "Configure **SNMPv3** with authentication and privacy (authPriv):\n\n```\nsnmp-server group <group> v3 priv\nsnmp-server user <user> <group> v3 auth sha <auth-key> priv aes 128 <priv-key>\n```",  # noqa: E501
                "CIS 4.3"
            )
        return None

    # CIS 4.4 - Ensure SNMP access is restricted by ACL
    def _has_snmp_acl(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        community_with_acl = parser.find_objects(r"^snmp-server community\s+\S+\s+(ro|rw)\s+\S+")
        group_with_acl = parser.find_objects(r"^snmp-server group\s+\S+\s+v3\s+\S+\s+access")
        return len(community_with_acl) > 0 or len(group_with_acl) > 0

    def get_snmp_acl(self, filename: str):
        if self._is_snmp_configured(filename) and not self._has_snmp_acl(filename):
            return Issue(
                "SNMP access not restricted by ACL",
                "SNMP is enabled but no ACL is applied to community strings or SNMPv3 groups to restrict which management stations can communicate with the SNMP agent.",  # noqa: E501
                "Without an ACL, any host with IP reachability to the device can query SNMP. This enables reconnaissance of device configuration and aids targeted attacks.",  # noqa: E501
                "SNMP enumeration requires only an SNMP client (snmpwalk) and knowledge of the community string or SNMPv3 credentials.",  # noqa: E501
                "Apply an ACL to restrict SNMP access to authorised management hosts:\n\n```\nsnmp-server community <string> RO <acl-number>\nsnmp-server group <group> v3 priv access <acl-number>\n```",  # noqa: E501
                "CIS 4.4"
            )
        return None

    # CIS 4.5 - Ensure SNMP traps are sent to an authorised server
    def _has_snmp_traps(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        trap_host = parser.find_objects(r"^snmp-server host")
        trap_enable = parser.find_objects(r"^snmp-server enable traps")
        return len(trap_host) > 0 and len(trap_enable) > 0

    def get_snmp_traps(self, filename: str):
        if not self._has_snmp_traps(filename):
            return Issue(
                "SNMP traps not configured",
                "SNMP traps are not configured. Without traps, security-relevant events such as authentication failures, configuration changes, and link state changes are not proactively sent to a management station.",  # noqa: E501
                "Without SNMP traps, security events may go unnoticed until the next polling cycle, extending the window during which an attacker can operate undetected.",  # noqa: E501
                "This is a monitoring gap rather than a directly exploitable vulnerability.",  # noqa: E501
                "Enable SNMP traps and configure a **SNMPv3** trap receiver:\n\n```\nsnmp-server enable traps\nsnmp-server host <ip> version 3 priv <user>\n```",  # noqa: E501
                "CIS 4.5"
            )
        return None

    def analyze(self, config_file) -> None:
        issues = []

        issues.append(self.get_snmp_community_strings(config_file))
        issues.append(self.get_snmp_default_community(config_file))
        issues.append(self.get_snmp_v3(config_file))
        issues.append(self.get_snmp_acl(config_file))
        issues.append(self.get_snmp_traps(config_file))

        for issue in issues:
            if issue is not None:
                self.add_issue(issue)

