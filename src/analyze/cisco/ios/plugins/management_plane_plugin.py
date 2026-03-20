# flake8: noqa
# CIS Cisco IOS Benchmark references:
#   5.3.1  - Ensure Management Plane Protection (MPP) is configured
#   5.3.2  - Ensure an ACL is applied to restrict management access on VTY lines
#   5.4.1  - Ensure HTTPS management server uses TLS 1.2 or higher
#   5.5.1  - Ensure no local user accounts have direct privilege level 15
#   5.5.2  - Ensure Control Plane Policing (CoPP) is configured

from ..core.base_plugin import BasePlugin
from ....common.issue.issue import Issue


class PluginManagementPlane(BasePlugin):

    def __init__(self):
        super().__init__()

    def name(self):
        return "Management Plane Access Control"

    # CIS 5.3.1 - Management Plane Protection (MPP)

    def _has_management_plane_protection(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        mpp = parser.find_objects(r"^control-plane host")
        return len(mpp) > 0

    def get_management_plane_protection(self, filename: str):
        if not self._has_management_plane_protection(filename):
            return Issue(
                "Management Plane Protection (MPP) not configured",
                "Management Plane Protection (MPP) is not configured. MPP restricts which interfaces the device will accept management traffic on, limiting the attack surface for management protocols.",  # noqa: E501
                "Without MPP, management protocols such as SSH, SNMP, and Telnet are accepted on all interfaces, including those facing untrusted networks. This significantly increases the exposure of management services.",  # noqa: E501
                "An attacker with access to any interface on the device can attempt to reach management services without MPP.",  # noqa: E501
                "Configure Management Plane Protection to restrict management access to specific interfaces:\n\n```\ncontrol-plane host\n management-interface <interface> allow ssh snmp https\n```",  # noqa: E501
                "CIS 5.3.1"
            )
        return None

    def _has_ip_access_list_for_management(self, filename: str) -> bool:
        """Check if there is at least one named or numbered ACL applied to VTY lines."""
        parser = self.parse_cisco_ios_config_file(filename)
        vty_lines = parser.find_objects(r"^line vty")
        for vty in vty_lines:
            if vty.re_search_children(r"access-class"):
                return True
        return False

    # CIS 5.3.2 - ACL restricting VTY management access
    def get_management_acl(self, filename: str):
        if not self._has_ip_access_list_for_management(filename):
            return Issue(
                "No ACL protecting management access (VTY)",
                "No access-class is applied to VTY lines to restrict management access. Any host with IP reachability to the device can attempt to connect to management services.",
                "Without ACL protection, management services are exposed to the entire reachable network. This dramatically increases the opportunity for brute-force attacks against management protocols.",  # noqa: E501
                "Connecting to exposed management interfaces requires only basic network access and widely available tools such as SSH clients or SNMP scanners.",  # noqa: E501
                "Define an ACL that permits management access only from authorised hosts and apply it to all VTY lines:\n\n```\naccess-list 10 permit <management-host>\naccess-list 10 deny any\nline vty 0 4\n access-class 10 in\n```",  # noqa: E501
                "CIS 5.3.2"
            )
        return None

    def _has_no_ip_http_server(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        no_http = parser.find_objects(r"^no ip http server")
        http_enabled = parser.find_objects(r"^ip http server")
        if len(no_http) > 0:
            return True
        if len(http_enabled) > 0:
            return False
        return True  # default off on newer IOS

    def _has_ip_https_server(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        https = parser.find_objects(r"^ip http secure-server")
        no_https = parser.find_objects(r"^no ip http secure-server")
        return len(https) > 0 and len(no_https) == 0

    def _has_https_tls12_or_above(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        tls10_only = parser.find_objects(r"^ip http tls-version TLSv1$")
        tls11_only = parser.find_objects(r"^ip http tls-version TLSv1.1$")
        return len(tls10_only) == 0 and len(tls11_only) == 0

    # CIS 5.4.1 - HTTPS management using TLS 1.2+
    def get_https_tls_version(self, filename: str):
        if self._has_ip_https_server(filename) and not self._has_https_tls12_or_above(filename):
            return Issue(
                "HTTPS management using outdated TLS version",
                "The HTTPS management server is configured to use TLS 1.0 or TLS 1.1, which are deprecated protocols with known vulnerabilities.",
                "TLS 1.0 and 1.1 are vulnerable to attacks such as BEAST, POODLE, and other downgrade attacks. Using deprecated TLS versions risks the compromise of management credentials and session data.",  # noqa: E501
                "Downgrade attacks against TLS 1.0/1.1 are well-documented and tools are publicly available.",  # noqa: E501
                "Configure the HTTPS server to use only TLS 1.2 or higher:\n\n```\nip http tls-version TLSv1.2\n```",  # noqa: E501
                "CIS 5.4.1"
            )
        return None

    def _has_privilege_level_15_users(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        priv15 = parser.find_objects(r"^username\s+\S+\s+privilege\s+15")
        return len(priv15) > 0

    # CIS 5.5.1 - No users with direct privilege 15
    def get_no_direct_privilege_15(self, filename: str):
        if self._has_privilege_level_15_users(filename):
            return Issue(
                "Users configured with direct privilege level 15",
                "One or more local users are configured with privilege level 15 (full administrative access). Users should authenticate at a lower privilege level and escalate via 'enable' with a separate secret.",  # noqa: E501
                "Accounts with directly assigned privilege 15 have full device control. If such a credential is compromised, the attacker gains immediate full admin access without any additional authentication step.",  # noqa: E501
                "Credential theft or brute-force against a privilege 15 account immediately yields full administrative access to the device.",  # noqa: E501
                "Remove privilege 15 from local user accounts and require separate `enable secret` authentication.\nUse role-based access control (RBAC) and **AAA** to control privilege escalation.",  # noqa: E501
                "CIS 5.5.1"
            )
        return None

    def _has_control_plane_policing(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        cpp = parser.find_objects(r"^control-plane")
        if len(cpp) == 0:
            return False
        for cp in cpp:
            if cp.re_search_children(r"service-policy input"):
                return True
        return False

    # CIS 5.5.2 - Control Plane Policing (CoPP)
    def get_control_plane_policing(self, filename: str):
        if not self._has_control_plane_policing(filename):
            return Issue(
                "Control Plane Policing (CoPP) not configured",
                "Control Plane Policing (CoPP) is not configured. Without CoPP, the router's control plane is fully exposed to denial-of-service attacks that can overwhelm the CPU.",
                "The control plane handles routing protocol packets, management traffic, and exception packets. An attacker who floods the control plane can prevent the device from processing legitimate routing updates or management connections, causing a denial-of-service condition.",  # noqa: E501
                "CoPP attacks require only the ability to generate high-rate traffic directed at the device's control plane. This can be achieved with basic traffic generation tools.",  # noqa: E501
                "Configure **CoPP** using Modular QoS CLI (MQC) to rate-limit control-plane traffic:\n\n```\ncontrol-plane\n service-policy input <copp-policy-name>\n```",  # noqa: E501
                "CIS 5.5.2"
            )
        return None

    def analyze(self, config_file) -> None:
        issues = []

        issues.append(self.get_management_plane_protection(config_file))
        issues.append(self.get_management_acl(config_file))
        issues.append(self.get_https_tls_version(config_file))
        issues.append(self.get_no_direct_privilege_15(config_file))
        issues.append(self.get_control_plane_policing(config_file))

        for issue in issues:
            if issue is not None:
                self.add_issue(issue)
