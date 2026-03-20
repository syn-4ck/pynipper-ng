# flake8: noqa
# CIS Cisco IOS Benchmark references:
#   2.6.1  - Ensure 'ntp server' is configured (at least two servers)
#   2.6.2  - Ensure 'ntp authenticate' and 'ntp trusted-key' are set
#   2.6.3  - Ensure 'ntp access-group' restricts NTP peers

from ..core.base_plugin import BasePlugin
from ....common.issue.issue import Issue


class PluginNTP(BasePlugin):

    def __init__(self):
        super().__init__()

    def name(self):
        return "Network Time Protocol (NTP)"

    # CIS 2.6.1 - Ensure at least one NTP server is configured
    def _has_ntp_server(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        return len(parser.find_objects(r"^ntp server")) > 0

    def get_ntp_server(self, filename: str):
        if not self._has_ntp_server(filename):
            return Issue(
                "NTP server not configured",
                "No NTP server is configured. Accurate and synchronised time is required for security log correlation, certificate validation, and time-sensitive cryptographic protocols.",  # noqa: E501
                "Without NTP, device clocks may drift significantly, making it impossible to accurately correlate security events across devices during an incident investigation.",  # noqa: E501
                "The absence of NTP is observable through the device clock and logs. No active attack is needed.",  # noqa: E501
                "Configure at least two NTP servers for redundancy:\n\n```\nntp server <primary-ip> prefer\nntp server <secondary-ip>\n```",  # noqa: E501
                "CIS 2.6.1"
            )
        return None

    # CIS 2.6.2 - Ensure NTP authentication is configured
    def _has_ntp_authentication(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        ntp_auth = parser.find_objects(r"^ntp authenticate$")
        ntp_key = parser.find_objects(r"^ntp authentication-key")
        ntp_trusted = parser.find_objects(r"^ntp trusted-key")
        return len(ntp_auth) > 0 and len(ntp_key) > 0 and len(ntp_trusted) > 0

    def get_ntp_authentication(self, filename: str):
        if not self._has_ntp_server(filename):
            return None  # no NTP configured, skip
        if not self._has_ntp_authentication(filename):
            return Issue(
                "NTP authentication not configured",
                "NTP authentication (ntp authenticate, ntp authentication-key, ntp trusted-key) is not fully configured. Without it the device will synchronise with any reachable NTP source.",  # noqa: E501
                "An attacker able to inject NTP responses can manipulate the device clock, causing certificates to appear invalid, session tokens to expire incorrectly, or log timestamps to be falsified.",  # noqa: E501
                "NTP spoofing can be performed with freely available tools by anyone on the network path to the device.",  # noqa: E501
                "Enable NTP **MD5** authentication and reference the key on each server:\n\n```\nntp authenticate\nntp authentication-key <id> md5 <key>\nntp trusted-key <id>\nntp server <ip> key <id>\n```",  # noqa: E501
                "CIS 2.6.2"
            )
        return None

    # CIS 2.6.3 - Ensure 'ntp access-group' is configured
    def _has_ntp_access_group(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        return len(parser.find_objects(r"^ntp access-group")) > 0

    def get_ntp_access_group(self, filename: str):
        if not self._has_ntp_server(filename):
            return None  # no NTP configured, skip
        if not self._has_ntp_access_group(filename):
            return Issue(
                "NTP access-group not configured",
                "No NTP access-group is configured to restrict which hosts may query or peer with the device's NTP service.",  # noqa: E501
                "Without an NTP access-group, the device's NTP service is accessible from any host. This exposes the device to NTP amplification/reflection attacks and unauthorised time synchronisation.",  # noqa: E501
                "NTP amplification attacks using publicly accessible NTP servers are well documented. Restricting access with an ACL prevents the device from being used as a reflector.",  # noqa: E501
                "Restrict NTP access with access groups:\n\n```\nntp access-group peer <acl-number>\nntp access-group serve-only <acl-number>\n``` Define ACLs that permit only authorised NTP sources.",  # noqa: E501
                "CIS 2.6.3"
            )
        return None

    def analyze(self, config_file) -> None:
        issues = []

        issues.append(self.get_ntp_server(config_file))
        issues.append(self.get_ntp_authentication(config_file))
        issues.append(self.get_ntp_access_group(config_file))

        for issue in issues:
            if issue is not None:
                self.add_issue(issue)
