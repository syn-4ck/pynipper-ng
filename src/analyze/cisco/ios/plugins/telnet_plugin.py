# flake8: noqa
# CIS Cisco IOS Benchmark references:
#   2.2.1  - Ensure 'transport input ssh' is set on all VTY lines (disable Telnet)

from ..core.base_plugin import BasePlugin
from ....common.issue.issue import Issue


class PluginTelnet(BasePlugin):

    def __init__(self):
        super().__init__()

    def name(self):
        return "Telnet"

    # CIS 2.2.1 - Ensure Telnet is disabled on all VTY lines
    def _is_telnet_enabled(self, filename: str) -> bool:
        """Return True if Telnet is potentially accessible on any VTY line."""
        parser = self.parse_cisco_ios_config_file(filename)
        # Explicit disablement patterns
        transport_none = parser.find_objects(r"transport input none")
        ssh_only = parser.find_objects(r"transport input ssh")
        telnet_disabled = parser.find_objects(r"no transport input telnet")
        if len(transport_none) > 0 or len(ssh_only) > 0 or len(telnet_disabled) > 0:
            return False
        return True

    def get_telnet_enabled(self, filename: str):
        if self._is_telnet_enabled(filename):
            return Issue(
                "Telnet access not disabled",
                "Telnet is not explicitly disabled on VTY lines. Telnet transmits all session data, including authentication credentials, in cleartext.",  # noqa: E501
                "An attacker who can monitor network traffic on the path between the administrator and the device can capture credentials and session data transmitted via Telnet.",  # noqa: E501
                "Packet capture of Telnet sessions is trivial with freely available tools such as Wireshark and can immediately expose administrative credentials and device configuration.",  # noqa: E501
                "Disable Telnet and allow only SSH on all VTY lines:\n\n```\nline vty 0 4\n transport input ssh\n``` Alternatively, deny all transports: transport input none.",  # noqa: E501
                "CIS 2.2.1"
            )
        return None

    def analyze(self, config_file) -> None:
        issues = []

        issues.append(self.get_telnet_enabled(config_file))

        for issue in issues:
            if issue is not None:
                self.add_issue(issue)