# flake8: noqa
# CIS Cisco IOS Benchmark references:
#   2.4.1  - Ensure 'no ip domain-lookup' is set or a DNS server is configured

from ..core.base_plugin import BasePlugin
from ....common.issue.issue import Issue


class PluginDNS(BasePlugin):

    def __init__(self):
        super().__init__()

    def name(self):
        return "Domain Name System (DNS)"

    # CIS 2.4.1 - Ensure 'no ip domain-lookup' is set or DNS servers are configured
    def _has_name_server(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        return len(parser.find_objects(r"^ip name-server")) > 0

    def _has_no_domain_lookup(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        return len(parser.find_objects(r"^no ip domain-lookup")) > 0

    def get_dns_lookup_control(self, filename: str):
        if not self._has_name_server(filename) and not self._has_no_domain_lookup(filename):
            return Issue(
                "DNS lookup not controlled (no server or disable)",
                "No DNS server is configured and 'no ip domain-lookup' is not set. Without a DNS server, unresolved hostname queries are broadcast on all interfaces, which may leak information and cause delays.",  # noqa: E501
                "Broadcast DNS queries can be captured by any host on connected segments, revealing internal naming conventions. A mistyped CLI command may trigger a broadcast Telnet/DNS lookup that stalls the console for up to 30 seconds, disrupting operations.",  # noqa: E501
                "Any host on a connected broadcast domain can passively receive DNS broadcast queries sent by the device.",  # noqa: E501
                "Disable DNS lookups to prevent broadcast queries:\n\n```\nno ip domain-lookup\n```\n\nOr if DNS is required, configure only trusted resolvers:\n\n```\nip name-server <trusted-ip>\n```",  # noqa: E501
                "CIS 2.4.1"
            )
        return None

    def analyze(self, config_file) -> None:
        issues = []

        issues.append(self.get_dns_lookup_control(config_file))

        for issue in issues:
            if issue is not None:
                self.add_issue(issue)
