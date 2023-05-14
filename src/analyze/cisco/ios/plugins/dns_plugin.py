
from ..core.base_plugin import BasePlugin
from ....common.issue.issue import Issue


class PluginDNS(BasePlugin):

    def __init__(self):
        super().__init__()

    def name(self):
        return "Domain Name System (DNS)"

    def _has_dns_enabled(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        domain_name_enable = parser.find_objects("ip name-server ")
        if (len(domain_name_enable) > 0):
            return True
        else:
            return False

    def _has_no_domain_lookup(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        no_domain_lookup_enable = parser.find_objects("no ip domain-lookup")
        if (len(no_domain_lookup_enable) > 0):
            return True
        else:
            return False

    def get_domain_name(self, filename: str):
        if (not self._has_dns_enabled(filename) and not self._has_no_domain_lookup(filename)):
            return Issue(
                "Domain Lookups",
                "Cisco IOS-based devices support name lookups using the DNS. However, if a DNS server has not been configured, then the DNS request is broadcast.It is determined that name lookups had not been disabled and no DNS servers had been configured.",  # noqa: E501
                "An attacker who was able to capture network traffic could monitor DNS queries from the device. Furthermore, Cisco devices can connect to Telnet servers by supplying only the hostname or IP address of the server. A mistyped Cisco command could be interpreted as an attempt to connect to a Telnet server and broadcast on the network.",  # noqa: E501
                "It would be trivial for an attacker to capture network traffic broadcast from a device. Furthermore, network traffic capture tools are widely available on the Internet.",  # noqa: E501
                "It is recommends that domain lookups be disabled. Domain lookups can be disabled with the following command: no ip domain-lookup. If domain lookups are required, It is recommends that DNS be configured. DNS can be configured with the following command: ip name-server <IP address>."  # noqa: E501
            )

    def analyze(self, config_file) -> None:
        issues = []

        issues.append(self.get_domain_name(config_file))

        for issue in issues:
            if issue is not None:
                self.add_issue(issue)
