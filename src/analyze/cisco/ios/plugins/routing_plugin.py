# flake8: noqa
# CIS Cisco IOS Benchmark references:
#   2.1.1  - Ensure 'no ip source-route' is set
#   2.1.2  - Ensure 'no ip proxy-arp' is set on all interfaces
#   2.1.3  - Ensure no tunnel interfaces are defined (review required)
#   2.1.4  - Ensure 'ip verify unicast source reachable-via rx' (uRPF) is set

from ..core.base_plugin import BasePlugin
from ....common.issue.issue import Issue


class PluginRouting(BasePlugin):

    def __init__(self):
        super().__init__()

    def name(self):
        return "Routing Security"

    # CIS 2.1.1 - Ensure 'no ip source-route' is set
    def _has_ip_source_route(self, filename: str) -> bool:
        """Return True if IP source routing is enabled (not disabled)."""
        parser = self.parse_cisco_ios_config_file(filename)
        return len(parser.find_objects(r"^no ip source-route")) == 0

    def get_ip_source_route(self, filename: str):
        if self._has_ip_source_route(filename):
            return Issue(
                "IP source routing not disabled",
                "IP source routing is enabled. This feature allows individual IP packets to specify their own route through the network, which has been used in several historical attacks.",  # noqa: E501
                "Source routing can be abused by attackers to bypass access controls, to probe internal network topology, and to redirect traffic along attacker-specified paths.",  # noqa: E501
                "Crafting source-routed packets requires only standard packet-forging tools that are freely available.",  # noqa: E501
                "Disable IP source routing globally:\n\n```\nno ip source-route\n```",  # noqa: E501
                "CIS 2.1.1"
            )
        return None

    # CIS 2.1.2 - Ensure 'no ip proxy-arp' is set on all interfaces
    def _has_proxy_arp(self, filename: str) -> bool:
        """Return True if proxy ARP is not explicitly disabled on any interface."""
        parser = self.parse_cisco_ios_config_file(filename)
        return len(parser.find_objects(r"no ip proxy-arp")) == 0

    def get_ip_proxy_arp(self, filename: str):
        if self._has_proxy_arp(filename):
            return Issue(
                "Proxy ARP not disabled on interfaces",
                "Proxy ARP is not explicitly disabled. Proxy ARP allows the router to respond to ARP requests on behalf of hosts on other subnets, effectively bridging Layer 2 boundaries.",  # noqa: E501
                "Proxy ARP breaks the Layer 2 security perimeter, enabling hosts with misconfigured gateways to reach unauthorised networks. It can also be used to bypass PVLAN restrictions.",  # noqa: E501
                "Exploiting Proxy ARP requires sending crafted ARP requests from a directly connected segment — no special tools beyond basic networking are needed.",  # noqa: E501
                "Disable Proxy ARP on all interfaces where it is not required:\n\n```\ninterface <type> <number>\n no ip proxy-arp\n```",  # noqa: E501
                "CIS 2.1.2"
            )
        return None

    # CIS 2.1.3 - Ensure no unnecessary tunnel interfaces are defined
    def _has_tunnel_interface(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        return len(parser.find_objects(r"^interface [Tt]unnel")) > 0

    def get_tunnel_interface(self, filename: str):
        if self._has_tunnel_interface(filename):
            return Issue(
                "Tunnel interfaces detected",
                "One or more tunnel interfaces are configured on the device. Unless explicitly required and documented, tunnel interfaces expand the attack surface and can be used as covert channels.",  # noqa: E501
                "Undocumented tunnel interfaces can be used as covert communication channels by an attacker who has gained partial access to the network.",  # noqa: E501
                "Identifying and creating tunnel interfaces requires network access and some knowledge of IOS — but their presence may be overlooked during routine audits.",  # noqa: E501
                "Remove unnecessary tunnel interfaces. If tunnels are required, document, authenticate with IPsec, and review regularly:\n\n```\nno interface tunnel <n>\n```",  # noqa: E501
                "CIS 2.1.3"
            )
        return None

    # CIS 2.1.4 - Ensure uRPF is configured on all external/high-risk interfaces
    def _has_urpf(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        return len(parser.find_objects(r"ip verify unicast source reachable-via rx")) > 0

    def get_urpf(self, filename: str):
        if not self._has_urpf(filename):
            return Issue(
                "Unicast Reverse Path Forwarding (uRPF) not configured",
                "uRPF (ip verify unicast source reachable-via rx) is not configured. Without it, the device forwards packets with spoofed source addresses.",  # noqa: E501
                "Without uRPF, an attacker can send packets with forged source IP addresses. This enables IP spoofing attacks, reflection/amplification DDoS attacks, and makes it harder to trace attack traffic.",  # noqa: E501
                "IP spoofing is straightforward using raw-socket tools. Without uRPF the device will forward spoofed traffic unchecked.",  # noqa: E501
                "Enable strict uRPF on all external-facing or high-risk interfaces:\n\n```\ninterface <type> <number>\n ip verify unicast source reachable-via rx\n``` Use loose mode only where asymmetric routing prevents strict mode.",  # noqa: E501
                "CIS 2.1.4"
            )
        return None

    def analyze(self, config_file) -> None:
        issues = []

        issues.append(self.get_ip_source_route(config_file))
        issues.append(self.get_ip_proxy_arp(config_file))
        issues.append(self.get_tunnel_interface(config_file))
        issues.append(self.get_urpf(config_file))

        for issue in issues:
            if issue is not None:
                self.add_issue(issue)