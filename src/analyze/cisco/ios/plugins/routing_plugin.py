# flake8: noqa

from ..core.base_plugin import BasePlugin
from ....common.issue.issue import Issue

class PluginRouting(BasePlugin):
    
    def __init__(self):
        super().__init__()

    def name(self):
        return "Routing rules"
    
    def _has_ip_sourceroute(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        no_source_route_defined = parser.find_objects("no ip source-route")
        if (len(no_source_route_defined) > 0):
            return False
        else:
            return True
    
    def get_ip_source_route(self, filename: str):
        if self._has_ip_sourceroute(filename):
            return Issue(
                "Handling of IP datagrams",
                "Disable the handling of IP datagrams with source routing header options.",  # noqa: E501
                "Organizations should plan and implement network policies to ensure unnecessary services are explicitly disabled. The 'ip source-route' feature has been used in several attacks and should be disabled.",  # noqa: E501
                "Source routing is a feature of IP whereby individual packets can specify routes. This feature is used in several kinds of attacks. Cisco routers normally accept and process source routes. Unless a network depends on source routing, it should be disabled.",  # noqa: E501
                "Disable source routing: no ip source-route"  # noqa: E501
            )
    
    def _has_ip_proxy_arp(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        no_proxy_arp = parser.find_objects("no ip proxy-arp")
        if (len(no_proxy_arp) > 0):
            return False
        else:
            return True
    
    def get_ip_proxy_arp(self, filename: str):
        if self._has_ip_proxy_arp(filename):
            return Issue(
                "Proxy ARP",
                "Disable proxy ARP on all interfaces.",  # noqa: E501
                "Address Resolution Protocol (ARP) provides resolution between IP and MAC Addresses (or other Network and Link Layer addresses on none IP networks) within a Layer 2 network. Proxy ARP is a service where a device connected to one network (in this case the Cisco router) answers ARP Requests which are addressed to a host on another network, replying with its own MAC Address and forwarding the traffic on to the intended host. Sometimes used for extending broadcast domains across WAN links, in most cases Proxy ARP on enterprise networks is used to enable communication for hosts with misconfigured subnet masks, a situation which should no longer be a common problem. Proxy ARP effectively breaks the LAN Security Perimeter, extending a network across multiple Layer 2 segments. Using Proxy ARP can also allow other security controls such as PVLAN to be bypassed.",  # noqa: E501
                "Organizations should plan and implement network policies to ensure unnecessary services are explicitly disabled. The 'ip proxy-arp' feature effectively breaks the LAN security perimeter and should be disabled.",  # noqa: E501
                "Disable proxy ARP on all interfaces: no ip proxy-arp"  # noqa: E501
            )
    
    def _has_tunnel_interface(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        tunnel_interface = parser.find_objects("interface tunnel-ipsec")
        if (len(tunnel_interface) > 0):
            return True
        else:
            return False
    
    def get_tunnel_interface(self, filename: str):
        if self._has_tunnel_interface(filename):
            return Issue(
                "Tunnel interfaces",
                "Verify no tunnel interfaces are defined.",  # noqa: E501
                "Organizations should plan and implement enterprise network security policies that disable insecure and unnecessary features that increase attack surfaces such as 'tunnel interfaces'.",  # noqa: E501
                "Tunnel interfaces should not exist in general. They can be used for malicious purposes. If they are necessary, the network admin's should be well aware of them and their purpose.",  # noqa: E501
                "Remove any tunnel interfaces: no interface tunnel {nstance}"  # noqa: E501
            )
    
    def _has_uRPF(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        fib = parser.find_objects("ip verify unicast source reachable-via rx")
        if (len(fib) > 0):
            return True
        else:
            return False
    
    def get_uRPF(self, filename: str):
        if not self._has_uRPF(filename):
            return Issue(
                "uRPF",
                "Examines incoming packets to determine whether the source address is in the Forwarding Information Base (FIB) and permits the packet only if the source is reachable through the interface on which the packet was received (sometimes referred to as strict mode).",  # noqa: E501
                "Organizations should plan and implement enterprise security policies that protect the confidentiality, integrity, and availability of network devices. The 'unicast Reverse-Path Forwarding' (uRPF) feature dynamically uses the router table to either accept or drop packets when arriving on an interface.",  # noqa: E501
                "Enabled uRPF helps mitigate IP spoofing by ensuring only packet source IP addresses only originate from expected interfaces. Configure unicast reverse-path forwarding (uRPF) on all external or high risk interfaces.",  # noqa: E501
                "Configure uRPF in all interfaces: ip verify unicast source reachable-via rx"  # noqa: E501
            )
    
    def analyze(self, config_file) -> None:
        issues = []

        issues.append(self.get_ip_source_route(config_file))
        issues.append(self.get_ip_proxy_arp(config_file))
        issues.append(self.get_tunnel_interface(config_file))
        issues.append(self.get_uRPF(config_file))

        for issue in issues:
            if issue is not None:
                self.add_issue(issue)