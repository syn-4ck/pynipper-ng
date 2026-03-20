# flake8: noqa
# CIS Cisco IOS Benchmark references:
#   6.1.1  - Ensure OSPF area authentication with MD5 is configured
#   6.2.1  - Ensure EIGRP neighbor authentication with MD5 key-chain is configured
#   6.3.1  - Ensure BGP neighbor MD5 password authentication is configured
#   6.4.1  - Ensure RIPv2 is used (not RIPv1) and MD5 authentication is configured

from ..core.base_plugin import BasePlugin
from ....common.issue.issue import Issue


class PluginRoutingProtocols(BasePlugin):

    def __init__(self):
        super().__init__()

    def name(self):
        return "Routing Protocol Authentication"

    # CIS 6.1.1 - OSPF authentication

    def _has_ospf_authentication(self, filename: str) -> bool:
        """Check whether OSPF interfaces use MD5 or SHA authentication."""
        parser = self.parse_cisco_ios_config_file(filename)
        ospf_process = parser.find_objects(r"^router ospf")
        if not ospf_process:
            return True  # OSPF not configured, no finding needed
        # Check for interface-level OSPF authentication
        ip_ospf_auth_key = parser.find_objects(r"ip ospf message-digest-key|ip ospf authentication key-chain")
        # Check for area authentication configured under router ospf
        area_auth = any(
            proc.re_search_children(r"area.*authentication")
            for proc in ospf_process
        )
        return len(ip_ospf_auth_key) > 0 or area_auth

    def _is_ospf_configured(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        ospf_process = parser.find_objects(r"^router ospf")
        return len(ospf_process) > 0

    def get_ospf_authentication(self, filename: str):
        if self._is_ospf_configured(filename) and not self._has_ospf_authentication(filename):
            return Issue(
                "OSPF authentication not configured",
                "OSPF is configured but authentication is not enabled. Without authentication, OSPF peers accept routing updates from any device on the segment.",
                "An attacker on the same network segment could inject malicious OSPF routing updates, enabling route hijacking, traffic interception, or denial of service by advertising false routes.",  # noqa: E501
                "Injecting OSPF updates requires only an OSPF-capable device on the same network segment. Tools such as Scapy or GNS3 can be used to craft and inject OSPF packets.",  # noqa: E501
                "Enable **OSPF** **MD5** authentication on all OSPF interfaces and areas:\n\n```\ninterface <type> <number>\n ip ospf message-digest-key <key-id> md5 <key>\nrouter ospf <process-id>\n area <area-id> authentication message-digest\n```",  # noqa: E501
                "CIS 6.1.1"
            )
        return None

    def _is_eigrp_configured(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        eigrp = parser.find_objects(r"^router eigrp")
        return len(eigrp) > 0

    def _has_eigrp_authentication(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        # Interface-level EIGRP authentication via key chains
        auth_mode = parser.find_objects(r"ip authentication mode eigrp")
        auth_key = parser.find_objects(r"ip authentication key-chain eigrp")
        return len(auth_mode) > 0 and len(auth_key) > 0

    # CIS 6.2.1 - EIGRP authentication
    def get_eigrp_authentication(self, filename: str):
        if self._is_eigrp_configured(filename) and not self._has_eigrp_authentication(filename):
            return Issue(
                "EIGRP authentication not configured",
                "EIGRP is configured but neighbor authentication is not enabled. Without authentication, EIGRP accepts routing updates from any neighbor.",
                "An attacker on the same network segment could inject malicious EIGRP routing updates, enabling route hijacking and traffic redirection.",  # noqa: E501
                "EIGRP update injection requires only a device on the same network segment and EIGRP-capable software.",  # noqa: E501
                "Configure **EIGRP** **MD5** authentication using key chains on all EIGRP-participating interfaces:\n\n```\ninterface <type> <number>\n ip authentication mode eigrp <as-number> md5\n ip authentication key-chain eigrp <as-number> <key-chain-name>\n```",  # noqa: E501
                "CIS 6.2.1"
            )
        return None

    def _is_bgp_configured(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        bgp = parser.find_objects(r"^router bgp")
        return len(bgp) > 0

    def _has_bgp_authentication(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        # BGP neighbor password configured under router bgp
        bgp_procs = parser.find_objects(r"^router bgp")
        for bgp_proc in bgp_procs:
            if bgp_proc.re_search_children(r"neighbor.*password"):
                return True
        return False

    # CIS 6.3.1 - BGP authentication
    def get_bgp_authentication(self, filename: str):
        if self._is_bgp_configured(filename) and not self._has_bgp_authentication(filename):
            return Issue(
                "BGP neighbor authentication not configured",
                "BGP is configured but MD5 neighbor authentication is not enabled. Without authentication, BGP sessions can be hijacked or disrupted by a third party.",
                "BGP session hijacking or injection of malicious route updates can redirect Internet traffic, cause denial-of-service conditions, or intercept data. BGP is a critical protocol for Internet routing.",  # noqa: E501
                "BGP attacks such as TCP RST injection and session hijacking are well-documented. An attacker on the path between BGP peers can disrupt sessions without MD5 authentication.",  # noqa: E501
                "Configure **MD5** authentication for all **BGP** neighbors, and consider adding TTL security (GTSM):\n\n```\nrouter bgp <as-number>\n neighbor <ip-address> password <strong-password>\n neighbor <ip-address> ttl-security hops 1\n```",  # noqa: E501
                "CIS 6.3.1"
            )
        return None

    def _is_rip_configured(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        rip = parser.find_objects(r"^router rip")
        return len(rip) > 0

    def _has_ripv2_authentication(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        rip_auth = parser.find_objects(r"ip rip authentication mode")
        rip_key = parser.find_objects(r"ip rip authentication key-chain")
        return len(rip_auth) > 0 and len(rip_key) > 0

    # CIS 6.4.1 - RIP version and authentication
    def get_rip_version_and_auth(self, filename: str):
        if self._is_rip_configured(filename):
            parser = self.parse_cisco_ios_config_file(filename)
            rip_procs = parser.find_objects(r"^router rip")
            version_2 = any(proc.re_search_children(r"version 2") for proc in rip_procs)
            if not version_2:
                return Issue(
                    "RIPv1 in use instead of RIPv2",
                    "RIP version 1 (RIPv1) is configured. RIPv1 does not support authentication and broadcasts routing updates to all hosts on the segment.",
                    "RIPv1 routing updates can be intercepted and injected by any host on the same broadcast domain, enabling route poisoning and traffic redirection attacks.",  # noqa: E501
                    "Injecting RIPv1 updates requires only basic networking tools and access to the broadcast domain.",  # noqa: E501
                    "Upgrade to **RIPv2** and enable **MD5** authentication on all participating interfaces:\n\n```\nrouter rip\n version 2\ninterface <type> <number>\n ip rip authentication mode md5\n ip rip authentication key-chain <key-chain-name>\n```",  # noqa: E501
                    "CIS 6.4.1"
                )
            if not self._has_ripv2_authentication(filename):
                return Issue(
                    "RIPv2 authentication not configured",
                    "RIPv2 is configured but authentication is not enabled. Without authentication, RIPv2 accepts routing updates from any source.",
                    "RIPv2 routing updates can be injected by any host on the same broadcast domain, enabling route poisoning, traffic redirection, and denial of service.",  # noqa: E501
                    "Injecting RIPv2 updates requires only basic networking tools and access to the broadcast domain.",  # noqa: E501
                    "Enable **MD5** authentication for **RIPv2** on all participating interfaces:\n\n```\ninterface <type> <number>\n ip rip authentication mode md5\n ip rip authentication key-chain <key-chain-name>\n```",  # noqa: E501
                    "CIS 6.4.1"
                )
        return None

    def analyze(self, config_file) -> None:
        issues = []

        issues.append(self.get_ospf_authentication(config_file))
        issues.append(self.get_eigrp_authentication(config_file))
        issues.append(self.get_bgp_authentication(config_file))
        issues.append(self.get_rip_version_and_auth(config_file))

        for issue in issues:
            if issue is not None:
                self.add_issue(issue)
