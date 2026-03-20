# flake8: noqa
# CIS Cisco IOS Benchmark references:
#   2.1.5  - Ensure 'no ip directed-broadcast' is set on all interfaces
#   2.1.6  - Ensure 'no ip unreachables' is set on all interfaces
#   2.1.7  - Ensure 'no ip redirects' is set on all interfaces
#   2.1.8  - Ensure 'no ip mask-reply' is set on all interfaces
#   2.1.9  - Ensure ingress anti-spoofing ACL is applied on externally facing interfaces

from ..core.base_plugin import BasePlugin
from ....common.issue.issue import Issue


class PluginInterfaceSecurity(BasePlugin):

    def __init__(self):
        super().__init__()

    def name(self):
        return "Interface-Level Security"

    def _get_all_interfaces(self, filename: str) -> list:
        parser = self.parse_cisco_ios_config_file(filename)
        return parser.find_objects(r"^interface")

    # CIS 2.1.5 - Ensure 'no ip directed-broadcast' is set on all interfaces
    def _has_directed_broadcast_on_any_interface(self, filename: str) -> bool:
        """Returns True if any interface is missing 'no ip directed-broadcast'."""
        for iface in self._get_all_interfaces(filename):
            # IOS versions before 12.0 required explicit 'no ip directed-broadcast';
            # later versions disable it by default. Flag if 'ip directed-broadcast' is
            # explicitly enabled (without the 'no' prefix).
            db = iface.re_search_children(r"(?<!\bno\s)\bip directed-broadcast\b")
            if db:
                return True
        return False

    def get_ip_directed_broadcast(self, filename: str):
        if self._has_directed_broadcast_on_any_interface(filename):
            return Issue(
                "IP directed-broadcast enabled on one or more interfaces",
                "One or more interfaces have 'ip directed-broadcast' explicitly enabled. Directed broadcasts amplify traffic to all hosts on a subnet and were the basis of Smurf amplification attacks.",  # noqa: E501
                "Directed broadcasts can be exploited in Smurf DDoS attacks where an attacker sends ICMP echo requests to a subnet broadcast address, causing all hosts on the subnet to reply to the spoofed victim, generating large amounts of traffic.",  # noqa: E501
                "Smurf attacks require only the ability to send spoofed IP packets toward the targeted subnet broadcast address, which is achievable with standard tools on permissive networks.",  # noqa: E501
                "Disable IP directed broadcasts on all interfaces:\n\n```\ninterface <type> <number>\n no ip directed-broadcast\n```",  # noqa: E501
                "CIS 2.1.5"
            )
        return None

    # CIS 2.1.6 - Ensure 'no ip unreachables' is set on all interfaces
    def _has_ip_unreachables_on_any_interface(self, filename: str) -> bool:
        """Returns True if any interface is missing the 'no ip unreachables' command."""
        for iface in self._get_all_interfaces(filename):
            no_unreach = iface.re_search_children(r"no ip unreachables")
            if not no_unreach:
                return True
        return False

    def get_ip_unreachables(self, filename: str):
        if self._has_ip_unreachables_on_any_interface(filename):
            return Issue(
                "ICMP unreachable messages not disabled on all interfaces",
                "One or more interfaces send ICMP unreachable messages. These messages expose routing topology and can aid network reconnaissance and DoS attacks.",  # noqa: E501
                "ICMP unreachables reveal whether specific hosts or ports are accessible, enabling network mapping. They also participate in path MTU discovery and can be abused in certain fragmentation and denial-of-service attacks.",  # noqa: E501
                "Sending packets to closed ports or unreachable destinations and observing ICMP replies is a standard reconnaissance technique.",  # noqa: E501
                "Disable ICMP unreachable messages on all interfaces:\n\n```\ninterface <type> <number>\n no ip unreachables\n```",  # noqa: E501
                "CIS 2.1.6"
            )
        return None

    # CIS 2.1.7 - Ensure 'no ip redirects' is set on all interfaces
    def _has_ip_redirects_on_any_interface(self, filename: str) -> bool:
        """Returns True if any interface is missing 'no ip redirects'."""
        for iface in self._get_all_interfaces(filename):
            no_redir = iface.re_search_children(r"no ip redirects")
            if not no_redir:
                return True
        return False

    def get_ip_redirects(self, filename: str):
        if self._has_ip_redirects_on_any_interface(filename):
            return Issue(
                "ICMP redirects not disabled on all interfaces",
                "One or more interfaces send ICMP redirect messages. ICMP redirects can be used to manipulate the routing decisions of hosts on the same subnet.",  # noqa: E501
                "ICMP redirect messages instruct hosts to change their routing path. An attacker who can send crafted ICMP redirect packets to hosts can redirect traffic through a host they control, enabling man-in-the-middle attacks.",  # noqa: E501
                "Crafting and injecting ICMP redirect packets requires only L2 or L3 access to the same network segment and standard packet-crafting tools.",  # noqa: E501
                "Disable ICMP redirects on all interfaces:\n\n```\ninterface <type> <number>\n no ip redirects\n```",  # noqa: E501
                "CIS 2.1.7"
            )
        return None

    # CIS 2.1.8 - Ensure 'no ip mask-reply' is set on all interfaces
    def _has_ip_mask_reply_on_any_interface(self, filename: str) -> bool:
        """Returns True if any interface is missing 'no ip mask-reply'."""
        for iface in self._get_all_interfaces(filename):
            no_mask = iface.re_search_children(r"no ip mask-reply")
            if not no_mask:
                return True
        return False

    def get_ip_mask_reply(self, filename: str):
        if self._has_ip_mask_reply_on_any_interface(filename):
            return Issue(
                "ICMP mask reply not disabled on all interfaces",
                "One or more interfaces respond to ICMP address mask requests. ICMP mask replies expose the subnet mask configuration of attached interfaces.",  # noqa: E501
                "ICMP mask replies disclose subnet mask information to unauthenticated requesters, aiding network topology reconnaissance.",  # noqa: E501
                "Sending ICMP mask request packets is trivial with standard tools like Nmap or Scapy.",  # noqa: E501
                "Disable ICMP mask replies on all interfaces:\n\n```\ninterface <type> <number>\n no ip mask-reply\n```",  # noqa: E501
                "CIS 2.1.8"
            )
        return None

    # CIS 2.1.9 - Ensure anti-spoofing (ingress filtering) ACL on external interfaces
    def _has_antispoofing_acl(self, filename: str) -> bool:
        """
        Heuristic: look for interfaces with 'ip access-group ... in' applied.
        A dedicated interface marked with a description containing 'external',
        'outside', 'internet', or 'wan' without any inbound ACL is flagged.
        """
        parser = self.parse_cisco_ios_config_file(filename)
        external_markers = r"(?i)(external|outside|internet|wan|untrusted|uplink)"
        ext_ifaces = []
        for iface in parser.find_objects(r"^interface"):
            desc = iface.re_search_children(r"description")
            if desc:
                desc_text = desc[0].re_match_typed(r'description\s+(.+)', default='')
                import re
                if re.search(external_markers, desc_text):
                    ext_ifaces.append(iface)

        if not ext_ifaces:
            return True  # Cannot determine; no marked external interfaces found

        for iface in ext_ifaces:
            acl_in = iface.re_search_children(r"ip access-group\s+\S+\s+in")
            if not acl_in:
                return False  # external interface missing inbound ACL
        return True

    def get_antispoofing_acl(self, filename: str):
        if not self._has_antispoofing_acl(filename):
            return Issue(
                "Anti-spoofing ingress ACL missing on external interface(s)",
                "One or more interfaces described as external/outside/WAN do not have an inbound ACL applied. Without ingress filtering, spoofed source IP packets can enter the device from untrusted networks.",  # noqa: E501
                "Without ingress anti-spoofing ACLs, attackers can inject packets with forged source addresses (RFC 1918 ranges, loopback, etc.) that bypass source-based security controls and enable DoS amplification attacks against internal hosts.",  # noqa: E501\n
                "IP source spoofing is trivial with standard packet-crafting tools. BCP38 ingress filtering is widely recommended to prevent it, but must be configured explicitly.",  # noqa: E501
                "Apply an inbound anti-spoofing ACL on all externally facing interfaces.\nDeny RFC 1918, loopback, and other bogon source addresses arriving from untrusted interfaces:\n\n```\nip access-list extended ANTISPOOFING-IN\n deny ip 10.0.0.0 0.255.255.255 any\n deny ip 172.16.0.0 0.15.255.255 any\n deny ip 192.168.0.0 0.0.255.255 any\n deny ip 127.0.0.0 0.255.255.255 any\n permit ip any any\ninterface <external-interface>\n ip access-group ANTISPOOFING-IN in\n```",  # noqa: E501
                "CIS 2.1.9"
            )
        return None

    def analyze(self, config_file) -> None:
        issues = []

        issues.append(self.get_ip_directed_broadcast(config_file))
        issues.append(self.get_ip_unreachables(config_file))
        issues.append(self.get_ip_redirects(config_file))
        issues.append(self.get_ip_mask_reply(config_file))
        issues.append(self.get_antispoofing_acl(config_file))

        for issue in issues:
            if issue is not None:
                self.add_issue(issue)
