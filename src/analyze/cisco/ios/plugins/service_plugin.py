# flake8: noqa
# CIS Cisco IOS Benchmark references:
#   1.1.1  - Ensure 'no service pad' is set
#   1.1.2  - Ensure 'no service udp-small-servers' is set
#   1.1.3  - Ensure 'no service tcp-small-servers' is set
#   1.1.4  - Ensure 'no ip bootp server' is set
#   1.1.5  - Ensure 'no ip finger' is set
#   1.1.6  - Ensure 'no ip identd' is set
#   1.1.7  - Ensure 'no service config' is set
#   1.2.1  - Ensure 'service tcp-keepalives-in' and 'service tcp-keepalives-out' are set
#   1.2.2  - Ensure 'ip tcp synwait-time' <= 10 is set
#   1.2.3  - Ensure 'no mop enabled' is set on all Ethernet interfaces
#   1.2.4  - Ensure 'no ip gratuitous-arps' is set

from ..core.base_plugin import BasePlugin
from ....common.issue.issue import Issue


class PluginService(BasePlugin):

    def __init__(self):
        super().__init__()

    def name(self):
        return "Global Services Security"

    # CIS 1.1.1 - Ensure 'no service pad' is set
    def _has_no_service_pad(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        return len(parser.find_objects(r"^no service pad")) > 0

    def get_service_pad(self, filename: str):
        if not self._has_no_service_pad(filename):
            return Issue(
                "PAD service not disabled",
                "The Packet Assembler/Disassembler (PAD) service is enabled. PAD is associated with legacy X.25 networks and has no use on modern IOS deployments.",  # noqa: E501
                "Unnecessary services increase the attack surface of the device. Disabling unused services follows the principle of least functionality.",  # noqa: E501
                "This is a configuration hygiene issue; PAD exploitation is extremely rare on modern networks.",  # noqa: E501
                "Disable the PAD service:\n\n```\nno service pad\n```",  # noqa: E501
                "CIS 1.1.1"
            )
        return None

    # CIS 1.1.2 - Ensure 'no service udp-small-servers' is set
    def _has_no_udp_small_servers(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        return len(parser.find_objects(r"^no service udp-small-servers")) > 0

    def get_udp_small_servers(self, filename: str):
        if not self._has_no_udp_small_servers(filename):
            return Issue(
                "UDP small servers not disabled",
                "UDP small servers (echo, discard, daytime, chargen) are enabled. These services are unused in modern networks and can participate in amplification attacks.",  # noqa: E501
                "The chargen and echo services can be paired to create traffic loops between two devices, consuming bandwidth and CPU. They can also be abused in UDP reflection/amplification attacks.",  # noqa: E501
                "Sending a single UDP packet to the chargen port is sufficient to trigger a high-volume response; no authentication is needed.",  # noqa: E501
                "Disable UDP small servers:\n\n```\nno service udp-small-servers\n```",  # noqa: E501
                "CIS 1.1.2"
            )
        return None

    # CIS 1.1.3 - Ensure 'no service tcp-small-servers' is set
    def _has_no_tcp_small_servers(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        return len(parser.find_objects(r"^no service tcp-small-servers")) > 0

    def get_tcp_small_servers(self, filename: str):
        if not self._has_no_tcp_small_servers(filename):
            return Issue(
                "TCP small servers not disabled",
                "TCP small servers (echo, discard, daytime, chargen) are enabled. These services are unnecessary and expose the device to information disclosure and traffic loop attacks.",  # noqa: E501
                "TCP small servers can reveal device uptime (daytime) and be used to generate traffic loops between devices. This can cause CPU load and aid attacker reconnaissance.",  # noqa: E501
                "Connecting to TCP small server ports is trivial with any TCP client.",  # noqa: E501
                "Disable TCP small servers:\n\n```\nno service tcp-small-servers\n```",  # noqa: E501
                "CIS 1.1.3"
            )
        return None

    # CIS 1.1.4 - Ensure 'no ip bootp server' is set
    def _has_no_bootp_server(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        return len(parser.find_objects(r"^no ip bootp server")) > 0

    def get_bootp_server(self, filename: str):
        if not self._has_no_bootp_server(filename):
            return Issue(
                "BOOTP server not disabled",
                "The BOOTP server is enabled. BOOTP is a legacy protocol replaced by DHCP and is not required on modern network infrastructure devices.",  # noqa: E501
                "BOOTP has no authentication mechanism. Any host on a connected segment can send BOOTP requests to obtain network configuration information or exhaust the address pool.",  # noqa: E501
                "Sending BOOTP requests requires only a UDP socket and is trivial with standard tools.",  # noqa: E501
                "Disable the BOOTP server:\n\n```\nno ip bootp server\n```",  # noqa: E501
                "CIS 1.1.4"
            )
        return None

    # CIS 1.1.5 - Ensure 'no ip finger' is set
    def _has_no_ip_finger(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        return len(parser.find_objects(r"^no ip finger|^no service finger")) > 0

    def get_ip_finger(self, filename: str):
        if not self._has_no_ip_finger(filename):
            return Issue(
                "Finger service not disabled",
                "The Finger service is enabled. Finger responds to unauthenticated queries with information about active users and sessions on the device.",  # noqa: E501
                "The Finger service discloses usernames and active session information without any authentication, aiding attacker reconnaissance.",  # noqa: E501
                "Querying the Finger service is possible with any Finger client, which are bundled with most Unix/Linux systems.",  # noqa: E501
                "Disable the Finger service:\n\n```\nno ip finger\n```",  # noqa: E501
                "CIS 1.1.5"
            )
        return None

    # CIS 1.1.6 - Ensure 'no ip identd' is set
    def _has_no_ip_identd(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        return len(parser.find_objects(r"^no ip identd")) > 0

    def get_ip_identd(self, filename: str):
        if not self._has_no_ip_identd(filename):
            return Issue(
                "Identification service (identd) not disabled",
                "The identd service is enabled. This protocol identifies the owner of TCP connections and is not required on network devices.",  # noqa: E501
                "The identd service can expose information about internal processes and sessions, aiding targeted attacks.",  # noqa: E501
                "Querying identd requires only a TCP connection to port 113.",  # noqa: E501
                "Disable identd:\n\n```\nno ip identd\n```",  # noqa: E501
                "CIS 1.1.6"
            )
        return None

    # CIS 1.1.7 - Ensure 'no service config' is set
    def _has_no_service_config(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        return len(parser.find_objects(r"^no service config")) > 0

    def get_service_config(self, filename: str):
        if not self._has_no_service_config(filename):
            return Issue(
                "Auto-configuration from network (service config) not disabled",
                "'no service config' is not set. The device may attempt to load its startup configuration from a TFTP server, allowing a rogue server to replace the device configuration.",  # noqa: E501
                "If an attacker can intercept or spoof TFTP responses during device boot, they can replace the entire device configuration, including ACLs and credentials.",  # noqa: E501
                "Exploiting this requires the ability to respond to TFTP requests before the legitimate server does (e.g., via MITM or rogue TFTP server on the local segment).",  # noqa: E501
                "Disable automatic configuration loading from the network:\n\n```\nno service config\n```",  # noqa: E501
                "CIS 1.1.7"
            )
        return None

    # CIS 1.2.1 - Ensure TCP keepalives-in and keepalives-out are set
    def _has_tcp_keepalives(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        keepalives_in = parser.find_objects(r"^service tcp-keepalives-in")
        keepalives_out = parser.find_objects(r"^service tcp-keepalives-out")
        return len(keepalives_in) > 0 and len(keepalives_out) > 0

    def get_tcp_keepalives(self, filename: str):
        if not self._has_tcp_keepalives(filename):
            return Issue(
                "TCP keepalives not enabled",
                "'service tcp-keepalives-in' and/or 'service tcp-keepalives-out' are not configured. Without keepalives, stale TCP sessions remain open indefinitely.",  # noqa: E501
                "Orphaned TCP sessions consume connection table entries and memory. An attacker can deliberately abandon connections to exhaust device resources (half-open connection attack).",  # noqa: E501
                "Flooding a device with half-open TCP connections requires only basic network access and standard packet-generation tools.",  # noqa: E501
                "Enable TCP keepalives in both directions:\n\n```\nservice tcp-keepalives-in\nservice tcp-keepalives-out\n```",  # noqa: E501
                "CIS 1.2.1"
            )
        return None

    # CIS 1.2.2 - Ensure 'ip tcp synwait-time' <= 10 is set
    def _get_tcp_synwait(self, filename: str) -> int:
        parser = self.parse_cisco_ios_config_file(filename)
        objs = parser.find_objects(r"^ip tcp synwait-time")
        if objs:
            val = objs[0].re_match_typed(r'^ip tcp synwait-time\s+(\d+)', default='')
            return int(val) if val else 0
        return 0

    def get_tcp_synwait_time(self, filename: str):
        synwait = self._get_tcp_synwait(filename)
        if synwait == 0:
            return Issue(
                "TCP SYN wait time not configured",
                "'ip tcp synwait-time' is not configured. The default IOS value is 30 seconds, meaning half-open TCP connections are held for up to 30 seconds before timing out.",  # noqa: E501
                "A long SYN wait time makes the device more susceptible to TCP SYN flood attacks. An attacker can exhaust the device's half-open connection table by sending many SYN packets, causing connection handling to degrade.",  # noqa: E501
                "TCP SYN flood attacks are trivial to execute with standard packet-generation tools and require no authentication.",  # noqa: E501
                "Set the TCP SYN wait time to 10 seconds or less:\n\n```\nip tcp synwait-time 10\n```",  # noqa: E501
                "CIS 1.2.2"
            )
        if synwait > 10:
            return Issue(
                "TCP SYN wait time too long",
                f"The TCP SYN wait time is configured to {synwait} seconds. The CIS Benchmark recommends 10 seconds or less.",  # noqa: E501
                "A long SYN wait time increases the window during which incomplete TCP connections occupy resources, amplifying the impact of SYN flood denial-of-service attacks.",  # noqa: E501
                "TCP SYN flood attacks are trivial to execute and require no authentication.",  # noqa: E501
                "Reduce the TCP SYN wait time:\n\n```\nip tcp synwait-time 10\n```",  # noqa: E501
                "CIS 1.2.2"
            )
        return None

    # CIS 1.2.3 - Ensure MOP is disabled on all Ethernet interfaces
    def _has_mop_on_ethernet_interfaces(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        eth_ifaces = parser.find_objects(r"^interface [Ee]thernet|^interface [Ff]ast[Ee]thernet|^interface [Gg]ig|^interface [Tt]en[Gg]")
        for iface in eth_ifaces:
            no_mop = iface.re_search_children(r"no mop enabled")
            if not no_mop:
                return True  # at least one interface has MOP enabled
        return False

    def get_mop_disabled(self, filename: str):
        if self._has_mop_on_ethernet_interfaces(filename):
            return Issue(
                "MOP (Maintenance Operations Protocol) enabled on Ethernet interfaces",
                "MOP is enabled on one or more Ethernet interfaces. MOP is a legacy DEC protocol that serves no purpose on modern IOS deployments and exposes an unnecessary service on the interface.",  # noqa: E501
                "MOP provides remote boot and diagnostics capabilities without authentication. An attacker on the same L2 segment could potentially use MOP to send diagnostic commands or gather information about the device.",  # noqa: E501
                "Exploiting MOP requires L2 access to the segment. MOP tooling exists in legacy network management platforms.",  # noqa: E501
                "Disable MOP on all Ethernet interfaces:\n\n```\ninterface <type> <number>\n no mop enabled\n```",  # noqa: E501
                "CIS 1.2.3"
            )
        return None

    # CIS 1.2.4 - Ensure 'no ip gratuitous-arps' is set
    def _has_no_gratuitous_arps(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        return len(parser.find_objects(r"^no ip gratuitous-arps")) > 0

    def get_gratuitous_arps(self, filename: str):
        if not self._has_no_gratuitous_arps(filename):
            return Issue(
                "Gratuitous ARP responses not suppressed",
                "'no ip gratuitous-arps' is not configured. The device will respond to ARP requests for secondary addresses and will send gratuitous ARPs when an interface comes up.",  # noqa: E501
                "Gratuitous ARP responses can be exploited in ARP cache poisoning attacks. An attacker can trigger unsolicited ARP updates on the local segment, redirecting traffic intended for the device to a host they control.",  # noqa: E501
                "ARP poisoning attacks require only L2 access to the segment and are achievable with tools such as arpspoof or Scapy.",  # noqa: E501
                "Suppress gratuitous ARP on all interfaces:\n\n```\nno ip gratuitous-arps\n```",  # noqa: E501
                "CIS 1.2.4"
            )
        return None

    def analyze(self, config_file) -> None:
        issues = []

        issues.append(self.get_service_pad(config_file))
        issues.append(self.get_udp_small_servers(config_file))
        issues.append(self.get_tcp_small_servers(config_file))
        issues.append(self.get_bootp_server(config_file))
        issues.append(self.get_ip_finger(config_file))
        issues.append(self.get_ip_identd(config_file))
        issues.append(self.get_service_config(config_file))
        issues.append(self.get_tcp_keepalives(config_file))
        issues.append(self.get_tcp_synwait_time(config_file))
        issues.append(self.get_mop_disabled(config_file))
        issues.append(self.get_gratuitous_arps(config_file))

        for issue in issues:
            if issue is not None:
                self.add_issue(issue)

