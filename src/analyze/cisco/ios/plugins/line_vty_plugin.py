# flake8: noqa
# CIS Cisco IOS Benchmark references:
#   5.2.1  - Ensure 'access-class' is configured on all VTY lines
#   5.2.2  - Ensure 'exec-timeout' ≤ 10 minutes is set on all VTY lines
#   5.2.3  - Ensure 'transport input ssh' is set on all VTY lines
#   5.2.4  - Ensure 'logging synchronous' is configured on all VTY lines
#   5.2.5  - Ensure 'login authentication' is configured on all VTY lines

from ..core.base_plugin import BasePlugin
from ....common.issue.issue import Issue


class PluginLineVTY(BasePlugin):

    def __init__(self):
        super().__init__()

    def name(self):
        return "Line VTY Security"

    # CIS 5.2.1 - access-class on all VTY lines

    def _get_vty_lines(self, filename: str) -> list:
        parser = self.parse_cisco_ios_config_file(filename)
        return parser.find_objects(r"^line vty")

    def _vty_lines_have_acl(self, filename: str) -> bool:
        vty_lines = self._get_vty_lines(filename)
        for line in vty_lines:
            acl = line.re_search_children(r"access-class")
            if not acl:
                return False
        return len(vty_lines) > 0

    def get_vty_access_class(self, filename: str):
        if not self._vty_lines_have_acl(filename):
            return Issue(
                "VTY lines not restricted by access-class",
                "One or more VTY lines do not have an access-class configured to restrict which hosts can initiate remote management connections (SSH/Telnet).",
                "Without an access-class, any host on any network can attempt to connect to the management interfaces of the device. This significantly increases the attack surface for brute-force and unauthorized access attacks.",  # noqa: E501
                "Any host with IP connectivity to the device can attempt to connect to the VTY lines. Brute-force tools for SSH and Telnet are widely available.",  # noqa: E501
                "Apply an ACL to all VTY lines to restrict access to authorised management hosts:\n\n```\naccess-list 10 permit <mgmt-host>\naccess-list 10 deny any\nline vty 0 4\n access-class 10 in\n```",  # noqa: E501
                "CIS 5.2.1"
            )
        return None

    def _vty_lines_have_exec_timeout(self, filename: str) -> bool:
        vty_lines = self._get_vty_lines(filename)
        for line in vty_lines:
            timeout = line.re_search_children(r"exec-timeout")
            if not timeout:
                return False
            match = timeout[0].re_match_typed(r'exec-timeout\s+(\d+)', default='')
            if not match or int(match) == 0:
                return False
        return len(vty_lines) > 0

    # CIS 5.2.2 - exec-timeout on all VTY lines
    def get_vty_exec_timeout(self, filename: str):
        if not self._vty_lines_have_exec_timeout(filename):
            return Issue(
                "VTY exec-timeout not configured or disabled",
                "One or more VTY lines do not have a non-zero exec-timeout configured. Without a timeout, idle VTY sessions remain open indefinitely.",
                "An idle authenticated session that remains open can be hijacked by an attacker who gains access to the network. Unlimited sessions also consume device resources.",  # noqa: E501
                "Session hijacking of idle connections is possible in some network environments. Keeping sessions open indefinitely increases the exposure window.",  # noqa: E501
                "Configure a non-zero exec-timeout on all VTY lines (10 minutes or less recommended):\n\n```\nline vty 0 4\n exec-timeout 10 0\n```",  # noqa: E501
                "CIS 5.2.2"
            )
        return None

    def _vty_lines_transport_ssh_only(self, filename: str) -> bool:
        vty_lines = self._get_vty_lines(filename)
        for line in vty_lines:
            transport = line.re_search_children(r"transport input")
            if not transport:
                return False
            match = transport[0].re_match_typed(r'transport input\s+(.+)', default='').strip().lower()
            if match not in ('ssh', 'ssh ssh'):
                return False
        return len(vty_lines) > 0

    # CIS 5.2.3 - transport input ssh only on all VTY lines
    def get_vty_transport_input_ssh(self, filename: str):
        if not self._vty_lines_transport_ssh_only(filename):
            return Issue(
                "VTY transport input not restricted to SSH",
                "One or more VTY lines allow transport protocols other than SSH (such as Telnet). SSH is the only encrypted remote management protocol that should be permitted.",
                "Allowing Telnet or other cleartext protocols on VTY lines exposes authentication credentials and session data to network eavesdropping.",  # noqa: E501
                "Packet capture of Telnet sessions is trivial with freely available tools such as Wireshark and can immediately expose administrative credentials.",  # noqa: E501
                "Restrict VTY line input to SSH only:\n\n```\nline vty 0 4\n transport input ssh\n```",  # noqa: E501
                "CIS 5.2.3"
            )
        return None

    def _vty_lines_have_logging_sync(self, filename: str) -> bool:
        vty_lines = self._get_vty_lines(filename)
        for line in vty_lines:
            sync = line.re_search_children(r"logging synchronous")
            if not sync:
                return False
        return len(vty_lines) > 0

    # CIS 5.2.4 - logging synchronous on all VTY lines
    def get_vty_logging_sync(self, filename: str):
        if not self._vty_lines_have_logging_sync(filename):
            return Issue(
                "VTY logging synchronous not configured",
                "The 'logging synchronous' command is not configured on all VTY lines. Without it, asynchronous log messages can interrupt command entry and corrupt the display.",
                "Asynchronous log messages interrupting command entry can cause administrators to accidentally execute unintended commands, potentially misconfiguring the device.",  # noqa: E501
                "This is an operational risk that could lead to accidental configuration errors rather than a directly exploitable vulnerability.",  # noqa: E501
                "Enable synchronous logging on all VTY lines:\n\n```\nline vty 0 4\n logging synchronous\n```",  # noqa: E501
                "CIS 5.2.4"
            )
        return None

    def _vty_lines_have_login_authentication(self, filename: str) -> bool:
        vty_lines = self._get_vty_lines(filename)
        for line in vty_lines:
            login = line.re_search_children(r"login")
            if not login:
                return False
        return len(vty_lines) > 0

    # CIS 5.2.5 - login authentication on all VTY lines
    def get_vty_login(self, filename: str):
        if not self._vty_lines_have_login_authentication(filename):
            return Issue(
                "VTY login authentication not configured",
                "One or more VTY lines do not have a login authentication requirement configured. Without login, a remote user connecting to the VTY line may gain CLI access without providing any credentials.",  # noqa: E501
                "Without authentication on VTY lines, any host permitted by the access-class (or any host if no access-class is defined) can access the device CLI without a password.",  # noqa: E501
                "Connecting to an unauthenticated VTY line requires only IP connectivity to the device.",  # noqa: E501
                "Configure login authentication on all VTY lines using **AAA** or local credentials:\n\n```\nline vty 0 4\n login authentication <list-name>\n```",  # noqa: E501
                "CIS 5.2.5"
            )
        return None

    def analyze(self, config_file) -> None:
        issues = []

        issues.append(self.get_vty_access_class(config_file))
        issues.append(self.get_vty_exec_timeout(config_file))
        issues.append(self.get_vty_transport_input_ssh(config_file))
        issues.append(self.get_vty_logging_sync(config_file))
        issues.append(self.get_vty_login(config_file))

        for issue in issues:
            if issue is not None:
                self.add_issue(issue)
