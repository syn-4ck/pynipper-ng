# flake8: noqa
# CIS Cisco IOS Benchmark references:
#   5.1.1  - Ensure 'exec-timeout' is configured to 5 minutes or less on console line
#   5.1.2  - Ensure 'transport input none' is set on the console line
#   5.1.3  - Ensure 'login' (authentication) is configured on the console line
#   5.1.4  - Ensure 'logging synchronous' is configured on the console line

from ..core.base_plugin import BasePlugin
from ....common.issue.issue import Issue


class PluginLineConsole(BasePlugin):

    def __init__(self):
        super().__init__()

    def name(self):
        return "Line Console Security"

    # CIS 5.1.1 - exec-timeout on console line

    def _get_console_timeout(self, filename: str) -> int:
        """Return console exec-timeout in minutes (0 = no timeout / not set)."""
        parser = self.parse_cisco_ios_config_file(filename)
        console_lines = parser.find_objects(r"^line con(sole)?\s+0")
        for line in console_lines:
            timeout = line.re_search_children(r"exec-timeout")
            if timeout:
                match = timeout[0].re_match_typed(
                    r'exec-timeout\s+(\d+)', default='')
                if match:
                    return int(match)
        return -1  # not configured

    def get_console_exec_timeout(self, filename: str):
        timeout = self._get_console_timeout(filename)
        if timeout == -1:
            return Issue(
                "Console exec-timeout not configured",
                "The console line does not have an exec-timeout configured. Without a timeout, an unattended console session remains active indefinitely.",
                "An unattended console session could be used by an unauthorized person with physical access to the device to gain full administrative access without authentication.",  # noqa: E501
                "Physical access to the console port means the attacker does not need any credentials if a session is already active.",  # noqa: E501
                "Configure an exec-timeout on the console line to disconnect idle sessions (5 minutes or less recommended):\n\n```\nline console 0\n exec-timeout 5 0\n```",  # noqa: E501
                "CIS 5.1.1"
            )
        if timeout == 0:
            return Issue(
                "Console exec-timeout set to 0 (disabled)",
                "The console line exec-timeout is configured to 0, which disables the timeout. An unattended console session will remain active indefinitely.",
                "An unattended console session could be used by an unauthorized person with physical access to gain full administrative control of the device.",  # noqa: E501
                "Physical access to the console port means no credentials are required if a session is already active.",  # noqa: E501
                "Set a non-zero exec-timeout on the console line:\n\n```\nline console 0\n exec-timeout 5 0\n```",  # noqa: E501
                "CIS 5.1.1"
            )
        return None

    def _console_has_transport_input_none(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        console_lines = parser.find_objects(r"^line con(sole)?\s+0")
        for line in console_lines:
            transport = line.re_search_children(r"transport input")
            if transport:
                match = transport[0].re_match_typed(r'transport input\s+(\S+)', default='')
                if match.lower() == 'none':
                    return True
        return False

    # CIS 5.1.2 - transport input none on console line
    def get_console_transport_input(self, filename: str):
        if not self._console_has_transport_input_none(filename):
            return Issue(
                "Console transport input not restricted",
                "The console line does not explicitly restrict inbound transport protocols. It is recommended to set 'transport input none' on the console line.",
                "Leaving transport input unrestricted on the console line may allow inbound connections from methods other than direct physical access, which is not standard practice.",  # noqa: E501
                "Exploitation depends on the specific IOS version and configuration but is mitigated by physical security.",  # noqa: E501
                "Restrict inbound connections on the console line:\n\n```\nline console 0\n transport input none\n```",  # noqa: E501
                "CIS 5.1.2"
            )
        return None

    def _console_has_login(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        console_lines = parser.find_objects(r"^line con(sole)?\s+0")
        for line in console_lines:
            login = line.re_search_children(r"login")
            if login:
                return True
        return False

    # CIS 5.1.3 - login authentication on console line
    def get_console_login(self, filename: str):
        if not self._console_has_login(filename):
            return Issue(
                "Console login not configured",
                "The console line does not have a login requirement configured. Without login authentication, anyone with physical access to the device can access the CLI without a password.",
                "Without console authentication, physical access to the device immediately grants full CLI access. This is a critical control for physical security.",  # noqa: E501
                "Physical access to the console port bypasses all network-based security controls.",  # noqa: E501
                "Configure login authentication on the console line using **AAA** or a local password:\n\n```\nline console 0\n login authentication <list-name>\n```",  # noqa: E501
                "CIS 5.1.3"
            )
        return None

    def _console_has_logging_sync(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        console_lines = parser.find_objects(r"^line con(sole)?\s+0")
        for line in console_lines:
            sync = line.re_search_children(r"logging synchronous")
            if sync:
                return True
        return False

    # CIS 5.1.4 - logging synchronous on console line
    def get_console_logging_sync(self, filename: str):
        if not self._console_has_logging_sync(filename):
            return Issue(
                "Console logging synchronous not configured",
                "The 'logging synchronous' command is not configured on the console line. Without it, log messages can interrupt command entry, potentially causing administrators to miss prompts or accidentally execute wrong commands.",  # noqa: E501
                "Without logging synchronous, log messages can corrupt the display of partial commands or prompts, causing configuration errors during administration.",  # noqa: E501
                "This is a usability and operational risk, and not directly exploitable.",  # noqa: E501
                "Enable synchronous logging on the console line:\n\n```\nline console 0\n logging synchronous\n```",  # noqa: E501
                "CIS 5.1.4"
            )
        return None

    def analyze(self, config_file) -> None:
        issues = []

        issues.append(self.get_console_exec_timeout(config_file))
        issues.append(self.get_console_transport_input(config_file))
        issues.append(self.get_console_login(config_file))
        issues.append(self.get_console_logging_sync(config_file))

        for issue in issues:
            if issue is not None:
                self.add_issue(issue)
