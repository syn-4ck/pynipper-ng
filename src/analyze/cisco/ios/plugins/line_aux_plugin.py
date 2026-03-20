# flake8: noqa
# CIS Cisco IOS Benchmark references:
#   5.3.1  - Ensure 'no exec' is set on the AUX line
#   5.3.2  - Ensure 'exec-timeout' <= 5 minutes is set on the AUX line
#   5.3.3  - Ensure 'transport input none' is set on the AUX line
#   5.3.4  - Ensure 'login authentication' is configured on the AUX line

from ..core.base_plugin import BasePlugin
from ....common.issue.issue import Issue


class PluginLineAux(BasePlugin):

    def __init__(self):
        super().__init__()

    def name(self):
        return "Line AUX Security"

    def _get_aux_line(self, filename: str):
        parser = self.parse_cisco_ios_config_file(filename)
        aux_lines = parser.find_objects(r"^line aux\s+0")
        return aux_lines[0] if aux_lines else None

    # CIS 5.3.1 - Ensure 'no exec' is set on the AUX line
    def _aux_has_no_exec(self, filename: str) -> bool:
        line = self._get_aux_line(filename)
        if line is None:
            return True  # AUX line not present; no issue
        no_exec = line.re_search_children(r"no exec")
        return len(no_exec) > 0

    def get_aux_no_exec(self, filename: str):
        line = self._get_aux_line(filename)
        if line is None:
            return None
        if not self._aux_has_no_exec(filename):
            return Issue(
                "AUX line EXEC process not disabled",
                "The 'no exec' command is not set on the AUX line (line aux 0). The AUX port is primarily used for out-of-band modem access and should not provide an interactive EXEC session without explicit need.",  # noqa: E501
                "An active EXEC process on the AUX port means that anyone who can connect a modem or console cable to the AUX port can attempt to start an interactive CLI session. This significantly increases the physical attack surface of the device.",  # noqa: E501
                "Physical access to the AUX port combined with a null-modem cable or modem is sufficient to attempt a login if the EXEC process is active.",  # noqa: E501
                "Disable the EXEC process on the AUX line. If the AUX port is unused, also restrict transport and set a short timeout:\n\n```\nline aux 0\n no exec\n transport input none\n exec-timeout 0 1\n```",  # noqa: E501
                "CIS 5.3.1"
            )
        return None

    # CIS 5.3.2 - Ensure 'exec-timeout' <= 5 minutes is set on the AUX line
    def _get_aux_timeout(self, filename: str) -> int:
        line = self._get_aux_line(filename)
        if line is None:
            return -1
        timeout = line.re_search_children(r"exec-timeout")
        if timeout:
            val = timeout[0].re_match_typed(r'exec-timeout\s+(\d+)', default='')
            return int(val) if val else -1
        return -1  # not configured

    def get_aux_exec_timeout(self, filename: str):
        line = self._get_aux_line(filename)
        if line is None:
            return None
        timeout = self._get_aux_timeout(filename)
        if timeout == -1:
            return Issue(
                "AUX line exec-timeout not configured",
                "No exec-timeout is configured on the AUX line (line aux 0). Without a timeout, an idle or abandoned session on the AUX port remains active indefinitely.",  # noqa: E501
                "An unattended active AUX session provides persistent unauthenticated access to anyone with physical access to the port or attached modem.",  # noqa: E501
                "Physical access to the AUX port is sufficient to exploit an unattended session.",  # noqa: E501
                "Set a short exec-timeout on the AUX line:\n\n```\nline aux 0\n exec-timeout 5 0\n```",  # noqa: E501
                "CIS 5.3.2"
            )
        if timeout == 0:
            return Issue(
                "AUX line exec-timeout set to 0 (disabled)",
                "The AUX line exec-timeout is configured to 0, which disables idle session termination. Sessions remain active indefinitely.",  # noqa: E501
                "An indefinitely active AUX session leaves the device exposed to unauthorized access via the physical AUX port at all times.",  # noqa: E501
                "Physical access to the AUX port is sufficient to exploit an unattended session.",  # noqa: E501
                "Set a non-zero exec-timeout on the AUX line:\n\n```\nline aux 0\n exec-timeout 5 0\n```",  # noqa: E501
                "CIS 5.3.2"
            )
        if timeout > 5:
            return Issue(
                "AUX line exec-timeout exceeds recommended 5 minutes",
                f"The AUX line exec-timeout is set to {timeout} minutes. The CIS Benchmark recommends 5 minutes or less for the AUX line.",  # noqa: E501
                "A long timeout on the AUX line increases the window during which an unattended session can be hijacked by someone with physical access to the device.",  # noqa: E501
                "Physical access to the AUX port is sufficient to exploit an unattended session.",  # noqa: E501
                "Reduce the AUX exec-timeout to 5 minutes or less:\n\n```\nline aux 0\n exec-timeout 5 0\n```",  # noqa: E501
                "CIS 5.3.2"
            )
        return None

    # CIS 5.3.3 - Ensure 'transport input none' is set on the AUX line
    def _aux_has_transport_input_none(self, filename: str) -> bool:
        line = self._get_aux_line(filename)
        if line is None:
            return True
        transport = line.re_search_children(r"transport input")
        if transport:
            match = transport[0].re_match_typed(r'transport input\s+(\S+)', default='').lower()
            return match == 'none'
        return False

    def get_aux_transport_input(self, filename: str):
        line = self._get_aux_line(filename)
        if line is None:
            return None
        if not self._aux_has_transport_input_none(filename):
            return Issue(
                "AUX line transport input not restricted to none",
                "The AUX line does not have 'transport input none' configured. This allows inbound connection attempts through the AUX port interface.",  # noqa: E501
                "Allowing inbound transport protocols on the AUX line means that remote actors (via attached modems) can initiate sessions. Restricting to 'none' disables all inbound protocol access on the AUX port.",  # noqa: E501\n
                "This depends on whether a modem is attached to the AUX port; the risk is realized if the port is in use.",  # noqa: E501
                "Disable all inbound transport on the AUX line:\n\n```\nline aux 0\n transport input none\n```",  # noqa: E501
                "CIS 5.3.3"
            )
        return None

    # CIS 5.3.4 - Ensure 'login authentication' is configured on the AUX line
    def _aux_has_login(self, filename: str) -> bool:
        line = self._get_aux_line(filename)
        if line is None:
            return True
        login = line.re_search_children(r"login")
        return len(login) > 0

    def get_aux_login(self, filename: str):
        line = self._get_aux_line(filename)
        if line is None:
            return None
        if not self._aux_has_login(filename):
            return Issue(
                "AUX line login authentication not configured",
                "No login authentication is configured on the AUX line (line aux 0). Without it, anyone who connects to the AUX port can access the CLI without supplying credentials.",  # noqa: E501
                "Without authentication on the AUX line, physical access to the AUX port immediately grants unauthenticated CLI access, bypassing all logical security controls.",  # noqa: E501
                "Physical access to the AUX port is sufficient; no credentials or network access are required.",  # noqa: E501
                "Configure login authentication on the AUX line:\n\n```\nline aux 0\n login authentication default\n```",  # noqa: E501
                "CIS 5.3.4"
            )
        return None

    def analyze(self, config_file) -> None:
        issues = []

        issues.append(self.get_aux_no_exec(config_file))
        issues.append(self.get_aux_exec_timeout(config_file))
        issues.append(self.get_aux_transport_input(config_file))
        issues.append(self.get_aux_login(config_file))

        for issue in issues:
            if issue is not None:
                self.add_issue(issue)
