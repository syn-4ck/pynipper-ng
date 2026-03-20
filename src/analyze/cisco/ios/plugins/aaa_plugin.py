# flake8: noqa
# CIS Cisco IOS Benchmark references:
#   1.4.1  - Ensure 'aaa new-model' is set
#   1.4.2  - Ensure 'aaa authentication login' is configured
#   1.4.3  - Ensure 'aaa authentication enable default' is configured
#   1.4.4  - Ensure 'login authentication' is applied to management lines
#   1.4.5  - Ensure 'aaa authorization exec default' is configured
#   1.4.6  - Ensure 'aaa authorization network default' is configured
#   1.4.7  - Ensure 'aaa accounting exec default' is configured
#   1.4.8  - Ensure 'aaa accounting commands 15 default' is configured
#   1.4.9  - Ensure 'aaa accounting connection default' is configured

from ..core.base_plugin import BasePlugin
from ....common.issue.issue import Issue


class AAAPlugin(BasePlugin):

    def __init__(self):
        super().__init__()

    def name(self):
        return "Local Authentication, Authorization and Accounting (AAA)"

    # CIS 1.4.1 - Ensure 'aaa new-model' is set
    def _has_aaa_new_model(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        return len(parser.find_objects(r"^aaa new-model$")) > 0

    def get_aaa_new_model(self, filename: str):
        if not self._has_aaa_new_model(filename):
            return Issue(
                "AAA new-model not enabled",
                "The 'aaa new-model' command is not configured. AAA (Authentication, Authorization, and Accounting) new-model replaces the older per-line and per-interface authentication configuration.",  # noqa: E501
                "Without AAA new-model, access controls may be inconsistently applied across management interfaces. Devices relying on line-level passwords provide weaker authentication guarantees and no authorization or accounting capabilities.",  # noqa: E501
                "An attacker targeting management interfaces may be able to exploit weaker line-level authentication if AAA is not enforced.",  # noqa: E501
                "Enable **AAA** globally. Plan and configure authentication method lists **before** enabling to avoid locking yourself out:\n\n```\naaa new-model\n```",  # noqa: E501
                "CIS 1.4.1"
            )
        return None

    # CIS 1.4.2 - Ensure 'aaa authentication login' is configured
    def _has_aaa_authentication_login(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        return len(parser.find_objects(r"^aaa authentication login")) > 0

    def get_aaa_authentication_login(self, filename: str):
        if not self._has_aaa_authentication_login(filename):
            return Issue(
                "AAA authentication login not configured",
                "No 'aaa authentication login' method list is defined. Without it, login authentication relies on legacy line-level passwords.",  # noqa: E501
                "Without a defined AAA authentication login method list, administrators cannot enforce consistent authentication policies (e.g., RADIUS, TACACS+, local) across all management access points.",  # noqa: E501
                "An attacker may exploit inconsistent or absent authentication on management lines.",  # noqa: E501
                "Configure an **AAA** authentication method list for login:\n\n```\naaa authentication login default group tacacs+ local\n```",  # noqa: E501
                "CIS 1.4.2"
            )
        return None

    # CIS 1.4.3 - Ensure 'aaa authentication enable default' is configured
    def _has_aaa_authentication_enable(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        return len(parser.find_objects(r"^aaa authentication enable")) > 0

    def get_aaa_authentication_enable(self, filename: str):
        if not self._has_aaa_authentication_enable(filename):
            return Issue(
                "AAA authentication enable not configured",
                "No 'aaa authentication enable' method list is defined. Without it, privilege escalation to EXEC mode is not authenticated through AAA.",  # noqa: E501
                "Without AAA enable authentication, the 'enable' command may accept only the locally stored enable password, bypassing centralized authentication controls.",  # noqa: E501
                "An attacker with console or VTY access who knows the enable password can escalate privileges without any centralized AAA check.",  # noqa: E501
                "Configure **AAA** enable authentication:\n\n```\naaa authentication enable default group tacacs+ enable\n```",  # noqa: E501
                "CIS 1.4.3"
            )
        return None

    # CIS 1.4.4 - Ensure 'login authentication' is applied to management lines
    def _has_login_authentication_on_lines(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        return len(parser.find_objects(r"login authentication")) > 0

    def get_login_authentication_on_lines(self, filename: str):
        if not self._has_login_authentication_on_lines(filename):
            return Issue(
                "Login authentication not applied to management lines",
                "The 'login authentication' command is not present on any management line (console/VTY). Management lines must explicitly reference an AAA authentication list.",  # noqa: E501
                "Without 'login authentication' on management lines, the AAA method list is not applied, allowing access without centralized authentication controls.",  # noqa: E501
                "An attacker accessing a management line without the AAA list applied may log in using only a locally configured line password or no password at all.",  # noqa: E501
                "Apply a login authentication list to all management lines:\n\n```\nline console 0\n login authentication default\nline vty 0 4\n login authentication default\n```",  # noqa: E501
                "CIS 1.4.4"
            )
        return None

    # CIS 1.4.5 - Ensure 'aaa authorization exec default' is configured
    def _has_aaa_authorization_exec(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        return len(parser.find_objects(r"^aaa authorization exec")) > 0

    def get_aaa_authorization_exec(self, filename: str):
        if not self._has_aaa_authorization_exec(filename):
            return Issue(
                "AAA authorization exec not configured",
                "'aaa authorization exec default' is not configured. Without exec authorization, any authenticated user is automatically granted EXEC access regardless of their authorization level.",  # noqa: E501
                "Without exec authorization, a user who authenticates successfully is immediately given CLI access. Centralized authorization policies that restrict which users can access EXEC mode are not enforced.",  # noqa: E501
                "This is an authorization gap; a low-privilege user credential that authenticates successfully could gain EXEC access when only higher-privilege accounts should be permitted.",  # noqa: E501
                "Configure **AAA** exec authorization:\n\n```\naaa authorization exec default group tacacs+ local\n```",  # noqa: E501
                "CIS 1.4.5"
            )
        return None

    # CIS 1.4.6 - Ensure 'aaa authorization network default' is configured
    def _has_aaa_authorization_network(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        return len(parser.find_objects(r"^aaa authorization network")) > 0

    def get_aaa_authorization_network(self, filename: str):
        if not self._has_aaa_authorization_network(filename):
            return Issue(
                "AAA authorization network not configured",
                "'aaa authorization network default' is not configured. Without network authorization, network-level service requests such as PPP and SLIP may not be subject to centralized access control.",  # noqa: E501
                "Without network authorization, dial-up or VPN clients may be granted network access without the AAA server verifying authorization, bypassing per-user access policies.",  # noqa: E501
                "This is an authorization gap for devices handling dial or VPN sessions.",  # noqa: E501
                "Configure **AAA** network authorization:\n\n```\naaa authorization network default group tacacs+ local\n```",  # noqa: E501
                "CIS 1.4.6"
            )
        return None

    # CIS 1.4.7 - Ensure 'aaa accounting exec default' is configured
    def _has_aaa_accounting_exec(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        return len(parser.find_objects(r"^aaa accounting exec")) > 0

    def get_aaa_accounting_exec(self, filename: str):
        if not self._has_aaa_accounting_exec(filename):
            return Issue(
                "AAA accounting exec not configured",
                "'aaa accounting exec default' is not configured. Without exec accounting, EXEC session start and stop events are not sent to a centralized accounting server.",  # noqa: E501
                "Without exec session accounting, there is no centralized audit trail of when users started and ended privileged CLI sessions. This hinders accountability and incident investigation.",  # noqa: E501
                "This is an auditing gap that allows management sessions to go unrecorded in a centralized system.",  # noqa: E501
                "Configure **AAA** exec accounting:\n\n```\naaa accounting exec default start-stop group tacacs+\n```",  # noqa: E501
                "CIS 1.4.7"
            )
        return None

    # CIS 1.4.8 - Ensure 'aaa accounting commands 15 default' is configured
    def _has_aaa_accounting_commands_15(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        return len(parser.find_objects(r"^aaa accounting commands 15")) > 0

    def get_aaa_accounting_commands_15(self, filename: str):
        if not self._has_aaa_accounting_commands_15(filename):
            return Issue(
                "AAA accounting for privilege-15 commands not configured",
                "'aaa accounting commands 15 default' is not configured. Without command accounting, privilege-level-15 commands executed by administrators are not logged to a centralized server.",  # noqa: E501
                "Without command accounting, an administrator or attacker with privileged access can execute arbitrary commands without any record being sent to the AAA server. This eliminates the ability to detect configuration tampering through centralized audit logs.",  # noqa: E501
                "An attacker or insider who has obtained privileged credentials can execute destructive commands with no centralized audit trail.",  # noqa: E501
                "Configure **AAA** privilege-15 command accounting:\n\n```\naaa accounting commands 15 default start-stop group tacacs+\n```",  # noqa: E501
                "CIS 1.4.8"
            )
        return None

    # CIS 1.4.9 - Ensure 'aaa accounting connection default' is configured
    def _has_aaa_accounting_connection(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        return len(parser.find_objects(r"^aaa accounting connection")) > 0

    def get_aaa_accounting_connection(self, filename: str):
        if not self._has_aaa_accounting_connection(filename):
            return Issue(
                "AAA accounting connection not configured",
                "'aaa accounting connection default' is not configured. Outbound connections initiated from the device (e.g., Telnet, SSH from the device itself) are not tracked by the AAA server.",  # noqa: E501
                "Without connection accounting, outbound management connections from the device are not recorded. This can mask lateral movement where an attacker uses the compromised device to pivot to other systems.",  # noqa: E501
                "An attacker who compromises the device and uses it to pivot to other management systems would leave no centralized accounting record of those connections.",  # noqa: E501
                "Configure **AAA** connection accounting:\n\n```\naaa accounting connection default start-stop group tacacs+\n```",  # noqa: E501
                "CIS 1.4.9"
            )
        return None

    def analyze(self, config_file) -> None:
        issues = []

        issues.append(self.get_aaa_new_model(config_file))
        issues.append(self.get_aaa_authentication_login(config_file))
        issues.append(self.get_aaa_authentication_enable(config_file))
        issues.append(self.get_login_authentication_on_lines(config_file))
        issues.append(self.get_aaa_authorization_exec(config_file))
        issues.append(self.get_aaa_authorization_network(config_file))
        issues.append(self.get_aaa_accounting_exec(config_file))
        issues.append(self.get_aaa_accounting_commands_15(config_file))
        issues.append(self.get_aaa_accounting_connection(config_file))

        for issue in issues:
            if issue is not None:
                self.add_issue(issue)
