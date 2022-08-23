# flake8: noqa

from ..core.base_plugin import GenericPlugin
from ..issue.cisco_ios_issue import CiscoIOSIssue

class PluginSSH(GenericPlugin):

    def __init__(self):
        super().__init__()

    def name(self):
        return "Secure Shell (SSH)"

    # If the device has ssh configured -> true

    def _has_cisco_ios_ssh(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        transport_disable = parser.find_objects("transport input none")
        ssh_disable = parser.find_objects("no transport input ssh")
        ssh_ip_disable = parser.find_objects("no ip ssh")
        if (len(transport_disable) > 0 or len(ssh_disable) > 0 or len(ssh_ip_disable) > 0):
            return False
        else:
            return True

    # Number of ssh version

    def _get_cisco_ios_ssh_version(self, filename: str) -> str:
        parser = self.parse_cisco_ios_config_file(filename)
        ssh_version = parser.find_objects("ip ssh version")
        if (len(ssh_version) > 0):
            version = ssh_version[0].re_match_typed(
                r'^ip ssh version\s+(\S+)', default='')
            return version
        else:
            return ""

    def get_cisco_ios_ssh(self, filename: str):
        if (not self._has_cisco_ios_ssh(filename) or self._get_cisco_ios_ssh_version(filename) == "" or self._get_cisco_ios_ssh_version(filename) != "2"):
            parser = self.parse_cisco_ios_config_file(filename)
            return CiscoIOSIssue(
                "SSH Protocol Version",
                "The SSH service is commonly used for encrypted command-based remote device management. There are multiple SSH protocol versions and SSH servers will often support multiple versions to maintain backwards compatibility. Although flaws have been identified in implementations of version 2 of the SSH protocol, fundamental flaws exist in SSH protocol version 1.",  # noqa: E501
                "An attacker who was able to intercept SSH protocol version 1 traffic would be able to perform a man-in-the-middle style attack. The attacker could then capture network traffic and possibly authentication credentials.",  # noqa: E501
                "Although vulnerabilities are widely known, exploiting the vulnerabilities in the SSH protocol can be difficult.",
                "When SSH protocol version 2 support is configured on Cisco IOS devices, support for version 1 will be disabled. This can be configured with the following command: ip ssh version 2",  # noqa: E501
                parser.find_objects("ip ssh version")[0].linenum if len(parser.find_objects("ip ssh version")) > 0 else 0
            )
        return None

    # Number of max. retries configured to login with ssh

    def _get_cisco_ios_ssh_retries(self, filename: str) -> str:
        parser = self.parse_cisco_ios_config_file(filename)
        retries = parser.find_objects("ip ssh authentication-retries")
        if (len(retries) > 0):
            max_retries = retries[0].re_match_typed(
                r'^ip ssh authentication-retries\s+(\S+)', default='')
            return max_retries
        else:
            return ""

    def get_cisco_ios_ssh_reties(self, filename: str):
        retries = self._get_cisco_ios_ssh_retries(filename)
        if (retries == "" or retries > 5):
            parser = self.parse_cisco_ios_config_file(filename)
            return CiscoIOSIssue(
                "SSH retries misconfiguration",
                "The SSH service must have a defined number of retries, the recommended is between 0 and 5.",
                "Set a retries number allows to reduce the bruteforce and dictionary attacks. If a retry number is defined, the attacker can not test with an user multiple passwords.",  # noqa: E501
                "This issue improve the hardening of passwords in the network device.",
                "This can be configured with the following command: ip ssh authentication-retries <retry-number>.",
                parser.find_objects("ip ssh authentication-retries")[0].linenum if len(parser.find_objects("ip ssh authentication-retries")) else 0
            )
        return None

    # Number of seconds of ssh timeout

    def _get_cisco_ios_ssh_timeout(self, filename: str) -> int:
        parser = self.parse_cisco_ios_config_file(filename)
        timeout = parser.find_objects("ip ssh time-out")
        if (len(timeout) > 0):
            seconds = timeout[0].re_match_typed(
                r'^ip ssh time-out\s+(\S+)', default='')
            return int(seconds)
        else:
            return 0

    def get_cisco_ios_ssh_timeout(self, filename: str):
        timeout = self._get_cisco_ios_ssh_timeout(filename)
        if (timeout == 0 or timeout > 120):
            parser = self.parse_cisco_ios_config_file(filename)
            return CiscoIOSIssue(
                "SSH timeout misconfiguration",
                "The SSH service must have a defined timeout between 0 and 60 seconds.",
                "Set a timeout allows disable not used or malicious sessions in background.",
                "This issue only increase the device management security, it is not exploitable.",
                "This can be configured with the following command: ip ssh time-out <timeout-in-seconds>.",
                parser.find_objects("ip ssh time-out")[0].linenum if len(parser.find_objects("ip ssh time-out")) > 0 else 0
            )
        return None

    # Get the source interface

    def _get_cisco_ios_ssh_interface(self, filename: str) -> str:
        parser = self.parse_cisco_ios_config_file(filename)
        src_interface = parser.find_objects("ip ssh source-interface")
        if (len(src_interface) > 0):
            interface = src_interface[0].re_match_typed(
                r'^ip ssh source-interface\s+(\S+)', default='')
            return interface
        else:
            return ""

    def get_cisco_ios_ssh_interface(self, filename: str):
        if (self._get_cisco_ios_ssh_interface(filename) == ""):
            parser = self.parse_cisco_ios_config_file(filename)
            return CiscoIOSIssue(
                "SSH source-interface enabled",
                "The SSH service must have a controlated set of source interfaces to manage the device",
                "To reduce bruteforce attacks is usefull have a set of source interfaces, logged and filtered, to access to SSH device management.",
                "This issue only increase the device management security, it is not exploitable, but it reduce bruteforce attacks.",
                "This can be configured with the following command: ip ssh source-interface <interface> ",
                parser.find_objects("ip ssh source-interface")[0].linenum if len(parser.find_objects("ip ssh source-interface")) > 0 else 0
            )
        return None

    def analyze(self, config_file) -> None:
        issues = []

        issues.append(self.get_cisco_ios_ssh(config_file))
        issues.append(self.get_cisco_ios_ssh_reties(config_file))
        issues.append(self.get_cisco_ios_ssh_timeout(config_file))
        issues.append(self.get_cisco_ios_ssh_interface(config_file))

        for issue in issues:
            if issue is not None:
                self.add_issue(issue)
