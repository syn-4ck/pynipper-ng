# flake8: noqa
# CIS Cisco IOS Benchmark references:
#   2.2.2  - Ensure 'ip ssh version 2' is set
#   2.2.3  - Ensure 'ip ssh authentication-retries' <= 3
#   2.2.4  - Ensure 'ip ssh time-out' <= 60
#   2.2.5  - Ensure 'ip ssh source-interface' is set
#   2.2.6  - Ensure RSA key pair is >= 2048 bits

from ..core.base_plugin import BasePlugin
from ....common.issue.issue import Issue


class PluginSSH(BasePlugin):

    def __init__(self):
        super().__init__()

    def name(self):
        return "Secure Shell (SSH)"

    # CIS 2.2.2 - Ensure 'ip ssh version 2' is set
    def _get_ssh_version(self, filename: str) -> str:
        parser = self.parse_cisco_ios_config_file(filename)
        ssh_version = parser.find_objects(r"^ip ssh version")
        if ssh_version:
            return ssh_version[0].re_match_typed(r'^ip ssh version\s+(\S+)', default='')
        return ""

    def get_ssh_version(self, filename: str):
        version = self._get_ssh_version(filename)
        if version != "2":
            return Issue(
                "SSH protocol version 2 not enforced",
                f"SSH version 2 is not explicitly configured (current: '{version or 'not set'}'). SSHv1 has fundamental cryptographic flaws and must not be permitted.",  # noqa: E501
                "SSHv1 is vulnerable to man-in-the-middle attacks allowing an attacker to intercept and decrypt management sessions, including authentication credentials.",  # noqa: E501
                "SSHv1 downgrade attacks can be performed by an on-path attacker with standard network tooling.",  # noqa: E501
                "Enforce **SSHv2** only:\n\n```\nip ssh version 2\n```",  # noqa: E501
                "CIS 2.2.2"
            )
        return None

    # CIS 2.2.3 - Ensure 'ip ssh authentication-retries' <= 3
    def _get_ssh_retries(self, filename: str) -> int:
        parser = self.parse_cisco_ios_config_file(filename)
        retries = parser.find_objects(r"^ip ssh authentication-retries")
        if retries:
            val = retries[0].re_match_typed(r'^ip ssh authentication-retries\s+(\d+)', default='')
            return int(val) if val else -1
        return -1  # not configured

    def get_ssh_retries(self, filename: str):
        retries = self._get_ssh_retries(filename)
        if retries == -1:
            return Issue(
                "SSH authentication retries not configured",
                "The 'ip ssh authentication-retries' command is not set. Without a retry limit, an attacker can make unlimited authentication attempts per session.",  # noqa: E501
                "An unlimited retry count per SSH session makes the device more susceptible to online brute-force attacks within a single session.",  # noqa: E501
                "Automated brute-force tools can attempt many passwords within a single SSH session if retries are not limited.",  # noqa: E501
                "Set SSH authentication retries to 3 or fewer:\n\n```\nip ssh authentication-retries 3\n```",  # noqa: E501
                "CIS 2.2.3"
            )
        if retries > 3:
            return Issue(
                "SSH authentication retries too high",
                f"SSH authentication retries is set to {retries}. The CIS Benchmark recommends a maximum of 3 retries.",  # noqa: E501
                "A high retry limit increases the opportunity for brute-force attacks against SSH within a single session.",  # noqa: E501
                "Automated tools can cycle through many passwords within a single session if the retry limit is too permissive.",  # noqa: E501
                "Reduce SSH authentication retries to 3 or fewer:\n\n```\nip ssh authentication-retries 3\n```",  # noqa: E501
                "CIS 2.2.3"
            )
        return None

    # CIS 2.2.4 - Ensure 'ip ssh time-out' <= 60
    def _get_ssh_timeout(self, filename: str) -> int:
        parser = self.parse_cisco_ios_config_file(filename)
        timeout = parser.find_objects(r"^ip ssh time-out")
        if timeout:
            val = timeout[0].re_match_typed(r'^ip ssh time-out\s+(\d+)', default='')
            return int(val) if val else 0
        return 0  # not configured

    def get_ssh_timeout(self, filename: str):
        timeout = self._get_ssh_timeout(filename)
        if timeout == 0:
            return Issue(
                "SSH negotiation timeout not configured",
                "The 'ip ssh time-out' command is not set. Without a timeout, the SSH negotiation phase can be kept open indefinitely.",  # noqa: E501
                "An attacker can hold SSH negotiation sessions open to consume device resources or to slow connection handling.",  # noqa: E501
                "Holding SSH connections open in the negotiation phase is trivial and does not require authentication.",  # noqa: E501
                "Set the SSH negotiation timeout to 60 seconds or less:\n\n```\nip ssh time-out 60\n```",  # noqa: E501
                "CIS 2.2.4"
            )
        if timeout > 60:
            return Issue(
                "SSH negotiation timeout too high",
                f"The SSH negotiation timeout is set to {timeout} seconds. The CIS Benchmark recommends 60 seconds or less.",  # noqa: E501
                "An excessively long timeout permits attackers to hold SSH sessions in the negotiation phase for extended periods, consuming device connection resources.",  # noqa: E501
                "Holding SSH pre-auth sessions open requires only a TCP connection, no credentials are needed.",  # noqa: E501
                "Reduce the SSH timeout to 60 seconds or less:\n\n```\nip ssh time-out 60\n```",  # noqa: E501
                "CIS 2.2.4"
            )
        return None

    # CIS 2.2.5 - Ensure 'ip ssh source-interface' is set
    def _get_ssh_source_interface(self, filename: str) -> str:
        parser = self.parse_cisco_ios_config_file(filename)
        src = parser.find_objects(r"^ip ssh source-interface")
        if src:
            return src[0].re_match_typed(r'^ip ssh source-interface\s+(\S+)', default='')
        return ""

    def get_ssh_source_interface(self, filename: str):
        if not self._get_ssh_source_interface(filename):
            return Issue(
                "SSH source-interface not configured",
                "No 'ip ssh source-interface' is configured. Without it, SSH management connections may originate from different IP addresses depending on the routing path.",  # noqa: E501
                "Without a dedicated source interface, SSH traffic may originate from unexpected interfaces, making it harder to apply consistent ACLs and to trace management connections.",  # noqa: E501
                "This is a configuration hygiene issue rather than a directly exploitable vulnerability.",  # noqa: E501
                "Bind SSH to a stable management interface:\n\n```\nip ssh source-interface Loopback0\n```",  # noqa: E501
                "CIS 2.2.5"
            )
        return None

    # CIS 2.2.6 - Ensure RSA key pair is >= 2048 bits
    def _get_rsa_key_size(self, filename: str) -> int:
        """Parse 'crypto key generate rsa modulus <size>' from the config."""
        parser = self.parse_cisco_ios_config_file(filename)
        rsa = parser.find_objects(r"^crypto key generate rsa")
        if rsa:
            val = rsa[0].re_match_typed(r'modulus\s+(\d+)', default='')
            return int(val) if val else 0
        return 0  # not found in running config (key may exist but not shown)

    def get_rsa_key_size(self, filename: str):
        size = self._get_rsa_key_size(filename)
        if size == 0:
            return None  # key size not captured in config; cannot determine
        if size < 2048:
            return Issue(
                "RSA key size below 2048 bits",
                f"The RSA key pair is configured with a modulus of {size} bits. Keys smaller than 2048 bits do not provide adequate security for SSH or certificate operations.",  # noqa: E501
                "RSA keys smaller than 2048 bits are vulnerable to factoring attacks with modern computing resources. A compromised host key allows an attacker to perform man-in-the-middle attacks against SSH sessions, intercepting credentials and session data.",  # noqa: E501
                "Factoring 1024-bit RSA keys is feasible with nation-state-level resources. Smaller keys (512 bits) can be factored with commodity hardware.",  # noqa: E501
                "Generate a new RSA key pair with at least 2048 bits to support **SSHv2**:\n\n```\ncrypto key generate rsa modulus 2048\n``` Use 4096 bits for new deployments where performance permits.",  # noqa: E501
                "CIS 2.2.6"
            )
        return None

    def analyze(self, config_file) -> None:
        issues = []

        issues.append(self.get_ssh_version(config_file))
        issues.append(self.get_ssh_retries(config_file))
        issues.append(self.get_ssh_timeout(config_file))
        issues.append(self.get_ssh_source_interface(config_file))
        issues.append(self.get_rsa_key_size(config_file))

        for issue in issues:
            if issue is not None:
                self.add_issue(issue)
