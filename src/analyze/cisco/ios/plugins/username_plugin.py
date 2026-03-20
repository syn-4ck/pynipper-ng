# flake8: noqa
# CIS Cisco IOS Benchmark references:
#   1.3.1  - Ensure 'service password-encryption' is enabled
#   1.3.2  - Ensure no username uses password type 0 (cleartext)
#   1.3.3  - Ensure no username uses password type 7 (reversible Vigenere)
#   1.3.4  - Ensure no username uses password type 5 (weak MD5); prefer type 8/9

from ..core.base_plugin import BasePlugin
from ....common.issue.issue import Issue


class PluginUsername(BasePlugin):

    def __init__(self):
        super().__init__()

    def name(self):
        return "Username credentials"

    # CIS 1.3.1 - Ensure 'service password-encryption' is enabled
    def _has_service_password_encryption(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        if len(parser.find_objects(r"^no service password-encryption")) > 0:
            return False
        return (
            len(parser.find_objects(r"^service password-encryption")) > 0
            or len(parser.find_objects(r"^password encryption aes")) > 0
        )

    def get_service_password_encryption(self, filename: str):
        if not self._has_service_password_encryption(filename):
            return Issue(
                "Service password-encryption not enabled",
                "The 'service password-encryption' command is not enabled. Line passwords, CHAP passwords, and other non-secret passwords are stored in cleartext in the running configuration.",  # noqa: E501
                "Cleartext passwords visible in the running configuration can be read by anyone with access to the configuration file, such as via TFTP backup, 'show running-config', or physical access.",  # noqa: E501
                "Reading a device configuration via 'show run' or a backup file is sufficient to expose all unencrypted passwords.",  # noqa: E501
                "Enable service password-encryption (type-7 reversible). Prefer `enable secret` and `username secret` over `enable password` / `username password`:\n\n```\nservice password-encryption\n```",  # noqa: E501
                "CIS 1.3.1"
            )
        return None

    # CIS 1.3.2 - No type-0 (cleartext) username passwords
    def _has_type0_password(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        return len(parser.find_objects(r"^username\s+\S+\s+password\s+0\s+")) > 0

    def get_type0_passwords(self, filename: str):
        if self._has_type0_password(filename):
            return Issue(
                "Username with type-0 (cleartext) password",
                "One or more usernames are configured with a type-0 cleartext password. Type-0 passwords are stored in plaintext in the device configuration.",  # noqa: E501
                "Cleartext passwords in the configuration file are directly readable by anyone who obtains the configuration, including backups and TFTP transfers.",  # noqa: E501
                "No cracking is required — type-0 passwords are immediately usable by anyone who views the configuration.",  # noqa: E501
                "Replace all type-0 (clear-text) passwords with type-8 or type-9 hashed passwords:\n\n```\nusername <name> algorithm-type sha256 secret <password>\n```",  # noqa: E501
                "CIS 1.3.2"
            )
        return None

    # CIS 1.3.3 - No type-7 (reversible Vigenere) username passwords
    def _has_type7_password(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        return len(parser.find_objects(r"^username\s+\S+\s+password\s+7\s+")) > 0

    def get_type7_passwords(self, filename: str):
        if self._has_type7_password(filename):
            return Issue(
                "Username with type-7 (reversible) password",
                "One or more usernames are configured with a type-7 password. Type-7 uses the Vigenere cipher, which is reversible and provides no real security.",  # noqa: E501
                "Type-7 passwords can be instantly reversed by freely available online tools and scripts. Once the configuration is obtained, the original password is trivially recovered.",  # noqa: E501
                "Decryption of type-7 passwords is trivial — dozens of online tools and scripts exist that reverse them in milliseconds.",  # noqa: E501
                "Replace all type-7 (reversible) passwords with type-8 or type-9 hashed passwords:\n\n```\nusername <name> algorithm-type sha256 secret <password>\n```",  # noqa: E501
                "CIS 1.3.3"
            )
        return None

    # CIS 1.3.4 - No type-5 (MD5) username passwords
    def _has_type5_password(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        return len(parser.find_objects(r"^username\s+\S+\s+(?:password|secret)\s+5\s+")) > 0

    def get_type5_passwords(self, filename: str):
        if self._has_type5_password(filename):
            return Issue(
                "Username with type-5 (MD5) password — weak hash",
                "One or more usernames are configured with a type-5 password, which uses salted MD5. MD5 is a fast hash algorithm that can be brute-forced with modern GPU hardware.",  # noqa: E501
                "Type-5 passwords, while not reversible, are susceptible to offline brute-force and dictionary attacks using tools such as Hashcat, especially for short or common passwords.",  # noqa: E501
                "GPU-accelerated cracking tools such as Hashcat can test billions of MD5 candidates per second, making type-5 passwords vulnerable to offline attacks.",  # noqa: E501
                "Upgrade type-5 (MD5) passwords to type-8 (PBKDF2-SHA256) or type-9 (scrypt):\n\n```\nusername <name> algorithm-type sha256 secret <password>\n```",  # noqa: E501
                "CIS 1.3.4"
            )
        return None

    def analyze(self, config_file) -> None:
        issues = []

        issues.append(self.get_service_password_encryption(config_file))
        issues.append(self.get_type0_passwords(config_file))
        issues.append(self.get_type7_passwords(config_file))
        issues.append(self.get_type5_passwords(config_file))

        for issue in issues:
            if issue is not None:
                self.add_issue(issue)