# flake8: noqa
# CIS Cisco IOS Benchmark references:
#   1.3.1  - Ensure 'enable secret' is configured
#   1.3.2  - Ensure only 'enable secret' is used (not 'enable password')
#   1.6.1  - Ensure 'security passwords min-length' is set to at least 8 characters
#   1.6.2  - Ensure 'login delay' is configured
#   1.6.3  - Ensure 'login block-for' is configured
#   1.6.4  - Ensure 'login on-failure log' is configured
#   1.6.5  - Ensure 'login on-success log' is configured

from ..core.base_plugin import BasePlugin
from ....common.issue.issue import Issue


class PluginPasswordPolicy(BasePlugin):

    def __init__(self):
        super().__init__()

    def name(self):
        return "Password Policy and Enable Secret"

    # CIS 1.3.1 - Ensure 'enable secret' is configured

    def _has_enable_secret(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        secret = parser.find_objects(r"^enable secret")
        return len(secret) > 0

    def _has_enable_password(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        password = parser.find_objects(r"^enable password")
        return len(password) > 0

    def get_enable_secret(self, filename: str):
        if not self._has_enable_secret(filename):
            return Issue(
                "Enable secret not configured",
                "The 'enable secret' command is not configured. The enable secret stores a strongly hashed password (MD5 or SHA-256) for privileged EXEC mode access.",
                "Without an enable secret, privilege escalation to EXEC mode may be unprotected or rely on the weaker 'enable password'. Full administrative access to the device is at risk.",  # noqa: E501
                "If no enable secret is configured and the enable password is absent, an attacker may be able to access privileged mode without a password on some IOS versions.",  # noqa: E501
                "Configure an enable secret using a strong hashing algorithm.\nThis supersedes and should replace any `enable password` configuration:\n\n```\nenable algorithm-type sha256 secret <strong-password>\n```",  # noqa: E501
                "CIS 1.3.1"
            )
        return None

    # CIS 1.3.2 - Ensure only 'enable secret' is used
    def get_enable_password_plain(self, filename: str):
        if self._has_enable_password(filename) and self._has_enable_secret(filename):
            return Issue(
                "Enable password configured alongside enable secret",
                "'enable password' is configured in addition to 'enable secret'. The enable password is only used as a fallback on older IOS versions that do not support enable secret, and storing both can cause confusion.",  # noqa: E501
                "The 'enable password' may use weaker or cleartext storage. If the device falls back to using 'enable password', it provides weaker protection for privileged access.",  # noqa: E501
                "On older IOS versions where both are configured, the enable secret takes precedence. However the enable password still exists in configuration and may be recoverable.",  # noqa: E501
                "Remove the `enable password` and rely exclusively on `enable secret`:\n\n```\nno enable password\n```",  # noqa: E501
                "CIS 1.3.2"
            )
        if self._has_enable_password(filename) and not self._has_enable_secret(filename):
            return Issue(
                "Enable password used instead of enable secret",
                "The 'enable password' command is configured without an 'enable secret'. The enable password uses a reversible cipher (type 7) or cleartext storage, and does not provide strong protection for privileged access.",  # noqa: E501
                "Type 7 passwords are trivially reversible using publicly available tools. Cleartext passwords are directly readable in the configuration file. An attacker who obtains the running config can immediately recover the privileged password.",  # noqa: E501
                "Type 7 decryption tools and tables are freely available online. Decrypting a type 7 password takes seconds.",  # noqa: E501
                "Replace `enable password` with `enable secret` using a strong hashing algorithm:\n\n```\nenable algorithm-type sha256 secret <strong-password>\nno enable password\n```",  # noqa: E501
                "CIS 1.3.2"
            )
        return None

    def _has_security_password_min_length(self, filename: str) -> int:
        parser = self.parse_cisco_ios_config_file(filename)
        min_len = parser.find_objects(r"^security passwords min-length")
        if len(min_len) > 0:
            length = min_len[0].re_match_typed(
                r'^security passwords min-length\s+(\d+)', default='')
            return int(length) if length else 0
        return 0

    # CIS 1.6.1 - Ensure 'security passwords min-length' >= 8
    def get_security_password_min_length(self, filename: str):
        min_len = self._has_security_password_min_length(filename)
        if min_len == 0:
            return Issue(
                "Minimum password length not configured",
                "The 'security passwords min-length' command is not configured. Without a minimum length requirement, users and administrators may configure short or trivially guessable passwords.",  # noqa: E501
                "Short passwords are significantly more susceptible to brute-force and dictionary attacks. Without a minimum length policy, there is no enforcement to prevent weak passwords.",  # noqa: E501
                "Brute-force attacks against short passwords are significantly faster than against longer passwords.",  # noqa: E501
                "Configure a minimum password length of at least 10 characters (CIS recommends 10+):\n\n```\nsecurity passwords min-length 10\n```",  # noqa: E501
                "CIS 1.6.1"
            )
        if min_len < 8:
            return Issue(
                "Minimum password length below recommended threshold",
                f"The minimum password length is configured to {min_len} characters, which is below the CIS Benchmark recommended minimum of 8 characters.",
                "Passwords shorter than 8 characters are more susceptible to brute-force attacks, especially when combined with dictionary-based attacks.",  # noqa: E501
                "Brute-force attacks against passwords shorter than 8 characters can be completed in a practical timeframe with modern hardware.",  # noqa: E501
                "Increase the minimum password length to at least 10 characters:\n\n```\nsecurity passwords min-length 10\n```",  # noqa: E501
                "CIS 1.6.1"
            )
        return None

    def _has_login_delay(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        delay = parser.find_objects(r"^login delay")
        return len(delay) > 0

    # CIS 1.6.2 - Ensure 'login delay' is configured
    def get_login_delay(self, filename: str):
        if not self._has_login_delay(filename):
            return Issue(
                "Login delay not configured",
                "No login delay is configured. A login delay introduces a pause between failed authentication attempts, reducing the speed of brute-force attacks.",
                "Without a login delay, an attacker can attempt thousands of password guesses per second against the device.",  # noqa: E501
                "Automated brute-force tools can attempt many passwords per second without a delay.",  # noqa: E501
                "Configure a login delay to slow brute-force attacks (2–5 seconds recommended):\n\n```\nlogin delay 4\n```",  # noqa: E501
                "CIS 1.6.2"
            )
        return None

    def _has_login_block_for(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        block = parser.find_objects(r"^login block-for")
        return len(block) > 0

    # CIS 1.6.3 - Ensure 'login block-for' is configured
    def get_login_block_for(self, filename: str):
        if not self._has_login_block_for(filename):
            return Issue(
                "Login block-for (lockout) not configured",
                "The 'login block-for' command is not configured. This feature blocks further login attempts after a specified number of failures within a time window.",
                "Without a login lockout policy, an attacker can attempt an unlimited number of password guesses without being blocked, enabling unrestricted brute-force attacks.",  # noqa: E501
                "Automated password-guessing tools can exhaust common password lists very quickly if no lockout mechanism is in place.",  # noqa: E501
                "Configure a login lockout policy (blocks all logins for 120 s after 3 failures within 60 s):\n\n```\nlogin block-for 120 attempts 3 within 60\n```",  # noqa: E501
                "CIS 1.6.3"
            )
        return None

    def _has_login_on_failure_log(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        log = parser.find_objects(r"^login on-failure log")
        return len(log) > 0

    # CIS 1.6.4 - Ensure 'login on-failure log' is configured
    def get_login_on_failure_log(self, filename: str):
        if not self._has_login_on_failure_log(filename):
            return Issue(
                "Login failure logging not configured",
                "The 'login on-failure log' command is not configured. Without it, failed login attempts are not logged to syslog.",
                "Failed login attempts are a primary indicator of unauthorized access attempts. Without logging them, brute-force attacks against the device management interfaces may go undetected.",  # noqa: E501
                "This is a monitoring gap rather than a directly exploitable vulnerability, but it allows attacks to proceed undetected.",  # noqa: E501
                "Enable logging of failed login attempts:\n\n```\nlogin on-failure log\n```",  # noqa: E501
                "CIS 1.6.4"
            )
        return None

    def _has_login_on_success_log(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        log = parser.find_objects(r"^login on-success log")
        return len(log) > 0

    # CIS 1.6.5 - Ensure 'login on-success log' is configured
    def get_login_on_success_log(self, filename: str):
        if not self._has_login_on_success_log(filename):
            return Issue(
                "Successful login logging not configured",
                "The 'login on-success log' command is not configured. Without it, successful logins are not logged to syslog.",
                "Logging successful logins provides an audit trail of who accessed the device and when. Without this, unauthorized access that uses valid credentials cannot be detected through log analysis.",  # noqa: E501
                "This is a monitoring gap that allows authorized-credential-based intrusions to go undetected.",  # noqa: E501
                "Enable logging of successful login events:\n\n```\nlogin on-success log\n```",  # noqa: E501
                "CIS 1.6.5"
            )
        return None

    def analyze(self, config_file) -> None:
        issues = []

        issues.append(self.get_enable_secret(config_file))
        issues.append(self.get_enable_password_plain(config_file))
        issues.append(self.get_security_password_min_length(config_file))
        issues.append(self.get_login_delay(config_file))
        issues.append(self.get_login_block_for(config_file))
        issues.append(self.get_login_on_failure_log(config_file))
        issues.append(self.get_login_on_success_log(config_file))

        for issue in issues:
            if issue is not None:
                self.add_issue(issue)
