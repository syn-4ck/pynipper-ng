# flake8: noqa
# CIS Cisco IOS Benchmark references:
#   1.5.1  - Ensure 'banner login' is set
#   1.5.2  - Ensure 'banner motd' is set
#   1.5.3  - Ensure 'ip admission auth-proxy-banner http' is set (WebAuth banner)

from ..core.base_plugin import BasePlugin
from ....common.issue.issue import Issue


class PluginBanner(BasePlugin):

    def __init__(self):
        super().__init__()

    def name(self):
        return "Banners"

    # CIS 1.5.1 - Ensure 'banner login' is set
    def _has_banner_login(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        return len(parser.find_objects(r"^banner login")) > 0

    def get_banner_login(self, filename: str):
        if not self._has_banner_login(filename):
            return Issue(
                "Login banner not configured",
                "No 'banner login' is configured. The login banner is displayed before authentication and must include a legal warning notifying users that unauthorised access is prohibited.",  # noqa: E501
                "Without a legal warning banner, organisations may lose the right to prosecute intruders. Courts may rule that access to a system without a warning banner implies consent.",  # noqa: E501
                "Absence of a login banner is easily detected by connecting to any management interface. No active attack is required.",  # noqa: E501
                "Configure a login banner with an appropriate legal disclaimer:\n\n```\nbanner login ^\nUnauthorized access is prohibited. All activities are monitored and logged.\n^\n```",  # noqa: E501
                "CIS 1.5.1"
            )
        return None

    # CIS 1.5.2 - Ensure 'banner motd' is set
    def _has_banner_motd(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        return len(parser.find_objects(r"^banner motd")) > 0

    def get_banner_motd(self, filename: str):
        if not self._has_banner_motd(filename):
            return Issue(
                "MOTD banner not configured",
                "No 'banner motd' is configured. The Message-Of-The-Day (MOTD) banner is displayed on all terminals upon connection and should communicate the legal status of the device.",  # noqa: E501
                "Without an MOTD banner, there is no legal notice to warn unauthorised users before they interact with the device. This may weaken the legal standing of the organisation in the event of a breach.",  # noqa: E501
                "Absence of an MOTD banner is detected immediately on any connection to the device.",  # noqa: E501
                "Configure a message-of-the-day banner with a legal disclaimer:\n\n```\nbanner motd ^\nUnauthorized access is prohibited. All activities are monitored and logged.\n^\n```",  # noqa: E501
                "CIS 1.5.2"
            )
        return None

    # CIS 1.5.3 - Ensure 'ip admission auth-proxy-banner http' is set
    def _has_banner_webauth(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        return len(parser.find_objects(r"^ip admission auth-proxy-banner http")) > 0

    def get_banner_webauth(self, filename: str):
        if not self._has_banner_webauth(filename):
            return Issue(
                "WebAuth banner not configured",
                "The HTTP authentication proxy banner ('ip admission auth-proxy-banner http') is not configured. Users authenticating via the web-based auth proxy will not receive a legal warning.",  # noqa: E501
                "Without a WebAuth banner, users accessing HTTP management interfaces receive no legal warning, which may undermine the organisation's ability to enforce acceptable-use policies.",  # noqa: E501
                "Absence of this banner is detectable by connecting through the HTTP auth-proxy interface.",  # noqa: E501
                "Configure the WebAuth banner with a legal notice:\n\n```\nip admission auth-proxy-banner http ^Unauthorized access is prohibited.^",  # noqa: E501
                "CIS 1.5.3"
            )
        return None

    def analyze(self, config_file) -> None:
        issues = []

        issues.append(self.get_banner_login(config_file))
        issues.append(self.get_banner_motd(config_file))
        issues.append(self.get_banner_webauth(config_file))

        for issue in issues:
            if issue is not None:
                self.add_issue(issue)