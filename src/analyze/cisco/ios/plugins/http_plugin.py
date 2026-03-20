# flake8: noqa
# CIS Cisco IOS Benchmark references:
#   2.5.1  - Ensure 'no ip http server' is set (disable HTTP)
#   2.5.2  - Ensure 'ip http access-class' is set
#   2.5.3  - Ensure 'ip http authentication' is set
#   2.5.4  - Ensure 'ip http secure-server' uses TLS 1.2 or higher

from ..core.base_plugin import BasePlugin
from ....common.issue.issue import Issue


class PluginHTTP(BasePlugin):

    def __init__(self):
        super().__init__()

    def name(self):
        return "HyperText Transfer Protocol (HTTP)"

    # CIS 2.5.1 - Ensure 'no ip http server' is set
    def _is_http_enabled(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        http_disabled = parser.find_objects(r"^no ip http server")
        if len(http_disabled) > 0:
            return False
        # HTTP is enabled by default on older IOS; treat absence of 'no' as enabled
        return len(parser.find_objects(r"^ip http server")) > 0 or len(http_disabled) == 0

    def get_http_service(self, filename: str):
        parser = self.parse_cisco_ios_config_file(filename)
        http_disabled = parser.find_objects(r"^no ip http server")
        http_enabled = parser.find_objects(r"^ip http server")
        if len(http_disabled) > 0:
            return None
        if len(http_enabled) > 0:
            return Issue(
                "HTTP service enabled",
                "The cleartext HTTP service ('ip http server') is enabled. HTTP transmits all data including authentication credentials in cleartext.",  # noqa: E501
                "An attacker monitoring network traffic can capture administrative credentials transmitted over HTTP, gaining full control of the device.",  # noqa: E501
                "Packet sniffing tools are widely available and trivial to use. HTTP credentials can be captured from standard network captures.",  # noqa: E501
                "Disable the HTTP service. Use HTTPS or SSH for management access:\n\n```\nno ip http server\n```",  # noqa: E501
                "CIS 2.5.1"
            )
        return None

    # CIS 2.5.2 - Ensure 'ip http access-class' is set
    def _has_http_access_class(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        return len(parser.find_objects(r"^ip http access-class")) > 0

    def get_http_access_class(self, filename: str):
        parser = self.parse_cisco_ios_config_file(filename)
        http_enabled = parser.find_objects(r"^ip http server")
        https_enabled = parser.find_objects(r"^ip http secure-server")
        if (len(http_enabled) > 0 or len(https_enabled) > 0) and not self._has_http_access_class(filename):
            return Issue(
                "HTTP/HTTPS service not protected by access-class",
                "The HTTP or HTTPS management service is enabled but no access-class ACL is applied to restrict which hosts may connect.",  # noqa: E501
                "Without an access-class, any host with IP reachability to the device can attempt to authenticate to the HTTP management interface, increasing the attack surface.",  # noqa: E501
                "Connecting to an unprotected HTTP/HTTPS management interface requires only IP reachability and standard browser or curl tooling.",  # noqa: E501
                "Restrict HTTP/HTTPS management access to authorised hosts:\n\n```\nip http access-class <acl-number>\n```",  # noqa: E501
                "CIS 2.5.2"
            )
        return None

    # CIS 2.5.3 - Ensure 'ip http authentication' is set
    def _has_http_authentication(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        return len(parser.find_objects(r"^ip http auth")) > 0

    def get_http_authentication(self, filename: str):
        parser = self.parse_cisco_ios_config_file(filename)
        http_enabled = parser.find_objects(r"^ip http server")
        https_enabled = parser.find_objects(r"^ip http secure-server")
        if (len(http_enabled) > 0 or len(https_enabled) > 0) and not self._has_http_authentication(filename):
            return Issue(
                "HTTP/HTTPS authentication method not configured",
                "No explicit authentication method is configured for the HTTP/HTTPS management service. The default authentication method may be the enable password, which is weaker than AAA.",  # noqa: E501
                "Without explicit AAA or local authentication, the HTTP interface may fall back to the enable password for authentication, which is weaker than a proper AAA method list.",  # noqa: E501
                "Accessing the HTTP management interface with default credentials requires only IP connectivity and knowledge of the enable password.",  # noqa: E501
                "Configure authentication for the HTTP management service:\n\n```\nip http authentication aaa\n```",  # noqa: E501
                "CIS 2.5.3"
            )
        return None

    def analyze(self, config_file) -> None:
        issues = []

        issues.append(self.get_http_service(config_file))
        issues.append(self.get_http_access_class(config_file))
        issues.append(self.get_http_authentication(config_file))

        for issue in issues:
            if issue is not None:
                self.add_issue(issue)
