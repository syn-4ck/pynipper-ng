
from ..core.base_plugin import GenericPlugin
from ....common.issue.issue import Issue


class PluginHTTP(GenericPlugin):

    def __init__(self):
        super().__init__()

    def name(self):
        return "HyperText Transfer Protocol (HTTP)"

    # If the device has http configured -> true

    def _has_http(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        http_enable = parser.find_objects("ip http server")
        http_disable = parser.find_objects("no ip http server")
        if (len(http_enable) > 0):
            return True
        elif (len(http_disable) > 0):
            return False
        else:
            return True  # by default IOS Cisco devices has HTTP

    def get_cisco_ios_http(self, filename: str):
        if (self._has_http(filename)):
            return Issue(
                "HyperText Transport Protocol Service",
                "Recent Cisco IOS-based devices support web-based administration using the HTTP protocol. Cisco web-based administration facilities can sometimes be basic but they do provide a simple method of administering remote devices. However, HTTP is a clear-text protocol and is vulnerable to various packet-capture techniques.",  # noqa: E501
                "An attacker who was able to monitor network traffic could capture authentication credentials.",  # noqa: E501
                "Network packet and password sniffing tools are widely available on the Internet. Once authentication credentials have been captured it is trivial to use the credentials to log in using the captured credentials.",  # noqa: E501
                "It is recommended that, if not required, the HTTP service be disabled. If a remote method of access to the device is required, consider using HTTPS or SSH. The encrypted HTTPS and SSH services may require a firmware or hardware upgrade. The HTTP service can be disabled with the following IOS command: no ip http server. If it is not possible to upgrade the device to use the encrypted HTTPS or SSH services, additional security can be configured."  # noqa: E501
            )
        return None

    # Number of access list should be used to restrict access to HTTP server

    def _get_cisco_ios_http_access_list(self, filename: str):
        parser = self.parse_cisco_ios_config_file(filename)
        access_list = parser.find_objects("ip http access-class")
        if (len(access_list) > 0):
            num = access_list[0].re_match_typed(
                r'^ip http access-class\s+(\S+)', default='')
            return int(num)
        else:
            return None

    def get_cisco_ios_http_access_list(self, filename: str):
        if (self._get_cisco_ios_http_access_list(filename) is None):
            return Issue(
                "ACL restrict for HTTP service",
                "The HTTP service was not configured with an access-list to restrict network access to the device.",
                "An attacker who was able to monitor network traffic could capture authentication credentials. This issue is made more serious with the enable password being used for authentication as this would give the attacker full administrative access to the device with the captured credentials. This issue is mitigated slightly by employing an access list to restrict network access to the device.",  # noqa: E501
                "Network packet and password sniffing tools are widely available on the Internet. Once authentication credentials have been captured it is trivial to use the credentials to log in using the captured credentials. Furthermore, it may be possible for an attacker to masquerade as the administrators host in order to bypass configured network access restrictions.",  # noqa: E501
                "If you can't disable HTTP, an access list can be configured to restrict access to the device. An access list can be specified with the following command:ip http access-class <access-list-number>"  # noqa: E501
            )
        return None

    # Kind of auth in HTTP server

    def _get_cisco_ios_http_auth(self, filename: str) -> str:
        parser = self.parse_cisco_ios_config_file(filename)
        timeout = parser.find_objects("ip http auth")
        if (len(timeout) > 0):
            auth_type = timeout[0].re_match_typed(
                r'^ip http auth(entication)?\s+(\S+)', default='')
            return auth_type.split()[0]
        else:
            return ""

    def get_cisco_ios_http_auth(self, filename: str):
        if (self._get_cisco_ios_http_auth(filename) == ""):
            return Issue(
                "Authentication mode to HTTP service",
                "The HTTP service was not configured with an access-list to restrict network access to the device.",
                "An attacker who was able to monitor network traffic could capture authentication credentials. This issue is made more serious with the enable password being used for authentication as this would give the attacker full administrative access to the device with the captured credentials. This issue is mitigated slightly by employing an access list to restrict network access to the device.",  # noqa: E501
                "Network packet and password sniffing tools are widely available on the Internet. Once authentication credentials have been captured it is trivial to use the credentials to log in using the captured credentials. Furthermore, it may be possible for an attacker to masquerade as the administrators host in order to bypass configured network access restrictions.",  # noqa: E501
                "If you can't disable HTTP, the authentication method can be changed using the following command (where the authentication method is either local, enable, tacacs or aaa): ip http authentication <authentication-method>"  # noqa: E501
            )
        return None

    def analyze(self, config_file) -> None:
        issues = []

        issues.append(self.get_cisco_ios_http(config_file))
        issues.append(self.get_cisco_ios_http_access_list(config_file))
        issues.append(self.get_cisco_ios_http_auth(config_file))

        for issue in issues:
            if issue is not None:
                self.add_issue(issue)
