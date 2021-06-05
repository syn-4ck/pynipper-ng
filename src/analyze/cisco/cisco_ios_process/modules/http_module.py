# flake8: noqa
from ...cisco_parser.parse_config import parse_cisco_ios_config_file
from ...cisco_ios_process.cisco_ios_issue import CiscoIOSIssue

# If the device has http configured -> true


def _has_http(filename: str) -> bool:
    parser = parse_cisco_ios_config_file(filename)
    http_enable = parser.find_objects("ip http server")
    http_disable = parser.find_objects("no ip http server")
    if (len(http_enable) > 0):
        return True
    elif (len(http_disable) > 0):
        return False
    else:
        return True  # by default IOS Cisco devices has HTTP


def get_cisco_ios_http(issues: list, filename: str) -> CiscoIOSIssue:
    if (_has_http(filename)):
        http_issue = CiscoIOSIssue(
            "HyperText Transport Protocol Service",
            "Recent Cisco IOS-based devices support web-based administration using the HTTP protocol. Cisco web-based administration facilities can sometimes be basic but they do provide a simple method of administering remote devices. However, HTTP is a clear-text protocol and is vulnerable to various packet-capture techniques.",
            "An attacker who was able to monitor network traffic could capture authentication credentials.",
            "Network packet and password sniffing tools are widely available on the Internet. Once authentication credentials have been captured it is trivial to use the credentials to log in using the captured credentials.",
            "It is recommended that, if not required, the HTTP service be disabled. If a remote method of access to the device is required, consider using HTTPS or SSH. The encrypted HTTPS and SSH services may require a firmware or hardware upgrade. The HTTP service can be disabled with the following IOS command: no ip http server. If it is not possible to upgrade the device to use the encrypted HTTPS or SSH services, additional security can be configured."
        )
        issues.append(http_issue)

# Number of access list should be used to restrict access to HTTP server


def _get_cisco_ios_http_access_list(filename: str) -> str:
    parser = parse_cisco_ios_config_file(filename)
    access_list = parser.find_objects("ip http access-class")
    if (len(access_list) > 0):
        num = access_list[0].re_match_typed(
            r'^ip http access-class\s+(\S+)', default='')
        return int(num)
    else:
        return None


def get_cisco_ios_http_access_list(issues: list, filename: str) -> CiscoIOSIssue:
    if (_get_cisco_ios_http_access_list(filename) is None):
        http_acl_issue = CiscoIOSIssue(
            "ACL restrict for HTTP service",
            "The HTTP service was not configured with an access-list to restrict network access to the device.",
            "An attacker who was able to monitor network traffic could capture authentication credentials. This issue is made more serious with the enable password being used for authentication as this would give the attacker full administrative access to the device with the captured credentials. This issue is mitigated slightly by employing an access list to restrict network access to the device.",
            "Network packet and password sniffing tools are widely available on the Internet. Once authentication credentials have been captured it is trivial to use the credentials to log in using the captured credentials. Furthermore, it may be possible for an attacker to masquerade as the administrators host in order to bypass configured network access restrictions.",
            "If you can't disable HTTP, an access list can be configured to restrict access to the device. An access list can be specified with the following command:ip http access-class <access-list-number>"
        )
        issues.append(http_acl_issue)

# Kind of auth in HTTP server


def _get_cisco_ios_http_auth(filename: str) -> str:
    parser = parse_cisco_ios_config_file(filename)
    timeout = parser.find_objects("ip http auth")
    if (len(timeout) > 0):
        type = timeout[0].re_match_typed(
            r'^ip http auth(entication)?\s+(\S+)', default='')
        return type.split()[0]
    else:
        return None


def get_cisco_ios_http_auth(issues: list, filename: str) -> CiscoIOSIssue:
    if (_get_cisco_ios_http_auth(filename) is None):
        http_auth_issue = CiscoIOSIssue(
            "Authentication mode to HTTP service",
            "The HTTP service was not configured with an access-list to restrict network access to the device.",
            "An attacker who was able to monitor network traffic could capture authentication credentials. This issue is made more serious with the enable password being used for authentication as this would give the attacker full administrative access to the device with the captured credentials. This issue is mitigated slightly by employing an access list to restrict network access to the device.",
            "Network packet and password sniffing tools are widely available on the Internet. Once authentication credentials have been captured it is trivial to use the credentials to log in using the captured credentials. Furthermore, it may be possible for an attacker to masquerade as the administrators host in order to bypass configured network access restrictions.",
            "If you can't disable HTTP, the authentication method can be changed using the following command (where the authentication method is either local, enable, tacacs or aaa): ip http authentication <authentication-method>"
        )
        issues.append(http_auth_issue)


def get_http_missconfigurations(filename: str) -> list:
    issues = []
    get_cisco_ios_http(issues, filename)
    get_cisco_ios_http_access_list(issues, filename)
    get_cisco_ios_http_auth(issues, filename)
    return issues
