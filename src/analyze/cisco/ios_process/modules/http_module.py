# flake8: noqa
from ...parse_config import parse_cisco_ios_config_file
from ...ios_process.cisco_ios_issue import CiscoIOSIssue

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


def get_cisco_ios_http_access_list(filename: str) -> str:
    parser = parse_cisco_ios_config_file(filename)
    access_list = parser.find_objects("ip http access-class")
    if (len(access_list) > 0):
        num = host[0].re_match_typed(
            r'^ip http access-class\s+(\S+)', default='')
        return num
    else:
        return "Undefined"

# Kind of auth in HTTP server


def get_cisco_ios_http_auth(filename: str) -> str:
    parser = parse_cisco_ios_config_file(filename)
    timeout = parser.find_objects("ip http auth")
    if (len(timeout) > 0):
        type = host[0].re_match_typed(
            r'^ip http auth(entication)?\s+(\S+)', default='')
        return seconds.split()[0]
    else:
        return None


def get_http_missconfigurations(filename: str) -> list:
    issues = []
    get_cisco_ios_http(issues, filename)
    # get_cisco_ios_http_access_list(issues,filename)
    # get_cisco_ios_http_auth(issues,filename)
    return issues
