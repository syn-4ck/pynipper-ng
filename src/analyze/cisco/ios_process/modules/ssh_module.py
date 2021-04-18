from analyze.cisco.parse_config import parse_cisco_ios_config_file
from ...ios_process.cisco_ios_issue import CiscoIOSIssue

# If the device has ssh configured -> true


def _has_cisco_ios_ssh(filename: str) -> bool:
    parser = parse_cisco_ios_config_file(filename)
    transport_disable = parser.find_objects("transport input none")
    ssh_disable = parser.find_objects("no transport input ssh")
    ssh_ip_disable = parser.find_objects("no ip ssh")
    if (len(transport_disable) > 0 or len(ssh_disable) > 0 or len(ssh_ip_disable) > 0):
        return False
    else:
        return True

# Number of ssh version


def _get_cisco_ios_ssh_version(filename: str) -> str:
    parser = parse_cisco_ios_config_file(filename)
    ssh_version = parser.find_objects("ip ssh version")
    if (len(ssh_version) > 0):
        version = host[0].re_match_typed(
            r'^ip ssh version\s+(\S+)', default='')
        return version
    else:
        return None


def get_cisco_ios_ssh(issues: list, filename: str):
    if (not _has_cisco_ios_ssh(filename) or _get_cisco_ios_ssh_version(filename) is None or _get_cisco_ios_ssh_version(filename) != 2):
        ssh_version_issue = CiscoIOSIssue(
            "SSH Protocol Version",
            "The SSH service is commonly used for encrypted command-based remote device management. There are multiple SSH protocol versions and SSH servers will often support multiple versions to maintain backwards compatibility. Although flaws have been identified in implementations of version 2 of the SSH protocol, fundamental flaws exist in SSH protocol version 1.",
            "An attacker who was able to intercept SSH protocol version 1 traffic would be able to perform a man-in-the-middle style attack. The attacker could then capture network traffic and possibly authentication credentials.",
            "Although vulnerabilities are widely known, exploiting the vulnerabilities in the SSH protocol can be difficult.",
            "When SSH protocol version 2 support is configured on Cisco IOS devices, support for version 1 will be disabled. This can be configured with the following command: ip ssh version 2"
        )
        issues.append(ssh_version_issue)

# Number of max. retries configured to login with ssh


def get_cisco_ios_ssh_retries(filename: str) -> str:
    parser = parse_cisco_ios_config_file(filename)
    retries = parser.find_objects("ip ssh authentication-retries")
    if (len(retries) > 0):
        max_retries = host[0].re_match_typed(
            r'^ip ssh authentication-retries\s+(\S+)', default='')
        return max_retries
    else:
        return None

# Number of seconds of ssh timeout



def get_cisco_ios_ssh_timeout(filename: str) -> str:
    parser = parse_cisco_ios_config_file(filename)
    timeout = parser.find_objects("ip ssh time-out")
    if (len(timeout) > 0):
        seconds = host[0].re_match_typed(
            r'^ip ssh time-out\s+(\S+)', default='')
        return seconds
    else:
        return None

# Get the source interface


def get_cisco_ios_ssh_interface(filename: str) -> str:
    parser = parse_cisco_ios_config_file(filename)
    src_interface = parser.find_objects("ip ssh source-interface")
    if (len(src_interface) > 0):
        interface = host[0].re_match_typed(
            r'^ip ssh source-interface\s+(\S+)', default='')
        return interface
    else:
        return None


def get_ssh_missconfigurations(filename: str) -> list:
    issues = []
    get_cisco_ios_ssh(issues, filename)
    # get_cisco_ios_http_access_list(issues,filename)
    # get_cisco_ios_http_auth(issues,filename)
    return issues
