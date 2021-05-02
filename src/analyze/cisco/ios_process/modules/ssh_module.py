# flake8: noqa
from ...parse_config import parse_cisco_ios_config_file
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
        version = ssh_version[0].re_match_typed(
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


def _get_cisco_ios_ssh_retries(filename: str) -> str:
    parser = parse_cisco_ios_config_file(filename)
    retries = parser.find_objects("ip ssh authentication-retries")
    if (len(retries) > 0):
        max_retries = retries[0].re_match_typed(
            r'^ip ssh authentication-retries\s+(\S+)', default='')
        return max_retries
    else:
        return None

def get_cisco_ios_ssh_reties(issues: list, filename: str):
    retries = _get_cisco_ios_ssh_retries(filename)
    if (retries is None or retries > 5):
        ssh_retries_issue = CiscoIOSIssue(
            "SSH retries misconfiguration",
            "The SSH service must have a defined number of retries, the recommended is between 0 and 5.",
            "Set a retries number allows to reduce the bruteforce and dictionary attacks. If a retry number is defined, the attacker can not test with an user multiple passwords.",
            "This issue improve the hardening of passwords in the network device.",
            "This can be configured with the following command: ip ssh authentication-retries <retry-number>."
        )
        issues.append(ssh_retries_issue)

# Number of seconds of ssh timeout



def _get_cisco_ios_ssh_timeout(filename: str) -> str:
    parser = parse_cisco_ios_config_file(filename)
    timeout = parser.find_objects("ip ssh time-out")
    if (len(timeout) > 0):
        seconds = timeout[0].re_match_typed(
            r'^ip ssh time-out\s+(\S+)', default='')
        return int(seconds)
    else:
        return None

def get_cisco_ios_ssh_timeout(issues: list, filename: str):
    timeout = _get_cisco_ios_ssh_timeout(filename)
    if (timeout is None or timeout > 120):
        ssh_iface_issue = CiscoIOSIssue(
            "SSH timeout misconfiguration",
            "The SSH service must have a defined timeout between 0 and 60 seconds.",
            "Set a timeout allows disable not used or malicious sessions in background.",
            "This issue only increase the device management security, it is not exploitable.",
            "This can be configured with the following command: ip ssh time-out <timeout-in-seconds>."
        )
        issues.append(ssh_iface_issue)

# Get the source interface


def _get_cisco_ios_ssh_interface(filename: str) -> str:
    parser = parse_cisco_ios_config_file(filename)
    src_interface = parser.find_objects("ip ssh source-interface")
    if (len(src_interface) > 0):
        interface = src_interface[0].re_match_typed(
            r'^ip ssh source-interface\s+(\S+)', default='')
        return interface
    else:
        return None

def get_cisco_ios_ssh_interface(issues: list, filename: str):
    if (_get_cisco_ios_ssh_interface(filename) is None):
        ssh_iface_issue = CiscoIOSIssue(
            "SSH source-interface enabled",
            "The SSH service must have a controlated set of source interfaces to manage the device",
            "To reduce bruteforce attacks is usefull have a set of source interfaces, logged and filtered, to access to SSH device management.",
            "This issue only increase the device management security, it is not exploitable, but it reduce bruteforce attacks.",
            "This can be configured with the following command: ip ssh source-interface <interface> "
        )
        issues.append(ssh_iface_issue)

def get_ssh_missconfigurations(filename: str) -> list:
    issues = []
    get_cisco_ios_ssh(issues, filename)
    get_cisco_ios_ssh_timeout(issues, filename)
    get_cisco_ios_ssh_reties(issues, filename)
    get_cisco_ios_ssh_interface(issues, filename)
    return issues
