from ciscoconfparse import CiscoConfParse
import re


def parse_cisco_ios_config_file(filename: str) -> CiscoConfParse:
    return CiscoConfParse(filename, syntax='ios')

# Information about the device
# ----------------------------

# Return the device hostname


def get_cisco_ios_hostname(filename: str) -> str:
    parser = parse_cisco_ios_config_file(filename)
    host = parser.find_objects("^hostname")
    if (len(host) > 0):
        hostname = host[0].re_match_typed(r'^hostname\s+(\S+)', default='')
        return hostname
    else:
        return "?"

# Return the device version


def get_cisco_ios_version(filename: str) -> str:
    parser = parse_cisco_ios_config_file(filename)
    regex = re.compile(r'.+\(.+\).*')
    version = parser.find_objects("^version")
    if (len(version) > 0):
        version_number = version[0].re_match_typed(
            r'^version\s+(\S+)', default='')
        if (not regex.search(version_number)):
            # if i don't know the full IOS version, i get the first one subversion
            # motivation: report all possible vulns, better report more and false positives
            version_number = version_number + '(1)'
        return version_number
    else:
        return "?"


# Generic configuration
# ---------------------

# If the device has NOT a password-encryption policy -> true
def get_cisco_ios_passwd_enc(filename: str) -> bool:
    parser = parse_cisco_ios_config_file(filename)
    passwd_enc = parser.find_objects("no service password-encryption")
    if (len(passwd_enc) > 0):
        return True
    else:
        return False

# Return the number of min. length chars of the password policy


def get_cisco_ios_passwd_length(filename: str) -> str:
    parser = parse_cisco_ios_config_file(filename)
    passwd_length = parser.find_objects("security passwords min-length")
    if (len(passwd_length) > 0):
        passwd_length_number = passwd_length[0].re_match_typed(
            r'^security passwords min-length\s+(\S+)', default='')
        return passwd_length_number
    else:
        return "No specified"

# If the device has IP source routing configured -> true


def get_cisco_ios_ip_source_routing(filename: str) -> bool:
    parser = parse_cisco_ios_config_file(filename)
    ip_src_routing = parser.find_objects("no ip source routing")
    if (len(ip_src_routing) > 0):
        return False
    else:
        return True

# If the device has BOOTP server configured -> true


def get_cisco_ios_bootp(filename: str) -> bool:
    parser = parse_cisco_ios_config_file(filename)
    bootp_server = parser.find_objects("no ip bootp server")
    if (len(bootp_server) > 0):
        return False
    else:
        return True

# If the device has TCP keep-alives in -> true


def get_cisco_ios_tcp_keep_alives_in(filename: str) -> bool:
    parser = parse_cisco_ios_config_file(filename)
    keep_alives_in = parser.find_objects("service tcp-keepalives-in")
    if (len(keep_alives_in) > 0):
        return True
    else:
        return False

# If the device has TCP keep-alives out -> true


def get_cisco_ios_tcp_keep_alives_out(filename: str) -> bool:
    parser = parse_cisco_ios_config_file(filename)
    keep_alives_out = parser.find_objects("service tcp-keepalives-out")
    if (len(keep_alives_out) > 0):
        return True
    else:
        return False

# Services configuration
# -----------------------

# If the device has telnet configured -> true


def get_cisco_ios_telnet(filename: str) -> bool:
    parser = parse_cisco_ios_config_file(filename)
    transport_disable = parser.find_objects("transport input none")
    ssh_enable = parser.find_objects("transport input ssh")
    telnet_disable = parser.find_objects("no transport input telnet")
    if (len(transport_disable) > 0 or len(ssh_enable) > 0 or len(telnet_disable) > 0):
        return False
    else:
        return True
